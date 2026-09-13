#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""dnkd — lokalni razrjesitelj imena .dnk (MASKA faza F2). stdlib only.

Sto ovo zamjenjuje: A-zapis kao CINJENICU o tvojoj lokaciji. Ime se ne
razrjesava pitanjem mreze "gdje je X", nego lokalnim PULL-om (ZAKON17)
potpisane tvrdnje iz sidra, njezinom verifikacijom protiv PINOVANOG kljuca, i
lokalnim mapiranjem na stabilnu adresu iz 100.64.0.0/10 (RFC 6598).

Povijesni model je ARPANET HOSTS.TXT: razrjesenje imena bilo je LOKALNA
funkcija hosta (datoteka koju host povlaci i drzi kod sebe), a ne mrezna
usluga; DNS je 1983. nastao iz operativne nuzde skaliranja (RFC 882/883), ne iz
arhitektonskog uvjerenja. dnkd je isti model — s kriptografskim potpisom
umjesto centralnog SRI-NIC-a i s rokom trajanja umjesto rucnog azuriranja.

Sto dnkd NIJE i ne smije postati:
  * rekurzivni resolver — sve osim .dnk vraca REFUSED. Resolver koji
    prosljedjuje postaje proxy kroz koji ide sav tvoj promet: nova dodirna
    tocka, tocno ono sto MASKA uklanja.
  * TLS terminator s vlastitim CA u sistemskom trust storeu — to je STVARNA
    sigurnosna steta za korisnika (svaki tvoj kljuc postaje kljuc za sve
    stranice na tom uredjaju). Za .dnk imena TLS se terminira unutar aplikacije
    na loopbacku; ovaj demon NE dira trust store. Vidi docs/MASKA-FAZE.md.

Tri stanja po imenu, nikad tihi 0/False (doktrina Z53): OK | ALARM | NEPOZNATO.
Svako razrjesenje ide u GODOVI dnevnik — i uspjesno i neuspjesno.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import socket
import socketserver
import ssl
import struct
import sys
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from . import dns_wire as dw
from . import suglasnost as sg
from . import ui as ui_modul
from .godovi import Godovi
from .pelud import Pelud, PeludGreska, PSEUDO_TLD, parsiraj

VERZIJA = "1.0.0"
MASKA_DIR = Path(os.environ.get("MASKA_DIR", str(Path.home() / ".maska")))
KONFIG_DATOTEKA = MASKA_DIR / "dnkd.json"
MAX_TIJELO = 8192                 # PELUD zapis je ~350 B; sve iznad je smece ili napad

ZADANI_KONFIG: dict = {
    "slusaj_dns": "127.0.0.53:5353",
    "slusaj_http": "127.0.0.1:8099",
    "mapiranje_mreza": "100.80.0.0/12",
    "sidra": [],
    "imena": {},
    "na_nesuglasje": "odbij",
    "ttl_s": 120,
    "osvjezavanje_s": 60,
    "http_timeout_s": 5,
    "godovi": str(MASKA_DIR / "godovi.jsonl"),
    "mapiranje_datoteka": str(MASKA_DIR / "mapiranje.json"),
}


def log(poruka: str) -> None:
    print(f"[{time.strftime('%Y-%m-%dT%H:%M:%S')}] {poruka}", flush=True)


def log_err(poruka: str) -> None:
    print(f"[{time.strftime('%Y-%m-%dT%H:%M:%S')}] GRESKA: {poruka}", file=sys.stderr, flush=True)


def _adresa(spoj: str, zadani_port: int) -> tuple[str, int]:
    if ":" in spoj:
        host, _, port = spoj.rpartition(":")
        return host or "127.0.0.1", int(port)
    return spoj, zadani_port


# =============================================================================
# Mapiranje imena -> stabilna lokalna adresa
# =============================================================================
class Mapiranje:
    """Deterministicno, TRAJNO ime -> adresa iz RFC 6598 prostora.

    Deterministicno da isti uredjaj uvijek dobije istu adresu (bookmarki,
    firewall pravila, /etc/hosts izvoz), a trajno jer determinizam pada na
    koliziji: dva imena s istim izvedenim indeksom rjesavaju se JEDNOM i ta
    se odluka pamti, inace bi drugo ime mijenjalo adresu ovisno o redoslijedu
    pokretanja.
    """

    def __init__(self, mreza: str, datoteka: str | os.PathLike):
        self.mreza = ipaddress.ip_network(mreza, strict=False)
        if self.mreza.version != 4:
            raise ValueError("mapiranje_mreza mora biti IPv4 (RFC 6598: 100.64.0.0/10)")
        self.datoteka = Path(datoteka).expanduser()
        self.datoteka.parent.mkdir(parents=True, exist_ok=True)
        self._zauzeto: dict[str, str] = {}
        self._lock = threading.Lock()
        self._ucitaj()

    def _ucitaj(self) -> None:
        try:
            podaci = json.loads(self.datoteka.read_text(encoding="utf-8"))
            if isinstance(podaci, dict):
                self._zauzeto = {str(k): str(v) for k, v in podaci.get("imena", {}).items()}
        except (OSError, json.JSONDecodeError):
            self._zauzeto = {}

    def _zapisi(self) -> None:
        tmp = self.datoteka.with_suffix(self.datoteka.suffix + ".tmp")
        tmp.write_text(json.dumps({"mreza": str(self.mreza), "imena": self._zauzeto},
                                  ensure_ascii=False, indent=1), encoding="utf-8")
        os.replace(tmp, self.datoteka)

    def adresa(self, ime: str) -> str:
        with self._lock:
            if ime in self._zauzeto:
                return self._zauzeto[ime]
            zauzete = set(self._zauzeto.values())
            ukupno = self.mreza.num_addresses
            from hashlib import sha3_256
            poc = int(sha3_256(ime.encode("utf-8")).hexdigest()[:16], 16) % ukupno
            baza = int(self.mreza.network_address)
            for k in range(ukupno):
                kandidat = ipaddress.IPv4Address(baza + (poc + k) % ukupno)
                zadnji = int(kandidat) & 0xFF
                if zadnji in (0, 255):                 # izbjegni .0/.255 zbog alata koji ih odbijaju
                    continue
                tekst = str(kandidat)
                if tekst not in zauzete:
                    self._zauzeto[ime] = tekst
                    self._zapisi()
                    return tekst
            raise RuntimeError(f"mreza {self.mreza} je puna — nema slobodne adrese za {ime}")

    def sve(self) -> dict[str, str]:
        with self._lock:
            return dict(self._zauzeto)


# =============================================================================
# Stanje po imenu
# =============================================================================
@dataclass
class Unos:
    ime: str
    adresa: str
    zapis: Pelud | None = None
    stanje: str = "NEPOZNATO"
    razlog: str = "jos_nije_mjereno"
    zadnji_pull_t: float = 0.0
    zadnji_ok_t: float = 0.0
    po_sidru: dict = field(default_factory=dict)
    suglasnost: dict = field(default_factory=lambda: {"stanje": "NEPOZNATO", "razlog": "jos_nije_mjereno"})
    posluzi: bool = False               # smije li se odgovarati na DNS upite za ovo ime

    def kao_dict(self, sada: float | None = None) -> dict:
        sada = time.time() if sada is None else sada
        z = self.zapis
        return {
            "ime": self.ime,
            "adresa": self.adresa,
            "stanje": self.stanje,
            "razlog": self.razlog,
            "posluzuje_se": self.posluzi,
            "visina": (z.visina if z else None),
            "lokatori": (list(z.lokatori) if z else []),
            "preostalo_s": (z.preostalo_s(sada) if z else None),
            "exp": (z.exp if z else None),
            "pk": (z.pk if z else None),
            "zadnji_pull_prije_s": (round(sada - self.zadnji_pull_t, 1) if self.zadnji_pull_t else None),
            "zadnji_ok_prije_s": (round(sada - self.zadnji_ok_t, 1) if self.zadnji_ok_t else None),
            "po_sidru": self.po_sidru,
            "suglasnost": self.suglasnost,
        }


# =============================================================================
# Razrjesitelj
# =============================================================================
class Razrjesitelj:
    def __init__(self, konfig: dict):
        self.konfig = konfig
        self.mapiranje = Mapiranje(konfig["mapiranje_mreza"], konfig["mapiranje_datoteka"])
        self.godovi = Godovi(konfig["godovi"])
        self.unosi: dict[str, Unos] = {}
        self.lock = threading.Lock()
        self.ssl_kontekst = ssl.create_default_context()
        self.brojac_upita = 0
        self.pokrenut_t = time.time()
        for ime in konfig["imena"]:
            self.unosi[ime] = Unos(ime=ime, adresa=self.mapiranje.adresa(ime))

    # -- PULL --------------------------------------------------------------
    def _pull(self, sidro: str, ime: str) -> tuple[str | None, str]:
        """Povuci PELUD zapis sa sidra. (tekst, razlog). Nikad iznimka van."""
        url = sidro.rstrip("/") + "/" + ime + ".txt"
        zahtjev = urllib.request.Request(
            url, headers={"User-Agent": f"maska-dnkd/{VERZIJA}", "Accept": "text/plain"})
        try:
            with urllib.request.urlopen(zahtjev, timeout=self.konfig["http_timeout_s"],
                                        context=self.ssl_kontekst) as odgovor:
                if odgovor.status != 200:
                    return None, f"http_{odgovor.status}"
                return odgovor.read(MAX_TIJELO).decode("utf-8", "replace").strip(), ""
        except urllib.error.HTTPError as e:
            return None, f"http_{e.code}"
        except ssl.SSLError as e:
            # TLS se NE gasi na gresku. PELUD je potpisan pa MITM ne moze lagati
            # o sadrzaju, ali tihi prelazak na neprovjeren TLS je navika koja se
            # kasnije naplati na svemu ostalom (usporedi eho6_node CERT_NONE put).
            return None, f"tls_greska({type(e).__name__})"
        except (urllib.error.URLError, socket.timeout, OSError) as e:
            return None, f"mrezna_greska({type(e).__name__})"
        except UnicodeDecodeError:
            return None, "odgovor_nije_tekst"

    def _pinovani_pk(self, ime: str) -> str | None:
        return (self.konfig["imena"].get(ime) or {}).get("pk")

    def _javno_zrcalo(self, ime: str) -> str | None:
        return (self.konfig["imena"].get(ime) or {}).get("javno_zrcalo")

    # -- razrjesenje -------------------------------------------------------
    def osvjezi(self, ime: str) -> Unos:
        """Povuci sa SVIH sidara, verificiraj, izmjeri suglasnost, upisi u godove."""
        sada = time.time()
        poc = time.monotonic()
        with self.lock:
            unos = self.unosi.get(ime)
        if unos is None:
            raise KeyError(ime)

        pin = self._pinovani_pk(ime)
        sidra = self.konfig["sidra"] or []
        po_sidru: dict[str, dict] = {}
        valjani: list[tuple[str, Pelud]] = []

        for sidro in sidra:
            tekst, razlog = self._pull(sidro, ime)
            if tekst is None:
                po_sidru[sidro] = {"stanje": "NEPOZNATO", "razlog": razlog}
                continue
            try:
                zapis = parsiraj(tekst)
            except PeludGreska as e:
                po_sidru[sidro] = {"stanje": "ALARM", "razlog": f"zapis_neispravan: {e}"}
                continue
            ok, razlog_v = zapis.provjeri(pin, sada=sada)
            if not ok:
                po_sidru[sidro] = {"stanje": "ALARM", "razlog": razlog_v,
                                   "visina": zapis.visina}
                continue
            po_sidru[sidro] = {"stanje": "OK", "razlog": "", "visina": zapis.visina,
                               "preostalo_s": zapis.preostalo_s(sada)}
            valjani.append((sidro, zapis))

        ms = int((time.monotonic() - poc) * 1000)

        if not valjani:
            # nijedno sidro nije dalo valjanu tvrdnju. Razlikuj "mjerenje palo"
            # (NEPOZNATO) od "tvrdnja je stigla i NIJE valjana" (ALARM) — poruka
            # koja imenuje krivi uzrok gora je od nikakve (Z53 t.1).
            ima_alarm = any(s["stanje"] == "ALARM" for s in po_sidru.values())
            stanje = "ALARM" if ima_alarm else "NEPOZNATO"
            razlog = ("; ".join(f"{s}: {v['razlog']}" for s, v in po_sidru.items())
                      or "nema_konfiguriranih_sidara")
            with self.lock:
                unos.stanje, unos.razlog = stanje, razlog
                unos.po_sidru = po_sidru
                unos.zadnji_pull_t = sada
                # stari valjani zapis ostaje posluzen dok mu rok ne istekne:
                # pad sidra ne smije odmah ubiti ime koje je dokazano zivo
                if unos.zapis is not None and unos.zapis.preostalo_s(sada) > 0:
                    unos.posluzi = True
                    unos.razlog += " (posluzujem zapis koji jos vrijedi)"
                else:
                    unos.posluzi = False
            self.godovi.upisi(ime, stanje, razlog=razlog[:300], ms=ms,
                              sidara=len(sidra))
            return unos

        # najvisa visina lanca je najnovija tvrdnja; kod izjednacenja onaj s duljim rokom
        valjani.sort(key=lambda p: (p[1].visina, p[1].exp), reverse=True)
        izvor, zapis = valjani[0]

        razilazenje = ""
        if len(valjani) > 1:
            skupovi = {tuple(sorted(z.lokatori)) for _s, z in valjani}
            if len(skupovi) > 1:
                razilazenje = ("sidra se razilaze o lokatorima "
                               f"({len(skupovi)} razlicita skupa)")

        nalaz = sg.provjeri(zapis, self._javno_zrcalo(ime),
                            timeout=self.konfig["http_timeout_s"])

        stanje = "OK"
        razlozi = []
        if razilazenje:
            stanje, _ = "ALARM", razlozi.append(razilazenje)
        if nalaz.alarm:
            stanje = "ALARM"
            razlozi.append(f"nesuglasje s javnim DNS-om: {nalaz.razlog}")

        posluzi = True
        if nalaz.alarm and self.konfig["na_nesuglasje"] == "odbij":
            posluzi = False
            razlozi.append("odbijam posluzivati do razrjesenja (na_nesuglasje=odbij)")

        with self.lock:
            unos.zapis = zapis
            unos.stanje = stanje
            unos.razlog = "; ".join(razlozi)
            unos.po_sidru = po_sidru
            unos.suglasnost = nalaz.kao_dict()
            unos.zadnji_pull_t = sada
            unos.posluzi = posluzi
            if stanje == "OK":
                unos.zadnji_ok_t = sada

        self.godovi.upisi(ime, stanje, razlog=(unos.razlog or None), ms=ms,
                          sidro=izvor, visina=zapis.visina, adresa=unos.adresa,
                          suglasnost=nalaz.stanje, sidara_valjanih=len(valjani),
                          sidara=len(sidra))
        return unos

    def razrijesi(self, ime: str, dopusti_pull: bool = True) -> Unos | None:
        """Unos za ime; povlaci samo kad je tvrdnja istekla ili je jos nema."""
        with self.lock:
            unos = self.unosi.get(ime)
        if unos is None:
            return None
        sada = time.time()
        istekao = (unos.zapis is None) or (unos.zapis.preostalo_s(sada) <= 0)
        if dopusti_pull and istekao:
            try:
                return self.osvjezi(ime)
            except Exception as e:                      # demon ne smije pasti na jednom imenu
                log_err(f"osvjezi({ime}) iznimka: {type(e).__name__}: {e}")
                with self.lock:
                    unos.stanje, unos.razlog = "NEPOZNATO", f"iznimka: {type(e).__name__}"
                return unos
        return unos

    # -- nadzorne povrsine -------------------------------------------------
    def zdravlje(self) -> dict:
        sada = time.time()
        with self.lock:
            unosi = [u.kao_dict(sada) for u in self.unosi.values()]
        vatre = []
        for u in unosi:
            if u["stanje"] == "ALARM":
                vatre.append({"razlog": f"{u['ime']}: {u['razlog']}", "ozbiljnost": "critical"})
            elif u["stanje"] == "NEPOZNATO":
                vatre.append({"razlog": f"{u['ime']}: {u['razlog']}", "ozbiljnost": "warning"})
        if not self.konfig["sidra"]:
            vatre.append({"razlog": "nema konfiguriranih sidara — dnkd ne moze nista povuci",
                          "ozbiljnost": "critical"})
        if any(v["ozbiljnost"] == "critical" for v in vatre):
            stanje = "alarm"
        elif vatre:
            stanje = "NEPOZNATO"
        else:
            stanje = "ok"
        cijel, greske = self.godovi.provjeri()
        if not cijel:
            stanje = "alarm"
            vatre.append({"razlog": f"godovi lanac razbijen: {greske[0] if greske else '?'}",
                          "ozbiljnost": "critical"})
        return {
            "agent_id": "dnkd",
            "vrijeme": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(sada)),
            "stanje": stanje,
            "vatre": vatre,
            "verzija": VERZIJA,
            "uptime_s": round(sada - self.pokrenut_t, 1),
            "dok_count": self.godovi.broj(),
            "upita": self.brojac_upita,
            "imena": unosi,
            "godovi": self.godovi.sazetak(),
            "godovi_lanac": "CIJEL" if cijel else "RAZBIJEN",
        }


# =============================================================================
# DNS posluzitelj
# =============================================================================
class _DnsJezgra:
    def __init__(self, razrjesitelj: Razrjesitelj):
        self.r = razrjesitelj
        # TTL koji se posluzuje nikad nije dulji od ostatka tvrdnje: klijent ne
        # smije kesirati adresu dulje nego sto PELUD za nju jamci.
        self.ttl_gornja_granica = max(1, int(razrjesitelj.konfig["ttl_s"]))

    def odgovori(self, sirovo: bytes) -> bytes | None:
        try:
            upit = dw.parsiraj_upit(sirovo)
        except dw.DnsGreska:
            return dw.odgovor_formerr(sirovo)

        self.r.brojac_upita += 1
        ime = upit.ime

        if not ime.endswith(PSEUDO_TLD.lstrip(".")) and not ime.endswith(PSEUDO_TLD):
            # sve izvan .dnk je tudji posao — REFUSED, nikad prosljedjivanje
            return dw.odgovor_greska(upit, dw.RCODE_REFUSED)
        if upit.klasa != dw.KLASA_IN:
            return dw.odgovor_greska(upit, dw.RCODE_NOTIMP)

        unos = self.r.razrijesi(ime)
        if unos is None:
            return dw.odgovor_greska(upit, dw.RCODE_NXDOMAIN)

        if not unos.posluzi:
            # izmjeren problem koji nije "ime ne postoji": SERVFAIL je istina,
            # NXDOMAIN bi bio laz koju klijent kesira
            return dw.odgovor_greska(upit, dw.RCODE_SERVFAIL)

        ttl = (min(self.ttl_gornja_granica, unos.zapis.preostalo_s())
               if unos.zapis else 1)
        ttl = max(1, ttl)
        if upit.tip in (dw.TIP_A, dw.TIP_ANY):
            return dw.odgovor_a(upit, unos.adresa, ttl)
        if upit.tip == dw.TIP_TXT and unos.zapis is not None:
            return dw.odgovor_txt(upit, unos.zapis.txt_dijelovi(), ttl)
        if upit.tip in (dw.TIP_AAAA, dw.TIP_CNAME, dw.TIP_SOA, dw.TIP_NS, dw.TIP_TXT):
            return dw.odgovor_prazan(upit)          # ime postoji, taj tip ne (NODATA)
        return dw.odgovor_greska(upit, dw.RCODE_NOTIMP)


class _UdpHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        podaci, utor = self.request
        odgovor = self.server.jezgra.odgovori(podaci)
        if odgovor:
            utor.sendto(odgovor, self.client_address)


class _TcpHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        self.request.settimeout(5)
        try:
            glava = self.request.recv(2)
            if len(glava) < 2:
                return
            duzina = struct.unpack(">H", glava)[0]
            tijelo = b""
            while len(tijelo) < duzina:
                dio = self.request.recv(duzina - len(tijelo))
                if not dio:
                    return
                tijelo += dio
            odgovor = self.server.jezgra.odgovori(tijelo)
            if odgovor:
                self.request.sendall(struct.pack(">H", len(odgovor)) + odgovor)
        except (socket.timeout, OSError):
            return


class _UdpServer(socketserver.ThreadingUDPServer):
    allow_reuse_address = True
    daemon_threads = True


class _TcpServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


# =============================================================================
# HTTP nadzor + upravljacka ploca
# =============================================================================
class _HttpHandler(BaseHTTPRequestHandler):
    server_version = f"maska-dnkd/{VERZIJA}"
    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args) -> None:      # noqa: A002
        log(f"HTTP {self.address_string()} {format % args}")

    # -- pomocno -----------------------------------------------------------
    def _posalji(self, tijelo: bytes, tip: str = "application/json; charset=utf-8",
                 status: int = 200) -> None:
        self.send_response(status)
        self.send_header("Content-Type", tip)
        self.send_header("Content-Length", str(len(tijelo)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.end_headers()
        self.wfile.write(tijelo)

    def _json(self, podaci: dict, status: int = 200) -> None:
        self._posalji(json.dumps(podaci, ensure_ascii=False, indent=1).encode("utf-8"),
                      status=status)

    def _greska(self, status: int, razlog: str) -> None:
        self._json({"greska": razlog, "status": status}, status)

    def _lokalni_zahtjev(self) -> bool:
        """Obrana od CSRF/DNS-rebinding na lokalnu plocu: Host i Origin moraju biti nasi."""
        dopusteni_host = {f"127.0.0.1:{self.server.server_address[1]}",
                          f"localhost:{self.server.server_address[1]}"}
        if (self.headers.get("Host") or "") not in dopusteni_host:
            return False
        origin = self.headers.get("Origin")
        if origin and origin not in {f"http://{h}" for h in dopusteni_host}:
            return False
        return True

    # -- rute --------------------------------------------------------------
    def do_GET(self) -> None:
        put = self.path.split("?")[0].rstrip("/") or "/"
        r: Razrjesitelj = self.server.razrjesitelj
        if put in ("/", "/ploca"):
            self._posalji(ui_modul.ploca(self.server.server_address[1]).encode("utf-8"),
                          "text/html; charset=utf-8")
        elif put in ("/borg/health.json", "/health"):
            self._json(r.zdravlje())
        elif put == "/dnkd/stanje":
            self._json({"konfig": {k: v for k, v in r.konfig.items() if k != "imena"},
                        "imena_konfig": r.konfig["imena"],
                        "mapiranje": r.mapiranje.sve(),
                        "zdravlje": r.zdravlje()})
        elif put == "/dnkd/godovi":
            n = 50
            if "?" in self.path:
                from urllib.parse import parse_qs
                n = int((parse_qs(self.path.split("?", 1)[1]).get("n") or ["50"])[0])
            n = max(1, min(n, 1000))
            cijel, greske = r.godovi.provjeri()
            self._json({"lanac": "CIJEL" if cijel else "RAZBIJEN", "greske": greske,
                        "ukupno": r.godovi.broj(), "zapisi": r.godovi.zadnji(n)})
        elif put == "/favicon.ico":
            self._posalji(b"", "image/x-icon", 204)
        else:
            self._greska(404, f"nepoznata ruta: {put}")

    def do_POST(self) -> None:
        put = self.path.split("?")[0].rstrip("/")
        r: Razrjesitelj = self.server.razrjesitelj
        if not self._lokalni_zahtjev():
            self._greska(403, "zahtjev nije s lokalne ploce (Host/Origin ne odgovaraju)")
            return
        duzina = int(self.headers.get("Content-Length") or 0)
        sirovo = self.rfile.read(min(duzina, MAX_TIJELO)) if duzina else b"{}"
        try:
            tijelo = json.loads(sirovo.decode("utf-8") or "{}")
            if not isinstance(tijelo, dict):
                raise ValueError("tijelo mora biti JSON objekt")
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as e:
            self._greska(400, f"tijelo nije valjan JSON objekt: {e}")
            return

        if put == "/dnkd/osvjezi":
            ime = tijelo.get("ime")
            imena = [ime] if ime else list(r.konfig["imena"].keys())
            if not imena:
                self._greska(400, "nema imena u konfiguraciji koje bi se osvjezilo")
                return
            rezultat = []
            for i in imena:
                if i not in r.unosi:
                    rezultat.append({"ime": i, "stanje": "ALARM",
                                     "razlog": "ime nije u konfiguraciji"})
                    continue
                try:
                    rezultat.append(r.osvjezi(i).kao_dict())
                except Exception as e:
                    rezultat.append({"ime": i, "stanje": "NEPOZNATO",
                                     "razlog": f"{type(e).__name__}: {e}"})
            self._json({"osvjezeno": rezultat})
        elif put == "/dnkd/godovi/provjeri":
            cijel, greske = r.godovi.provjeri()
            self._json({"lanac": "CIJEL" if cijel else "RAZBIJEN", "greske": greske,
                        "ukupno": r.godovi.broj()})
        else:
            self._greska(404, f"nepoznata ruta: {put}")


class _HttpServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


# =============================================================================
# Konfiguracija
# =============================================================================
def ucitaj_konfig(putanja: str | os.PathLike | None = None) -> dict:
    p = Path(putanja).expanduser() if putanja else KONFIG_DATOTEKA
    konfig = dict(ZADANI_KONFIG)
    if p.exists():
        try:
            korisnicki = json.loads(p.read_text(encoding="utf-8"))
        except json.JSONDecodeError as e:
            raise SystemExit(f"konfiguracija {p} nije valjan JSON: {e}")
        nepoznata = sorted(set(korisnicki) - set(ZADANI_KONFIG) - {"_biljeska"})
        if nepoznata:
            raise SystemExit(f"nepoznate stavke u {p}: {nepoznata} — ispravi ili ukloni")
        konfig.update({k: v for k, v in korisnicki.items() if k != "_biljeska"})
    provjeri_konfig(konfig)
    return konfig


def provjeri_konfig(konfig: dict) -> None:
    if konfig["na_nesuglasje"] not in ("odbij", "posluzi"):
        raise SystemExit("na_nesuglasje mora biti 'odbij' ili 'posluzi'")
    mreza = ipaddress.ip_network(konfig["mapiranje_mreza"], strict=False)
    rfc6598 = ipaddress.ip_network("100.64.0.0/10")
    if not (mreza.subnet_of(rfc6598) or mreza.subnet_of(ipaddress.ip_network("127.0.0.0/8"))):
        raise SystemExit("mapiranje_mreza mora biti unutar 100.64.0.0/10 (RFC 6598) ili 127.0.0.0/8")
    for sidro in konfig["sidra"]:
        if not str(sidro).startswith(("http://", "https://")):
            raise SystemExit(f"sidro mora biti http(s) URL: {sidro!r}")
        if str(sidro).startswith("http://"):
            log_err(f"sidro {sidro} je obican HTTP — PELUD je potpisan pa sadrzaj ne moze "
                    f"biti podmetnut, ali tvoj upit je vidljiv mrezi")
    for ime, stavka in konfig["imena"].items():
        if not isinstance(stavka, dict):
            raise SystemExit(f"imena[{ime}] mora biti objekt s poljem pk")
        pk = stavka.get("pk", "")
        if not (isinstance(pk, str) and len(pk) == 64 and all(c in "0123456789abcdef" for c in pk.lower())):
            raise SystemExit(f"imena[{ime}].pk mora biti 64 hex znaka (pinovani Ed25519 kljuc)")
        nepoznata = sorted(set(stavka) - {"pk", "javno_zrcalo"})
        if nepoznata:
            raise SystemExit(f"imena[{ime}] ima nepoznata polja: {nepoznata}")


# =============================================================================
# Pokretanje
# =============================================================================
def _petlja_osvjezavanja(r: Razrjesitelj, zastoj: threading.Event) -> None:
    interval = max(10, int(r.konfig["osvjezavanje_s"]))
    while not zastoj.is_set():
        for ime in list(r.unosi.keys()):
            if zastoj.is_set():
                return
            unos = r.unosi[ime]
            preostalo = unos.zapis.preostalo_s() if unos.zapis else -1
            if preostalo <= 2 * interval:
                try:
                    r.osvjezi(ime)
                except Exception as e:
                    log_err(f"pozadinsko osvjezavanje {ime}: {type(e).__name__}: {e}")
        zastoj.wait(interval)


def pokreni(konfig: dict) -> int:
    r = Razrjesitelj(konfig)
    dns_host, dns_port = _adresa(konfig["slusaj_dns"], 5353)
    http_host, http_port = _adresa(konfig["slusaj_http"], 8099)

    jezgra = _DnsJezgra(r)
    try:
        udp = _UdpServer((dns_host, dns_port), _UdpHandler)
        tcp = _TcpServer((dns_host, dns_port), _TcpHandler)
    except OSError as e:
        log_err(f"ne mogu slusati DNS na {dns_host}:{dns_port}: {e}")
        log_err("na Linuxu je cijeli 127.0.0.0/8 lokalan pa root NIJE potreban za port > 1024; "
                "provjeri sudara li se port s vec pokrenutim dnkd-om")
        return 1
    udp.jezgra = jezgra
    tcp.jezgra = jezgra

    try:
        http = _HttpServer((http_host, http_port), _HttpHandler)
    except OSError as e:
        udp.server_close()
        tcp.server_close()
        log_err(f"ne mogu slusati HTTP na {http_host}:{http_port}: {e}")
        return 1
    http.razrjesitelj = r

    zastoj = threading.Event()
    niti = [
        threading.Thread(target=udp.serve_forever, name="dns-udp", daemon=True),
        threading.Thread(target=tcp.serve_forever, name="dns-tcp", daemon=True),
        threading.Thread(target=http.serve_forever, name="http", daemon=True),
        threading.Thread(target=_petlja_osvjezavanja, args=(r, zastoj),
                         name="osvjezavanje", daemon=True),
    ]
    for n in niti:
        n.start()

    log(f"dnkd v{VERZIJA} — DNS {dns_host}:{dns_port} (UDP+TCP), ploca http://{http_host}:{http_port}/")
    log(f"imena: {', '.join(konfig['imena']) or '(nijedno — konfiguriraj imena[])'}")
    log(f"sidra: {', '.join(konfig['sidra']) or '(nijedno — dnkd nema odakle povuci PELUD)'}")
    log(f"mapiranje: {konfig['mapiranje_mreza']} -> {r.mapiranje.sve()}")
    log(f"provjera: dig @{dns_host} -p {dns_port} {next(iter(konfig['imena']), 'ime.dnk')} A")
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        log("zaustavljam...")
    finally:
        zastoj.set()
        udp.shutdown()
        tcp.shutdown()
        http.shutdown()
        udp.server_close()
        tcp.server_close()
        http.server_close()
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python3 -m maska.dnkd",
                                 description="dnkd — lokalni razrjesitelj .dnk imena (MASKA F2)")
    ap.add_argument("--konfig", default=None, help=f"putanja do konfiguracije (zadano {KONFIG_DATOTEKA})")
    ap.add_argument("--provjeri-konfig", action="store_true",
                    help="samo provjeri konfiguraciju i izadji")
    ap.add_argument("--jednom", metavar="IME",
                    help="razrijesi jedno ime, ispisi rezultat i izadji (bez demona)")
    ap.add_argument("--verzija", action="version", version=f"maska-dnkd {VERZIJA}")
    a = ap.parse_args(argv)

    konfig = ucitaj_konfig(a.konfig)
    if a.provjeri_konfig:
        print(json.dumps(konfig, ensure_ascii=False, indent=1))
        print("konfiguracija je valjana")
        return 0
    if a.jednom:
        r = Razrjesitelj(konfig)
        if a.jednom not in r.unosi:
            print(f"GRESKA: ime {a.jednom!r} nije u konfiguraciji (imena[])")
            return 2
        unos = r.osvjezi(a.jednom)
        print(json.dumps(unos.kao_dict(), ensure_ascii=False, indent=1))
        return 0 if unos.stanje == "OK" else 1
    return pokreni(konfig)


if __name__ == "__main__":
    raise SystemExit(main())
