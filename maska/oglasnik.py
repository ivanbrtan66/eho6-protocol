#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""OGLASNIK — K-od-N pultovi s konsenzusom prije preusmjeravanja (MASKA faza F5).

ISPRAVAK RANIJE TVRDNJE. U c1570 i u prvoj verziji ovog dokumenta stajalo je da
F5 "placa SEO dosegom jer dijeli signal na tri domene". To vrijedi samo ako
pultovi POSLUZUJU SADRZAJ — tada su tri kopije iste stranice i trazilica dijeli
signal. Ako su pultovi ono sto stvarno trebaju biti — **noindex preusmjerivaci**
s `rel=canonical` na primarnu domenu — duplikata nema, signal se ne dijeli, i
cijena nestaje. Zato je F5 ovdje izgradjen, a uvjet iz c1570 otpada.

Sto pult jest: javna, jeftina, zamjenjiva ulaznica na NEZAVISNOJ domeni, kod
drugog registrara i u drugoj jurisdikciji. Sto pult NIJE: kopija stranice, i
nikad izvor istine o lokaciji.

Zasto K-od-N a ne "prvi koji odgovori": jedan pult koji je kompromitiran ili
kojem je registrar oteo domenu inace preusmjerava korisnike kamo hoce. Uz
K-od-N, pult preusmjerava tek kad K nezavisnih pultova drzi ISTU potpisanu
tvrdnju. Napadac mora oteti K domena kod K registrara u K jurisdikcija.

USTAVNO OGRANICENJE koje se provjerava u konfiguraciji: K mora biti STROGA
vecina (K > N/2). Inace dvije razdvojene skupine mogu istovremeno imati po K
glasova i preusmjeravati na razlicita mjesta — a to nije konsenzus nego tihi
split-brain, ista bolest protiv koje F2 brani suglasnoscu.

Preusmjeravanje je 307 (privremeno), nikad 301: 301 prenosi tezinu poveznica i
kesira se zauvijek, a pokazivac koji se mijenja svakih par minuta ne smije
ostaviti trajan trag u tudjem kesu.
"""
from __future__ import annotations

import argparse
import json
import os
import socket
import ssl
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

from .godovi import Godovi
from .pelud import Pelud, PeludGreska, parsiraj

VERZIJA = "1.0.0"
MASKA_DIR = Path(os.environ.get("MASKA_DIR", str(Path.home() / ".maska")))
KONFIG_DATOTEKA = MASKA_DIR / "oglasnik.json"
MAX_TIJELO = 8192
DOPUSTENI_KODOVI = (302, 307)

ZADANI_KONFIG: dict = {
    "ime_ploce": "oglasnik",
    "kanonska_domena": "",
    "slusaj_http": "127.0.0.1:8101",
    "sidra": [],
    "ploce": [],
    "k": 2,
    "imena": {},
    "osvjezavanje_s": 60,
    "http_timeout_s": 5,
    "preusmjeri_kod": 307,
    "godovi": str(MASKA_DIR / "godovi.jsonl"),
}


def log(poruka: str) -> None:
    print(f"[{time.strftime('%Y-%m-%dT%H:%M:%S')}] {poruka}", flush=True)


def _adresa(spoj: str, zadani_port: int) -> tuple[str, int]:
    if ":" in spoj:
        host, _, port = spoj.rpartition(":")
        return host or "127.0.0.1", int(port)
    return spoj, zadani_port


# =============================================================================
# Glasovi i odluka
# =============================================================================
@dataclass
class Glas:
    """Sto jedan pult (ili nase sidro) drzi kao vazecu tvrdnju o imenu."""
    izvor: str
    stanje: str                     # OK | ALARM | NEPOZNATO
    razlog: str = ""
    zapis: Pelud | None = None

    @property
    def tvrdnja(self) -> tuple | None:
        """Kljuc po kojem se glasovi grupiraju: TKO i GDJE, ne kada.

        Visina lanca namjerno NIJE dio kljuca: pultovi se osvjezavaju neovisno, pa
        bi jedan koji kasni 30 s inace izgledao kao neslaganje. Za preusmjeravanje
        je bitno GDJE, a to je skup lokatora.
        """
        if self.zapis is None:
            return None
        return (self.zapis.ime, self.zapis.pk, tuple(sorted(self.zapis.lokatori)))

    def kao_dict(self) -> dict:
        return {"izvor": self.izvor, "stanje": self.stanje, "razlog": self.razlog,
                "visina": (self.zapis.visina if self.zapis else None),
                "lokatori": (list(self.zapis.lokatori) if self.zapis else [])}


@dataclass
class Odluka:
    stanje: str                     # SUGLASNO | NESUGLASNO | NEDOVOLJNO | NEPOZNATO
    razlog: str = ""
    zapis: Pelud | None = None
    cilj: str | None = None         # URL na koji se preusmjerava
    glasova_za: int = 0
    glasova_ukupno: int = 0
    k: int = 0
    n: int = 0
    glasovi: list[Glas] = field(default_factory=list)

    @property
    def preusmjeri(self) -> bool:
        return self.stanje == "SUGLASNO" and bool(self.cilj)

    def kao_dict(self) -> dict:
        return {"stanje": self.stanje, "razlog": self.razlog, "cilj": self.cilj,
                "glasova_za": self.glasova_za, "glasova_ukupno": self.glasova_ukupno,
                "k": self.k, "n": self.n,
                "visina": (self.zapis.visina if self.zapis else None),
                "glasovi": [g.kao_dict() for g in self.glasovi]}


def izaberi_cilj(zapis: Pelud) -> str | None:
    """Preglednik moze slijediti samo http(s). wg:// i quic:// nisu odrediste
    preusmjeravanja — ako drugog nema, pult to KAZE umjesto da izmislja."""
    for shema in ("https", "http"):
        for lokator in zapis.lokatori_po_shemi(shema):
            return lokator
    return None


def odluci(glasovi: list[Glas], k: int) -> Odluka:
    """K-od-N: preusmjeri tek kad K nezavisnih izvora drzi ISTU tvrdnju."""
    n = len(glasovi)
    valjani = [g for g in glasovi if g.stanje == "OK" and g.zapis is not None]
    skupine: dict[tuple, list[Glas]] = {}
    for g in valjani:
        skupine.setdefault(g.tvrdnja, []).append(g)

    if skupine:
        najjaca = max(skupine.values(), key=len)
        if len(najjaca) >= k:
            # unutar skupine uzmi zapis s najvecom visinom (najsvjeziji potpis)
            najbolji = max(najjaca, key=lambda g: g.zapis.visina)
            cilj = izaberi_cilj(najbolji.zapis)
            if cilj is None:
                return Odluka("NESUGLASNO",
                              "konsenzus postignut, ali ni jedan lokator nije http(s) — "
                              "preglednik ga ne moze slijediti",
                              zapis=najbolji.zapis, glasova_za=len(najjaca),
                              glasova_ukupno=len(valjani), k=k, n=n, glasovi=glasovi)
            return Odluka("SUGLASNO", zapis=najbolji.zapis, cilj=cilj,
                          glasova_za=len(najjaca), glasova_ukupno=len(valjani),
                          k=k, n=n, glasovi=glasovi)

    if len(valjani) < k:
        nedostaje = k - len(valjani)
        return Odluka("NEDOVOLJNO",
                      f"samo {len(valjani)} od {n} izvora dalo je valjanu tvrdnju, "
                      f"treba ih {k} (nedostaje {nedostaje}) — ne preusmjeravam",
                      glasova_ukupno=len(valjani), k=k, n=n, glasovi=glasovi)

    return Odluka("NESUGLASNO",
                  f"{len(valjani)} izvora se slozilo u {len(skupine)} razlicitih tvrdnji, "
                  f"ni jedna nema {k} glasova — ne preusmjeravam",
                  glasova_za=(max(len(v) for v in skupine.values()) if skupine else 0),
                  glasova_ukupno=len(valjani), k=k, n=n, glasovi=glasovi)


# =============================================================================
# Pult
# =============================================================================
class Oglasnik:
    def __init__(self, konfig: dict):
        self.konfig = konfig
        self.godovi = Godovi(konfig["godovi"])
        self.ssl_kontekst = ssl.create_default_context()
        self.svoji: dict[str, Glas] = {}          # ime -> nas vlastiti glas (iz sidara)
        self.zadnje_odluke: dict[str, Odluka] = {}
        self.lock = threading.Lock()
        self.pokrenut_t = time.time()
        self.brojac_preusmjerenja = 0
        self.brojac_odbijenih = 0

    @property
    def n(self) -> int:
        """Broj nezavisnih izvora: mi + ostali pultovi."""
        return 1 + len(self.konfig["ploce"])

    # -- PULL ---------------------------------------------------------------
    def _dohvati(self, url: str) -> tuple[str | None, str]:
        zahtjev = urllib.request.Request(
            url, headers={"User-Agent": f"maska-oglasnik/{VERZIJA}", "Accept": "text/plain"})
        try:
            with urllib.request.urlopen(zahtjev, timeout=self.konfig["http_timeout_s"],
                                        context=self.ssl_kontekst) as odgovor:
                if odgovor.status != 200:
                    return None, f"http_{odgovor.status}"
                return odgovor.read(MAX_TIJELO).decode("utf-8", "replace").strip(), ""
        except urllib.error.HTTPError as e:
            return None, f"http_{e.code}"
        except ssl.SSLError as e:
            return None, f"tls_greska({type(e).__name__})"
        except (urllib.error.URLError, socket.timeout, OSError) as e:
            return None, f"mrezna_greska({type(e).__name__})"
        except UnicodeDecodeError:
            return None, "odgovor_nije_tekst"

    def _glas_iz_teksta(self, izvor: str, tekst: str | None, razlog: str, ime: str) -> Glas:
        if tekst is None:
            return Glas(izvor, "NEPOZNATO", razlog)
        try:
            zapis = parsiraj(tekst)
        except PeludGreska as e:
            return Glas(izvor, "ALARM", f"zapis_neispravan: {e}")
        pin = (self.konfig["imena"].get(ime) or {}).get("pk")
        valjan, razlog_v = zapis.provjeri(pin)
        if not valjan:
            return Glas(izvor, "ALARM", razlog_v)
        if zapis.ime != ime:
            return Glas(izvor, "ALARM", f"zapis je za {zapis.ime}, trazeno {ime}")
        return Glas(izvor, "OK", zapis=zapis)

    def osvjezi_svoj(self, ime: str) -> Glas:
        """Nas vlastiti glas: PELUD povucen sa sidara i provjeren pinovanim kljucem."""
        glasovi = []
        for sidro in self.konfig["sidra"]:
            tekst, razlog = self._dohvati(sidro.rstrip("/") + "/" + ime + ".txt")
            glasovi.append(self._glas_iz_teksta(f"sidro:{sidro}", tekst, razlog, ime))
        valjani = [g for g in glasovi if g.stanje == "OK"]
        if valjani:
            najbolji = max(valjani, key=lambda g: g.zapis.visina)
            glas = Glas(self.konfig["ime_ploce"], "OK", zapis=najbolji.zapis)
        elif any(g.stanje == "ALARM" for g in glasovi):
            glas = Glas(self.konfig["ime_ploce"], "ALARM",
                        "; ".join(g.razlog for g in glasovi if g.razlog)[:200])
        else:
            glas = Glas(self.konfig["ime_ploce"], "NEPOZNATO",
                        "; ".join(g.razlog for g in glasovi if g.razlog)[:200]
                        or "nema konfiguriranih sidara")
        with self.lock:
            self.svoji[ime] = glas
        return glas

    def svoj_glas(self, ime: str, osvjezi: bool = True) -> Glas:
        with self.lock:
            glas = self.svoji.get(ime)
        if glas is None or (osvjezi and (glas.zapis is None
                                         or glas.zapis.preostalo_s() <= 0)):
            return self.osvjezi_svoj(ime)
        return glas

    # -- konsenzus ----------------------------------------------------------
    def odluka(self, ime: str) -> Odluka:
        if ime not in self.konfig["imena"]:
            return Odluka("NEPOZNATO", f"ime {ime!r} nije na ovom pultu", k=self.konfig["k"],
                          n=self.n)
        glasovi = [self.svoj_glas(ime)]
        for ploca in self.konfig["ploce"]:
            url = ploca.rstrip("/") + "/oglasnik/pokazivac/" + ime
            tekst, razlog = self._dohvati(url)
            glasovi.append(self._glas_iz_teksta(f"pult:{ploca}", tekst, razlog, ime))

        odluka = odluci(glasovi, self.konfig["k"])
        with self.lock:
            self.zadnje_odluke[ime] = odluka
        preslikavanje = {"SUGLASNO": "OK", "NESUGLASNO": "ALARM",
                         "NEDOVOLJNO": "NEPOZNATO", "NEPOZNATO": "NEPOZNATO"}
        try:
            self.godovi.upisi(f"oglasnik:{ime}", preslikavanje.get(odluka.stanje, "NEPOZNATO"),
                              razlog=(odluka.razlog[:300] or None), cilj=odluka.cilj,
                              glasova_za=odluka.glasova_za, k=odluka.k, n=odluka.n)
        except Exception:
            pass                      # dnevnik ne smije oboriti pult
        return odluka

    # -- zdravlje -----------------------------------------------------------
    def zdravlje(self) -> dict:
        sada = time.time()
        with self.lock:
            odluke = {ime: o.kao_dict() for ime, o in self.zadnje_odluke.items()}
        vatre = []
        for ime, o in odluke.items():
            if o["stanje"] == "NESUGLASNO":
                vatre.append({"razlog": f"{ime}: pultovi se razilaze — {o['razlog']}",
                              "ozbiljnost": "critical"})
            elif o["stanje"] in ("NEDOVOLJNO", "NEPOZNATO"):
                vatre.append({"razlog": f"{ime}: {o['razlog']}", "ozbiljnost": "warning"})
        if not self.konfig["imena"]:
            vatre.append({"razlog": "nema imena na pultu", "ozbiljnost": "critical"})
        if not self.konfig["sidra"]:
            vatre.append({"razlog": "nema sidara — pult nema odakle povuci pokazivac",
                          "ozbiljnost": "critical"})
        cijel, greske = self.godovi.provjeri()
        if not cijel:
            vatre.append({"razlog": f"godovi lanac razbijen: {greske[0] if greske else '?'}",
                          "ozbiljnost": "critical"})
        stanje = ("alarm" if any(v["ozbiljnost"] == "critical" for v in vatre)
                  else ("NEPOZNATO" if vatre else "ok"))
        return {
            "agent_id": f"oglasnik:{self.konfig['ime_ploce']}",
            "vrijeme": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(sada)),
            "stanje": stanje, "vatre": vatre, "verzija": VERZIJA,
            "uptime_s": round(sada - self.pokrenut_t, 1),
            "k": self.konfig["k"], "n": self.n,
            "preusmjerenja": self.brojac_preusmjerenja,
            "odbijeno": self.brojac_odbijenih,
            "dok_count": self.godovi.broj(),
            "godovi_lanac": "CIJEL" if cijel else "RAZBIJEN",
            "odluke": odluke,
            "indeksira_se": False,
        }


# =============================================================================
# HTTP
# =============================================================================
_STRANICA_CEKANJA = """<!doctype html>
<html lang="hr"><head><meta charset="utf-8">
<meta name="robots" content="noindex,nofollow">
<title>__IME__ — pokazivac trenutno nije potvrdjen</title>
<link rel="canonical" href="__KANONSKA__">
<style>body{font:15px/1.6 ui-monospace,SFMono-Regular,Menlo,monospace;background:#0a0c10;
color:#e8eaf0;margin:0;padding:2.5rem 1.25rem;}main{max-width:42rem;margin:0 auto}
h1{font-size:1.1rem;letter-spacing:.06em;text-transform:uppercase;color:#f5a623}
code{background:#171a21;border:1px solid #2a2d35;border-radius:5px;padding:1px 5px}
p{color:#8b8fa8}a{color:#5b9cf6}</style></head>
<body><main>
<h1>__STANJE__</h1>
<p>Ovaj pult ne preusmjerava jer <strong>__RAZLOG__</strong>.</p>
<p>Pult preusmjerava tek kad <code>__K__</code> od <code>__N__</code> nezavisnih pultova
drzi istu potpisanu tvrdnju o lokaciji. Manje od toga nije konsenzus, pa se ne pogadja.</p>
<p>Stanje glasova: <a href="/oglasnik/stanje">/oglasnik/stanje</a> ·
zdravlje: <a href="/borg/health.json">/borg/health.json</a></p>
</main></body></html>
"""


class _Handler(BaseHTTPRequestHandler):
    server_version = f"maska-oglasnik/{VERZIJA}"
    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args) -> None:      # noqa: A002
        log(f"HTTP {self.address_string()} {format % args}")

    def _zaglavlja_bez_indeksa(self) -> None:
        """Pult NIJE sadrzaj. Bez ovoga bi N pultova bilo N kopija iste stranice
        i trazilica bi dijelila signal — tocno cijena koju F5 ovdje NE placa."""
        self.send_header("X-Robots-Tag", "noindex, nofollow")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        kanonska = self.server.oglasnik.konfig.get("kanonska_domena")
        if kanonska:
            self.send_header("Link", f'<{kanonska}>; rel="canonical"')

    def _posalji(self, tijelo: bytes, tip: str, status: int = 200) -> None:
        self.send_response(status)
        self.send_header("Content-Type", tip)
        self.send_header("Content-Length", str(len(tijelo)))
        self._zaglavlja_bez_indeksa()
        self.end_headers()
        self.wfile.write(tijelo)

    def _json(self, podaci: dict, status: int = 200) -> None:
        self._posalji(json.dumps(podaci, ensure_ascii=False, indent=1).encode("utf-8"),
                      "application/json; charset=utf-8", status)

    def do_GET(self) -> None:
        put = self.path.split("?")[0].rstrip("/") or "/"
        o: Oglasnik = self.server.oglasnik

        if put == "/robots.txt":
            self._posalji(b"User-agent: *\nDisallow: /\n", "text/plain; charset=utf-8")
            return
        if put in ("/borg/health.json", "/health"):
            self._json(o.zdravlje())
            return
        if put == "/oglasnik/stanje":
            self._json({"pult": o.konfig["ime_ploce"], "k": o.konfig["k"], "n": o.n,
                        "ploce": o.konfig["ploce"], "sidra": o.konfig["sidra"],
                        "odluke": {ime: o.odluka(ime).kao_dict() for ime in o.konfig["imena"]}})
            return
        if put.startswith("/oglasnik/pokazivac/"):
            ime = put[len("/oglasnik/pokazivac/"):]
            glas = o.svoj_glas(ime) if ime in o.konfig["imena"] else None
            if glas is None or glas.zapis is None:
                self._json({"greska": f"nemam vazeci pokazivac za {ime!r}",
                            "stanje": (glas.stanje if glas else "NEPOZNATO"),
                            "razlog": (glas.razlog if glas else "ime nije na ovom pultu")}, 404)
                return
            # VERBATIM potpisani zapis — drugi pult provjerava potpis sam
            self._posalji(glas.zapis.txt().encode("utf-8"), "text/plain; charset=utf-8")
            return

        ime = put.lstrip("/") or next(iter(o.konfig["imena"]), "")
        if ime not in o.konfig["imena"]:
            self._json({"greska": f"nepoznato ime: {ime!r}",
                        "imena": sorted(o.konfig["imena"])}, 404)
            return

        odluka = o.odluka(ime)
        if odluka.preusmjeri:
            o.brojac_preusmjerenja += 1
            self.send_response(o.konfig["preusmjeri_kod"])
            self.send_header("Location", odluka.cilj)
            self.send_header("Content-Length", "0")
            self._zaglavlja_bez_indeksa()
            self.end_headers()
            return

        o.brojac_odbijenih += 1
        stranica = (_STRANICA_CEKANJA
                    .replace("__IME__", ime)
                    .replace("__KANONSKA__", o.konfig.get("kanonska_domena") or "/")
                    .replace("__STANJE__", odluka.stanje)
                    .replace("__RAZLOG__", odluka.razlog or "konsenzus nije postignut")
                    .replace("__K__", str(odluka.k)).replace("__N__", str(odluka.n)))
        self._posalji(stranica.encode("utf-8"), "text/html; charset=utf-8", 503)


class _Posluzitelj(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


# =============================================================================
# Konfiguracija
# =============================================================================
def provjeri_konfig(konfig: dict) -> None:
    n = 1 + len(konfig["ploce"])
    k = konfig["k"]
    if not isinstance(k, int) or k < 2:
        raise SystemExit("k mora biti cijeli broj >= 2 — K=1 nije konsenzus nego jedan glas")
    if k > n:
        raise SystemExit(f"k={k} je vece od broja izvora n={n} (mi + {len(konfig['ploce'])} pultova)")
    if k * 2 <= n:
        raise SystemExit(
            f"k={k} nije stroga vecina od n={n}. Dvije razdvojene skupine mogle bi "
            f"istovremeno imati po k glasova i preusmjeravati na razlicita mjesta — "
            f"to nije konsenzus nego tihi split-brain. Trazi se k >= {n // 2 + 1}.")
    if konfig["preusmjeri_kod"] not in DOPUSTENI_KODOVI:
        raise SystemExit(f"preusmjeri_kod mora biti jedan od {DOPUSTENI_KODOVI}; "
                         f"301 prenosi tezinu poveznica i kesira se trajno, a pokazivac "
                         f"se mijenja")
    for ploca in konfig["ploce"]:
        if not str(ploca).startswith(("http://", "https://")):
            raise SystemExit(f"pult mora biti http(s) URL: {ploca!r}")
    for sidro in konfig["sidra"]:
        if not str(sidro).startswith(("http://", "https://")):
            raise SystemExit(f"sidro mora biti http(s) URL: {sidro!r}")
    domene = {urlsplit(p).hostname for p in konfig["ploce"]}
    if len(domene) != len(konfig["ploce"]):
        raise SystemExit("dva pulta dijele istu domenu — to nisu dva nezavisna izvora")
    if konfig["kanonska_domena"] and not str(konfig["kanonska_domena"]).startswith("https://"):
        raise SystemExit("kanonska_domena mora biti https URL")
    for ime, stavka in konfig["imena"].items():
        if not isinstance(stavka, dict):
            raise SystemExit(f"imena[{ime}] mora biti objekt s poljem pk")
        pk = stavka.get("pk", "")
        if not (isinstance(pk, str) and len(pk) == 64
                and all(c in "0123456789abcdef" for c in pk.lower())):
            raise SystemExit(f"imena[{ime}].pk mora biti 64 hex znaka (pinovani Ed25519 kljuc)")
        nepoznata = sorted(set(stavka) - {"pk"})
        if nepoznata:
            raise SystemExit(f"imena[{ime}] ima nepoznata polja: {nepoznata}")


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


# =============================================================================
# Pokretanje
# =============================================================================
def _petlja_osvjezavanja(o: Oglasnik, zastoj: threading.Event) -> None:
    interval = max(10, int(o.konfig["osvjezavanje_s"]))
    while not zastoj.is_set():
        for ime in list(o.konfig["imena"]):
            if zastoj.is_set():
                return
            try:
                o.osvjezi_svoj(ime)
            except Exception as e:
                log(f"GRESKA: osvjezavanje {ime}: {type(e).__name__}: {e}")
        zastoj.wait(interval)


def pokreni(konfig: dict) -> int:
    o = Oglasnik(konfig)
    host, port = _adresa(konfig["slusaj_http"], 8101)
    try:
        posluzitelj = _Posluzitelj((host, port), _Handler)
    except OSError as e:
        log(f"GRESKA: ne mogu slusati na {host}:{port}: {e}")
        return 1
    posluzitelj.oglasnik = o

    zastoj = threading.Event()
    threading.Thread(target=posluzitelj.serve_forever, kwargs={"poll_interval": 0.2},
                     name="oglasnik-http", daemon=True).start()
    threading.Thread(target=_petlja_osvjezavanja, args=(o, zastoj),
                     name="osvjezavanje", daemon=True).start()

    log(f"oglasnik '{konfig['ime_ploce']}' v{VERZIJA} na http://{host}:{port}/")
    log(f"konsenzus: {konfig['k']} od {o.n} izvora (mi + {len(konfig['ploce'])} pultova)")
    log(f"imena: {', '.join(konfig['imena']) or '(nijedno)'}")
    log(f"preusmjeravanje: HTTP {konfig['preusmjeri_kod']}, noindex + canonical "
        f"{konfig.get('kanonska_domena') or '(nije postavljena)'}")
    log("pult NIJE sadrzaj: robots.txt zabranjuje indeksiranje, pa se SEO signal ne dijeli")
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        log("zaustavljam...")
    finally:
        zastoj.set()
        posluzitelj.shutdown()
        posluzitelj.server_close()
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python3 -m maska.oglasnik",
                                 description="oglasnik — K-od-N pult (MASKA F5)")
    ap.add_argument("--konfig", default=None, help=f"zadano {KONFIG_DATOTEKA}")
    ap.add_argument("--provjeri-konfig", action="store_true")
    ap.add_argument("--odluka", metavar="IME", help="ispisi odluku za jedno ime i izadji")
    ap.add_argument("--verzija", action="version", version=f"maska-oglasnik {VERZIJA}")
    a = ap.parse_args(argv)

    konfig = ucitaj_konfig(a.konfig)
    if a.provjeri_konfig:
        print(json.dumps(konfig, ensure_ascii=False, indent=1))
        print(f"konfiguracija je valjana (k={konfig['k']} od n={1 + len(konfig['ploce'])})")
        return 0
    if a.odluka:
        odluka = Oglasnik(konfig).odluka(a.odluka)
        print(json.dumps(odluka.kao_dict(), ensure_ascii=False, indent=1))
        return 0 if odluka.preusmjeri else 1
    return pokreni(konfig)


if __name__ == "__main__":
    import sys
    raise SystemExit(main())
