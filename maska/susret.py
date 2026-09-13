#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SUSRET — sastajaliste na sidru: oglasna ploca + STUN (MASKA faza F4). stdlib only.

Ovo je tocka u kojoj sidro prestaje biti prolaz i postaje sastajaliste. Zato
ovaj servis NEMA endpoint koji prenosi teret — ni proxy, ni relej, ni
prosljedjivanje. Ne moze ga imati: kad bi ga imao, F4 ne bi ukinuo nista, samo
bi premjestio isti SPOF na novi port.

Sto sidro nakon F4 zna:  TKO postoji (ime, kandidati, vrijeme, mjereni NAT).
Sto sidro NE zna:        STO se prenosi. Nakon proboda promet ga ne dotice.
Sto sidro NE MOZE:       uci u vezu. Moze objaviti lazan kandidat i time
                         SPRIJECITI probod, ali ne procitati ga — WireGuard
                         autentificira kljucem, a MASKA probe su potpisane
                         Ed25519 kljucem peera. To je napad na dostupnost,
                         nikad na tajnost.

Dvije uloge u jednom procesu, namjerno:
  HTTP  — oglasna ploca (POST /susret/oglas, GET /susret/oglas/<ime>)
  UDP   — STUN Binding posluzitelj (maska/stun.py)

Zasto oboje na sidru: klasifikacija NAT-a trazi DVIJE tocke gledanja na
razlicitim IP adresama. Postava iz F3 ima tocno dva sidra (EU + NEW), pa se
susret instalira na oba i MASKA ne ovisi ni o jednom javnom STUN-u — javni STUN
bi vidio tko i kada trazi probod, a taj metapodatak ne mora napustiti flotu.

Oglas se prihvaca SAMO ako je potpisan pinovanim kljucem imena iz konfiguracije
i ako je svjez. Ploca koja prima nepotpisane oglase je ploca na koju bilo tko
zalijepi tudje ime.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from . import stun
from .probod import MAX_OGLAS, Oglas, ProbodGreska

VERZIJA = "1.0.0"
MASKA_DIR = Path(os.environ.get("MASKA_DIR", str(Path.home() / ".maska")))
KONFIG_DATOTEKA = MASKA_DIR / "susret.json"

ZADANI_KONFIG: dict = {
    "slusaj_http": "127.0.0.1:8100",
    "slusaj_stun": "0.0.0.0:3478",
    "drugo_sidro_stun": None,          # OTHER-ADDRESS: druga tocka gledanja (drugo sidro)
    "imena": {},                       # ime -> {"pk": "<64hex>"}
    "trajanje_oglasa_s": 120,
    "max_oglasa": 256,
    "upita_u_minuti_po_ip": 240,
}


def log(poruka: str) -> None:
    print(f"[{time.strftime('%Y-%m-%dT%H:%M:%S')}] {poruka}", flush=True)


def _adresa(spoj: str, zadani_port: int) -> tuple[str, int]:
    if ":" in spoj:
        host, _, port = spoj.rpartition(":")
        return host or "127.0.0.1", int(port)
    return spoj, zadani_port


# =============================================================================
# Ploca
# =============================================================================
@dataclass
class Unos:
    tekst: str                        # oglas VERBATIM — peer provjerava potpis sam
    ime: str
    primljen_t: float
    izvor_ip: str
    nat: str
    kandidata: int
    nonce: str

    def istekao(self, sada: float, trajanje_s: int) -> bool:
        return (sada - self.primljen_t) > trajanje_s


class Ploca:
    """Oglasi u memoriji, s rokom. Nista se ne pise na disk: oglas je efemeran,
    a trajni zapis lokacija bio bi upravo ono sto MASKA ne zeli ostaviti na sidru."""

    def __init__(self, trajanje_s: int, max_oglasa: int):
        self.trajanje_s = trajanje_s
        self.max_oglasa = max_oglasa
        self._unosi: dict[str, Unos] = {}
        self._nonce: dict[str, float] = {}
        self._lock = threading.Lock()
        self.brojac_prihvacenih = 0
        self.brojac_odbijenih = 0

    def _ocisti(self, sada: float) -> None:
        for ime in [i for i, u in self._unosi.items() if u.istekao(sada, self.trajanje_s)]:
            del self._unosi[ime]
        for nonce in [n for n, t in self._nonce.items() if sada - t > 2 * self.trajanje_s]:
            del self._nonce[nonce]

    def objavi(self, oglas: Oglas, tekst: str, izvor_ip: str,
               sada: float | None = None) -> tuple[bool, str]:
        sada = time.time() if sada is None else sada
        with self._lock:
            self._ocisti(sada)
            kljuc_nonce = f"{oglas.ime}:{oglas.nonce}"
            if kljuc_nonce in self._nonce:
                self.brojac_odbijenih += 1
                return False, "nonce_ponovljen (ponavljanje starog oglasa)"
            if oglas.ime not in self._unosi and len(self._unosi) >= self.max_oglasa:
                self.brojac_odbijenih += 1
                return False, f"ploca je puna ({self.max_oglasa} oglasa)"
            postojeci = self._unosi.get(oglas.ime)
            if postojeci and oglas.ts < Oglas.parsiraj(postojeci.tekst).ts:
                self.brojac_odbijenih += 1
                return False, "stariji oglas od postojeceg (ne prepisujem noviji)"
            self._nonce[kljuc_nonce] = sada
            self._unosi[oglas.ime] = Unos(tekst=tekst, ime=oglas.ime, primljen_t=sada,
                                          izvor_ip=izvor_ip, nat=oglas.nat,
                                          kandidata=len(oglas.kandidati), nonce=oglas.nonce)
            self.brojac_prihvacenih += 1
            return True, ""

    def dohvati(self, ime: str, sada: float | None = None) -> Unos | None:
        sada = time.time() if sada is None else sada
        with self._lock:
            self._ocisti(sada)
            return self._unosi.get(ime)

    def imena(self, sada: float | None = None) -> list[dict]:
        """Sve sto sidro zna: tko postoji. Nikad sadrzaj prometa."""
        sada = time.time() if sada is None else sada
        with self._lock:
            self._ocisti(sada)
            return [{"ime": u.ime, "nat": u.nat, "kandidata": u.kandidata,
                     "star_s": round(sada - u.primljen_t, 1)}
                    for u in sorted(self._unosi.values(), key=lambda x: x.ime)]


class Ogranicavac:
    """Jednostavno ogranicenje broja upita po IP-u u minuti. Stiti plocu od poplave."""

    def __init__(self, granica: int):
        self.granica = granica
        self._po_ip: dict[str, deque] = {}
        self._lock = threading.Lock()

    def dopusti(self, ip: str, sada: float | None = None) -> bool:
        sada = time.time() if sada is None else sada
        with self._lock:
            red = self._po_ip.setdefault(ip, deque())
            while red and sada - red[0] > 60:
                red.popleft()
            if len(red) >= self.granica:
                return False
            red.append(sada)
            if len(self._po_ip) > 4096:                  # ne rasti bez granice
                for k in [k for k, v in self._po_ip.items() if not v]:
                    del self._po_ip[k]
            return True


# =============================================================================
# HTTP
# =============================================================================
class _Handler(BaseHTTPRequestHandler):
    server_version = f"maska-susret/{VERZIJA}"
    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args) -> None:      # noqa: A002
        log(f"HTTP {self.address_string()} {format % args}")

    def _posalji(self, tijelo: bytes, tip: str, status: int = 200) -> None:
        self.send_response(status)
        self.send_header("Content-Type", tip)
        self.send_header("Content-Length", str(len(tijelo)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(tijelo)

    def _json(self, podaci: dict, status: int = 200) -> None:
        self._posalji(json.dumps(podaci, ensure_ascii=False, indent=1).encode("utf-8"),
                      "application/json; charset=utf-8", status)

    def _greska(self, status: int, razlog: str) -> None:
        self._json({"greska": razlog, "status": status}, status)

    def _dopusti(self) -> bool:
        if not self.server.ogranicavac.dopusti(self.client_address[0]):
            self._greska(429, "previse upita s ove adrese (ogranicenje po minuti)")
            return False
        return True

    def do_GET(self) -> None:
        if not self._dopusti():
            return
        put = self.path.split("?")[0].rstrip("/") or "/"
        s = self.server
        if put in ("/borg/health.json", "/health"):
            self._json(s.zdravlje())
        elif put == "/susret/imena":
            self._json({"imena": s.ploca.imena()})
        elif put.startswith("/susret/oglas/"):
            ime = put[len("/susret/oglas/"):]
            if not ime or len(ime) > 253:
                self._greska(400, "ime nije valjano")
                return
            unos = s.ploca.dohvati(ime)
            if unos is None:
                self._greska(404, f"nema svjezeg oglasa za {ime!r} "
                                  f"(rok je {s.konfig['trajanje_oglasa_s']} s)")
                return
            # VERBATIM: peer mora provjeriti potpis sam, sidro nije izvor istine
            self._posalji(unos.tekst.encode("utf-8"), "application/json; charset=utf-8")
        elif put == "/":
            self._json({"servis": "maska-susret", "verzija": VERZIJA,
                        "sto_znam": "tko postoji (imena i kandidati), nikad sadrzaj prometa",
                        "rute": ["POST /susret/oglas", "GET /susret/oglas/<ime>",
                                 "GET /susret/imena", "GET /borg/health.json"],
                        "relej": "ne postoji — susret nije prolaz nego sastajaliste"})
        else:
            self._greska(404, f"nepoznata ruta: {put}")

    def do_POST(self) -> None:
        if not self._dopusti():
            return
        put = self.path.split("?")[0].rstrip("/")
        s = self.server
        if put != "/susret/oglas":
            self._greska(404, f"nepoznata ruta: {put}")
            return
        duzina = int(self.headers.get("Content-Length") or 0)
        if duzina > MAX_OGLAS:
            self._greska(413, f"oglas veci od {MAX_OGLAS} B")
            return
        sirovo = self.rfile.read(duzina) if duzina else b""
        try:
            tekst = sirovo.decode("utf-8")
        except UnicodeDecodeError:
            self._greska(400, "oglas nije UTF-8")
            return
        try:
            oglas = Oglas.parsiraj(tekst)
        except ProbodGreska as e:
            s.ploca.brojac_odbijenih += 1
            self._greska(400, f"oglas se ne da procitati: {e}")
            return

        pin = (s.konfig["imena"].get(oglas.ime) or {}).get("pk")
        valjan, razlog = oglas.provjeri(pin)
        if not valjan:
            s.ploca.brojac_odbijenih += 1
            # 403, ne 400: oglas je citljiv ali nije ovlasten
            self._greska(403, f"oglas nije prihvacen: {razlog}")
            return

        ok, razlog = s.ploca.objavi(oglas, tekst, self.client_address[0])
        if not ok:
            self._greska(409, razlog)
            return
        self._json({"prihvaceno": True, "ime": oglas.ime, "kandidata": len(oglas.kandidati),
                    "nat": oglas.nat, "vrijedi_s": s.konfig["trajanje_oglasa_s"]}, 201)


class Susret(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, adresa: tuple[str, int], konfig: dict,
                 stun_posluzitelj: stun.Posluzitelj | None = None):
        super().__init__(adresa, _Handler)
        self.konfig = konfig
        self.ploca = Ploca(konfig["trajanje_oglasa_s"], konfig["max_oglasa"])
        self.ogranicavac = Ogranicavac(konfig["upita_u_minuti_po_ip"])
        self.stun = stun_posluzitelj
        self.pokrenut_t = time.time()

    def zdravlje(self) -> dict:
        sada = time.time()
        vatre = []
        if not self.konfig["imena"]:
            vatre.append({"razlog": "nema pinovanih imena — ploca ne moze prihvatiti ni jedan "
                                    "oglas", "ozbiljnost": "critical"})
        if self.stun is None:
            vatre.append({"razlog": "STUN posluzitelj nije pokrenut — ovo sidro nije tocka "
                                    "gledanja za mjerenje NAT-a", "ozbiljnost": "warning"})
        elif not self.konfig.get("drugo_sidro_stun"):
            vatre.append({"razlog": "drugo_sidro_stun nije postavljen — s jednom tockom gledanja "
                                    "klasifikacija NAT-a ostaje NEPOZNATO", "ozbiljnost": "warning"})
        stanje = ("alarm" if any(v["ozbiljnost"] == "critical" for v in vatre)
                  else ("NEPOZNATO" if vatre else "ok"))
        return {
            "agent_id": "susret",
            "vrijeme": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(sada)),
            "stanje": stanje, "vatre": vatre, "verzija": VERZIJA,
            "uptime_s": round(sada - self.pokrenut_t, 1),
            "oglasa_sada": len(self.ploca.imena(sada)),
            "prihvaceno": self.ploca.brojac_prihvacenih,
            "odbijeno": self.ploca.brojac_odbijenih,
            "stun_upita": (self.stun.brojac_upita if self.stun else None),
            "stun_smeca": (self.stun.brojac_smeca if self.stun else None),
            "imena": self.ploca.imena(sada),
            "relej": False,
        }


# =============================================================================
# Konfiguracija i pokretanje
# =============================================================================
def provjeri_konfig(konfig: dict) -> None:
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
    if konfig["trajanje_oglasa_s"] < 10 or konfig["trajanje_oglasa_s"] > 3600:
        raise SystemExit("trajanje_oglasa_s mora biti izmedju 10 i 3600")
    if konfig.get("drugo_sidro_stun"):
        host, port = _adresa(str(konfig["drugo_sidro_stun"]), 3478)
        try:
            ipaddress.ip_address(host)
        except ValueError:
            raise SystemExit("drugo_sidro_stun mora biti IP:PORT (OTHER-ADDRESS nosi adresu, "
                             "ne ime — klijent ga ne razrjesava)")
        del port


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


def pokreni(konfig: dict) -> int:
    stun_host, stun_port = _adresa(konfig["slusaj_stun"], 3478)
    http_host, http_port = _adresa(konfig["slusaj_http"], 8100)
    drugo = (_adresa(str(konfig["drugo_sidro_stun"]), 3478)
             if konfig.get("drugo_sidro_stun") else None)

    try:
        stun_posluzitelj = stun.Posluzitelj((stun_host, stun_port), drugo_sidro=drugo)
    except OSError as e:
        log(f"GRESKA: ne mogu slusati STUN na {stun_host}:{stun_port}: {e}")
        return 1
    stun_posluzitelj.pokreni_u_niti()

    try:
        susret = Susret((http_host, http_port), konfig, stun_posluzitelj)
    except OSError as e:
        stun_posluzitelj.server_close()
        log(f"GRESKA: ne mogu slusati HTTP na {http_host}:{http_port}: {e}")
        return 1

    nit = threading.Thread(target=susret.serve_forever, kwargs={"poll_interval": 0.2},
                           name="susret-http", daemon=True)
    nit.start()
    log(f"susret v{VERZIJA} — ploca http://{http_host}:{http_port}/, "
        f"STUN {stun_host}:{stun_port}"
        + (f", druga tocka gledanja {drugo[0]}:{drugo[1]}" if drugo else
           " (BEZ druge tocke gledanja — klasifikacija NAT-a ostaje NEPOZNATO)"))
    log(f"pinovana imena: {', '.join(konfig['imena']) or '(nijedno — ploca odbija sve)'}")
    log("relej NE postoji: susret je sastajaliste, ne prolaz")
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        log("zaustavljam...")
    finally:
        susret.shutdown()
        susret.server_close()
        stun_posluzitelj.shutdown()
        stun_posluzitelj.server_close()
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python3 -m maska.susret",
                                 description="susret — sastajaliste na sidru (MASKA F4)")
    ap.add_argument("--konfig", default=None, help=f"zadano {KONFIG_DATOTEKA}")
    ap.add_argument("--provjeri-konfig", action="store_true")
    ap.add_argument("--verzija", action="version", version=f"maska-susret {VERZIJA}")
    a = ap.parse_args(argv)
    konfig = ucitaj_konfig(a.konfig)
    if a.provjeri_konfig:
        print(json.dumps(konfig, ensure_ascii=False, indent=1))
        print("konfiguracija je valjana")
        return 0
    return pokreni(konfig)


if __name__ == "__main__":
    import sys
    raise SystemExit(main())
