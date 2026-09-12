#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Dodaj RIZOM put u tunel_watchdog_config.json — bez prepisivanja arhitekture.

Pravila kojih se drzi (i zato se smije pustiti na zivi EU cvor):
  * NIKAD `cat >` nad postojecim modulom. Konfiguracija se cita kao JSON, doda
    se JEDAN unos, i zapise atomarno (tmp + os.replace) — isti obrazac koji
    tunel_watchdog.py sam koristi kad brise zastavicu ceka_prvo_prikljucenje.
  * Backup PRIJE izmjene: <datoteka>.bak_rizom_<YYYYMMDDHHMMSS>.
  * Dozvole: www-data:www-data 0644, jer sve pod /var/www/genesis cita servis
    koji vise ne radi kao root (c2121/c2122).
  * Idempotentno: unos koji vec postoji se ne duplicira niti tiho mijenja.
  * --vrati vraca zadnji backup. Svaka izmjena je reverzibilna jednom naredbom.

Zasto ovako izgleda dodani unos (izmjereno iz postojece konfiguracije, ne pogodjeno):
  port + url + svjezina_url   — Z48: mjeri se i listener i JAVNI cilj, jer je
                                port koji slusa dokazano lagao (c2293).
  mora_sadrzavati="ts"        — medijapos /health vraca {"ts": ...} (biljeska u
                                tunel_watchdog.py starost_s); provjera po
                                SADRZAJU, ne po HTTP kodu (c2395: 200 nije dokaz).
  uredjaj="X96"               — c3166: kad padne cijeli uredjaj, jedna poruka
                                umjesto N. medijapos i medijapos-rizom dijele X96.
  ceka_prvo_prikljucenje=true — c2404: put koji se jos nikad nije prikljucio nije
                                kvar. Watchdog sam brise zastavicu na prvi OK.
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import pwd
import shutil
import sys
import time
from pathlib import Path

ZADANA_KONFIG = "/var/www/genesis/tools/tunel_watchdog_config.json"
VLASNIK = "www-data"
BILJESKA_KLJUC = "_biljeska_rizom"


def _biljeska(usluga: str, port: int, uredjaj: str, stari_port: int | None) -> str:
    return (f"RIZOM (MASKA F3): '{usluga}-rizom' mjeri DRUGI, neovisni put do iste usluge — "
            f"WireGuard sa rubnog uredjaja {uredjaj} prema ovom sidru, kroz nginx na "
            f"127.0.0.1:{port}. Stari ssh -R put"
            + (f" (port {stari_port})" if stari_port else "")
            + " se NE gasi i mjeri se dalje: dva puta, ne zamjena. Povod: "
              "_biljeska_c2395 — medijapos APP nije imao rezervni put. Kad oba puta "
              "prezive tjedan bez alarma, tek tada se odlucuje o gasenju starog.")


def ucitaj(putanja: Path) -> dict:
    try:
        podaci = json.loads(putanja.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise SystemExit(f"GRESKA: konfiguracija ne postoji: {putanja}")
    except json.JSONDecodeError as e:
        raise SystemExit(f"GRESKA: {putanja} nije valjan JSON ({e}) — ne diram je")
    if not isinstance(podaci, dict) or not isinstance(podaci.get("tuneli"), list):
        raise SystemExit(f"GRESKA: {putanja} nema listu 'tuneli' — ovo nije tunel_watchdog_config.json")
    return podaci


def napravi_backup(putanja: Path) -> Path:
    kopija = putanja.with_name(putanja.name + f".bak_rizom_{time.strftime('%Y%m%d%H%M%S')}")
    shutil.copy2(putanja, kopija)
    _dozvole(kopija)
    return kopija


def _dozvole(putanja: Path, bez_chown: bool = False) -> str:
    os.chmod(putanja, 0o644)
    if bez_chown:
        return "chmod 644 (chown preskocen na zahtjev)"
    try:
        zapis = pwd.getpwnam(VLASNIK)
    except KeyError:
        return f"chmod 644 (korisnik {VLASNIK} ne postoji na ovom stroju — chown preskocen)"
    try:
        os.chown(putanja, zapis.pw_uid, zapis.pw_gid)
        return f"chmod 644, chown {VLASNIK}:{VLASNIK}"
    except PermissionError:
        return (f"chmod 644, ali chown {VLASNIK} NIJE uspio (nisi root) — "
                f"pokreni: sudo chown {VLASNIK}:{VLASNIK} {putanja}")


def zapisi_atomarno(putanja: Path, podaci: dict, bez_chown: bool = False) -> str:
    tmp = putanja.with_name(putanja.name + ".tmp")
    tmp.write_text(json.dumps(podaci, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    poruka = _dozvole(tmp, bez_chown)
    os.replace(tmp, putanja)              # atomarno: watchdog nikad ne vidi pola datoteke
    return poruka


def dodaj(podaci: dict, usluga: str, port: int, uredjaj: str,
          mora_sadrzavati: str, svjezina_s: int) -> tuple[dict | None, str]:
    ime = f"{usluga}-rizom"
    postojeca = {t.get("ime") for t in podaci["tuneli"] if isinstance(t, dict)}
    if ime in postojeca:
        return None, f"unos '{ime}' vec postoji — nista se ne mijenja (idempotentno)"
    if usluga not in postojeca:
        return None, (f"u konfiguraciji nema unosa '{usluga}' — provjeri ime usluge; "
                      f"postojeci: {sorted(x for x in postojeca if x)}")
    zauzeti = {t.get("port") for t in podaci["tuneli"] if isinstance(t, dict)}
    if port in zauzeti:
        return None, f"port {port} je u konfiguraciji vec zauzet — izaberi drugi (--port)"

    unos = {
        "ime": ime,
        "port": port,
        "url": f"http://127.0.0.1:{port}/health",
        "svjezina_url": f"http://127.0.0.1:{port}/health",
        "svjezina_s": svjezina_s,
        "mora_sadrzavati": mora_sadrzavati,
        "uredjaj": uredjaj,
        "ceka_prvo_prikljucenje": True,
    }
    return unos, ""


def _stari_port(podaci: dict, usluga: str) -> int | None:
    for t in podaci["tuneli"]:
        if isinstance(t, dict) and t.get("ime") == usluga:
            return t.get("port")
    return None


def vrati(putanja: Path, bez_chown: bool) -> int:
    kopije = sorted(glob.glob(str(putanja) + ".bak_rizom_*"))
    if not kopije:
        print(f"GRESKA: nema ni jednog {putanja.name}.bak_rizom_* backupa za vracanje")
        return 1
    zadnji = Path(kopije[-1])
    prije = putanja.with_name(putanja.name + f".prije_vracanja_{time.strftime('%Y%m%d%H%M%S')}")
    shutil.copy2(putanja, prije)
    podaci = json.loads(zadnji.read_text(encoding="utf-8"))
    poruka = zapisi_atomarno(putanja, podaci, bez_chown)
    print(f"[OK]  vraceno iz {zadnji.name} ({poruka})")
    print(f"      stanje prije vracanja sacuvano u {prije.name}")
    print(f"      provjera: python3 /var/www/genesis/tools/tunel_watchdog.py")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="python3 rizom/patch_watchdog.py",
        description="Dodaj RIZOM (F3) put u tunel_watchdog_config.json — append, nikad prepis")
    ap.add_argument("--konfig", default=ZADANA_KONFIG, help=f"zadano {ZADANA_KONFIG}")
    ap.add_argument("--usluga", default="medijapos", help="ime postojeceg unosa (zadano medijapos)")
    ap.add_argument("--port", type=int, default=18196, help="lokalni nginx port RIZOM puta")
    ap.add_argument("--uredjaj", default="X96", help="grupa uredjaja za konsolidaciju alarma (c3166)")
    ap.add_argument("--mora-sadrzavati", default="ts",
                    help="tekst koji /health mora sadrzavati (medijapos vraca {\"ts\": ...})")
    ap.add_argument("--svjezina-s", type=int, default=180, help="prag starosti mjerenja u s")
    ap.add_argument("--pokazi", action="store_true", help="samo pokazi sto bi se dodalo (bez izmjene)")
    ap.add_argument("--vrati", action="store_true", help="vrati zadnji .bak_rizom_* backup")
    ap.add_argument("--bez-chown", action="store_true", help=f"ne mijenjaj vlasnika na {VLASNIK}")
    a = ap.parse_args(argv)

    putanja = Path(a.konfig)
    if a.vrati:
        return vrati(putanja, a.bez_chown)

    podaci = ucitaj(putanja)
    unos, razlog = dodaj(podaci, a.usluga, a.port, a.uredjaj, a.mora_sadrzavati, a.svjezina_s)
    if unos is None:
        print(f"[--]  {razlog}")
        return 0 if "vec postoji" in razlog else 1

    print("[..]  unos koji se dodaje:")
    print(json.dumps(unos, ensure_ascii=False, indent=1))
    if a.pokazi:
        print(f"[--]  --pokazi: {putanja} NIJE mijenjana")
        return 0

    if os.geteuid() != 0 and not a.bez_chown:
        print(f"[!!]  nisi root — chown {VLASNIK} nece uspjeti. Pokreni sa sudo, "
              f"ili s --bez-chown ako svjesno ostavljas trenutnog vlasnika.")

    kopija = napravi_backup(putanja)
    print(f"[OK]  backup: {kopija}")
    podaci["tuneli"].append(unos)
    podaci[BILJESKA_KLJUC] = _biljeska(a.usluga, a.port, a.uredjaj, _stari_port(podaci, a.usluga))
    poruka = zapisi_atomarno(putanja, podaci, a.bez_chown)
    print(f"[OK]  '{unos['ime']}' dodan u {putanja} ({poruka})")
    print(f"[..]  sljedeci korak — izmjeri odmah, ne cekaj cron:")
    print(f"      sudo -u {VLASNIK} python3 /var/www/genesis/tools/tunel_watchdog.py")
    print(f"[..]  ocekivano prvo stanje: NEPOZNATO 'ceka prvo prikljucenje' dok tunel ne procvate;")
    print(f"      watchdog sam brise tu zastavicu na prvi OK (c2404).")
    print(f"[..]  vracanje unatrag: python3 rizom/patch_watchdog.py --vrati --konfig {putanja}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
