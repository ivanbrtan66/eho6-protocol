#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""GODOVI — dnevnik mjerenja razrjesenja, lancan hashevima (MASKA, treci clan niza).

Cemu: "dostupan sam" je tvrdnja. Godovi je pretvaraju u povijest koju netko
DRUGI moze provjeriti: svaki lookup (uspjesan i neuspjesan) upisuje se kao
redak, svaki redak nosi hash prethodnog. Presjeci stablo i vide se godine —
tko naknadno izbrise ili prepise jedan ispad, razbije lanac na tom mjestu i
provjeri() tocno imenuje redak.

Ne skriva kvar: ishod ALARM i NEPOZNATO upisuju se istom tezinom kao OK. Godovi
u kojima su samo uspjesi nisu mjerenje nego marketing.

Format: JSON Lines, append-only, jedan redak = jedno mjerenje.
  {"i":1,"t":1789...,"ime":"medijapos.dnk","ishod":"OK","ms":8,
   "sidro":"https://...","prev":"<sha3-256 prethodnog>","h":"<sha3-256 ovog>"}
h = SHA3-256(kanonski JSON retka BEZ polja h) — isti hash koji Genesis lanac
koristi za body_sha, da se godovi mogu kasnije usidriti bez promjene formata.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path

try:
    import fcntl
except ImportError:                                    # pragma: no cover
    fcntl = None                                       # Windows nije ciljna platforma

PRAZAN_HASH = "0" * 64
ISHODI = ("OK", "ALARM", "NEPOZNATO")
_MAX_REP = 4096                                        # koliko bajtova s kraja za zadnji redak


def kanonski_json(podaci: dict) -> str:
    return json.dumps(podaci, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _hash_retka(redak: dict) -> str:
    bez_h = {k: v for k, v in redak.items() if k != "h"}
    return hashlib.sha3_256(kanonski_json(bez_h).encode("utf-8")).hexdigest()


class Godovi:
    """Append-only dnevnik s lancem hasheva. Siguran za vise procesa (flock)."""

    def __init__(self, putanja: str | os.PathLike):
        self.putanja = Path(putanja).expanduser()
        self.putanja.parent.mkdir(parents=True, exist_ok=True)
        if not self.putanja.exists():
            self.putanja.touch(mode=0o644)

    # -- citanje -----------------------------------------------------------
    def _zadnji_redak(self) -> dict | None:
        """Zadnji valjani redak bez citanja cijele datoteke."""
        velicina = self.putanja.stat().st_size
        if velicina == 0:
            return None
        with self.putanja.open("rb") as f:
            f.seek(max(0, velicina - _MAX_REP))
            rep = f.read()
        for linija in reversed(rep.split(b"\n")):
            linija = linija.strip()
            if not linija:
                continue
            try:
                return json.loads(linija)
            except json.JSONDecodeError:
                # okrnjen zadnji redak (npr. pad usred pisanja) — preskoci ga,
                # ali ga provjeri() mora prijaviti, ne sakriti
                continue
        return None

    def stanje_glave(self) -> tuple[int, str]:
        z = self._zadnji_redak()
        if not z:
            return 0, PRAZAN_HASH
        return int(z.get("i", 0)), str(z.get("h", PRAZAN_HASH))

    def broj(self) -> int:
        return self.stanje_glave()[0]

    def zadnji(self, n: int = 20) -> list[dict]:
        """Zadnjih n redaka (najnoviji zadnji). Cita cijelu datoteku — za UI."""
        redovi: list[dict] = []
        with self.putanja.open("r", encoding="utf-8") as f:
            for linija in f:
                linija = linija.strip()
                if not linija:
                    continue
                try:
                    redovi.append(json.loads(linija))
                except json.JSONDecodeError:
                    redovi.append({"i": None, "ishod": "NEPOZNATO",
                                   "razlog": "redak_necitljiv"})
        return redovi[-n:] if n > 0 else redovi

    # -- pisanje -----------------------------------------------------------
    def upisi(self, ime: str, ishod: str, **dodatno) -> dict:
        """Dodaj mjerenje. Vraca upisani redak (s i, t, prev, h)."""
        if ishod not in ISHODI:
            raise ValueError(f"ishod mora biti jedan od {ISHODI}, dobiveno {ishod!r}")
        with self.putanja.open("a+", encoding="utf-8") as f:
            if fcntl is not None:
                fcntl.flock(f.fileno(), fcntl.LOCK_EX)
            try:
                i, prev = self.stanje_glave()      # pod lockom — inace dva procesa daju isti i
                redak = {"i": i + 1, "t": round(time.time(), 3), "ime": ime,
                         "ishod": ishod, "prev": prev}
                for k, v in dodatno.items():
                    if k not in redak and v is not None:
                        redak[k] = v
                redak["h"] = _hash_retka(redak)
                f.write(kanonski_json(redak) + "\n")
                f.flush()
                os.fsync(f.fileno())               # mjerenje koje nije na disku nije mjerenje
            finally:
                if fcntl is not None:
                    fcntl.flock(f.fileno(), fcntl.LOCK_UN)
        return redak

    # -- provjera ----------------------------------------------------------
    def provjeri(self) -> tuple[bool, list[str]]:
        """(cijel, greske). Imenuje TOCAN redak na kojem lanac puca."""
        greske: list[str] = []
        ocekivani_prev = PRAZAN_HASH
        ocekivani_i = 1
        with self.putanja.open("r", encoding="utf-8") as f:
            for broj_linije, linija in enumerate(f, 1):
                linija = linija.strip()
                if not linija:
                    continue
                try:
                    redak = json.loads(linija)
                except json.JSONDecodeError as e:
                    greske.append(f"linija {broj_linije}: nije valjan JSON ({e.msg})")
                    return False, greske
                if redak.get("i") != ocekivani_i:
                    greske.append(f"linija {broj_linije}: i={redak.get('i')}, ocekivano {ocekivani_i}")
                if redak.get("prev") != ocekivani_prev:
                    greske.append(f"linija {broj_linije}: prev ne pokazuje na prethodni hash")
                izracunan = _hash_retka(redak)
                if redak.get("h") != izracunan:
                    greske.append(f"linija {broj_linije}: h ne odgovara sadrzaju "
                                  f"(sadrzaj je promijenjen nakon upisa)")
                ocekivani_prev = redak.get("h", PRAZAN_HASH)
                ocekivani_i = int(redak.get("i", ocekivani_i)) + 1
        return (not greske), greske

    def sazetak(self, n: int = 200) -> dict:
        """Brojevi za nadzor: koliko OK/ALARM/NEPOZNATO u zadnjih n mjerenja."""
        zadnji = self.zadnji(n)
        brojaci = {k: 0 for k in ISHODI}
        for r in zadnji:
            ishod = r.get("ishod")
            if ishod in brojaci:
                brojaci[ishod] += 1
        ukupno = self.broj()
        return {"ukupno": ukupno, "uzorak": len(zadnji), "po_ishodu": brojaci,
                "zadnji_t": (zadnji[-1].get("t") if zadnji else None)}


def _cli(argv: list[str]) -> int:
    import argparse
    ap = argparse.ArgumentParser(prog="python3 -m maska.godovi",
                                 description="GODOVI dnevnik: provjeri / ispisi")
    ap.add_argument("datoteka", help="putanja do godovi.jsonl")
    ap.add_argument("--n", type=int, default=20, help="koliko zadnjih redaka ispisati")
    ap.add_argument("--samo-provjera", action="store_true")
    a = ap.parse_args(argv)

    g = Godovi(a.datoteka)
    cijel, greske = g.provjeri()
    print(f"lanac: {'CIJEL' if cijel else 'RAZBIJEN'} ({g.broj()} mjerenja)")
    for greska in greske:
        print(f"  ! {greska}")
    if not a.samo_provjera:
        for r in g.zadnji(a.n):
            print(f"  #{r.get('i')} {time.strftime('%H:%M:%S', time.localtime(r.get('t', 0)))} "
                  f"{r.get('ime')} {r.get('ishod')} {r.get('razlog', '')}")
        print("sazetak:", kanonski_json(g.sazetak()))
    return 0 if cijel else 1


if __name__ == "__main__":
    import sys
    raise SystemExit(_cli(sys.argv[1:]))
