#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""GODOVI: dnevnik mjerenja mora otkriti naknadnu izmjenu i imenovati redak."""
import json
import pathlib
import sys
import tempfile
import threading
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from maska.godovi import PRAZAN_HASH, Godovi, kanonski_json  # noqa: E402


class TestGodovi(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.put = pathlib.Path(self.dir.name) / "godovi.jsonl"
        self.g = Godovi(self.put)

    def tearDown(self):
        self.dir.cleanup()

    def _linije(self):
        return [json.loads(l) for l in self.put.read_text().splitlines() if l.strip()]

    def test_prvi_redak_pokazuje_na_prazan_hash(self):
        r = self.g.upisi("a.dnk", "OK")
        self.assertEqual(1, r["i"])
        self.assertEqual(PRAZAN_HASH, r["prev"])

    def test_lanac_se_nastavlja(self):
        r1 = self.g.upisi("a.dnk", "OK", ms=5)
        r2 = self.g.upisi("a.dnk", "ALARM", razlog="potpis_nevaljan")
        self.assertEqual(r1["h"], r2["prev"])
        self.assertEqual((True, []), self.g.provjeri())

    def test_kvar_se_upisuje_istom_tezinom(self):
        for ishod in ("OK", "ALARM", "NEPOZNATO"):
            self.g.upisi("a.dnk", ishod)
        self.assertEqual({"OK": 1, "ALARM": 1, "NEPOZNATO": 1},
                         self.g.sazetak()["po_ishodu"])

    def test_nepoznat_ishod_odbijen(self):
        with self.assertRaises(ValueError):
            self.g.upisi("a.dnk", "skoro_ok")

    def test_promjena_sadrzaja_razbija_lanac(self):
        self.g.upisi("a.dnk", "OK")
        self.g.upisi("a.dnk", "ALARM", razlog="pao")
        self.g.upisi("a.dnk", "OK")
        linije = self._linije()
        linije[1]["ishod"] = "OK"                     # prikrivanje ispada
        self.put.write_text("\n".join(kanonski_json(l) for l in linije) + "\n")
        cijel, greske = self.g.provjeri()
        self.assertFalse(cijel)
        self.assertTrue(any("linija 2" in g for g in greske), greske)

    def test_brisanje_retka_razbija_lanac(self):
        for _ in range(3):
            self.g.upisi("a.dnk", "OK")
        linije = self._linije()
        del linije[1]
        self.put.write_text("\n".join(kanonski_json(l) for l in linije) + "\n")
        cijel, greske = self.g.provjeri()
        self.assertFalse(cijel)
        self.assertTrue(any("prev" in g or "ocekivano" in g for g in greske), greske)

    def test_pokvaren_json_imenuje_liniju(self):
        self.g.upisi("a.dnk", "OK")
        with self.put.open("a") as f:
            f.write('{"i": 2, nije json\n')
        cijel, greske = self.g.provjeri()
        self.assertFalse(cijel)
        self.assertIn("linija 2", greske[0])

    def test_paralelni_upisi_ne_gube_redak(self):
        """Dva procesa/niti ne smiju dobiti isti indeks (flock + citanje pod lockom)."""
        def radi():
            for _ in range(10):
                self.g.upisi("a.dnk", "OK")
        niti = [threading.Thread(target=radi) for _ in range(4)]
        for n in niti:
            n.start()
        for n in niti:
            n.join()
        self.assertEqual(40, self.g.broj())
        self.assertEqual((True, []), self.g.provjeri())
        indeksi = [r["i"] for r in self._linije()]
        self.assertEqual(list(range(1, 41)), sorted(indeksi))

    def test_zadnji_vraca_najnovije(self):
        for i in range(5):
            self.g.upisi(f"{i}.dnk", "OK")
        self.assertEqual(["3.dnk", "4.dnk"], [r["ime"] for r in self.g.zadnji(2)])

    def test_prazan_dnevnik_je_cijel(self):
        self.assertEqual((True, []), self.g.provjeri())
        self.assertEqual(0, self.g.broj())
        self.assertEqual((0, PRAZAN_HASH), self.g.stanje_glave())

    def test_polja_se_ne_prepisuju(self):
        r = self.g.upisi("a.dnk", "OK", i=999, h="podmetnuto")
        self.assertEqual(1, r["i"])
        self.assertNotEqual("podmetnuto", r["h"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
