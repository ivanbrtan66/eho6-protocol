#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""PELUD zapis (F1): sto se smije procitati, sto se mora odbiti, i zasto."""
import pathlib
import sys
import time
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from maska import kripto                                    # noqa: E402
from maska.pelud import (MAX_VIJEK_S, Pelud, PeludGreska,    # noqa: E402
                         parsiraj, spoji_dijelove)

LOKATORI = ["wg://217.160.71.124:51820/" + "A" * 42,
            "https://genesis-medijapos.limit-connect.com"]


class TestIzdavanjeIProvjera(unittest.TestCase):
    def setUp(self):
        self.sk, self.pk = kripto.ed25519_novi_kljuc()
        self.z = Pelud.izdaj("medijapos.dnk", self.sk, 4287, LOKATORI, vijek_s=600)

    def test_krug_tekst_objekt(self):
        tekst = self.z.txt()
        z2 = parsiraj(tekst)
        self.assertEqual(z2.txt(), tekst)
        self.assertEqual(z2.lokatori, LOKATORI)
        self.assertEqual(z2.visina, 4287)
        self.assertEqual((True, ""), z2.provjeri(self.pk.hex()))

    def test_bez_pina_nije_valjan(self):
        """Potpis provjeren kljucem IZ zapisa ne dokazuje nista."""
        self.assertEqual((False, "pk_nije_pinovan"), self.z.provjeri(None))
        self.assertEqual((False, "pk_nije_pinovan"), self.z.provjeri(""))

    def test_tudji_pin(self):
        _sk2, pk2 = kripto.ed25519_novi_kljuc()
        valjan, razlog = self.z.provjeri(pk2.hex())
        self.assertFalse(valjan)
        self.assertEqual("pk_ne_odgovara_pinovanom", razlog)

    def test_podmetnuta_visina_pada_na_potpisu(self):
        podmetnut = parsiraj(self.z.txt().replace("h=4287", "h=9999"))
        self.assertEqual((False, "potpis_nevaljan"), podmetnut.provjeri(self.pk.hex()))

    def test_podmetnut_lokator_pada_na_potpisu(self):
        podmetnut = parsiraj(self.z.txt().replace("217.160.71.124", "203.0.113.9"))
        self.assertEqual((False, "potpis_nevaljan"), podmetnut.provjeri(self.pk.hex()))

    def test_istekao(self):
        z = Pelud.izdaj("medijapos.dnk", self.sk, 4287, LOKATORI, vijek_s=60,
                        sada=time.time() - 3600)
        valjan, razlog = z.provjeri(self.pk.hex())
        self.assertFalse(valjan)
        self.assertTrue(razlog.startswith("istekao_prije_"), razlog)

    def test_tolerancija_pomaka_satova(self):
        z = Pelud.izdaj("medijapos.dnk", self.sk, 4287, LOKATORI, vijek_s=60,
                        sada=time.time() - 90)          # istekao prije 30 s
        self.assertTrue(z.provjeri(self.pk.hex(), dopusteni_pomak_s=120)[0])
        self.assertFalse(z.provjeri(self.pk.hex(), dopusteni_pomak_s=0)[0])

    def test_exp_predaleko_u_buducnosti(self):
        z = Pelud(ime="medijapos.dnk", pk=self.pk.hex(), visina=4287,
                  exp=int(time.time()) + 10 * MAX_VIJEK_S, lokatori=LOKATORI)
        z.potpisi(self.sk)
        self.assertEqual("exp_predaleko_u_buducnosti", z.provjeri(self.pk.hex())[1])

    def test_ttl_nikad_dulji_od_ostatka(self):
        z = Pelud.izdaj("medijapos.dnk", self.sk, 4287, LOKATORI, vijek_s=30)
        self.assertLessEqual(z.ttl_s(), 30)
        self.assertGreaterEqual(z.ttl_s(), 1)

    def test_potpis_tudjim_kljucem_odbijen(self):
        sk2, _pk2 = kripto.ed25519_novi_kljuc()
        with self.assertRaises(PeludGreska):
            self.z.potpisi(sk2)

    def test_nepotpisan_se_ne_serijalizira(self):
        z = Pelud(ime="a.dnk", pk=self.pk.hex(), visina=1,
                  exp=int(time.time()) + 60, lokatori=LOKATORI)
        with self.assertRaises(PeludGreska):
            z.txt()


class TestStrogoCitanje(unittest.TestCase):
    def setUp(self):
        self.sk, self.pk = kripto.ed25519_novi_kljuc()
        self.tekst = Pelud.izdaj("medijapos.dnk", self.sk, 4287, LOKATORI).txt()

    def _greska(self, tekst, dio_poruke):
        with self.assertRaises(PeludGreska) as ctx:
            parsiraj(tekst)
        self.assertIn(dio_poruke, str(ctx.exception))

    def test_nepoznato_polje_odbijeno(self):
        self._greska(self.tekst + " extra=1", "nepoznata polja")

    def test_ponovljeno_polje_odbijeno(self):
        self._greska(self.tekst + " h=1", "ponovljeno")

    def test_dvostruki_razmak_odbijen(self):
        self._greska(self.tekst.replace("alg=", " alg="), "dvostruki razmak")

    def test_promijenjen_red_polja_odbijen(self):
        d = self.tekst.split(" ")
        d[1], d[2] = d[2], d[1]
        self._greska(" ".join(d), "kanonskom obliku")

    def test_kriva_verzija(self):
        self._greska(self.tekst.replace("v=PELUD1", "v=PELUD2"), "v mora biti")

    def test_prazan_zapis(self):
        self._greska("   ", "prazan")

    def test_nedostaje_potpis(self):
        self._greska(self.tekst.split(" sig=")[0], "nedostaje obavezno polje 'sig'")

    def test_ml_dsa_odbijen_dok_ne_postoji(self):
        """Rezervirano ime algoritma ne smije proci kao 'provjereno'."""
        self._greska(self.tekst.replace("alg=ed25519", "alg=ml-dsa-65"), "REZERVIRAN")

    def test_nepoznat_alg(self):
        self._greska(self.tekst.replace("alg=ed25519", "alg=rsa"), "alg nije podrzan")


class TestValidacijaPolja(unittest.TestCase):
    def setUp(self):
        self.sk, self.pk = kripto.ed25519_novi_kljuc()

    def test_ime_mora_biti_dnk(self):
        with self.assertRaises(PeludGreska):
            Pelud.izdaj("medijapos.com", self.sk, 1, LOKATORI)

    def test_ime_se_normalizira(self):
        z = Pelud.izdaj("MedijaPos.DNK", self.sk, 1, LOKATORI)
        self.assertEqual("medijapos.dnk", z.ime)

    def test_bez_lokatora(self):
        with self.assertRaises(PeludGreska):
            Pelud.izdaj("a.dnk", self.sk, 1, [])

    def test_nepodrzana_shema_lokatora(self):
        with self.assertRaises(PeludGreska):
            Pelud.izdaj("a.dnk", self.sk, 1, ["ftp://example.com"])

    def test_wg_lokator_bez_porta(self):
        with self.assertRaises(PeludGreska):
            Pelud.izdaj("a.dnk", self.sk, 1, ["wg://1.2.3.4/kljuc"])

    def test_vijek_izvan_granica(self):
        for vijek in (0, -1, MAX_VIJEK_S + 1):
            with self.subTest(vijek=vijek), self.assertRaises(PeludGreska):
                Pelud.izdaj("a.dnk", self.sk, 1, LOKATORI, vijek_s=vijek)

    def test_negativna_visina(self):
        with self.assertRaises(PeludGreska):
            Pelud(ime="a.dnk", pk=self.pk.hex(), visina=-1,
                  exp=int(time.time()) + 60, lokatori=LOKATORI)


class TestDnsDijelovi(unittest.TestCase):
    def test_dijelovi_su_do_255_bajtova_i_spajaju_se(self):
        sk, _pk = kripto.ed25519_novi_kljuc()
        z = Pelud.izdaj("medijapos.dnk", sk, 4287,
                        LOKATORI + ["quic://198.51.100.7:8443"], ws="a" * 64)
        dijelovi = z.txt_dijelovi()
        self.assertGreater(len(dijelovi), 1, "zapis s tri lokatora prelazi 255 B")
        for d in dijelovi:
            self.assertLessEqual(len(d.encode("utf-8")), 255)
        self.assertEqual(z.txt(), spoji_dijelove(dijelovi))
        self.assertEqual(z.txt(), parsiraj(spoji_dijelove(dijelovi)).txt())


if __name__ == "__main__":
    unittest.main(verbosity=2)
