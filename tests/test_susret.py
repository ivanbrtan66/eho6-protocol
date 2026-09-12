#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SUSRET (F4): oglasna ploca na sidru — sto prima, sto odbija, i sto NE moze.

Najvazniji test u ovoj datoteci nije nijedan pozitivan slucaj nego
test_nema_releja: susret ne smije imati rutu koja prenosi teret. Da je ima,
F4 ne bi ukinuo jedinstvenu tocku kvara nego bi je preselio na novi port.
"""
import json
import pathlib
import sys
import threading
import time
import unittest
import urllib.error
import urllib.request

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from maska import kripto                                      # noqa: E402
from maska import susret as sus                               # noqa: E402
from maska import stun                                        # noqa: E402
from maska.probod import Kandidat, Oglas, TIP_HOST, TIP_REFLEKS  # noqa: E402

KANDIDATI = [Kandidat(TIP_HOST, "192.168.1.20", 51820),
             Kandidat(TIP_REFLEKS, "198.51.100.7", 40000)]


class Osnova(unittest.TestCase):
    granica_upita = 240
    pinuj = True

    def setUp(self):
        self.sk, self.pk = kripto.ed25519_novi_kljuc()
        konfig = dict(sus.ZADANI_KONFIG)
        konfig.update({
            "imena": ({"x96": {"pk": self.pk.hex()}} if self.pinuj else {}),
            "upita_u_minuti_po_ip": self.granica_upita,
            "drugo_sidro_stun": "203.0.113.10:3478",
        })
        sus.provjeri_konfig(konfig)
        self.konfig = konfig
        self.stun = stun.Posluzitelj(("127.0.0.1", 0))
        self.stun.pokreni_u_niti()
        self.srv = sus.Susret(("127.0.0.1", 0), konfig, self.stun)
        threading.Thread(target=self.srv.serve_forever, kwargs={"poll_interval": 0.02},
                         daemon=True).start()
        self.baza = f"http://127.0.0.1:{self.srv.server_address[1]}"
        self.addCleanup(self.stun.server_close)
        self.addCleanup(self.stun.shutdown)
        self.addCleanup(self.srv.server_close)
        self.addCleanup(self.srv.shutdown)

    # -- pomocno -----------------------------------------------------------
    def oglas(self, **kwargs) -> Oglas:
        return Oglas.napravi(kwargs.pop("ime", "x96"), kwargs.pop("kandidati", KANDIDATI),
                             kwargs.pop("sk", self.sk), **kwargs)

    def posalji(self, tijelo, put="/susret/oglas"):
        if isinstance(tijelo, str):
            tijelo = tijelo.encode("utf-8")
        zahtjev = urllib.request.Request(self.baza + put, data=tijelo, method="POST",
                                         headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(zahtjev, timeout=5) as odgovor:
                return odgovor.status, json.loads(odgovor.read() or b"{}")
        except urllib.error.HTTPError as e:
            sirovo = e.read()
            try:
                return e.code, json.loads(sirovo or b"{}")
            except json.JSONDecodeError:
                return e.code, {"sirovo": sirovo[:200].decode("utf-8", "replace")}

    def dohvati(self, put):
        try:
            with urllib.request.urlopen(self.baza + put, timeout=5) as odgovor:
                return odgovor.status, odgovor.read().decode("utf-8")
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode("utf-8", "replace")


class TestPloca(Osnova):
    def test_potpisan_oglas_se_prihvaca_i_sluzi_verbatim(self):
        oglas = self.oglas(nat="EIM")
        status, tijelo = self.posalji(oglas.tekst())
        self.assertEqual(201, status, tijelo)
        self.assertEqual(2, tijelo["kandidata"])

        status, sirovo = self.dohvati("/susret/oglas/x96")
        self.assertEqual(200, status)
        self.assertEqual(oglas.tekst(), sirovo, "sidro ne smije prepakirati oglas")
        self.assertEqual((True, ""), Oglas.parsiraj(sirovo).provjeri(self.pk.hex()))

    def test_tudji_kljuc_odbijen(self):
        sk2, _pk2 = kripto.ed25519_novi_kljuc()
        status, tijelo = self.posalji(self.oglas(sk=sk2).tekst())
        self.assertEqual(403, status)
        self.assertIn("pk_ne_odgovara_pinovanom", tijelo["greska"])

    def test_nepinovano_ime_odbijeno(self):
        status, tijelo = self.posalji(self.oglas(ime="tudje").tekst())
        self.assertEqual(403, status)
        self.assertIn("pk_nije_pinovan", tijelo["greska"])

    def test_podmetnut_oglas_odbijen(self):
        podmetnut = self.oglas().tekst().replace("198.51.100.7", "203.0.113.9")
        status, tijelo = self.posalji(podmetnut)
        self.assertEqual(403, status)
        self.assertIn("potpis_nevaljan", tijelo["greska"])

    def test_ponovljen_nonce_odbijen(self):
        oglas = self.oglas()
        self.assertEqual(201, self.posalji(oglas.tekst())[0])
        status, tijelo = self.posalji(oglas.tekst())
        self.assertEqual(409, status)
        self.assertIn("nonce_ponovljen", tijelo["greska"])

    def test_stariji_oglas_ne_prepisuje_noviji(self):
        noviji = self.oglas()
        self.assertEqual(201, self.posalji(noviji.tekst())[0])
        stariji = self.oglas(sada=time.time() - 60)
        status, tijelo = self.posalji(stariji.tekst())
        self.assertEqual(409, status)
        self.assertIn("stariji", tijelo["greska"])
        _s, sirovo = self.dohvati("/susret/oglas/x96")
        self.assertEqual(noviji.tekst(), sirovo)

    def test_smece_nije_oglas(self):
        status, _t = self.posalji("{ovo nije json")
        self.assertEqual(400, status)

    def test_prevelik_oglas(self):
        status, _t = self.posalji(b"x" * 9000)
        self.assertEqual(413, status)

    def test_nepoznato_ime_je_404(self):
        status, _t = self.dohvati("/susret/oglas/nepostoji")
        self.assertEqual(404, status)

    def test_oglas_istekne(self):
        ploca = sus.Ploca(trajanje_s=120, max_oglasa=10)
        oglas = self.oglas()
        sada = time.time()
        self.assertEqual((True, ""), ploca.objavi(oglas, oglas.tekst(), "127.0.0.1", sada=sada))
        self.assertIsNotNone(ploca.dohvati("x96", sada=sada + 119))
        self.assertIsNone(ploca.dohvati("x96", sada=sada + 121),
                          "oglas s rokom mora nestati sam")

    def test_puna_ploca(self):
        ploca = sus.Ploca(trajanje_s=120, max_oglasa=1)
        prvi = self.oglas(ime="x96")
        ploca.objavi(prvi, prvi.tekst(), "127.0.0.1")
        drugi = Oglas.napravi("drugi", KANDIDATI, self.sk)
        ok, razlog = ploca.objavi(drugi, drugi.tekst(), "127.0.0.1")
        self.assertFalse(ok)
        self.assertIn("puna", razlog)

    def test_sidro_zna_samo_tko_postoji(self):
        self.posalji(self.oglas(nat="EIM").tekst())
        _s, sirovo = self.dohvati("/susret/imena")
        imena = json.loads(sirovo)["imena"]
        self.assertEqual(1, len(imena))
        self.assertEqual({"ime", "nat", "kandidata", "star_s"}, set(imena[0]))
        self.assertEqual("x96", imena[0]["ime"])


class TestNemaReleja(Osnova):
    def test_nema_releja(self):
        """Susret NE SMIJE imati rutu koja prenosi teret — to je cijela poanta F4."""
        for put in ("/susret/relej", "/relay", "/proxy", "/susret/prenesi",
                    "/susret/oglas/x96/prenesi"):
            with self.subTest(put=put):
                self.assertEqual(404, self.dohvati(put)[0])
                self.assertEqual(404, self.posalji(b"{}", put)[0])

    def test_zdravlje_izricito_kaze_da_releja_nema(self):
        _s, sirovo = self.dohvati("/borg/health.json")
        self.assertIs(False, json.loads(sirovo)["relej"])

    def test_korijen_opisuje_sto_sidro_zna(self):
        _s, sirovo = self.dohvati("/")
        opis = json.loads(sirovo)
        self.assertIn("tko postoji", opis["sto_znam"])
        self.assertIn("sastajaliste", opis["relej"])


class TestZdravlje(Osnova):
    def test_zdravo_sidro_je_ok(self):
        _s, sirovo = self.dohvati("/borg/health.json")
        z = json.loads(sirovo)
        self.assertEqual("ok", z["stanje"], z["vatre"])
        for polje in ("stanje", "vatre", "vrijeme", "oglasa_sada", "stun_upita"):
            self.assertIn(polje, z)
        self.assertRegex(z["vrijeme"], r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")

    def test_stun_upiti_se_broje(self):
        stun.otkrij(self.stun.server_address, rto_s=0.2, slanja=2)
        _s, sirovo = self.dohvati("/borg/health.json")
        self.assertGreaterEqual(json.loads(sirovo)["stun_upita"], 1)


class TestZdravljeBezImena(Osnova):
    pinuj = False

    def test_bez_pinovanih_imena_je_alarm(self):
        _s, sirovo = self.dohvati("/borg/health.json")
        z = json.loads(sirovo)
        self.assertEqual("alarm", z["stanje"])
        self.assertTrue(any("nema pinovanih imena" in v["razlog"] for v in z["vatre"]))


class TestBezDrugogSidra(unittest.TestCase):
    def test_bez_druge_tocke_gledanja_nije_zeleno(self):
        """S jednom tockom gledanja NAT se ne moze klasificirati — to mora biti vidljivo."""
        sk, pk = kripto.ed25519_novi_kljuc()
        konfig = dict(sus.ZADANI_KONFIG)
        konfig.update({"imena": {"x96": {"pk": pk.hex()}}, "drugo_sidro_stun": None})
        srv = sus.Susret(("127.0.0.1", 0), konfig, stun.Posluzitelj(("127.0.0.1", 0)))
        self.addCleanup(srv.server_close)
        z = srv.zdravlje()
        self.assertEqual("NEPOZNATO", z["stanje"])
        self.assertTrue(any("drugo_sidro_stun" in v["razlog"] for v in z["vatre"]))
        del sk


class TestOgranicenje(Osnova):
    granica_upita = 3

    def test_previse_upita_daje_429(self):
        kodovi = [self.dohvati("/susret/imena")[0] for _ in range(5)]
        self.assertIn(429, kodovi)
        self.assertEqual(3, kodovi.count(200))


class TestKonfiguracija(unittest.TestCase):
    def _pada(self, dio_poruke, **prepisi):
        konfig = dict(sus.ZADANI_KONFIG)
        konfig.update(prepisi)
        with self.assertRaises(SystemExit) as ctx:
            sus.provjeri_konfig(konfig)
        self.assertIn(dio_poruke, str(ctx.exception))

    def test_kratak_pk(self):
        self._pada("64 hex", imena={"x96": {"pk": "abcd"}})

    def test_nepoznato_polje_imena(self):
        self._pada("nepoznata polja", imena={"x96": {"pk": "a" * 64, "ip": "1.2.3.4"}})

    def test_predugo_trajanje_oglasa(self):
        self._pada("10 i 3600", trajanje_oglasa_s=99999)

    def test_drugo_sidro_mora_biti_ip(self):
        self._pada("IP:PORT", drugo_sidro_stun="fina-connect.online:3478")

    def test_nepoznata_stavka_u_datoteci(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            p = pathlib.Path(d) / "susret.json"
            p.write_text(json.dumps({"slusaj_http": "127.0.0.1:8100", "tipfeler": 1}))
            with self.assertRaises(SystemExit) as ctx:
                sus.ucitaj_konfig(p)
            self.assertIn("tipfeler", str(ctx.exception))


if __name__ == "__main__":
    unittest.main(verbosity=2)
