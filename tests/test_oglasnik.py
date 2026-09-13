#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""OGLASNIK (F5): K-od-N konsenzus, i dokaz da pult NE placa SEO dosegom.

Tri pulta stvarno se pokrecu na loopbacku, svaki sa svojim sidrom, i medjusobno
se PULL-aju. Tako se testira i ono sto je jedina svrha ove faze: da pult koji je
otet (ili kojem je registrar promijenio odrediste) NE moze sam preusmjeriti
korisnika, jer nema K glasova.
"""
import json
import pathlib
import re
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from maska import kripto                                        # noqa: E402
from maska import oglasnik as og                                # noqa: E402
from maska.pelud import Pelud                                   # noqa: E402

IME = "medijapos.dnk"
CILJ_A = "https://genesis-medijapos.limit-connect.com"
CILJ_B = "https://podmetnuto.example"


def _pelud(sk, lokatori, visina=4287):
    return Pelud.izdaj(IME, sk, visina, lokatori, vijek_s=600)


class Sidro:
    """Sidro koje sluzi PELUD zapis; test mijenja sto tocno sluzi."""

    def __init__(self, sk, lokatori=None, visina=4287, host="127.0.0.1"):
        self.sk, self.lokatori, self.visina = sk, (lokatori or [CILJ_A]), visina
        self.host = host
        self.mrtvo = False
        sidro = self

        class H(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a):
                pass

            def do_GET(self):
                if sidro.mrtvo:
                    self.send_response(503)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                if self.path != f"/{IME}.txt":
                    self.send_response(404)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                t = _pelud(sidro.sk, sidro.lokatori, sidro.visina).txt().encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(t)))
                self.end_headers()
                self.wfile.write(t)

        self.srv = ThreadingHTTPServer((host, 0), H)
        self.srv.daemon_threads = True
        threading.Thread(target=self.srv.serve_forever, kwargs={"poll_interval": 0.02},
                         daemon=True).start()

    @property
    def url(self):
        return f"http://{self.host}:{self.srv.server_address[1]}"

    def zatvori(self):
        self.srv.shutdown()
        self.srv.server_close()


class Pult:
    """Pravi Oglasnik na loopbacku. Domena se glumi razlicitim portom."""

    def __init__(self, ime, sidro_url, k, godovi, host="127.0.0.1"):
        self.host = host
        # Pultovi se povezuju TEK kad svi imaju adresu (povezi()), jer je topologija
        # kruzna: svaki PULL-a svakoga. Do tada stoji mjesto-drzac koji zadovoljava
        # ustavno pravilo k > n/2 — konfiguracija se ne smije zaobici ni u testu.
        konfig = dict(og.ZADANI_KONFIG)
        konfig.update({"ime_ploce": ime, "sidra": [sidro_url],
                       "ploce": ["https://mjesto-drzac.invalid"], "k": k,
                       "imena": {IME: {"pk": PK}}, "godovi": godovi,
                       "kanonska_domena": "https://genesis.limit-connect.com",
                       "http_timeout_s": 2})
        og.provjeri_konfig(konfig)
        self.o = og.Oglasnik(konfig)
        self.srv = og._Posluzitelj((host, 0), og._Handler)
        self.srv.oglasnik = self.o
        self.srv.RequestHandlerClass.log_message = lambda *a, **k: None
        threading.Thread(target=self.srv.serve_forever, kwargs={"poll_interval": 0.02},
                         daemon=True).start()

    def povezi(self, ploce):
        """Poveži pult s ostalima tek kad su svi digli svoje adrese."""
        self.o.konfig["ploce"] = list(ploce)
        og.provjeri_konfig(self.o.konfig)

    @property
    def url(self):
        return f"http://{self.host}:{self.srv.server_address[1]}"

    def zatvori(self):
        self.srv.shutdown()
        self.srv.server_close()


SK, PKB = kripto.ed25519_novi_kljuc()
PK = PKB.hex()


class TestOdluka(unittest.TestCase):
    """Cista logika konsenzusa, bez mreze."""

    def setUp(self):
        self.zapis = _pelud(SK, [CILJ_A])
        self.drugi = _pelud(SK, [CILJ_B])

    def glas(self, izvor, zapis=None, stanje="OK", razlog=""):
        return og.Glas(izvor, stanje, razlog, zapis)

    def test_k_od_n_postignut(self):
        o = og.odluci([self.glas("a", self.zapis), self.glas("b", self.zapis),
                       self.glas("c", None, "NEPOZNATO", "pao")], k=2)
        self.assertEqual("SUGLASNO", o.stanje)
        self.assertEqual(CILJ_A, o.cilj)
        self.assertEqual(2, o.glasova_za)
        self.assertTrue(o.preusmjeri)

    def test_otet_pult_ne_moze_sam_preusmjeriti(self):
        """Jedan oteti pult protiv dva postena: vecina odlucuje, otmica ne prolazi."""
        o = og.odluci([self.glas("a", self.zapis), self.glas("b", self.zapis),
                       self.glas("otet", self.drugi)], k=2)
        self.assertEqual("SUGLASNO", o.stanje)
        self.assertEqual(CILJ_A, o.cilj, "cilj otetog pulta ne smije pobijediti")

    def test_svi_se_razilaze(self):
        treci = _pelud(SK, ["https://treci.example"])
        o = og.odluci([self.glas("a", self.zapis), self.glas("b", self.drugi),
                       self.glas("c", treci)], k=2)
        self.assertEqual("NESUGLASNO", o.stanje)
        self.assertIsNone(o.cilj)
        self.assertFalse(o.preusmjeri)

    def test_premalo_izvora(self):
        o = og.odluci([self.glas("a", self.zapis),
                       self.glas("b", None, "NEPOZNATO", "pao"),
                       self.glas("c", None, "NEPOZNATO", "pao")], k=2)
        self.assertEqual("NEDOVOLJNO", o.stanje)
        self.assertIn("nedostaje 1", o.razlog)

    def test_nevaljan_potpis_nije_glas(self):
        o = og.odluci([self.glas("a", self.zapis),
                       self.glas("b", None, "ALARM", "potpis_nevaljan")], k=2)
        self.assertEqual("NEDOVOLJNO", o.stanje)

    def test_razlicita_visina_nije_neslaganje(self):
        """Pult koji kasni ima manju visinu, ali isti skup lokatora — to je slaganje."""
        stariji = _pelud(SK, [CILJ_A], visina=4200)
        o = og.odluci([self.glas("a", self.zapis), self.glas("b", stariji)], k=2)
        self.assertEqual("SUGLASNO", o.stanje)
        self.assertEqual(4287, o.zapis.visina, "koristi se najsvjeziji potpis iz skupine")

    def test_bez_http_lokatora_nema_preusmjeravanja(self):
        samo_wg = _pelud(SK, ["wg://217.160.71.124:51820/" + "A" * 42])
        o = og.odluci([self.glas("a", samo_wg), self.glas("b", samo_wg)], k=2)
        self.assertEqual("NESUGLASNO", o.stanje)
        self.assertIn("http(s)", o.razlog)

    def test_https_ima_prednost_pred_http(self):
        mjesano = _pelud(SK, ["http://staro.example", "https://novo.example"])
        o = og.odluci([self.glas("a", mjesano), self.glas("b", mjesano)], k=2)
        self.assertEqual("https://novo.example", o.cilj)


class TestKonfiguracija(unittest.TestCase):
    def _konfig(self, **prepisi):
        k = dict(og.ZADANI_KONFIG)
        k.update({"ploce": ["https://a.example", "https://b.example"], "k": 2,
                  "imena": {IME: {"pk": PK}}})
        k.update(prepisi)
        return k

    def _pada(self, dio, **prepisi):
        with self.assertRaises(SystemExit) as ctx:
            og.provjeri_konfig(self._konfig(**prepisi))
        self.assertIn(dio, str(ctx.exception))

    def test_valjana_postava(self):
        og.provjeri_konfig(self._konfig())

    def test_k_jedan_nije_konsenzus(self):
        self._pada("nije konsenzus", k=1)

    def test_k_vece_od_n(self):
        self._pada("vece od broja izvora", k=5)

    def test_k_mora_biti_stroga_vecina(self):
        """Bez toga dvije skupine mogu imati po K glasova i preusmjeravati razlicito."""
        self._pada("stroga vecina", k=2,
                   ploce=["https://a.example", "https://b.example", "https://c.example"])

    def test_dva_pulta_na_istoj_domeni(self):
        self._pada("nisu dva nezavisna izvora",
                   ploce=["https://a.example/x", "https://a.example/y"])

    def test_trajno_preusmjeravanje_odbijeno(self):
        self._pada("301 prenosi", preusmjeri_kod=301)

    def test_kanonska_domena_mora_biti_https(self):
        self._pada("https URL", kanonska_domena="http://genesis.limit-connect.com")

    def test_kratak_pk(self):
        self._pada("64 hex", imena={IME: {"pk": "abcd"}})


class TestTriPulta(unittest.TestCase):
    """Tri prava pulta na loopbacku, svaki sa svojim sidrom."""

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.hostovi = ("127.0.0.1", "127.0.0.2", "127.0.0.3")
        self.sidra = [Sidro(SK, host=h) for h in self.hostovi]
        for s in self.sidra:
            self.addCleanup(s.zatvori)
        self.a = Pult("a", self.sidra[0].url, 2, f"{self.dir.name}/a.jsonl", self.hostovi[0])
        self.b = Pult("b", self.sidra[1].url, 2, f"{self.dir.name}/b.jsonl", self.hostovi[1])
        self.c = Pult("c", self.sidra[2].url, 2, f"{self.dir.name}/c.jsonl", self.hostovi[2])
        for p in (self.a, self.b, self.c):
            self.addCleanup(p.zatvori)
        self.a.povezi([self.b.url, self.c.url])
        self.b.povezi([self.a.url, self.c.url])
        self.c.povezi([self.a.url, self.b.url])

    def dohvati(self, url, prati=False):
        klasa = urllib.request.HTTPRedirectHandler if prati else _BezPracenja
        otvarac = urllib.request.build_opener(klasa())
        try:
            with otvarac.open(url, timeout=5) as o:
                return o.status, dict(o.headers), o.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            return e.code, dict(e.headers), e.read().decode("utf-8", "replace")

    def test_svi_slozni_pult_preusmjerava(self):
        status, zaglavlja, _t = self.dohvati(f"{self.a.url}/{IME}")
        self.assertEqual(307, status)
        self.assertEqual(CILJ_A, zaglavlja["Location"])
        self.assertIn("noindex", zaglavlja["X-Robots-Tag"])

    def test_jedan_otet_pult_ne_mijenja_ishod(self):
        self.sidra[1].lokatori = [CILJ_B]          # B-ovo sidro pocinje lagati
        self.b.o.osvjezi_svoj(IME)
        status, zaglavlja, _t = self.dohvati(f"{self.a.url}/{IME}")
        self.assertEqual(307, status)
        self.assertEqual(CILJ_A, zaglavlja["Location"],
                         "A i C su slozni — oteti B ne smije promijeniti odrediste")

    def test_svi_razliciti_nema_preusmjeravanja(self):
        self.sidra[1].lokatori = [CILJ_B]
        self.sidra[2].lokatori = ["https://treci.example"]
        self.b.o.osvjezi_svoj(IME)
        self.c.o.osvjezi_svoj(IME)
        status, _z, tijelo = self.dohvati(f"{self.a.url}/{IME}")
        self.assertEqual(503, status)
        self.assertIn("NESUGLASNO", tijelo)
        self.assertIn("noindex", tijelo)

    def test_pad_dvaju_pultova_nema_preusmjeravanja(self):
        self.b.zatvori()
        self.c.zatvori()
        status, _z, tijelo = self.dohvati(f"{self.a.url}/{IME}")
        self.assertEqual(503, status)
        self.assertIn("NEDOVOLJNO", tijelo)

    def test_pokazivac_se_sluzi_verbatim(self):
        _s, _z, tijelo = self.dohvati(f"{self.b.url}/oglasnik/pokazivac/{IME}")
        zapis = og.parsiraj(tijelo)
        self.assertEqual((True, ""), zapis.provjeri(PK))

    def test_robots_txt_zabranjuje_indeksiranje(self):
        _s, _z, tijelo = self.dohvati(f"{self.a.url}/robots.txt")
        self.assertIn("Disallow: /", tijelo)

    def test_svaki_odgovor_nosi_noindex_i_canonical(self):
        """Ovo je mehanizam zbog kojeg F5 NE placa SEO dosegom."""
        for put in ("/robots.txt", "/borg/health.json", f"/oglasnik/pokazivac/{IME}",
                    f"/{IME}"):
            with self.subTest(put=put):
                _s, zaglavlja, _t = self.dohvati(self.a.url + put)
                self.assertIn("noindex", zaglavlja.get("X-Robots-Tag", ""))
                self.assertIn("rel=\"canonical\"", zaglavlja.get("Link", ""))

    def test_zdravlje_trostanje(self):
        self.dohvati(f"{self.a.url}/{IME}")
        _s, _z, tijelo = self.dohvati(f"{self.a.url}/borg/health.json")
        z = json.loads(tijelo)
        self.assertEqual("ok", z["stanje"], z["vatre"])
        self.assertEqual(2, z["k"])
        self.assertEqual(3, z["n"])
        self.assertIs(False, z["indeksira_se"])

    def test_razilazenje_je_alarm_u_zdravlju(self):
        self.sidra[1].lokatori = [CILJ_B]
        self.sidra[2].lokatori = ["https://treci.example"]
        self.b.o.osvjezi_svoj(IME)
        self.c.o.osvjezi_svoj(IME)
        self.dohvati(f"{self.a.url}/{IME}")
        _s, _z, tijelo = self.dohvati(f"{self.a.url}/borg/health.json")
        z = json.loads(tijelo)
        self.assertEqual("alarm", z["stanje"])
        self.assertTrue(any("razilaze" in v["razlog"] for v in z["vatre"]))

    def test_odluke_idu_u_godove(self):
        self.dohvati(f"{self.a.url}/{IME}")
        zapisi = self.a.o.godovi.zadnji(5)
        self.assertTrue(zapisi)
        self.assertEqual(f"oglasnik:{IME}", zapisi[-1]["ime"])
        self.assertEqual((True, []), self.a.o.godovi.provjeri())

    def test_nepoznato_ime(self):
        status, _z, _t = self.dohvati(f"{self.a.url}/tudje.dnk")
        self.assertEqual(404, status)


class _BezPracenja(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


if __name__ == "__main__":
    unittest.main(verbosity=2)
