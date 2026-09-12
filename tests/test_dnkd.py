#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""dnkd (F2): razrjesenje, verifikacija, ponasanje pri kvaru, DNS odgovori.

Sidro je pravi HTTP posluzitelj na loopbacku (ne mock), pa se testira i PULL
put, ne samo logika. javno_zrcalo je izostavljeno gdje nije predmet testa —
inace bi test ovisio o javnom DNS-u, sto ga cini mjerenjem tudje mreze.
"""
import json
import pathlib
import struct
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from maska import dns_wire as dw            # noqa: E402
from maska import kripto                    # noqa: E402
from maska import dnkd                      # noqa: E402
from maska.pelud import Pelud               # noqa: E402

IME = "medijapos.dnk"
LOK_A = ["wg://217.160.71.124:51820/" + "A" * 42]
LOK_B = ["wg://203.0.113.9:51820/" + "B" * 42]


class Sidro:
    """Minimalno sidro koje sluzi PELUD zapis; ponasanje se mijenja u testu."""

    def __init__(self, sk, lokatori=None, visina=4287):
        self.sk = sk
        self.lokatori = lokatori or LOK_A
        self.visina = visina
        self.kvar = None                     # None | "500" | "podmetni" | "smece"
        self.pozivi = 0
        sidro = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a):
                pass

            def do_GET(self):
                sidro.pozivi += 1
                if sidro.kvar == "500":
                    self.send_response(500)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                if self.path != f"/{IME}.txt":
                    self.send_response(404)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                if sidro.kvar == "smece":
                    tijelo = b"v=PELUD1 ovo nije zapis"
                else:
                    z = Pelud.izdaj(IME, sidro.sk, sidro.visina, sidro.lokatori, vijek_s=300)
                    tekst = z.txt()
                    if sidro.kvar == "podmetni":
                        tekst = tekst.replace(f"h={sidro.visina}", "h=99999")
                    tijelo = tekst.encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(tijelo)))
                self.end_headers()
                self.wfile.write(tijelo)

        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.srv.daemon_threads = True
        # poll_interval 0.05 s: sa zadanih 0.5 s shutdown() po testu cini 33 testa
        # dugima ~17 s, a mjeri samo cekanje test-servera. Razrjesenje traje ~14 ms.
        threading.Thread(target=self.srv.serve_forever, kwargs={"poll_interval": 0.05},
                         daemon=True).start()

    @property
    def url(self):
        return f"http://127.0.0.1:{self.srv.server_address[1]}"

    def zatvori(self):
        self.srv.shutdown()
        self.srv.server_close()


class Osnova(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.sk, self.pk = kripto.ed25519_novi_kljuc()
        self.sidro = Sidro(self.sk)
        self.addCleanup(self.sidro.zatvori)
        self.addCleanup(self.dir.cleanup)

    def konfig(self, **prepisi):
        k = dict(dnkd.ZADANI_KONFIG)
        k.update({
            "sidra": [self.sidro.url],
            "imena": {IME: {"pk": self.pk.hex()}},
            "godovi": str(pathlib.Path(self.dir.name) / "godovi.jsonl"),
            "mapiranje_datoteka": str(pathlib.Path(self.dir.name) / "mapiranje.json"),
            "http_timeout_s": 3,
        })
        k.update(prepisi)
        dnkd.provjeri_konfig(k)
        return k

    def razrjesitelj(self, **prepisi):
        return dnkd.Razrjesitelj(self.konfig(**prepisi))


class TestRazrjesenje(Osnova):
    def test_uspjesno_razrjesenje(self):
        r = self.razrjesitelj()
        u = r.osvjezi(IME)
        self.assertEqual("OK", u.stanje, u.razlog)
        self.assertTrue(u.posluzi)
        self.assertEqual(4287, u.zapis.visina)
        self.assertEqual(LOK_A, u.zapis.lokatori)

    def test_adresa_je_u_mapiranoj_mrezi_i_stabilna(self):
        import ipaddress
        r = self.razrjesitelj()
        adresa = r.unosi[IME].adresa
        self.assertIn(ipaddress.ip_address(adresa),
                      ipaddress.ip_network("100.80.0.0/12"))
        r2 = self.razrjesitelj()                      # novi proces, isto mapiranje
        self.assertEqual(adresa, r2.unosi[IME].adresa)

    def test_mapiranje_ne_dira_rizom_prostor(self):
        """dnkd imena i RIZOM mesh moraju biti disjunktni po konstrukciji."""
        import ipaddress
        r = self.razrjesitelj()
        self.assertFalse(ipaddress.ip_network("100.80.0.0/12")
                         .overlaps(ipaddress.ip_network("100.64.0.0/12")))
        self.assertNotIn(ipaddress.ip_address(r.unosi[IME].adresa),
                         ipaddress.ip_network("100.64.0.0/12"))

    def test_podmetnut_zapis_je_alarm(self):
        r = self.razrjesitelj()
        self.sidro.kvar = "podmetni"
        u = r.osvjezi(IME)
        self.assertEqual("ALARM", u.stanje)
        self.assertIn("potpis_nevaljan", u.razlog)
        self.assertIsNone(u.zapis, "podmetnut zapis se NE smije zapamtiti")

    def test_neispravan_zapis_je_alarm_a_ne_nepoznato(self):
        r = self.razrjesitelj()
        self.sidro.kvar = "smece"
        u = r.osvjezi(IME)
        self.assertEqual("ALARM", u.stanje, "tvrdnja je stigla i neispravna je")

    def test_pad_sidra_je_nepoznato(self):
        r = self.razrjesitelj()
        self.sidro.kvar = "500"
        u = r.osvjezi(IME)
        self.assertEqual("NEPOZNATO", u.stanje, "mjerenje je palo, nije izmjeren kvar imena")
        self.assertIn("http_500", u.razlog)

    def test_stari_valjani_zapis_prezivi_pad_sidra(self):
        """Pad sidra ne smije ubiti ime koje je dokazano zivo do isteka roka."""
        r = self.razrjesitelj()
        r.osvjezi(IME)
        self.sidro.kvar = "500"
        u = r.osvjezi(IME)
        self.assertTrue(u.posluzi)
        self.assertIn("posluzujem zapis koji jos vrijedi", u.razlog)
        self.assertIsNotNone(u.zapis)

    def test_tudji_pinovani_kljuc_odbija_sve(self):
        _sk2, pk2 = kripto.ed25519_novi_kljuc()
        r = self.razrjesitelj(imena={IME: {"pk": pk2.hex()}})
        u = r.osvjezi(IME)
        self.assertEqual("ALARM", u.stanje)
        self.assertIn("pk_ne_odgovara_pinovanom", u.razlog)

    def test_bez_sidara_je_nepoznato_i_vatra(self):
        r = self.razrjesitelj(sidra=[])
        u = r.osvjezi(IME)
        self.assertEqual("NEPOZNATO", u.stanje)
        z = r.zdravlje()
        self.assertEqual("alarm", z["stanje"])
        self.assertTrue(any("nema konfiguriranih sidara" in v["razlog"] for v in z["vatre"]))

    def test_dva_sidra_koja_se_razilaze_su_alarm(self):
        drugo = Sidro(self.sk, lokatori=LOK_B)
        self.addCleanup(drugo.zatvori)
        r = self.razrjesitelj(sidra=[self.sidro.url, drugo.url])
        u = r.osvjezi(IME)
        self.assertEqual("ALARM", u.stanje)
        self.assertIn("razilaze", u.razlog)
        self.assertTrue(u.posluzi, "razilazenje sidara je alarm, ali ime ostaje dosezljivo")

    def test_visa_visina_lanca_pobjedjuje(self):
        starije = Sidro(self.sk, lokatori=LOK_A, visina=4200)
        self.addCleanup(starije.zatvori)
        self.sidro.visina = 4300
        self.sidro.lokatori = LOK_A
        r = self.razrjesitelj(sidra=[starije.url, self.sidro.url])
        u = r.osvjezi(IME)
        self.assertEqual(4300, u.zapis.visina)

    def test_svako_mjerenje_ide_u_godove(self):
        r = self.razrjesitelj()
        r.osvjezi(IME)
        self.sidro.kvar = "500"
        r.osvjezi(IME)
        self.sidro.kvar = "podmetni"
        r.osvjezi(IME)
        self.assertEqual(["OK", "NEPOZNATO", "ALARM"],
                         [z["ishod"] for z in r.godovi.zadnji(3)])
        self.assertEqual((True, []), r.godovi.provjeri())

    def test_razrijesi_ne_povlaci_dok_zapis_vrijedi(self):
        r = self.razrjesitelj()
        r.osvjezi(IME)
        prije = self.sidro.pozivi
        r.razrijesi(IME)
        self.assertEqual(prije, self.sidro.pozivi, "valjan zapis se ne povlaci ponovno")

    def test_nepoznato_ime_nije_u_unosima(self):
        r = self.razrjesitelj()
        self.assertIsNone(r.razrijesi("tudje.dnk"))


class TestDnsOdgovori(Osnova):
    def jezgra(self, **prepisi):
        r = self.razrjesitelj(**prepisi)
        r.osvjezi(IME)
        return r, dnkd._DnsJezgra(r)

    def odgovor(self, jezgra, ime, tip):
        id_, paket = dw.izgradi_upit(ime, tip)
        return dw.parsiraj_odgovor(jezgra.odgovori(paket), id_)

    def test_a_zapis_daje_mapiranu_adresu(self):
        r, j = self.jezgra()
        odg = self.odgovor(j, IME, dw.TIP_A)
        self.assertEqual(dw.RCODE_NOERROR, odg["rcode"])
        self.assertEqual(r.unosi[IME].adresa, dw.a_iz_rdata(odg["zapisi"][0][1]))

    def test_txt_vraca_cijeli_pelud(self):
        r, j = self.jezgra()
        odg = self.odgovor(j, IME, dw.TIP_TXT)
        self.assertEqual(r.unosi[IME].zapis.txt(), dw.txt_iz_rdata(odg["zapisi"][0][1]))

    def test_aaaa_je_nodata_ne_greska(self):
        _r, j = self.jezgra()
        odg = self.odgovor(j, IME, dw.TIP_AAAA)
        self.assertEqual(dw.RCODE_NOERROR, odg["rcode"])
        self.assertEqual([], odg["zapisi"])

    def test_izvan_dnk_je_refused(self):
        _r, j = self.jezgra()
        for ime in ("example.com", "genesis.limit-connect.com", "localhost"):
            with self.subTest(ime=ime):
                self.assertEqual(dw.RCODE_REFUSED, self.odgovor(j, ime, dw.TIP_A)["rcode"])

    def test_nekonfigurirano_dnk_ime_je_nxdomain(self):
        _r, j = self.jezgra()
        self.assertEqual(dw.RCODE_NXDOMAIN, self.odgovor(j, "tudje.dnk", dw.TIP_A)["rcode"])

    def test_ttl_ogranicen_konfiguracijom(self):
        _r, j = self.jezgra(ttl_s=30)
        id_, paket = dw.izgradi_upit(IME, dw.TIP_A)
        odgovor = j.odgovori(paket)
        u = dw.parsiraj_upit(paket)
        poz = 12 + u.duzina_pitanja + 2
        self.assertLessEqual(struct.unpack(">I", odgovor[poz + 4:poz + 8])[0], 30)

    def test_servfail_kad_se_ime_ne_posluzuje(self):
        r, j = self.jezgra()
        r.unosi[IME].posluzi = False
        self.assertEqual(dw.RCODE_SERVFAIL, self.odgovor(j, IME, dw.TIP_A)["rcode"])

    def test_formerr_na_smece(self):
        _r, j = self.jezgra()
        odg = dw.parsiraj_odgovor(j.odgovori(b"\x01\x02\x03"))
        self.assertEqual(dw.RCODE_FORMERR, odg["rcode"])

    def test_brojac_upita_raste(self):
        r, j = self.jezgra()
        prije = r.brojac_upita
        self.odgovor(j, IME, dw.TIP_A)
        self.assertEqual(prije + 1, r.brojac_upita)


class TestKonfiguracija(Osnova):
    def _pada(self, dio_poruke, **prepisi):
        k = dict(dnkd.ZADANI_KONFIG)
        k.update({"sidra": [self.sidro.url], "imena": {IME: {"pk": self.pk.hex()}}})
        k.update(prepisi)
        with self.assertRaises(SystemExit) as ctx:
            dnkd.provjeri_konfig(k)
        self.assertIn(dio_poruke, str(ctx.exception))

    def test_kratak_pin(self):
        self._pada("64 hex", imena={IME: {"pk": "abcd"}})

    def test_pin_nije_hex(self):
        self._pada("64 hex", imena={IME: {"pk": "z" * 64}})

    def test_nepoznato_polje_imena(self):
        self._pada("nepoznata polja", imena={IME: {"pk": self.pk.hex(), "ip": "1.2.3.4"}})

    def test_mreza_izvan_rfc6598(self):
        self._pada("100.64.0.0/10", mapiranje_mreza="10.0.0.0/8")

    def test_sidro_nije_url(self):
        self._pada("http(s) URL", sidra=["genesis.limit-connect.com"])

    def test_nepoznata_vrijednost_na_nesuglasje(self):
        self._pada("odbij", na_nesuglasje="ignoriraj")

    def test_nepoznata_stavka_u_datoteci_odbijena(self):
        p = pathlib.Path(self.dir.name) / "dnkd.json"
        p.write_text(json.dumps({"slusaj_dns": "127.0.0.53:5353", "tipfeler": 1}))
        with self.assertRaises(SystemExit) as ctx:
            dnkd.ucitaj_konfig(p)
        self.assertIn("tipfeler", str(ctx.exception))

    def test_biljeska_je_dopustena(self):
        p = pathlib.Path(self.dir.name) / "dnkd2.json"
        p.write_text(json.dumps({
            "_biljeska": "objasnjenje za citaca", "sidra": [self.sidro.url],
            "imena": {IME: {"pk": self.pk.hex()}},
            "godovi": str(pathlib.Path(self.dir.name) / "g.jsonl"),
            "mapiranje_datoteka": str(pathlib.Path(self.dir.name) / "m.json")}))
        k = dnkd.ucitaj_konfig(p)
        self.assertNotIn("_biljeska", k)


class TestHttpPovrsina(Osnova):
    def test_zdravlje_ima_polja_koja_watchdog_cita(self):
        """tunel_watchdog.py cita 'stanje', 'vatre[].razlog/ozbiljnost' i 'vrijeme'."""
        r = self.razrjesitelj()
        r.osvjezi(IME)
        z = r.zdravlje()
        for polje in ("stanje", "vatre", "vrijeme", "dok_count", "imena", "godovi_lanac"):
            self.assertIn(polje, z)
        self.assertEqual("ok", z["stanje"])
        self.assertRegex(z["vrijeme"], r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")

    def test_razbijen_lanac_godova_gasi_zeleno(self):
        r = self.razrjesitelj()
        r.osvjezi(IME)
        p = pathlib.Path(r.godovi.putanja)
        linije = p.read_text().splitlines()
        podaci = json.loads(linije[0])
        podaci["ishod"] = "ALARM"
        p.write_text(json.dumps(podaci, sort_keys=True, separators=(",", ":")) + "\n")
        z = r.zdravlje()
        self.assertEqual("alarm", z["stanje"])
        self.assertEqual("RAZBIJEN", z["godovi_lanac"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
