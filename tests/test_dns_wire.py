#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""DNS kodek: ono sto dnkd mora tocno pogoditi na zici."""
import pathlib
import struct
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from maska import dns_wire as dw  # noqa: E402


def upit(ime="medijapos.dnk", tip=dw.TIP_A):
    id_, paket = dw.izgradi_upit(ime, tip)
    return id_, dw.parsiraj_upit(paket)


class TestImena(unittest.TestCase):
    def test_krug(self):
        podaci = dw.kodiraj_ime("medijapos.dnk")
        self.assertEqual(("medijapos.dnk", len(podaci)), dw.dekodiraj_ime(podaci, 0))

    def test_korijen(self):
        self.assertEqual(b"\x00", dw.kodiraj_ime("."))

    def test_preduga_oznaka(self):
        with self.assertRaises(dw.DnsGreska):
            dw.kodiraj_ime("a" * 64 + ".dnk")

    def test_kompresijski_pokazivac(self):
        paket = b"\x00" * 12 + dw.kodiraj_ime("medijapos.dnk") + b"\xc0\x0c"
        poz = 12 + len(dw.kodiraj_ime("medijapos.dnk"))
        self.assertEqual(("medijapos.dnk", poz + 2), dw.dekodiraj_ime(paket, poz))

    def test_pokazivac_unaprijed_odbijen(self):
        """Pokazivac koji ne pokazuje natrag je klasican put u beskonacnu petlju."""
        with self.assertRaises(dw.DnsGreska):
            dw.dekodiraj_ime(b"\xc0\x20" + b"\x00" * 40, 0)

    def test_pokazivac_na_sebe_odbijen(self):
        with self.assertRaises(dw.DnsGreska):
            dw.dekodiraj_ime(b"\x00" * 12 + b"\xc0\x0c", 12)


class TestUpit(unittest.TestCase):
    def test_parsiranje(self):
        _id, u = upit("medijapos.dnk", dw.TIP_TXT)
        self.assertEqual("medijapos.dnk", u.ime)
        self.assertEqual(dw.TIP_TXT, u.tip)
        self.assertEqual(dw.KLASA_IN, u.klasa)
        self.assertTrue(u.rd)

    def test_odgovor_nije_upit(self):
        with self.assertRaises(dw.DnsGreska):
            dw.parsiraj_upit(struct.pack(">HHHHHH", 1, 0x8000, 1, 0, 0, 0))

    def test_kraci_od_zaglavlja(self):
        with self.assertRaises(dw.DnsGreska):
            dw.parsiraj_upit(b"\x00\x01")

    def test_vise_pitanja_odbijeno(self):
        with self.assertRaises(dw.DnsGreska):
            dw.parsiraj_upit(struct.pack(">HHHHHH", 1, 0, 2, 0, 0, 0)
                             + dw.kodiraj_ime("a.dnk") + struct.pack(">HH", 1, 1))

    def test_formerr_zadrzava_id(self):
        odg = dw.parsiraj_odgovor(dw.odgovor_formerr(b"\x12\x34smece"))
        self.assertEqual(dw.RCODE_FORMERR, odg["rcode"])


class TestOdgovori(unittest.TestCase):
    def test_a_zapis(self):
        id_, u = upit()
        odg = dw.parsiraj_odgovor(dw.odgovor_a(u, "100.80.12.34", 120), id_)
        self.assertEqual(dw.RCODE_NOERROR, odg["rcode"])
        self.assertEqual("100.80.12.34", dw.a_iz_rdata(odg["zapisi"][0][1]))

    def test_a_ttl_se_prenosi(self):
        _id, u = upit()
        paket = dw.odgovor_a(u, "100.80.0.5", 77)
        poz = 12 + u.duzina_pitanja + 2                      # iza pokazivaca na ime
        ttl = struct.unpack(">I", paket[poz + 4:poz + 8])[0]
        self.assertEqual(77, ttl)

    def test_a_ttl_nula_postaje_jedan(self):
        _id, u = upit()
        paket = dw.odgovor_a(u, "100.80.0.5", 0)
        poz = 12 + u.duzina_pitanja + 2
        self.assertEqual(1, struct.unpack(">I", paket[poz + 4:poz + 8])[0])

    def test_neispravna_adresa(self):
        _id, u = upit()
        for adresa in ("300.1.1.1", "1.2.3", "nije-ip"):
            with self.subTest(adresa=adresa), self.assertRaises((dw.DnsGreska, ValueError)):
                dw.odgovor_a(u, adresa, 60)

    def test_txt_spajanje(self):
        id_, u = upit(tip=dw.TIP_TXT)
        dijelovi = ["a" * 255, "b" * 30]
        odg = dw.parsiraj_odgovor(dw.odgovor_txt(u, dijelovi, 120), id_)
        self.assertEqual("".join(dijelovi), dw.txt_iz_rdata(odg["zapisi"][0][1]))

    def test_txt_predug_dio_odbijen(self):
        _id, u = upit(tip=dw.TIP_TXT)
        with self.assertRaises(dw.DnsGreska):
            dw.odgovor_txt(u, ["x" * 256], 120)

    def test_tc_zastavica_na_velikom_odgovoru(self):
        """Odrezan PELUD bez TC zastavice izgledao bi kao neispravan potpis."""
        id_, u = upit(tip=dw.TIP_TXT)
        odg = dw.parsiraj_odgovor(dw.odgovor_txt(u, ["z" * 255] * 3, 120), id_)
        self.assertTrue(odg["tc"])

    def test_prazan_odgovor_je_noerror(self):
        id_, u = upit(tip=dw.TIP_AAAA)
        odg = dw.parsiraj_odgovor(dw.odgovor_prazan(u), id_)
        self.assertEqual(dw.RCODE_NOERROR, odg["rcode"])
        self.assertEqual([], odg["zapisi"])

    def test_rcode_greske(self):
        for rcode in (dw.RCODE_REFUSED, dw.RCODE_NXDOMAIN, dw.RCODE_SERVFAIL, dw.RCODE_NOTIMP):
            id_, u = upit()
            with self.subTest(rcode=dw.IME_RCODE[rcode]):
                odg = dw.parsiraj_odgovor(dw.odgovor_greska(u, rcode), id_)
                self.assertEqual(rcode, odg["rcode"])

    def test_krivi_id_odbijen(self):
        """Odgovor s tudjim ID-om je tudji odgovor (ili napad), ne nas."""
        id_, u = upit()
        with self.assertRaises(dw.DnsGreska):
            dw.parsiraj_odgovor(dw.odgovor_a(u, "100.80.1.1", 60), (id_ + 1) % 0x10000)

    def test_aa_zastavica_na_autoritativnom_odgovoru(self):
        _id, u = upit()
        zastavice = struct.unpack(">H", dw.odgovor_a(u, "100.80.1.1", 60)[2:4])[0]
        self.assertTrue(zastavice & 0x0400, "dnkd je autoritativan za .dnk")


if __name__ == "__main__":
    unittest.main(verbosity=2)
