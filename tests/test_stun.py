#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""STUN (F4): format na zici, klijent protiv pravog posluzitelja, klasifikacija NAT-a.

Klasifikacija se testira kroz PRAVE UDP sockete na loopbacku, s posluziteljem
koji glumi drugu tocku gledanja. Simetricni NAT (EDM) se simulira posluziteljem
koji prijavljuje drugaciji mapirani port — tocno ono sto klijent vidi kad mu NAT
dodijeli novi port po odredistu.
"""
import pathlib
import socket
import socketserver
import struct
import sys
import threading
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from maska import stun  # noqa: E402


class TestPoruke(unittest.TestCase):
    def test_krug_kodiranja(self):
        p = stun.Poruka(stun.ZAHTJEV_VEZIVANJA).dodaj_tekst(stun.A_SOFTWARE, "test")
        p2 = stun.Poruka.parsiraj(p.kodiraj())
        self.assertEqual(p.tip, p2.tip)
        self.assertEqual(p.tid, p2.tid)
        self.assertEqual(b"test", p2.prvi(stun.A_SOFTWARE))

    def test_rfc5769_xor_mapped_address(self):
        """RFC 5769 sec. 2.2 uzorak: 192.0.2.1:32853 uz zadani transaction ID.

        Ocekivana vrijednost je izvedena iz same specifikacije:
        port 0x8055 XOR 0x2112 = 0xA147; 192.0.2.1 = c0000201 XOR 2112a442 = e112a643.
        """
        tid = bytes.fromhex("b7e7a701bc34d686fa87dfae")
        vrijednost = stun.kodiraj_adresu("192.0.2.1", 32853, tid, xor=True)
        self.assertEqual("0001a147e112a643", vrijednost.hex())
        self.assertEqual(("192.0.2.1", 32853), stun.dekodiraj_adresu(vrijednost, tid, xor=True))

    def test_mapped_address_bez_xora(self):
        tid = bytes.fromhex("b7e7a701bc34d686fa87dfae")
        v = stun.kodiraj_adresu("217.160.71.124", 51820, tid, xor=False)
        self.assertEqual(("217.160.71.124", 51820), stun.dekodiraj_adresu(v, tid, xor=False))

    def test_ipv6_xor_koristi_tid(self):
        tid = bytes.fromhex("b7e7a701bc34d686fa87dfae")
        v = stun.kodiraj_adresu("2001:db8::1", 4711, tid, xor=True)
        self.assertEqual(("2001:db8::1", 4711), stun.dekodiraj_adresu(v, tid, xor=True))
        drugi_tid = bytes(12)
        self.assertNotEqual(("2001:db8::1", 4711),
                            stun.dekodiraj_adresu(v, drugi_tid, xor=True))

    def test_atributi_su_poravnati_na_4(self):
        p = stun.Poruka(stun.ZAHTJEV_VEZIVANJA).dodaj_tekst(stun.A_SOFTWARE, "abc")
        sirovo = p.kodiraj()
        duzina = struct.unpack(">H", sirovo[2:4])[0]
        self.assertEqual(0, duzina % 4, "tijelo mora biti umnozak 4 bajta")
        self.assertEqual(b"abc", stun.Poruka.parsiraj(sirovo).prvi(stun.A_SOFTWARE))

    def test_otisak_se_provjerava(self):
        p = stun.Poruka(stun.ODGOVOR_VEZIVANJA).dodaj_tekst(stun.A_SOFTWARE, "x")
        sirovo = p.kodiraj(otisak=True)
        self.assertTrue(stun.Poruka.parsiraj(sirovo).provjeri_otisak(sirovo))
        pokvareno = bytearray(sirovo)
        pokvareno[21] ^= 0x01
        self.assertFalse(stun.Poruka.parsiraj(bytes(pokvareno)).provjeri_otisak(bytes(pokvareno)))

    def test_integritet_se_provjerava(self):
        kljuc = b"tajna-kratkotrajna"
        p = stun.Poruka(stun.ODGOVOR_VEZIVANJA).dodaj_tekst(stun.A_SOFTWARE, "x")
        sirovo = p.kodiraj(kljuc=kljuc, otisak=True)
        procitana = stun.Poruka.parsiraj(sirovo)
        self.assertTrue(procitana.provjeri_integritet(kljuc, sirovo))
        self.assertFalse(procitana.provjeri_integritet(b"drugi kljuc", sirovo))

    def test_integritet_pokriva_sadrzaj(self):
        kljuc = b"tajna"
        sirovo = bytearray(stun.Poruka(stun.ODGOVOR_VEZIVANJA)
                           .dodaj_adresu(stun.A_XOR_MAPPED_ADDRESS, "1.2.3.4", 1234, xor=True)
                           .kodiraj(kljuc=kljuc, otisak=True))
        sirovo[25] ^= 0x01                       # promijeni adresu u tijelu
        procitana = stun.Poruka.parsiraj(bytes(sirovo))
        self.assertFalse(procitana.provjeri_integritet(kljuc, bytes(sirovo)))

    def test_odbija_ne_stun(self):
        for smece in (b"", b"kratko", b"\x00" * 20,
                      struct.pack(">HHI12s", 1, 0, 0xDEADBEEF, b"x" * 12)):
            with self.subTest(duzina=len(smece)), self.assertRaises(stun.StunGreska):
                stun.Poruka.parsiraj(smece)

    def test_odbija_skraceno_tijelo(self):
        sirovo = struct.pack(">HHI12s", stun.ZAHTJEV_VEZIVANJA, 40,
                             stun.MAGICNI_KEKS, b"x" * 12)
        with self.assertRaises(stun.StunGreska):
            stun.Poruka.parsiraj(sirovo)

    def test_nerazumljivi_obavezni_atribut(self):
        p = stun.Poruka(stun.ODGOVOR_VEZIVANJA).dodaj(0x0099, b"xxxx")
        self.assertEqual([0x0099], stun.Poruka.parsiraj(p.kodiraj()).nerazumljivi_obavezni)
        q = stun.Poruka(stun.ODGOVOR_VEZIVANJA).dodaj(0x8099, b"xxxx")
        self.assertEqual([], stun.Poruka.parsiraj(q.kodiraj()).nerazumljivi_obavezni,
                         "atributi >= 0x8000 smiju biti nepoznati")


class TestKlijentPosluzitelj(unittest.TestCase):
    """Pravi UDP na loopbacku — ne mock."""

    def posluzitelj(self, host="127.0.0.1", pomak_porta=0):
        p = (_SidroSDrugimPogledom((host, 0), pomak_porta=pomak_porta) if pomak_porta
             else stun.Posluzitelj((host, 0)))
        p.pokreni_u_niti()
        self.addCleanup(p.server_close)
        self.addCleanup(p.shutdown)
        return p

    def test_otkrivanje_vraca_nas_port(self):
        p = self.posluzitelj()
        utor = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        utor.bind(("127.0.0.1", 0))
        self.addCleanup(utor.close)
        refleks = stun.otkrij(p.server_address, utor=utor)
        self.assertEqual(utor.getsockname()[1], refleks.port)
        self.assertEqual("127.0.0.1", refleks.ip)
        self.assertGreaterEqual(refleks.rtt_ms, 0)

    def test_nedosezljiv_posluzitelj(self):
        with self.assertRaises(stun.StunGreska) as ctx:
            stun.otkrij(("127.0.0.1", 1), rto_s=0.05, slanja=2)
        self.assertIn("ne odgovara", str(ctx.exception))

    def test_posluzitelj_ne_odgovara_na_smece(self):
        p = self.posluzitelj()
        utor = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        utor.settimeout(0.4)
        self.addCleanup(utor.close)
        utor.sendto(b"ovo nije STUN", p.server_address)
        with self.assertRaises((socket.timeout, TimeoutError)):
            utor.recvfrom(2048)
        self.assertEqual(1, p.brojac_smeca)

    def test_dva_sidra_ista_adresa_je_EIM(self):
        a = self.posluzitelj("127.0.0.1")
        b = self.posluzitelj("127.0.0.2")
        utor = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        utor.bind(("0.0.0.0", 0))
        self.addCleanup(utor.close)
        nalaz = stun.klasificiraj([a.server_address, b.server_address], utor=utor)
        self.assertEqual("EIM", nalaz.ponasanje, nalaz.razlog)
        self.assertTrue(nalaz.probod_moguc)
        self.assertEqual(2, len(nalaz.refleksi))

    def test_razlicit_port_po_odredistu_je_EDM(self):
        """Drugo sidro vidi drugi port = NAT je dodijelio novo mapiranje po odredistu."""
        a = self.posluzitelj("127.0.0.1")
        b = self.posluzitelj("127.0.0.2", pomak_porta=1)
        utor = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        utor.bind(("0.0.0.0", 0))
        self.addCleanup(utor.close)
        nalaz = stun.klasificiraj([a.server_address, b.server_address], utor=utor)
        self.assertEqual("EDM", nalaz.ponasanje)
        self.assertFalse(nalaz.probod_moguc)
        self.assertIn("simetricni", nalaz.razlog)

    def test_jedno_sidro_je_NEPOZNATO(self):
        """Jedna tocka gledanja ne moze razlikovati EIM od EDM-a."""
        a = self.posluzitelj()
        nalaz = stun.klasificiraj([a.server_address])
        self.assertEqual("NEPOZNATO", nalaz.ponasanje)
        self.assertFalse(nalaz.probod_moguc)
        self.assertIn("DVA sidra", nalaz.razlog)

    def test_dva_sidra_na_istoj_adresi_je_NEPOZNATO(self):
        """Dva porta na ISTOM IP-u nisu dvije tocke gledanja."""
        a = self.posluzitelj("127.0.0.1")
        b = self.posluzitelj("127.0.0.1")
        nalaz = stun.klasificiraj([a.server_address, b.server_address])
        self.assertEqual("NEPOZNATO", nalaz.ponasanje)
        self.assertIn("razlicitim IP", nalaz.razlog)

    def test_sva_sidra_pala_je_NEPOZNATO(self):
        nalaz = stun.klasificiraj([("127.0.0.1", 1), ("127.0.0.2", 1)],
                                  rto_s=0.05, slanja=1)
        self.assertEqual("NEPOZNATO", nalaz.ponasanje)
        self.assertIn("ni jedno sidro", nalaz.razlog)

    def test_nalaz_kao_dict_nosi_mjerenje(self):
        a = self.posluzitelj("127.0.0.1")
        b = self.posluzitelj("127.0.0.2")
        d = stun.klasificiraj([a.server_address, b.server_address]).kao_dict()
        self.assertEqual({"ponasanje", "razlog", "probod_moguc", "lokalni_port", "refleksi"},
                         set(d))
        self.assertEqual(2, len(d["refleksi"]))


class _SidroSDrugimPogledom(socketserver.ThreadingUDPServer):
    """Druga tocka gledanja koja vidi port pomaknut za N.

    NIJE maskirani produkcijski posluzitelj nego zaseban, minimalan STUN koji
    simulira ono sto klijent vidi kad mu simetricni NAT dodijeli NOVO mapiranje
    prema drugom odredistu: odgovor stize na pravi port (inace se nista ne bi
    izmjerilo), ali PRIJAVLJENA adresa je druga.
    """
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, adresa, pomak_porta: int = 0):
        self.pomak_porta = pomak_porta
        self.brojac_smeca = 0
        posluzitelj = self

        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                podaci, utor = self.request
                try:
                    zahtjev = stun.Poruka.parsiraj(podaci)
                except stun.StunGreska:
                    posluzitelj.brojac_smeca += 1
                    return
                if zahtjev.tip != stun.ZAHTJEV_VEZIVANJA:
                    return
                ip, port = self.client_address
                odgovor = stun.Poruka(stun.ODGOVOR_VEZIVANJA, tid=zahtjev.tid)
                odgovor.dodaj_adresu(stun.A_XOR_MAPPED_ADDRESS, ip,
                                     port + posluzitelj.pomak_porta, xor=True)
                utor.sendto(odgovor.kodiraj(otisak=True), self.client_address)

        super().__init__(adresa, Handler)

    def pokreni_u_niti(self):
        nit = threading.Thread(target=self.serve_forever, kwargs={"poll_interval": 0.02},
                               daemon=True)
        nit.start()
        return nit


if __name__ == "__main__":
    unittest.main(verbosity=2)
