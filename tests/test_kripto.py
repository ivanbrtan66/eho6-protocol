#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Kripto sloj protiv OBJAVLJENIH vektora, ne protiv sebe samog.

Implementacija koja se provjerava samo vlastitim izlazom dokazuje jedino da je
dosljedna — i lazna implementacija je dosljedna. Zato: RFC 8032 sec. 7.1
(Ed25519) i RFC 7748 sec. 5.2/6.1 (X25519), plus medjuoperativnost s potpisom
koji generira postojeci eho6_node.py.
"""
import importlib.util
import pathlib
import shutil
import subprocess
import sys
import unittest

KORIJEN = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(KORIJEN))
from maska import kripto  # noqa: E402

# RFC 8032, sec. 7.1 — Test 1, 2 i 3
ED_VEKTORI = [
    ("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
     "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
     "",
     "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a"
     "33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"),
    ("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
     "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
     "72",
     "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e1"
     "5996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"),
    ("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
     "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
     "af82",
     "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d1"
     "6f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"),
]


class TestEd25519(unittest.TestCase):
    def test_rfc8032_vektori(self):
        for sk_hex, pk_hex, msg_hex, sig_hex in ED_VEKTORI:
            sk, pk = bytes.fromhex(sk_hex), bytes.fromhex(pk_hex)
            msg, sig = bytes.fromhex(msg_hex), bytes.fromhex(sig_hex)
            with self.subTest(poruka=msg_hex or "(prazna)"):
                self.assertEqual(kripto.ed25519_pubkey(sk), pk, "javni kljuc")
                self.assertEqual(kripto.ed25519_sign(sk, msg), sig, "potpis")
                self.assertTrue(kripto.ed25519_verify(pk, sig, msg), "verifikacija")

    def test_odbija_podmetanje(self):
        sk_hex, pk_hex, _msg, sig_hex = ED_VEKTORI[1]
        pk, sig = bytes.fromhex(pk_hex), bytes.fromhex(sig_hex)
        self.assertFalse(kripto.ed25519_verify(pk, sig, b"\x73"), "promijenjena poruka")
        drugi_pk = kripto.ed25519_pubkey(bytes.fromhex(ED_VEKTORI[0][0]))
        self.assertFalse(kripto.ed25519_verify(drugi_pk, sig, b"\x72"), "tudji kljuc")
        pokvaren = bytearray(sig); pokvaren[0] ^= 0x01
        self.assertFalse(kripto.ed25519_verify(pk, bytes(pokvaren), b"\x72"), "promijenjen R")
        pokvaren = bytearray(sig); pokvaren[63] ^= 0x01
        self.assertFalse(kripto.ed25519_verify(pk, bytes(pokvaren), b"\x72"), "promijenjen S")

    def test_odbija_nekanonski_S(self):
        """S >= Q je malleability: ista tvrdnja s dva valjana kodiranja."""
        sk, pk = kripto.ed25519_novi_kljuc()
        sig = bytearray(kripto.ed25519_sign(sk, b"test"))
        S = int.from_bytes(sig[32:], "little") + kripto.Q
        sig[32:] = S.to_bytes(32, "little")
        self.assertFalse(kripto.ed25519_verify(pk, bytes(sig), b"test"))

    def test_odbija_neispravne_duzine(self):
        sk, pk = kripto.ed25519_novi_kljuc()
        sig = kripto.ed25519_sign(sk, b"x")
        self.assertFalse(kripto.ed25519_verify(pk[:31], sig, b"x"))
        self.assertFalse(kripto.ed25519_verify(pk, sig[:63], b"x"))
        self.assertFalse(kripto.ed25519_verify(b"\xff" * 32, sig, b"x"), "kljuc van krivulje")

    def test_interoperabilnost_s_eho6_node(self):
        """Potpis starog jednodatotecnog demona mora proci novu verifikaciju."""
        put = KORIJEN / "eho6_node.py"
        spec = importlib.util.spec_from_file_location("eho6_node_test", put)
        modul = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(modul)
        sk = bytes.fromhex(ED_VEKTORI[0][0])
        self.assertEqual(modul.ed25519_pubkey(sk), kripto.ed25519_pubkey(sk))
        poruka = b"v=PELUD1 proba medjuoperativnosti"
        stari_potpis = modul.ed25519_sign(sk, poruka)
        self.assertEqual(stari_potpis, kripto.ed25519_sign(sk, poruka))
        self.assertTrue(kripto.ed25519_verify(kripto.ed25519_pubkey(sk), stari_potpis, poruka))


class TestX25519(unittest.TestCase):
    def test_rfc7748_5_2(self):
        skalar = bytes.fromhex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4")
        u = bytes.fromhex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c")
        ocekivano = "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"
        self.assertEqual(kripto.x25519(skalar, u).hex(), ocekivano)

    @unittest.skipUnless(shutil.which("openssl"), "openssl nije dostupan")
    def test_krizna_provjera_openssl(self):
        """Neovisna implementacija mora izvesti ISTI javni kljuc iz istog privatnog.

        Vlastiti vektori dokazuju dosljednost; tudja implementacija dokazuje
        ispravnost. PKCS#8 X25519: privatni kljuc su zadnja 32 bajta DER-a,
        javni isto (SubjectPublicKeyInfo bez dodatnog ovoja).
        """
        der = subprocess.run(["openssl", "genpkey", "-algorithm", "X25519", "-outform", "DER"],
                             capture_output=True, check=True).stdout
        privatni = der[-32:]
        javni_openssl = subprocess.run(
            ["openssl", "pkey", "-inform", "DER", "-pubout", "-outform", "DER"],
            input=der, capture_output=True, check=True).stdout[-32:]
        self.assertEqual(kripto.x25519_pubkey(privatni), javni_openssl)
        sk_moj, pk_moj = kripto.x25519_novi_kljuc()
        self.assertEqual(kripto.x25519(privatni, pk_moj), kripto.x25519(sk_moj, javni_openssl),
                         "zajednicka tajna se mora poklopiti s tudjim kljucem")

    def test_dh_simetrija(self):
        ska, pka = kripto.x25519_novi_kljuc()
        skb, pkb = kripto.x25519_novi_kljuc()
        self.assertEqual(kripto.x25519(ska, pkb), kripto.x25519(skb, pka))

    def test_kljuc_je_klamiran(self):
        """WireGuard privatni kljuc mora biti klamiran kao u `wg genkey`."""
        sk, _pk = kripto.x25519_novi_kljuc()
        self.assertEqual(sk[0] & 7, 0)
        self.assertEqual(sk[31] & 128, 0)
        self.assertEqual(sk[31] & 64, 64)

    def test_odbija_krivu_duzinu(self):
        with self.assertRaises(ValueError):
            kripto.x25519(b"\x01" * 31, b"\x09" + b"\x00" * 31)


class TestPomocno(unittest.TestCase):
    def test_usporedba_konstantnog_vremena(self):
        self.assertTrue(kripto.jednaki_bajtovi(b"abc", b"abc"))
        self.assertFalse(kripto.jednaki_bajtovi(b"abc", b"abd"))

    def test_sha3(self):
        import hashlib
        self.assertEqual(kripto.sha3(b"genesis"), hashlib.sha3_256(b"genesis").hexdigest())


if __name__ == "__main__":
    unittest.main(verbosity=2)
