#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""RIZOM (F3): izolacija, plan adresa, dozvole i idempotencija patchera.

Ovo su testovi TVRDNJI iz dokumentacije, ne kozmetike. Ako AllowedIPs ikad
postane 0.0.0.0/0, promet rubnog uredjaja pocinje ici kroz sidro i "potpuna
izolacija" je prestala biti istina — pa taj test mora pasti.
"""
import ipaddress
import json
import os
import pathlib
import stat
import sys
import tempfile
import unittest

KORIJEN = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(KORIJEN))
from maska import kripto                        # noqa: E402
from rizom import patch_watchdog, rizom_konfig  # noqa: E402

ZIVA_KONFIG = {
    "cvor": "EU",
    "alarm_cmd": "/usr/local/bin/alarm_ivan.sh",
    "_biljeska_c2395": "MEDIJAPOS APP (X96:8093 -> EU:18096) NEMA REZERVNI PUT.",
    "tuneli": [
        {"ime": "medijapos", "port": 18096, "url": "https://genesis-medijapos.limit-connect.com/",
         "svjezina_url": "https://genesis-medijapos.limit-connect.com/health",
         "svjezina_s": 180, "mora_sadrzavati": "MedijaPos", "uredjaj": "X96"},
        {"ime": "lebdeci", "port": 18097, "url": "https://genesis-lebdeci.limit-connect.com/",
         "svjezina_s": 180, "uredjaj": "X96"},
        {"ime": "tonka", "port": 18098, "url": "http://127.0.0.1:18098/health.json",
         "svjezina_s": 180, "ceka_prvo_prikljucenje": True},
    ],
}


class TestPlanAdresa(unittest.TestCase):
    def test_rizom_i_dnkd_prostori_su_disjunktni(self):
        rizom = ipaddress.ip_network(rizom_konfig.RIZOM_MREZA)
        dnkd_mreza = ipaddress.ip_network("100.80.0.0/12")
        self.assertFalse(rizom.overlaps(dnkd_mreza))
        self.assertTrue(rizom.subnet_of(ipaddress.ip_network("100.64.0.0/10")))
        self.assertTrue(dnkd_mreza.subnet_of(ipaddress.ip_network("100.64.0.0/10")))

    def test_oktet_je_deterministican_i_u_granicama(self):
        for ime in ("x96", "a16", "zdenko", "tonka", "rubni2"):
            with self.subTest(uredjaj=ime):
                o = rizom_konfig.oktet_uredjaja(ime)
                self.assertEqual(o, rizom_konfig.oktet_uredjaja(ime))
                self.assertGreaterEqual(o, 2, "sidro drzi .1")
                self.assertLessEqual(o, 250)

    def test_razliciti_uredjaji_razlicite_adrese(self):
        okteti = {ime: rizom_konfig.oktet_uredjaja(ime)
                  for ime in ("x96", "a16", "zdenko", "tonka", "rubni2", "lebdeci")}
        self.assertEqual(len(okteti), len(set(okteti.values())), okteti)

    def test_sidra_imaju_razlicite_podmreze(self):
        eu = rizom_konfig.Sidro("eu", "genesis.limit-connect.com", treci_oktet=1)
        new = rizom_konfig.Sidro("new", "fina-connect.online", treci_oktet=2)
        self.assertFalse(ipaddress.ip_network(eu.mreza).overlaps(ipaddress.ip_network(new.mreza)))
        self.assertEqual("100.64.1.1", eu.adresa)
        self.assertEqual("100.64.2.1", new.adresa)


class TestGeneriranje(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.izlaz = pathlib.Path(self.dir.name) / "izlaz"
        self.sidra = [rizom_konfig.Sidro("eu", "genesis.limit-connect.com", treci_oktet=1),
                      rizom_konfig.Sidro("new", "fina-connect.online", treci_oktet=2)]
        self.manifest = rizom_konfig.generiraj("x96", self.sidra, 8093, "medijapos",
                                               18196, self.izlaz)

    def _tekst(self, *dijelovi):
        return (self.izlaz.joinpath(*dijelovi)).read_text(encoding="utf-8")

    @staticmethod
    def _direktive(tekst):
        """Samo stvarne WireGuard direktive — komentari nisu konfiguracija."""
        return [l.strip() for l in tekst.splitlines()
                if l.strip() and not l.strip().startswith("#")]

    def test_allowed_ips_nikad_ne_preuzima_sav_promet(self):
        for sidro in ("eu", "new"):
            konf = self._tekst("x96", f"rizom-{sidro}.conf")
            dopustene = [d for d in self._direktive(konf) if d.startswith("AllowedIPs")]
            self.assertEqual(1, len(dopustene), dopustene)
            self.assertNotIn("0.0.0.0/0", dopustene[0], "tunel ne smije preuzeti default rutu")
            self.assertNotIn("::/0", dopustene[0])
            self.assertTrue(dopustene[0].startswith("AllowedIPs = 100.64."), dopustene[0])
            self.assertTrue(dopustene[0].endswith("/32"), dopustene[0])

    def test_rub_ima_keepalive_a_sidro_ne(self):
        self.assertIn(f"PersistentKeepalive = {rizom_konfig.KEEPALIVE_S}",
                      self._direktive(self._tekst("x96", "rizom-eu.conf")))
        self.assertFalse([d for d in self._direktive(self._tekst("eu", "rizom-eu.conf"))
                          if d.startswith("PersistentKeepalive")])

    def test_rub_nema_endpoint_na_strani_sidra(self):
        """Rub je za NAT-om: sidro ga ne smije pokusavati zvati prvo."""
        direktive = self._direktive(self._tekst("eu", "rizom-eu.conf"))
        self.assertFalse([d for d in direktive if d.startswith("Endpoint")], direktive)
        self.assertIn("[Peer]", direktive)

    def test_konfiguracija_ne_mijenja_dns_na_rubu(self):
        self.assertFalse([d for d in self._direktive(self._tekst("x96", "rizom-eu.conf"))
                          if d.startswith("DNS")], "wg-quick ne smije prepisati resolv.conf")

    def test_dozvole_tajnih_datoteka(self):
        for put in (("x96", "rizom-eu.conf"), ("x96", "kljucevi", "rub.privatni"),
                    ("eu", "kljucevi", "sidro.privatni.PREMJESTI_I_IZBRISI")):
            with self.subTest(put="/".join(put)):
                nacin = stat.S_IMODE(os.stat(self.izlaz.joinpath(*put)).st_mode)
                self.assertEqual(0o600, nacin)

    def test_manifest_nema_privatnih_kljuceva(self):
        sirovo = self._tekst("manifest.json")
        podaci = json.loads(sirovo)
        privatni = (self.izlaz / "x96" / "kljucevi" / "rub.privatni").read_text().strip()
        self.assertNotIn(privatni, sirovo)
        self.assertIn("javni_kljuc_ruba", podaci)
        self.assertEqual(2, len(podaci["sidra"]))

    def test_javni_kljuc_odgovara_privatnom(self):
        privatni = rizom_konfig.wg_dekodiraj(
            (self.izlaz / "x96" / "kljucevi" / "rub.privatni").read_text())
        javni = rizom_konfig.wg_dekodiraj(
            (self.izlaz / "x96" / "kljucevi" / "rub.javni").read_text())
        self.assertEqual(kripto.x25519_pubkey(privatni), javni)

    def test_javni_kljuc_ruba_je_u_konfiguraciji_sidra(self):
        javni = (self.izlaz / "x96" / "kljucevi" / "rub.javni").read_text().strip()
        self.assertIn(javni, self._tekst("eu", "rizom-eu.conf"))

    def test_svako_sidro_dobije_svoj_nginx_port(self):
        portovi = [s["nginx_port_na_sidru"] for s in self.manifest["sidra"]]
        self.assertEqual(len(portovi), len(set(portovi)))
        self.assertIn(f"listen 127.0.0.1:{portovi[0]}", self._tekst("eu", "nginx-medijapos-rizom.conf"))
        self.assertIn(f"listen 127.0.0.1:{portovi[1]}", self._tekst("new", "nginx-medijapos-rizom.conf"))

    def test_nginx_ne_kesira_i_ima_kratke_timeoute(self):
        konf = self._tekst("eu", "nginx-medijapos-rizom.conf")
        self.assertIn("proxy_buffering off", konf, "kes bi lagao watchdogu da je rub ziv")
        self.assertIn("proxy_connect_timeout 5s", konf)

    def test_dani_javni_kljuc_sidra_se_koristi(self):
        _sk, pk = kripto.x25519_novi_kljuc()
        dani = rizom_konfig.wg_kodiraj(pk)
        izlaz2 = pathlib.Path(self.dir.name) / "izlaz2"
        sidra = [rizom_konfig.Sidro("eu", "genesis.limit-connect.com", treci_oktet=1,
                                    javni_kljuc=dani),
                 rizom_konfig.Sidro("new", "fina-connect.online", treci_oktet=2)]
        m = rizom_konfig.generiraj("x96", sidra, 8093, "medijapos", 18196, izlaz2)
        self.assertEqual(dani, m["sidra"][0]["javni_kljuc_sidra"])
        self.assertFalse(m["sidra"][0]["kljuc_sidra_generiran_ovdje"])
        self.assertFalse((izlaz2 / "eu" / "kljucevi" / "sidro.privatni.PREMJESTI_I_IZBRISI").exists())
        direktive = self._direktive((izlaz2 / "eu" / "rizom-eu.conf").read_text())
        self.assertNotIn("[Interface]", direktive, "kljuc sidra je vanjski — nema [Interface] bloka")
        self.assertFalse([d for d in direktive if d.startswith("PrivateKey")], direktive)

    def test_ponovno_generiranje_pravi_backup(self):
        rizom_konfig.generiraj("x96", self.sidra, 8093, "medijapos", 18196, self.izlaz)
        self.assertTrue((self.izlaz / "x96" / "rizom-eu.conf.bak").exists())

    def test_jedno_sidro_odbijeno_u_cli(self):
        kod = rizom_konfig._cli(["--uredjaj", "x96", "--usluga-port", "8093",
                                 "--sidro", "eu:genesis.limit-connect.com",
                                 "--izlaz", str(self.izlaz)])
        self.assertEqual(2, kod)


class TestPatchWatchdog(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.put = pathlib.Path(self.dir.name) / "tunel_watchdog_config.json"
        self.put.write_text(json.dumps(ZIVA_KONFIG, ensure_ascii=False, indent=1))

    def _pokreni(self, *dodatno):
        return patch_watchdog.main(["--konfig", str(self.put), "--bez-chown", *dodatno])

    def _podaci(self):
        return json.loads(self.put.read_text())

    def test_dodaje_unos_i_cuva_postojece(self):
        self.assertEqual(0, self._pokreni())
        imena = [t["ime"] for t in self._podaci()["tuneli"]]
        self.assertEqual(["medijapos", "lebdeci", "tonka", "medijapos-rizom"], imena)

    def test_novi_unos_ima_polja_koja_watchdog_stvarno_cita(self):
        self._pokreni()
        unos = [t for t in self._podaci()["tuneli"] if t["ime"] == "medijapos-rizom"][0]
        self.assertEqual({"ime", "port", "url", "svjezina_url", "svjezina_s",
                          "mora_sadrzavati", "uredjaj", "ceka_prvo_prikljucenje"},
                         set(unos))
        self.assertEqual("X96", unos["uredjaj"], "isti fizicki uredjaj kao medijapos (c3166)")
        self.assertTrue(unos["ceka_prvo_prikljucenje"], "put koji se jos nije javio nije kvar (c2404)")
        self.assertEqual("ts", unos["mora_sadrzavati"], "200 nije dokaz sadrzaja (c2395)")

    def test_backup_nastaje_prije_izmjene(self):
        self._pokreni()
        kopije = list(pathlib.Path(self.dir.name).glob("*.bak_rizom_*"))
        self.assertEqual(1, len(kopije))
        self.assertEqual(ZIVA_KONFIG["tuneli"][0]["ime"],
                         json.loads(kopije[0].read_text())["tuneli"][0]["ime"])
        self.assertNotIn("medijapos-rizom",
                         [t["ime"] for t in json.loads(kopije[0].read_text())["tuneli"]])

    def test_idempotentno(self):
        self._pokreni()
        self.assertEqual(0, self._pokreni())
        imena = [t["ime"] for t in self._podaci()["tuneli"]]
        self.assertEqual(1, imena.count("medijapos-rizom"))

    def test_pokazi_ne_mijenja_nista(self):
        prije = self.put.read_text()
        self.assertEqual(0, self._pokreni("--pokazi"))
        self.assertEqual(prije, self.put.read_text())

    def test_zauzet_port_odbijen(self):
        self.assertEqual(1, self._pokreni("--port", "18096"))
        self.assertNotIn("medijapos-rizom", [t["ime"] for t in self._podaci()["tuneli"]])

    def test_nepoznata_usluga_odbijena(self):
        self.assertEqual(1, self._pokreni("--usluga", "nepostojeca"))

    def test_vracanje_vraca_izvorno_stanje(self):
        self._pokreni()
        self.assertEqual(0, self._pokreni("--vrati"))
        self.assertNotIn("medijapos-rizom", [t["ime"] for t in self._podaci()["tuneli"]])
        self.assertEqual(ZIVA_KONFIG["tuneli"][0], self._podaci()["tuneli"][0])

    def test_odbija_datoteku_koja_nije_watchdog_config(self):
        drugo = pathlib.Path(self.dir.name) / "drugo.json"
        drugo.write_text('{"nesto": 1}')
        with self.assertRaises(SystemExit):
            patch_watchdog.main(["--konfig", str(drugo), "--bez-chown"])

    def test_odbija_pokvaren_json(self):
        self.put.write_text("{nije json")
        with self.assertRaises(SystemExit):
            self._pokreni()

    def test_biljeska_objasnjava_zasto(self):
        self._pokreni()
        biljeska = self._podaci()[patch_watchdog.BILJESKA_KLJUC]
        self.assertIn("18096", biljeska, "biljeska imenuje stari put")
        self.assertIn("NE gasi", biljeska)


if __name__ == "__main__":
    unittest.main(verbosity=2)
