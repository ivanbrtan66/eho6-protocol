#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""PROBOD (F4) kroz SIMULIRANI NAT — dokaz, ne tvrdnja.

Zasto simulator: probod se ne da dokazati na jednom stroju bez dva NAT-a, a
tvrdnja "radi kroz NAT" bez dokaza je tocno ono sto ovaj projekt ne radi. Zato
je NAT modeliran onako kako se stvarno ponasa, po dvije osi koje odlucuju:

  MAPIRANJE   EIM — isto vanjsko mapiranje bez obzira na odrediste
              EDM — novo mapiranje po odredistu (simetricni NAT)
  FILTRIRANJE EIF — propusta svakoga
              ADF — propusta samo adrese kojima je unutarnja strana prva slala

Kljucni test nije da kod kod EDM-a odbije pokusati (to je samo zastavica), nego
da probod kroz EDM STVARNO ne prolazi i kad kodu slazes da je EIM. Bez tog
testa "RELEJ kod simetricnog NAT-a" je pretpostavka, ne mjerenje.

Sto ovi testovi NE dokazuju: da stvarni ISP-ov CGNAT ima bas ovo ponasanje.
Simulator modelira RFC 4787 razrede, ne konkretnu kutiju kod tvog operatera —
to ostaje pilot na terenu.
"""
import pathlib
import queue
import sys
import threading
import time
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from maska import kripto                                     # noqa: E402
from maska.godovi import Godovi                              # noqa: E402
from maska.probod import (MAX_KANDIDATA, Ishod, Kandidat, Oglas,  # noqa: E402
                          Proba, Probod, ProbodGreska, TIP_HOST, TIP_REFLEKS,
                          WgPredaja)

SIDRO = ("203.0.113.10", 3478)          # TEST-NET-3: adresa sidra u simulaciji


# =============================================================================
# Simulirana mreza i NAT
# =============================================================================
class SimuliranaMreza:
    def __init__(self):
        self.kutije: dict[str, "NatKutija"] = {}
        self.izgubljeno = 0

    def prijavi(self, kutija: "NatKutija") -> None:
        self.kutije[kutija.vanjski_ip] = kutija

    def isporuci(self, odrediste, podaci, izvor) -> None:
        kutija = self.kutije.get(odrediste[0])
        if kutija is None:
            self.izgubljeno += 1            # npr. promet prema sidru: izlazi iz simulacije
            return
        kutija.ulaz(odrediste[1], podaci, izvor)


class NatKutija:
    def __init__(self, mreza: SimuliranaMreza, vanjski_ip: str,
                 mapiranje: str = "EIM", filtriranje: str = "ADF"):
        self.mreza = mreza
        self.vanjski_ip = vanjski_ip
        self.mapiranje = mapiranje
        self.filtriranje = filtriranje
        self.mapiranja: dict = {}           # kljuc -> vanjski port
        self.obrnuto: dict[int, int] = {}   # vanjski port -> unutarnji port
        self.dozvoljeni: dict[int, set] = {}  # vanjski port -> adrese kojima smo slali
        self.prijenosi: dict[int, "SimuliraniPrijenos"] = {}
        self._sljedeci = 40000
        self.odbaceno_filtrom = 0
        self.odbaceno_bez_mapiranja = 0
        self.lock = threading.Lock()
        mreza.prijavi(self)

    def prikljuci(self, unutarnji_port: int, prijenos: "SimuliraniPrijenos") -> None:
        self.prijenosi[unutarnji_port] = prijenos

    def _kljuc(self, unutarnji_port: int, odrediste):
        return unutarnji_port if self.mapiranje == "EIM" else (unutarnji_port, odrediste)

    def mapiranje_za(self, unutarnji_port: int, odrediste) -> int:
        """Vanjski port koji NAT dodijeli za taj (izvor, odrediste) par."""
        with self.lock:
            kljuc = self._kljuc(unutarnji_port, odrediste)
            if kljuc not in self.mapiranja:
                self.mapiranja[kljuc] = self._sljedeci
                self.obrnuto[self._sljedeci] = unutarnji_port
                self.dozvoljeni[self._sljedeci] = set()
                self._sljedeci += 1
            return self.mapiranja[kljuc]

    def refleks(self, unutarnji_port: int, sidro=SIDRO) -> tuple[str, int]:
        """Sto sidro vidi kao nasu vanjsku adresu — isto sto bi vratio STUN."""
        return (self.vanjski_ip, self.mapiranje_za(unutarnji_port, sidro))

    def izlaz(self, unutarnji_port: int, podaci: bytes, odrediste) -> None:
        vanjski_port = self.mapiranje_za(unutarnji_port, odrediste)
        with self.lock:
            self.dozvoljeni[vanjski_port].add(
                odrediste[0] if self.filtriranje == "ADF" else odrediste)
        self.mreza.isporuci(odrediste, podaci, (self.vanjski_ip, vanjski_port))

    def ulaz(self, vanjski_port: int, podaci: bytes, izvor) -> None:
        with self.lock:
            unutarnji_port = self.obrnuto.get(vanjski_port)
            if unutarnji_port is None:
                self.odbaceno_bez_mapiranja += 1     # EDM: peer gadja mrtvo mapiranje
                return
            if self.filtriranje == "ADF" and izvor[0] not in self.dozvoljeni[vanjski_port]:
                self.odbaceno_filtrom += 1
                return
            prijenos = self.prijenosi.get(unutarnji_port)
        if prijenos is not None:
            prijenos.red.put((podaci, izvor))


class SimuliraniPrijenos:
    """Implementira maska.probod.Prijenos nad simuliranim NAT-om."""

    def __init__(self, kutija: NatKutija, unutarnji_ip: str, unutarnji_port: int,
                 salji: bool = True):
        self.kutija = kutija
        self.unutarnji_ip = unutarnji_ip
        self.unutarnji_port = unutarnji_port
        self.red: queue.Queue = queue.Queue()
        self.salji = salji                  # False = simulira put koji ne izlazi
        self.poslano = 0
        kutija.prikljuci(unutarnji_port, self)

    def posalji(self, podaci: bytes, adresa) -> None:
        if not self.salji:
            return
        self.poslano += 1
        self.kutija.izlaz(self.unutarnji_port, podaci, adresa)

    def primi(self, cekanje_s: float):
        try:
            return self.red.get(timeout=max(0.001, cekanje_s))
        except queue.Empty:
            return None

    def lokalna_adresa(self):
        return (self.unutarnji_ip, self.unutarnji_port)


def _postava(mapiranje_a="EIM", filtriranje_a="ADF", mapiranje_b="EIM", filtriranje_b="ADF",
             salje_a=True, salje_b=True):
    mreza = SimuliranaMreza()
    kutija_a = NatKutija(mreza, "198.51.100.7", mapiranje_a, filtriranje_a)
    kutija_b = NatKutija(mreza, "203.0.113.55", mapiranje_b, filtriranje_b)
    prijenos_a = SimuliraniPrijenos(kutija_a, "192.168.1.20", 51820, salji=salje_a)
    prijenos_b = SimuliraniPrijenos(kutija_b, "10.0.0.5", 51820, salji=salje_b)
    return mreza, kutija_a, kutija_b, prijenos_a, prijenos_b


def _kandidati(kutija: NatKutija, prijenos: SimuliraniPrijenos) -> list[Kandidat]:
    """Kandidati kakve bi cvor objavio: lokalni + ono sto sidro vidi (STUN)."""
    refleks = kutija.refleks(prijenos.unutarnji_port)
    return [Kandidat(TIP_HOST, *prijenos.lokalna_adresa()),
            Kandidat(TIP_REFLEKS, refleks[0], refleks[1])]


def _istovremeno(probod_a: Probod, kandidati_a, kandidati_b, probod_b,
                 trajanje_s=2.5, nat_a="EIM", nat_b="EIM") -> tuple[Ishod, Ishod]:
    """Obje strane probijaju u isto vrijeme — probod jednostrano nije probod."""
    ishodi: dict[str, Ishod] = {}

    def radi(ime, probod, nasi, njihovi, nas_nat, njihov_nat):
        ishodi[ime] = probod.probij(nasi, njihovi, trajanje_s=trajanje_s,
                                    nas_nat=nas_nat, peer_nat=njihov_nat)

    niti = [
        threading.Thread(target=radi, args=("a", probod_a, kandidati_a, kandidati_b,
                                            nat_a, nat_b)),
        threading.Thread(target=radi, args=("b", probod_b, kandidati_b, kandidati_a,
                                            nat_b, nat_a)),
    ]
    for n in niti:
        n.start()
    for n in niti:
        n.join(timeout=trajanje_s + 5)
    return ishodi.get("a"), ishodi.get("b")


# =============================================================================
class TestProbodKrozNat(unittest.TestCase):
    def setUp(self):
        self.sk_a, self.pk_a = kripto.ed25519_novi_kljuc()
        self.sk_b, self.pk_b = kripto.ed25519_novi_kljuc()

    def _parovi(self, prijenos_a, prijenos_b):
        a = Probod("a-x96", self.sk_a, "b-tonka", self.pk_b.hex(), prijenos_a)
        b = Probod("b-tonka", self.sk_b, "a-x96", self.pk_a.hex(), prijenos_b)
        return a, b

    def test_dva_EIM_nata_probod_uspijeva(self):
        _m, ka, kb, pa, pb = _postava()
        a, b = self._parovi(pa, pb)
        ishod_a, ishod_b = _istovremeno(a, _kandidati(ka, pa), _kandidati(kb, pb), b)
        self.assertEqual("NEPOSREDAN", ishod_a.stanje, ishod_a.razlog)
        self.assertEqual("NEPOSREDAN", ishod_b.stanje, ishod_b.razlog)
        self.assertIsNotNone(ishod_a.par)
        self.assertIsNotNone(ishod_a.rtt_ms)
        self.assertTrue(ishod_a.neposredan)
        # obje strane su nominirale ISTU adresu para
        self.assertEqual(ishod_a.par[1].adresa, kb.refleks(pb.unutarnji_port))

    def test_puni_kanal_EIF_takodjer_prolazi(self):
        _m, ka, kb, pa, pb = _postava(filtriranje_a="EIF", filtriranje_b="EIF")
        a, b = self._parovi(pa, pb)
        ishod_a, _ = _istovremeno(a, _kandidati(ka, pa), _kandidati(kb, pb), b)
        self.assertEqual("NEPOSREDAN", ishod_a.stanje, ishod_a.razlog)

    def test_simetricni_nat_se_ne_pokusava(self):
        """Kod EDM-a kod NE trosi 6 s na nadu — odmah kaze RELEJ i zasto."""
        _m, ka, kb, pa, pb = _postava(mapiranje_b="EDM")
        a, _b = self._parovi(pa, pb)
        poc = time.monotonic()
        ishod = a.probij(_kandidati(ka, pa), _kandidati(kb, pb),
                         trajanje_s=5.0, nas_nat="EIM", peer_nat="EDM")
        proteklo = time.monotonic() - poc
        self.assertEqual("RELEJ", ishod.stanje)
        self.assertIn("simetrican", ishod.razlog)
        self.assertIn("sidro", ishod.razlog)
        self.assertLess(proteklo, 1.0, "odluka je poznata unaprijed, ne ceka se")
        self.assertEqual(0, pa.poslano, "kod EDM-a se ne salje ni jedna proba")

    def test_simetricni_nat_STVARNO_ne_prolazi(self):
        """Kljucni test: i kad kodu slazemo da je EIM, probod kroz EDM pada.

        Bez ovoga bi 'RELEJ kod simetricnog NAT-a' bio samo postovanje zastavice,
        a ne cinjenica o mrezi. Mehanizam kod EDM + ADF: mapiranje koje je peer
        otvorio prema SIDRU propusta samo sidro; promet s nase adrese dolazi na
        to mapiranje i pada na filtru, jer je peerov izlaz prema nama otvorio
        DRUGO mapiranje.
        """
        _m, ka, kb, pa, pb = _postava(mapiranje_b="EDM")
        a, b = self._parovi(pa, pb)
        ishod_a, ishod_b = _istovremeno(a, _kandidati(ka, pa), _kandidati(kb, pb), b,
                                        trajanje_s=1.5, nat_a="EIM", nat_b="EIM")
        self.assertEqual("RELEJ", ishod_a.stanje, ishod_a.razlog)
        self.assertEqual("RELEJ", ishod_b.stanje, ishod_b.razlog)
        self.assertIsNone(ishod_a.par)
        self.assertGreater(kb.odbaceno_filtrom + kb.odbaceno_bez_mapiranja, 0,
                           "promet prema mapiranju koje vrijedi samo za sidro mora propasti")

    def test_simetricni_nat_pada_i_bez_filtriranja(self):
        """EDM + EIF: ulazna proba prodje, ali odgovor izadje s DRUGOG porta.

        Zato ni potpuno otvoren filtar ne spasava simetricni NAT: potvrda stize s
        adrese kojoj nismo slali, pa par nikad nije dvosmjerno potvrdjen. Odbijamo
        je namjerno — prihvatiti potvrdu s druge adrese znaci vjerovati bilo kome
        tko vidi promet.
        """
        _m, ka, kb, pa, pb = _postava(mapiranje_b="EDM", filtriranje_b="EIF")
        a, b = self._parovi(pa, pb)
        ishod_a, _ishod_b = _istovremeno(a, _kandidati(ka, pa), _kandidati(kb, pb), b,
                                         trajanje_s=1.5, nat_a="EIM", nat_b="EIM")
        self.assertEqual("RELEJ", ishod_a.stanje, ishod_a.razlog)
        self.assertGreater(pb.poslano, 0, "peer je slao, ali s drugog mapiranja")

    def test_jednosmjerni_promet_nije_veza(self):
        """B prima ali ne odgovara: A ne smije proglasiti NEPOSREDAN."""
        _m, ka, kb, pa, pb = _postava(filtriranje_a="EIF", salje_b=False)
        a, b = self._parovi(pa, pb)
        ishod_a, _ = _istovremeno(a, _kandidati(ka, pa), _kandidati(kb, pb), b,
                                  trajanje_s=1.5)
        self.assertEqual("RELEJ", ishod_a.stanje)
        self.assertIsNone(ishod_a.par)
        self.assertIn("smjer", ishod_a.razlog.lower() + ishod_a.razlog)

    def test_bez_tudjih_kandidata_je_NEPOZNATO(self):
        _m, ka, _kb, pa, _pb = _postava()
        a, _b = self._parovi(pa, _pb)
        ishod = a.probij(_kandidati(ka, pa), [], trajanje_s=0.5)
        self.assertEqual("NEPOZNATO", ishod.stanje)
        self.assertIn("ni jedan kandidat", ishod.razlog)

    def test_krivotvorena_proba_se_ignorira(self):
        """Proba potpisana tudjim kljucem ne smije otvoriti par."""
        _m, ka, kb, pa, pb = _postava()
        a, _b = self._parovi(pa, pb)
        sk_napadac, _pk = kripto.ed25519_novi_kljuc()
        lazna = Proba("PROBA", "b-tonka", "aabbcc", int(time.time()),
                      "198.51.100.7:40000").potpisi(sk_napadac)
        pa.red.put((lazna.bajtovi(), ("192.0.2.66", 1234)))
        ishod = a.probij(_kandidati(ka, pa), _kandidati(kb, pb), trajanje_s=0.8)
        self.assertNotEqual("NEPOSREDAN", ishod.stanje)
        self.assertNotIn("192.0.2.66", str(ishod.kao_dict()))

    def test_ponovljena_proba_se_ne_broji_dvaput(self):
        _m, ka, kb, pa, pb = _postava()
        a, _b = self._parovi(pa, pb)
        proba = Proba("PROBA", "b-tonka", "ponovljeni-nonce", int(time.time()),
                      "198.51.100.7:40000").potpisi(self.sk_b)
        for _ in range(3):
            pa.red.put((proba.bajtovi(), ("203.0.113.55", 40000)))
        a.probij(_kandidati(ka, pa), _kandidati(kb, pb), trajanje_s=0.6)
        self.assertIn("ponovljeni-nonce", a.vidjeni_nonce)
        self.assertEqual(1, len(a.vidjeni_nonce))

    def test_upravljacka_strana_je_manje_ime(self):
        _m, _ka, _kb, pa, pb = _postava()
        a, b = self._parovi(pa, pb)
        self.assertTrue(a.upravljacka, "a-x96 < b-tonka")
        self.assertFalse(b.upravljacka)

    def test_isto_ime_je_greska(self):
        _m, _ka, _kb, pa, _pb = _postava()
        with self.assertRaises(ProbodGreska):
            Probod("isti", self.sk_a, "isti", self.pk_b.hex(), pa)

    def test_ishod_ide_u_godove(self):
        import tempfile
        from maska.probod import _upisi
        with tempfile.TemporaryDirectory() as d:
            g = Godovi(pathlib.Path(d) / "godovi.jsonl")
            _upisi(g, "a", "b", Ishod("NEPOSREDAN", par=(Kandidat(TIP_HOST, "1.2.3.4", 5),
                                                         Kandidat(TIP_REFLEKS, "5.6.7.8", 9)),
                                      rtt_ms=12, nat="EIM", peer_nat="EIM"))
            _upisi(g, "a", "b", Ishod("RELEJ", razlog="simetricni NAT", nat="EDM"))
            _upisi(g, "a", "b", Ishod("NEPOZNATO", razlog="sidro ne odgovara"))
            zapisi = g.zadnji(3)
            self.assertEqual(["OK", "ALARM", "NEPOZNATO"], [z["ishod"] for z in zapisi])
            self.assertEqual("probod:a->b", zapisi[0]["ime"])
            self.assertEqual((True, []), g.provjeri())


class TestProba(unittest.TestCase):
    def setUp(self):
        self.sk, self.pk = kripto.ed25519_novi_kljuc()
        self.proba = Proba("PROBA", "x96", "deadbeef", int(time.time()),
                           "1.2.3.4:5678").potpisi(self.sk)

    def test_krug(self):
        self.assertEqual((True, ""),
                         Proba.parsiraj(self.proba.bajtovi()).provjeri(self.pk.hex()))

    def test_odgovor_nije_veci_od_upita(self):
        """Nema amplifikacije: POTVRDA je iste velicine kao PROBA."""
        potvrda = Proba("POTVRDA", "x96", "deadbeef", self.proba.ts,
                        "1.2.3.4:5678").potpisi(self.sk)
        self.assertLessEqual(len(potvrda.bajtovi()), len(self.proba.bajtovi()) + 2)

    def test_podmetnuto_odrediste_pada(self):
        podmetnuta = self.proba.bajtovi().replace(b"1.2.3.4", b"9.9.9.9")
        self.assertEqual("potpis_nevaljan",
                         Proba.parsiraj(podmetnuta).provjeri(self.pk.hex())[1])

    def test_stara_proba_pada(self):
        stara = Proba("PROBA", "x96", "aa", int(time.time()) - 300,
                      "1.2.3.4:5678").potpisi(self.sk)
        valjana, razlog = Proba.parsiraj(stara.bajtovi()).provjeri(self.pk.hex())
        self.assertFalse(valjana)
        self.assertIn("odmak", razlog)

    def test_nepoznata_vrsta(self):
        with self.assertRaises(ProbodGreska):
            Proba.parsiraj(self.proba.bajtovi().replace(b"PROBA", b"NAPAD"))

    def test_prevelika_proba(self):
        with self.assertRaises(ProbodGreska):
            Proba.parsiraj(b"x" * 600)

    def test_smece_nije_proba(self):
        for smece in (b"", b"MASKA-PROBOD1", b"bilo sto drugo", b"\xff\xfe"):
            with self.subTest(smece=smece), self.assertRaises(ProbodGreska):
                Proba.parsiraj(smece)


class TestOglas(unittest.TestCase):
    def setUp(self):
        self.sk, self.pk = kripto.ed25519_novi_kljuc()
        self.kandidati = [Kandidat(TIP_HOST, "192.168.1.20", 51820),
                          Kandidat(TIP_REFLEKS, "198.51.100.7", 40000)]
        self.oglas = Oglas.napravi("x96", self.kandidati, self.sk, nat="EIM", wg_pk="a" * 44)

    def test_krug_i_provjera(self):
        procitan = Oglas.parsiraj(self.oglas.tekst())
        self.assertEqual((True, ""), procitan.provjeri(self.pk.hex()))
        self.assertEqual(self.kandidati, procitan.kandidati)
        self.assertEqual("EIM", procitan.nat)

    def test_bez_pina_pada(self):
        self.assertEqual("pk_nije_pinovan", self.oglas.provjeri(None)[1])

    def test_podmetnut_kandidat_pada(self):
        podmetnut = Oglas.parsiraj(self.oglas.tekst().replace("198.51.100.7", "203.0.113.9"))
        self.assertEqual("potpis_nevaljan", podmetnut.provjeri(self.pk.hex())[1])

    def test_podmetnut_nat_pada(self):
        """Lazni 'EIM' na tudjem oglasu mora pasti na potpisu."""
        podmetnut = Oglas.parsiraj(self.oglas.tekst().replace('"nat":"EIM"', '"nat":"EDM"'))
        self.assertEqual("potpis_nevaljan", podmetnut.provjeri(self.pk.hex())[1])

    def test_star_oglas_pada(self):
        star = Oglas.napravi("x96", self.kandidati, self.sk, sada=time.time() - 600)
        valjan, razlog = star.provjeri(self.pk.hex())
        self.assertFalse(valjan)
        self.assertIn("star", razlog)

    def test_oglas_iz_buducnosti_pada(self):
        budući = Oglas.napravi("x96", self.kandidati, self.sk, sada=time.time() + 600)
        self.assertEqual("oglas_iz_buducnosti", budući.provjeri(self.pk.hex())[1])

    def test_nepoznato_polje_odbijeno(self):
        with self.assertRaises(ProbodGreska) as ctx:
            Oglas.parsiraj(self.oglas.tekst().replace('{"ime"', '{"extra":1,"ime"'))
        self.assertIn("nepoznata polja", str(ctx.exception))

    def test_nekanonski_oblik_odbijen(self):
        with self.assertRaises(ProbodGreska):
            Oglas.parsiraj(" " + self.oglas.tekst().replace('","', '" , '))

    def test_prazan_popis_kandidata(self):
        with self.assertRaises(ProbodGreska):
            Oglas.napravi("x96", [], self.sk)

    def test_previse_kandidata(self):
        previse = [Kandidat(TIP_HOST, f"10.0.0.{i}", 51820) for i in range(MAX_KANDIDATA + 1)]
        with self.assertRaises(ProbodGreska):
            Oglas.napravi("x96", previse, self.sk)

    def test_nepoznat_tip_kandidata(self):
        with self.assertRaises(ProbodGreska):
            Kandidat("relej_turn", "1.2.3.4", 1234)

    def test_svaki_oglas_ima_nov_nonce(self):
        drugi = Oglas.napravi("x96", self.kandidati, self.sk)
        self.assertNotEqual(self.oglas.nonce, drugi.nonce)


class TestWgPredaja(unittest.TestCase):
    """Predaja se dokazuje POMAKOM handshakea, ne izostankom greske od `wg set`."""

    def _predaja(self, handshakes: list[int | None], set_kod: int = 0):
        pozivi = []
        stanje = {"i": 0}

        def pokretac(naredba):
            pozivi.append(naredba)
            if naredba[1] == "set":
                return (set_kod, "" if set_kod == 0 else "greska iz wg")
            if naredba[3] == "latest-handshakes":
                i = min(stanje["i"], len(handshakes) - 1)
                stanje["i"] += 1
                v = handshakes[i]
                return (0, "") if v is None else (0, f"PEERPK\t{v}\n")
            if naredba[3] == "endpoints":
                return (0, "PEERPK\t203.0.113.10:51820\n")
            return (1, "nepoznata naredba")

        return WgPredaja("rizom-eu", pokretac=pokretac), pozivi

    def test_handshake_napreduje_znaci_neposredan(self):
        predaja, pozivi = self._predaja([1000, 1000, 1042])
        ishod = predaja.predaj("PEERPK", ("198.51.100.7", 40000),
                               relej=("203.0.113.10", 51820), spavaj=lambda s: None)
        self.assertEqual("NEPOSREDAN", ishod["stanje"])
        self.assertEqual("198.51.100.7:40000", ishod["endpoint"])
        self.assertTrue(any(n[:3] == ["wg", "set", "rizom-eu"] for n in pozivi))

    def test_handshake_ne_napreduje_vraca_na_relej(self):
        predaja, pozivi = self._predaja([1000] * 40)
        ishod = predaja.predaj("PEERPK", ("198.51.100.7", 40000),
                               relej=("203.0.113.10", 51820), cekanje_s=2.0,
                               spavaj=lambda s: None)
        self.assertEqual("RELEJ", ishod["stanje"])
        self.assertTrue(ishod["vracen_na_relej"])
        self.assertEqual("203.0.113.10:51820", ishod["endpoint"])
        zadnji_set = [n for n in pozivi if n[1] == "set"][-1]
        self.assertEqual("203.0.113.10:51820", zadnji_set[-1],
                         "zadnja naredba mora vratiti endpoint na sidro")

    def test_wg_set_pao_je_NEPOZNATO(self):
        predaja, _ = self._predaja([1000], set_kod=1)
        ishod = predaja.predaj("PEERPK", ("198.51.100.7", 40000), spavaj=lambda s: None)
        self.assertEqual("NEPOZNATO", ishod["stanje"])
        self.assertIn("wg set", ishod["razlog"])

    def test_prvi_handshake_uopce(self):
        """Peer koji jos nikad nije imao handshake: bilo koja vrijednost je napredak."""
        predaja, _ = self._predaja([None, 2000])
        ishod = predaja.predaj("PEERPK", ("198.51.100.7", 40000), spavaj=lambda s: None)
        self.assertEqual("NEPOSREDAN", ishod["stanje"])

    def test_wg_nije_instaliran(self):
        predaja = WgPredaja("rizom-eu", pokretac=lambda n: (127, "wg nije instaliran"))
        self.assertIsNone(predaja.handshake("PEERPK"))
        ishod = predaja.predaj("PEERPK", ("1.2.3.4", 5), spavaj=lambda s: None)
        self.assertEqual("NEPOZNATO", ishod["stanje"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
