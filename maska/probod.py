#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""PROBOD — ICE-lite probijanje NAT-a i predaja puta WireGuardu (MASKA faza F4). stdlib only.

Cemu F4: dok sav promet ide kroz sidro, sidro je jedina dodirna tocka — pa je i
jedina tocka kvara, i jedino mjesto s kojeg se promet moze citati. Nakon proboda
sidro zna samo TKO postoji, ne i STO se prenosi, a njegov pad ne ruši
uspostavljenu vezu. To je jedina faza koja SPOF stvarno ukida; F1-F3 ga
premjestaju na manje krhko mjesto.

Redoslijed, i zasto tocno takav:

  1. IZMJERI prije nego probas (maska/stun.py). Simetricni NAT (EDM) daje novi
     port po odredistu — adresa koju vidi sidro EU ne vrijedi za peera, pa probod
     ne moze uspjeti. Kod koji to ne izmjeri "pokusava" i onda tise padne na
     relej, a korisniku javi "probijeno". Ovdje se EDM prijavi kao EDM.
  2. OGLAS: svaka strana objavi svoje kandidate na sidru, POTPISANO (Ed25519,
     pinovani kljuc, ts + nonce protiv ponavljanja). Sidro je oglasna ploca, ne
     prolaz — nema endpointa koji prenosi teret.
  3. ISTOVREMENI PROBOD: obje strane salju probe na sve tudje kandidate s ISTOG
     socketa s kojeg su mjerile mapiranje. Izlazna proba otvara NAT mapiranje,
     tudja proba ulazi kroz njega.
  4. NOMINACIJA: par koji je potvrdjen U OBA SMJERA i ima najmanji RTT.
     Upravljacka strana je leksikografski manje ime — bez pogadjanja i bez
     pregovora koji mogu zapeti.
  5. PREDAJA WireGuardu (neobavezno): `wg set <sucelje> peer <pk> endpoint <par>`,
     pa provjera da se `latest-handshakes` STVARNO pomaknuo. Ako se ne pomakne,
     endpoint se vraca na sidro i ishod je RELEJ — nikad tiha tvrdnja uspjeha.

Sto sidro moze i ne moze slagati (bitno za prosudbu rizika): sidro moze objaviti
lazan kandidat, jer adresu koju ono opaza peer ne moze kriptografski provjeriti.
Time moze SPRIJECITI vezu, ali ne i uci u nju: WireGuard autentificira kljucem,
ne adresom, a MASKA probe su potpisane Ed25519 kljucem peera. Laz sidra je
napad na dostupnost, ne na tajnost.

NIJE implementirano: TURN relej (RFC 5766), puni ICE (RFC 8445) s parovima
kandidata po prioritetu i agresivnom nominacijom, IPv6 kandidati. Relej ovdje
znaci "postojeci RIZOM tunel kroz sidro (F3)", ne TURN.
"""
from __future__ import annotations

import base64
import json
import os
import secrets
import socket
import subprocess
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Callable, Protocol

from . import kripto
from . import stun

VERZIJA_PROBE = "MASKA-PROBOD1"
VRSTE_PROBE = ("PROBA", "POTVRDA", "NOMINACIJA")
MAX_PROBA = 512                  # proba je ~200 B; sve iznad je smece ili napad
MAX_OGLAS = 4096
MAX_STAROST_OGLASA_S = 120       # tolerancija razilazenja satova i mreznog kasnjenja
MAX_KANDIDATA = 8                # gornja granica: N*M parova, ne beskonacna petlja
ZADANO_TRAJANJE_S = 6.0
INTERVAL_PROBE_S = 0.05          # 20 proba/s po kandidatu — dovoljno za NAT, bez poplave
HANDSHAKE_CEKANJE_S = 8.0


class ProbodGreska(ValueError):
    """Ulaz se ne da procitati ili ne prolazi provjeru."""


def _b64u(podaci: bytes) -> str:
    return base64.urlsafe_b64encode(podaci).decode().rstrip("=")


def _b64u_dekod(tekst: str) -> bytes:
    return base64.urlsafe_b64decode(tekst + "=" * (-len(tekst) % 4))


def _kanonski(podaci: dict) -> bytes:
    return json.dumps(podaci, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


# =============================================================================
# Kandidati i oglas
# =============================================================================
TIP_HOST = "host"                # adresa na lokalnom sucelju
TIP_REFLEKS = "refleks"          # sto sidro vidi kao nasu vanjsku adresu (STUN)
TIP_SIDRO_VIDI = "sidro_vidi"    # endpoint WireGuarda kako ga opaza sidro (netvrdiv)

PRIORITET = {TIP_HOST: 120, TIP_REFLEKS: 100, TIP_SIDRO_VIDI: 60}


@dataclass(frozen=True)
class Kandidat:
    tip: str
    ip: str
    port: int

    def __post_init__(self) -> None:
        if self.tip not in PRIORITET:
            raise ProbodGreska(f"nepoznat tip kandidata: {self.tip!r}")
        if not 1 <= self.port <= 65535:
            raise ProbodGreska(f"port izvan granica: {self.port}")

    @property
    def adresa(self) -> tuple[str, int]:
        return (self.ip, self.port)

    @property
    def prioritet(self) -> int:
        return PRIORITET[self.tip]

    def kao_dict(self) -> dict:
        return {"tip": self.tip, "ip": self.ip, "port": self.port}

    @classmethod
    def iz_dict(cls, d: dict) -> "Kandidat":
        if set(d) != {"tip", "ip", "port"}:
            raise ProbodGreska(f"kandidat ima neocekivana polja: {sorted(d)}")
        return cls(tip=str(d["tip"]), ip=str(d["ip"]), port=int(d["port"]))

    def __str__(self) -> str:
        return f"{self.tip}:{self.ip}:{self.port}"


@dataclass
class Oglas:
    """Potpisani skup kandidata jedne strane. Sidro ga samo drzi; peer ga provjerava."""
    ime: str
    kandidati: list[Kandidat]
    ts: int
    nonce: str
    nat: str = "NEPOZNATO"                 # EIM | EDM | NEPOZNATO (mjerenje, ne obecanje)
    wg_pk: str | None = None               # javni WireGuard kljuc (base64), za predaju
    pk: str = ""                           # Ed25519 javni kljuc objavitelja (64 hex)
    sig: str | None = None

    @classmethod
    def napravi(cls, ime: str, kandidati: list[Kandidat], sk32: bytes,
                nat: str = "NEPOZNATO", wg_pk: str | None = None,
                sada: float | None = None) -> "Oglas":
        if not kandidati:
            raise ProbodGreska("oglas bez kandidata nema svrhu")
        if len(kandidati) > MAX_KANDIDATA:
            raise ProbodGreska(f"najvise {MAX_KANDIDATA} kandidata po oglasu")
        oglas = cls(ime=ime, kandidati=list(kandidati),
                    ts=int(time.time() if sada is None else sada),
                    nonce=secrets.token_hex(8), nat=nat, wg_pk=wg_pk,
                    pk=kripto.ed25519_pubkey(sk32).hex())
        oglas.sig = _b64u(kripto.ed25519_sign(sk32, oglas.kanonski()))
        return oglas

    def _polja(self) -> dict:
        p = {"ime": self.ime, "ts": self.ts, "nonce": self.nonce, "nat": self.nat,
             "pk": self.pk, "kandidati": [k.kao_dict() for k in self.kandidati]}
        if self.wg_pk:
            p["wg_pk"] = self.wg_pk
        return p

    def kanonski(self) -> bytes:
        return _kanonski(self._polja())

    def tekst(self) -> str:
        if not self.sig:
            raise ProbodGreska("nepotpisan oglas se ne serijalizira")
        p = self._polja()
        p["sig"] = self.sig
        return _kanonski(p).decode("utf-8")

    @classmethod
    def parsiraj(cls, tekst: str | bytes) -> "Oglas":
        if isinstance(tekst, (bytes, bytearray)):
            tekst = tekst.decode("utf-8", "strict")
        if len(tekst.encode("utf-8")) > MAX_OGLAS:
            raise ProbodGreska(f"oglas veci od {MAX_OGLAS} B")
        try:
            p = json.loads(tekst)
        except json.JSONDecodeError as e:
            raise ProbodGreska(f"oglas nije valjan JSON: {e}") from e
        if not isinstance(p, dict):
            raise ProbodGreska("oglas mora biti JSON objekt")
        dopusteno = {"ime", "ts", "nonce", "nat", "pk", "kandidati", "wg_pk", "sig"}
        nepoznata = sorted(set(p) - dopusteno)
        if nepoznata:
            raise ProbodGreska(f"nepoznata polja odbijena (potpis ih ne pokriva): {nepoznata}")
        for obavezno in ("ime", "ts", "nonce", "nat", "pk", "kandidati", "sig"):
            if obavezno not in p:
                raise ProbodGreska(f"nedostaje obavezno polje {obavezno!r}")
        if not isinstance(p["kandidati"], list) or not p["kandidati"]:
            raise ProbodGreska("kandidati moraju biti neprazna lista")
        if len(p["kandidati"]) > MAX_KANDIDATA:
            raise ProbodGreska(f"najvise {MAX_KANDIDATA} kandidata po oglasu")
        oglas = cls(ime=str(p["ime"]), kandidati=[Kandidat.iz_dict(k) for k in p["kandidati"]],
                    ts=int(p["ts"]), nonce=str(p["nonce"]), nat=str(p["nat"]),
                    wg_pk=(str(p["wg_pk"]) if p.get("wg_pk") else None), pk=str(p["pk"]),
                    sig=str(p["sig"]))
        if oglas.tekst() != tekst:
            raise ProbodGreska("oglas nije u kanonskom obliku (redoslijed polja ili razmaci)")
        return oglas

    def provjeri(self, pinovani_pk: str | None, sada: float | None = None,
                 max_starost_s: int = MAX_STAROST_OGLASA_S) -> tuple[bool, str]:
        sada = time.time() if sada is None else sada
        if not self.sig:
            return False, "nema_potpisa"
        if not pinovani_pk:
            return False, "pk_nije_pinovan"
        if pinovani_pk.strip().lower() != self.pk.lower():
            return False, "pk_ne_odgovara_pinovanom"
        try:
            potpis = _b64u_dekod(self.sig)
        except Exception:
            return False, "sig_nije_base64url"
        if not kripto.ed25519_verify(bytes.fromhex(self.pk), potpis, self.kanonski()):
            return False, "potpis_nevaljan"
        starost = sada - self.ts
        if starost > max_starost_s:
            return False, f"oglas_star_{int(starost)}s"
        if starost < -max_starost_s:
            return False, "oglas_iz_buducnosti"
        return True, ""


# =============================================================================
# Prijenos (da se protokol moze testirati kroz simulirani NAT)
# =============================================================================
class Prijenos(Protocol):
    def posalji(self, podaci: bytes, adresa: tuple[str, int]) -> None: ...
    def primi(self, cekanje_s: float) -> tuple[bytes, tuple[str, int]] | None: ...
    def lokalna_adresa(self) -> tuple[str, int]: ...


class UdpPrijenos:
    """Pravi UDP socket. Isti socket kojim se mjerio NAT mora probijati — inace
    mjeris jedno mapiranje a koristis drugo."""

    def __init__(self, utor: socket.socket):
        self.utor = utor

    @classmethod
    def novi(cls, port: int = 0, host: str = "0.0.0.0") -> "UdpPrijenos":
        utor = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        utor.bind((host, port))
        return cls(utor)

    def posalji(self, podaci: bytes, adresa: tuple[str, int]) -> None:
        try:
            self.utor.sendto(podaci, adresa)
        except OSError:
            pass                  # nedosezljiv kandidat nije greska nego rezultat

    def primi(self, cekanje_s: float):
        self.utor.settimeout(max(0.001, cekanje_s))
        try:
            return self.utor.recvfrom(MAX_PROBA + 64)
        except (socket.timeout, TimeoutError, OSError):
            return None

    def lokalna_adresa(self) -> tuple[str, int]:
        return self.utor.getsockname()

    def zatvori(self) -> None:
        self.utor.close()


# =============================================================================
# Proba na zici (tekstualno — citljivo u tcpdump -A, kao PELUD)
# =============================================================================
@dataclass
class Proba:
    vrsta: str
    ime: str
    nonce: str
    ts: int
    odrediste: str                 # "ip:port" kojemu je proba namijenjena
    sig: str | None = None

    def kanonski(self) -> bytes:
        return (f"{VERZIJA_PROBE} {self.vrsta} ime={self.ime} nonce={self.nonce} "
                f"ts={self.ts} do={self.odrediste}").encode("utf-8")

    def potpisi(self, sk32: bytes) -> "Proba":
        self.sig = _b64u(kripto.ed25519_sign(sk32, self.kanonski()))
        return self

    def bajtovi(self) -> bytes:
        if not self.sig:
            raise ProbodGreska("nepotpisana proba se ne salje")
        return self.kanonski() + b" sig=" + self.sig.encode()

    @classmethod
    def parsiraj(cls, podaci: bytes) -> "Proba":
        if len(podaci) > MAX_PROBA:
            raise ProbodGreska("proba prevelika")
        try:
            tekst = podaci.decode("utf-8")
        except UnicodeDecodeError as e:
            raise ProbodGreska("proba nije UTF-8") from e
        dijelovi = tekst.split(" ")
        if len(dijelovi) != 7 or dijelovi[0] != VERZIJA_PROBE:
            raise ProbodGreska("nije MASKA-PROBOD1 proba")
        vrsta = dijelovi[1]
        if vrsta not in VRSTE_PROBE:
            raise ProbodGreska(f"nepoznata vrsta probe: {vrsta!r}")
        polja = {}
        for dio in dijelovi[2:]:
            if "=" not in dio:
                raise ProbodGreska(f"dio probe nije k=v: {dio!r}")
            k, v = dio.split("=", 1)
            if k in polja:
                raise ProbodGreska(f"polje {k!r} ponovljeno")
            polja[k] = v
        if set(polja) != {"ime", "nonce", "ts", "do", "sig"}:
            raise ProbodGreska(f"proba ima neocekivana polja: {sorted(polja)}")
        proba = cls(vrsta=vrsta, ime=polja["ime"], nonce=polja["nonce"],
                    ts=int(polja["ts"]), odrediste=polja["do"], sig=polja["sig"])
        if proba.bajtovi() != podaci:
            raise ProbodGreska("proba nije u kanonskom obliku")
        return proba

    def provjeri(self, pinovani_pk: str, sada: float | None = None,
                 max_odmak_s: int = 30) -> tuple[bool, str]:
        sada = time.time() if sada is None else sada
        if not self.sig:
            return False, "nema_potpisa"
        try:
            potpis = _b64u_dekod(self.sig)
        except Exception:
            return False, "sig_nije_base64url"
        if not kripto.ed25519_verify(bytes.fromhex(pinovani_pk), potpis, self.kanonski()):
            return False, "potpis_nevaljan"
        if abs(sada - self.ts) > max_odmak_s:
            return False, f"proba_odmak_{int(sada - self.ts)}s"
        return True, ""


# =============================================================================
# Ishod
# =============================================================================
@dataclass
class Ishod:
    stanje: str                       # NEPOSREDAN | RELEJ | NEPOZNATO
    razlog: str = ""
    par: tuple[Kandidat, Kandidat] | None = None     # (nas, njihov)
    rtt_ms: int | None = None
    nat: str = "NEPOZNATO"
    peer_nat: str = "NEPOZNATO"
    potvrdjeni: list[str] = field(default_factory=list)
    wg: dict = field(default_factory=dict)

    @property
    def neposredan(self) -> bool:
        return self.stanje == "NEPOSREDAN"

    def kao_dict(self) -> dict:
        return {
            "stanje": self.stanje, "razlog": self.razlog,
            "nas_kandidat": (str(self.par[0]) if self.par else None),
            "njihov_kandidat": (str(self.par[1]) if self.par else None),
            "rtt_ms": self.rtt_ms, "nas_nat": self.nat, "peer_nat": self.peer_nat,
            "potvrdjeni_parovi": self.potvrdjeni, "wg": self.wg,
        }


# =============================================================================
# Oglasna ploca (klijent prema sidru)
# =============================================================================
class Ploca:
    """HTTP klijent prema susret servisu na sidru. PULL, nikad push od sidra."""

    def __init__(self, sidra: list[str], timeout_s: float = 5.0):
        self.sidra = [s.rstrip("/") for s in sidra]
        self.timeout_s = timeout_s

    def objavi(self, oglas: Oglas) -> tuple[int, list[str]]:
        tijelo = oglas.tekst().encode("utf-8")
        uspjelo, greske = 0, []
        for sidro in self.sidra:
            zahtjev = urllib.request.Request(
                sidro + "/susret/oglas", data=tijelo, method="POST",
                headers={"Content-Type": "application/json; charset=utf-8",
                         "User-Agent": "maska-probod/1.0"})
            try:
                with urllib.request.urlopen(zahtjev, timeout=self.timeout_s) as odgovor:
                    if odgovor.status in (200, 201):
                        uspjelo += 1
                    else:
                        greske.append(f"{sidro}: http_{odgovor.status}")
            except urllib.error.HTTPError as e:
                greske.append(f"{sidro}: http_{e.code}")
            except (urllib.error.URLError, OSError) as e:
                greske.append(f"{sidro}: {type(e).__name__}")
        return uspjelo, greske

    def dohvati(self, ime: str) -> tuple[Oglas | None, list[str]]:
        """Prvi oglas koji se DA PROCITATI; potpis provjerava pozivatelj, ne sidro."""
        greske = []
        for sidro in self.sidra:
            zahtjev = urllib.request.Request(
                f"{sidro}/susret/oglas/{ime}", headers={"User-Agent": "maska-probod/1.0"})
            try:
                with urllib.request.urlopen(zahtjev, timeout=self.timeout_s) as odgovor:
                    if odgovor.status != 200:
                        greske.append(f"{sidro}: http_{odgovor.status}")
                        continue
                    sirovo = odgovor.read(MAX_OGLAS + 1)
            except urllib.error.HTTPError as e:
                greske.append(f"{sidro}: http_{e.code}")
                continue
            except (urllib.error.URLError, OSError) as e:
                greske.append(f"{sidro}: {type(e).__name__}")
                continue
            try:
                return Oglas.parsiraj(sirovo), greske
            except ProbodGreska as e:
                greske.append(f"{sidro}: {e}")
        return None, greske


# =============================================================================
# Probod
# =============================================================================
class Probod:
    """Jedan pokusaj proboda prema jednom peeru.

    ime / peer_ime: leksikografski manje ime je UPRAVLJACKA strana i ono nominira.
    Bez pregovora o roli — pregovor koji moze zapeti nije mehanizam nego nada.
    """

    def __init__(self, ime: str, sk32: bytes, peer_ime: str, peer_pk: str,
                 prijenos: Prijenos, sada: Callable[[], float] = time.time):
        if ime == peer_ime:
            raise ProbodGreska("ime i peer_ime moraju biti razliciti")
        self.ime = ime
        self.sk = sk32
        self.peer_ime = peer_ime
        self.peer_pk = peer_pk
        self.prijenos = prijenos
        self.sada = sada
        self.upravljacka = ime < peer_ime
        self.vidjeni_nonce: set[str] = set()

    # -- kandidati ---------------------------------------------------------
    def kandidati(self, stun_sidra: list[tuple[str, int]] | None = None,
                  utor: socket.socket | None = None,
                  dodatni: list[Kandidat] | None = None) -> tuple[list[Kandidat], stun.NatNalaz]:
        """Lokalni + refleksivni kandidati, uz IZMJEREN nalaz o NAT-u."""
        lokalni_ip, lokalni_port = self.prijenos.lokalna_adresa()
        kandidati: list[Kandidat] = []
        if lokalni_ip not in ("0.0.0.0", "::"):
            kandidati.append(Kandidat(TIP_HOST, lokalni_ip, lokalni_port))
        else:
            for ip in _lokalne_adrese():
                kandidati.append(Kandidat(TIP_HOST, ip, lokalni_port))

        nalaz = stun.NatNalaz("NEPOZNATO", "STUN sidra nisu dana")
        if stun_sidra:
            nalaz = stun.klasificiraj(stun_sidra, utor=utor)
            for refleks in nalaz.refleksi:
                k = Kandidat(TIP_REFLEKS, refleks.ip, refleks.port)
                if k not in kandidati:
                    kandidati.append(k)
        for k in (dodatni or []):
            if k not in kandidati:
                kandidati.append(k)
        return kandidati[:MAX_KANDIDATA], nalaz

    # -- probijanje --------------------------------------------------------
    def probij(self, nasi: list[Kandidat], njihovi: list[Kandidat],
               trajanje_s: float = ZADANO_TRAJANJE_S, nas_nat: str = "NEPOZNATO",
               peer_nat: str = "NEPOZNATO") -> Ishod:
        """Istovremeno slanje proba na sve tudje kandidate + odgovaranje na tudje.

        Uspjeh = par potvrdjen U OBA SMJERA: dobili smo POTVRDU na svoju probu I
        vidjeli tudju probu s te adrese. Jednosmjerni promet nije veza.
        """
        if not njihovi:
            return Ishod("NEPOZNATO", "peer nije objavio ni jedan kandidat",
                         nat=nas_nat, peer_nat=peer_nat)
        if nas_nat == "EDM" or peer_nat == "EDM":
            # Ne "pokusavaj pa vidi": kod EDM-a vanjsko mapiranje vrijedi samo za
            # sidro, pa probod NE MOZE uspjeti. Lazna nada trosi 6 s po pokusaju
            # i zamuti dijagnostiku.
            koji = "nas" if nas_nat == "EDM" else "peerov"
            return Ishod("RELEJ", f"{koji} NAT je simetrican (EDM) — probod nije moguc, "
                                  f"put ostaje kroz sidro (RIZOM/F3)",
                         nat=nas_nat, peer_nat=peer_nat)

        poc = self.sada()
        poslano_u: dict[str, float] = {}          # nonce -> vrijeme slanja
        nonce_za: dict[str, tuple[str, int]] = {}  # nonce -> adresa kojoj je poslana
        rtt_po_adresi: dict[tuple[str, int], int] = {}
        vidjeli_probu: set[tuple[str, int]] = set()
        potvrdjeni: dict[tuple[str, int], int] = {}
        nominiran: tuple[str, int] | None = None
        zadnje_slanje = 0.0

        while self.sada() - poc < trajanje_s:
            sada = self.sada()
            if sada - zadnje_slanje >= INTERVAL_PROBE_S:
                zadnje_slanje = sada
                for k in njihovi:
                    proba = Proba("PROBA", self.ime, secrets.token_hex(6), int(sada),
                                  f"{k.ip}:{k.port}").potpisi(self.sk)
                    poslano_u[proba.nonce] = sada
                    nonce_za[proba.nonce] = k.adresa
                    self.prijenos.posalji(proba.bajtovi(), k.adresa)

            primljeno = self.prijenos.primi(INTERVAL_PROBE_S)
            if primljeno is None:
                continue
            podaci, od_koga = primljeno
            try:
                proba = Proba.parsiraj(podaci)
            except ProbodGreska:
                continue                       # tudji paket na istom portu
            if proba.ime != self.peer_ime:
                continue
            valjana, _razlog = proba.provjeri(self.peer_pk, sada=self.sada())
            if not valjana:
                continue
            if proba.vrsta == "PROBA":
                if proba.nonce in self.vidjeni_nonce:
                    continue                   # ponavljanje
                self.vidjeni_nonce.add(proba.nonce)
                vidjeli_probu.add(od_koga)
                odgovor = Proba("POTVRDA", self.ime, proba.nonce, int(self.sada()),
                                f"{od_koga[0]}:{od_koga[1]}").potpisi(self.sk)
                self.prijenos.posalji(odgovor.bajtovi(), od_koga)
            elif proba.vrsta == "POTVRDA":
                poslano = poslano_u.get(proba.nonce)
                if poslano is None or nonce_za.get(proba.nonce) != od_koga:
                    continue                   # potvrda na probu koju nismo poslali toj adresi
                rtt = int((self.sada() - poslano) * 1000)
                rtt_po_adresi[od_koga] = min(rtt, rtt_po_adresi.get(od_koga, rtt))
                potvrdjeni[od_koga] = rtt_po_adresi[od_koga]
            elif proba.vrsta == "NOMINACIJA":
                if not self.upravljacka:
                    nominiran = od_koga

            dvosmjerni = {a: r for a, r in potvrdjeni.items() if a in vidjeli_probu}
            if dvosmjerni and self.upravljacka:
                najbolji = min(dvosmjerni, key=lambda a: dvosmjerni[a])
                nominacija = Proba("NOMINACIJA", self.ime, secrets.token_hex(6),
                                   int(self.sada()), f"{najbolji[0]}:{najbolji[1]}").potpisi(self.sk)
                self.prijenos.posalji(nominacija.bajtovi(), najbolji)
                nominiran = najbolji
                break
            if nominiran and nominiran in dvosmjerni:
                break

        dvosmjerni = {a: r for a, r in potvrdjeni.items() if a in vidjeli_probu}
        odabran = nominiran if (nominiran in dvosmjerni) else (
            min(dvosmjerni, key=lambda a: dvosmjerni[a]) if dvosmjerni else None)

        popis = [f"{a[0]}:{a[1]}={r}ms" for a, r in sorted(dvosmjerni.items(),
                                                          key=lambda x: x[1])]
        if odabran is None:
            if potvrdjeni:
                razlog = ("promet samo u jednom smjeru (dobili smo potvrdu, tudju probu nismo "
                          "vidjeli) — filtriranje NAT-a ne propusta ulazni promet")
            elif vidjeli_probu:
                razlog = ("vidimo tudje probe, nase ne stizu do njih — filtriranje na "
                          "peerovoj strani")
            else:
                razlog = "ni jedna proba nije prosla u ni jednom smjeru"
            return Ishod("RELEJ", razlog + "; put ostaje kroz sidro (RIZOM/F3)",
                         nat=nas_nat, peer_nat=peer_nat, potvrdjeni=popis)

        nas_ip, nas_port = self.prijenos.lokalna_adresa()
        nas = next((k for k in nasi if k.port == nas_port), Kandidat(TIP_HOST, nas_ip, nas_port))
        njihov = next((k for k in njihovi if k.adresa == odabran),
                      Kandidat(TIP_REFLEKS, odabran[0], odabran[1]))
        return Ishod("NEPOSREDAN", "", par=(nas, njihov), rtt_ms=dvosmjerni[odabran],
                     nat=nas_nat, peer_nat=peer_nat, potvrdjeni=popis)


def _lokalne_adrese() -> list[str]:
    """IPv4 adrese lokalnih sucelja, bez loopbacka. Bez vanjskih zavisnosti."""
    adrese: set[str] = set()
    try:
        for podaci in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            adrese.add(podaci[4][0])
    except OSError:
        pass
    try:
        u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        u.connect(("192.0.2.1", 9))              # TEST-NET-1: nista se ne slje
        adrese.add(u.getsockname()[0])
        u.close()
    except OSError:
        pass
    return sorted(a for a in adrese if not a.startswith("127."))


# =============================================================================
# Predaja puta WireGuardu
# =============================================================================
class WgPredaja:
    """Prebaci WireGuard peera na probijeni endpoint i DOKAZI da je proslo.

    Dokaz je pomak `latest-handshakes`, ne izostanak greske od `wg set`. Ako se
    handshake ne pomakne, endpoint se vraca na sidro i ishod je RELEJ.

    pokretac: injektiran da se ponasanje moze testirati bez WireGuarda; u
    produkciji je subprocess.run.
    """

    def __init__(self, sucelje: str, pokretac: Callable[[list[str]], tuple[int, str]] | None = None):
        self.sucelje = sucelje
        self.pokretac = pokretac or self._pokreni

    @staticmethod
    def _pokreni(naredba: list[str]) -> tuple[int, str]:
        try:
            r = subprocess.run(naredba, capture_output=True, text=True, timeout=10)
            return r.returncode, (r.stdout or "") + (r.stderr or "")
        except FileNotFoundError:
            return 127, "wg nije instaliran (apt install wireguard-tools)"
        except subprocess.TimeoutExpired:
            return 124, "wg se nije vratio u 10 s"

    def handshake(self, peer_pk: str) -> int | None:
        """Epoch zadnjeg handshakea za peera; None = ne moze se izmjeriti."""
        kod, izlaz = self.pokretac(["wg", "show", self.sucelje, "latest-handshakes"])
        if kod != 0:
            return None
        for linija in izlaz.splitlines():
            dijelovi = linija.split()
            if len(dijelovi) >= 2 and dijelovi[0] == peer_pk:
                try:
                    return int(dijelovi[1])
                except ValueError:
                    return None
        return None

    def endpoint(self, peer_pk: str) -> str | None:
        kod, izlaz = self.pokretac(["wg", "show", self.sucelje, "endpoints"])
        if kod != 0:
            return None
        for linija in izlaz.splitlines():
            dijelovi = linija.split()
            if len(dijelovi) >= 2 and dijelovi[0] == peer_pk:
                return dijelovi[1] if dijelovi[1] != "(none)" else None
        return None

    def postavi(self, peer_pk: str, adresa: tuple[str, int]) -> tuple[bool, str]:
        kod, izlaz = self.pokretac(["wg", "set", self.sucelje, "peer", peer_pk,
                                    "endpoint", f"{adresa[0]}:{adresa[1]}"])
        return (kod == 0), (izlaz.strip() if kod != 0 else "")

    def predaj(self, peer_pk: str, novi: tuple[str, int],
               relej: tuple[str, int] | None = None,
               cekanje_s: float = HANDSHAKE_CEKANJE_S,
               spavaj: Callable[[float], None] = time.sleep) -> dict:
        """Prebaci na `novi`; ako handshake ne napreduje, vrati na `relej`."""
        prije = self.handshake(peer_pk)
        stari_endpoint = self.endpoint(peer_pk)
        ok, greska = self.postavi(peer_pk, novi)
        if not ok:
            return {"stanje": "NEPOZNATO", "razlog": f"wg set nije uspio: {greska}",
                    "endpoint": stari_endpoint}

        cekano = 0.0
        while cekano < cekanje_s:
            spavaj(0.5)
            cekano += 0.5
            poslije = self.handshake(peer_pk)
            if poslije is not None and (prije is None or poslije > prije):
                return {"stanje": "NEPOSREDAN", "endpoint": f"{novi[0]}:{novi[1]}",
                        "handshake_prije": prije, "handshake_poslije": poslije,
                        "cekano_s": round(cekano, 1)}

        vraceno = None
        if relej:
            vracen_ok, vracena_greska = self.postavi(peer_pk, relej)
            vraceno = f"{relej[0]}:{relej[1]}" if vracen_ok else f"NEUSPJELO ({vracena_greska})"
        return {"stanje": "RELEJ",
                "razlog": (f"handshake se nije pomaknuo u {cekanje_s:.0f} s nakon prebacivanja na "
                           f"{novi[0]}:{novi[1]}"),
                "endpoint": vraceno or stari_endpoint, "vracen_na_relej": bool(relej),
                "handshake_prije": prije}


# =============================================================================
# Cijeli ciklus (za CLI i za sluzbu)
# =============================================================================
def izvedi(ime: str, sk32: bytes, peer_ime: str, peer_pk: str, sidra: list[str],
           stun_sidra: list[tuple[str, int]], lokalni_port: int = 0,
           trajanje_s: float = ZADANO_TRAJANJE_S, wg: dict | None = None,
           godovi=None) -> Ishod:
    """Izmjeri -> objavi -> dohvati -> probij -> (neobavezno) predaj WireGuardu."""
    prijenos = UdpPrijenos.novi(port=lokalni_port)
    try:
        probod = Probod(ime, sk32, peer_ime, peer_pk, prijenos)
        nasi, nalaz = probod.kandidati(stun_sidra=stun_sidra, utor=prijenos.utor)
        oglas = Oglas.napravi(ime, nasi, sk32, nat=nalaz.ponasanje,
                              wg_pk=(wg or {}).get("nas_pk"))
        ploca = Ploca(sidra)
        objavljeno, greske_objave = ploca.objavi(oglas)
        if objavljeno == 0:
            ishod = Ishod("NEPOZNATO", "ni jedno sidro nije prihvatilo oglas: "
                          + "; ".join(greske_objave), nat=nalaz.ponasanje)
            _upisi(godovi, ime, peer_ime, ishod)
            return ishod

        peer_oglas, greske_dohvata = ploca.dohvati(peer_ime)
        if peer_oglas is None:
            ishod = Ishod("NEPOZNATO", f"peer {peer_ime} nije na oglasnoj ploci: "
                          + "; ".join(greske_dohvata), nat=nalaz.ponasanje)
            _upisi(godovi, ime, peer_ime, ishod)
            return ishod
        valjan, razlog = peer_oglas.provjeri(peer_pk)
        if not valjan:
            ishod = Ishod("NEPOZNATO", f"peerov oglas nije valjan: {razlog}", nat=nalaz.ponasanje)
            _upisi(godovi, ime, peer_ime, ishod)
            return ishod

        ishod = probod.probij(nasi, peer_oglas.kandidati, trajanje_s=trajanje_s,
                              nas_nat=nalaz.ponasanje, peer_nat=peer_oglas.nat)

        if ishod.neposredan and wg and wg.get("sucelje") and peer_oglas.wg_pk:
            predaja = WgPredaja(wg["sucelje"])
            ishod.wg = predaja.predaj(peer_oglas.wg_pk, ishod.par[1].adresa,
                                      relej=wg.get("relej"))
            if ishod.wg.get("stanje") != "NEPOSREDAN":
                ishod.stanje = "RELEJ"
                ishod.razlog = (ishod.wg.get("razlog") or "predaja WireGuardu nije uspjela") \
                    + "; MASKA put je probijen, ali WireGuard ostaje na releju"
        _upisi(godovi, ime, peer_ime, ishod)
        return ishod
    finally:
        prijenos.zatvori()


def _upisi(godovi, ime: str, peer_ime: str, ishod: Ishod) -> None:
    """Svaki pokusaj u godove — i probijen i pao. Bez toga nema povijesti."""
    if godovi is None:
        return
    preslikavanje = {"NEPOSREDAN": "OK", "RELEJ": "ALARM", "NEPOZNATO": "NEPOZNATO"}
    try:
        godovi.upisi(f"probod:{ime}->{peer_ime}", preslikavanje.get(ishod.stanje, "NEPOZNATO"),
                     razlog=(ishod.razlog[:300] or None), rtt_ms=ishod.rtt_ms,
                     nas_nat=ishod.nat, peer_nat=ishod.peer_nat,
                     par=(str(ishod.par[1]) if ishod.par else None))
    except Exception:
        pass                      # dnevnik ne smije oboriti probod


def _cli(argv: list[str]) -> int:
    import argparse
    import pathlib
    ap = argparse.ArgumentParser(prog="python3 -m maska.probod",
                                 description="PROBOD — probij NAT prema peeru (MASKA F4)")
    ap.add_argument("--ime", required=True, help="nase ime na oglasnoj ploci")
    ap.add_argument("--kljuc", required=True, help="datoteka s 32-bajtnim Ed25519 tajnim kljucem")
    ap.add_argument("--peer", required=True, help="peerovo ime")
    ap.add_argument("--peer-pk", required=True, help="peerov pinovani Ed25519 kljuc (64 hex)")
    ap.add_argument("--sidro", action="append", required=True, metavar="URL",
                    help="susret sidro (HTTP); navesti dva")
    ap.add_argument("--stun", action="append", required=True, metavar="HOST:PORT",
                    help="STUN sidro; DVA na razlicitim IP adresama za mjerenje NAT-a")
    ap.add_argument("--port", type=int, default=0, help="lokalni UDP port proboda")
    ap.add_argument("--trajanje", type=float, default=ZADANO_TRAJANJE_S)
    ap.add_argument("--wg-sucelje", default=None, help="npr. rizom-eu (predaja puta WireGuardu)")
    ap.add_argument("--wg-nas-pk", default=None, help="nas javni WireGuard kljuc (base64)")
    ap.add_argument("--wg-relej", default=None, metavar="HOST:PORT",
                    help="endpoint sidra na koji se vraca ako predaja ne uspije")
    ap.add_argument("--godovi", default=None, help="putanja do godovi.jsonl")
    a = ap.parse_args(argv)

    sk = pathlib.Path(a.kljuc).read_bytes()[:32]
    if len(sk) != 32:
        print("GRESKA: kljuc mora imati tocno 32 bajta")
        return 2

    def razdvoji(spoj: str) -> tuple[str, int]:
        host, _, port = spoj.rpartition(":")
        return host, int(port)

    godovi = None
    if a.godovi:
        from .godovi import Godovi
        godovi = Godovi(a.godovi)

    wg = None
    if a.wg_sucelje:
        wg = {"sucelje": a.wg_sucelje, "nas_pk": a.wg_nas_pk,
              "relej": (razdvoji(a.wg_relej) if a.wg_relej else None)}

    ishod = izvedi(a.ime, sk, a.peer, a.peer_pk, a.sidro,
                   [razdvoji(x) for x in a.stun], lokalni_port=a.port,
                   trajanje_s=a.trajanje, wg=wg, godovi=godovi)
    print(json.dumps(ishod.kao_dict(), ensure_ascii=False, indent=1))
    if ishod.neposredan:
        print(f"# NEPOSREDAN put: {ishod.par[1]} ({ishod.rtt_ms} ms) — sidro od sada zna samo "
              f"tko postoji, ne i sto se prenosi")
        return 0
    if ishod.stanje == "RELEJ":
        print("# RELEJ: probod nije uspio, promet ostaje kroz sidro (RIZOM/F3). "
              "Ovo je mjerenje, ne kvar.")
        return 1
    print("# NEPOZNATO: mjerenje nije dovrseno — NE tvrdi ni probod ni relej")
    return 2


if __name__ == "__main__":
    import sys
    raise SystemExit(_cli(sys.argv[1:]))
