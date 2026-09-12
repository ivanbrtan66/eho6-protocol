#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Minimalni DNS kodek (RFC 1035) — samo ono sto dnkd stvarno treba, stdlib only.

Zasto rucno a ne dnspython: rubni uredjaji (Termux ARM, X96) instaliraju se
jednom naredbom bez pip-a; svaka vanjska zavisnost je jedna tocka kvara vise.
Opseg je namjerno uzak: procitaj upit, sastavi A/TXT/prazan/odbijeni odgovor,
sastavi izlazni upit i procitaj odgovor (za provjeru suglasnosti s javnim DNS-om).

Ovo NIJE rekurzivni resolver i ne smije postati: dnkd odgovara samo na .dnk i
sve ostalo ODBIJA (REFUSED). Resolver koji prosljedjuje postaje proxy kroz koji
prolazi sav korisnikov promet — to je nova dodirna tocka, tocno ono sto MASKA
uklanja.
"""
from __future__ import annotations

import random
import struct

TIP_A = 1
TIP_NS = 2
TIP_CNAME = 5
TIP_SOA = 6
TIP_TXT = 16
TIP_AAAA = 28
TIP_OPT = 41
TIP_ANY = 255

KLASA_IN = 1

RCODE_NOERROR = 0
RCODE_FORMERR = 1
RCODE_SERVFAIL = 2
RCODE_NXDOMAIN = 3
RCODE_NOTIMP = 4
RCODE_REFUSED = 5

IME_TIPA = {TIP_A: "A", TIP_NS: "NS", TIP_CNAME: "CNAME", TIP_SOA: "SOA",
            TIP_TXT: "TXT", TIP_AAAA: "AAAA", TIP_OPT: "OPT", TIP_ANY: "ANY"}
IME_RCODE = {RCODE_NOERROR: "NOERROR", RCODE_FORMERR: "FORMERR",
             RCODE_SERVFAIL: "SERVFAIL", RCODE_NXDOMAIN: "NXDOMAIN",
             RCODE_NOTIMP: "NOTIMP", RCODE_REFUSED: "REFUSED"}

MAX_UDP = 512          # bez EDNS0; veci odgovor nosi TC zastavicu
MAX_SKOKOVA = 16       # zastita od petlje kompresijskih pokazivaca


class DnsGreska(ValueError):
    """Paket se ne moze procitati. Poziva se FORMERR, nikad tiho ignoriranje."""


# =============================================================================
# Imena
# =============================================================================
def kodiraj_ime(ime: str) -> bytes:
    ime = ime.strip().rstrip(".")
    if not ime:
        return b"\x00"
    out = bytearray()
    for oznaka in ime.split("."):
        sirovo = oznaka.encode("idna") if any(ord(c) > 127 for c in oznaka) else oznaka.encode()
        if not 1 <= len(sirovo) <= 63:
            raise DnsGreska(f"oznaka imena mora biti 1-63 bajta: {oznaka!r}")
        out.append(len(sirovo))
        out += sirovo
    out.append(0)
    if len(out) > 255:
        raise DnsGreska("ime dulje od 255 bajtova")
    return bytes(out)


def dekodiraj_ime(podaci: bytes, poz: int) -> tuple[str, int]:
    """(ime, pozicija_nakon). Podrzava kompresijske pokazivace (0xC0)."""
    oznake: list[str] = []
    skokovi = 0
    poz_nakon = None
    while True:
        if poz >= len(podaci):
            raise DnsGreska("ime izlazi izvan paketa")
        duzina = podaci[poz]
        if duzina == 0:
            poz += 1
            break
        if duzina & 0xC0 == 0xC0:
            if poz + 1 >= len(podaci):
                raise DnsGreska("skraceni kompresijski pokazivac")
            cilj = ((duzina & 0x3F) << 8) | podaci[poz + 1]
            if poz_nakon is None:
                poz_nakon = poz + 2
            skokovi += 1
            if skokovi > MAX_SKOKOVA:
                raise DnsGreska("petlja kompresijskih pokazivaca")
            if cilj >= poz:
                raise DnsGreska("pokazivac ne pokazuje natrag — odbijeno")
            poz = cilj
            continue
        if duzina & 0xC0:
            raise DnsGreska(f"nepoznat tip oznake: {duzina:#x}")
        poz += 1
        if poz + duzina > len(podaci):
            raise DnsGreska("oznaka izlazi izvan paketa")
        oznake.append(podaci[poz:poz + duzina].decode("latin-1"))
        poz += duzina
    return ".".join(oznake).lower(), (poz_nakon if poz_nakon is not None else poz)


# =============================================================================
# Upit
# =============================================================================
class Upit:
    __slots__ = ("id", "zastavice", "ime", "tip", "klasa", "sirovo", "duzina_pitanja", "opt")

    def __init__(self, id_, zastavice, ime, tip, klasa, sirovo, duzina_pitanja, opt):
        self.id = id_
        self.zastavice = zastavice
        self.ime = ime
        self.tip = tip
        self.klasa = klasa
        self.sirovo = sirovo
        self.duzina_pitanja = duzina_pitanja
        self.opt = opt

    @property
    def rd(self) -> bool:
        return bool(self.zastavice & 0x0100)

    def __repr__(self) -> str:
        return (f"<Upit id={self.id:#06x} {self.ime!r} "
                f"{IME_TIPA.get(self.tip, self.tip)}>")


def parsiraj_upit(podaci: bytes) -> Upit:
    if len(podaci) < 12:
        raise DnsGreska("kraci od DNS zaglavlja")
    id_, zastavice, qd, an, ns, ar = struct.unpack(">HHHHHH", podaci[:12])
    if zastavice & 0x8000:
        raise DnsGreska("paket je odgovor, ne upit")
    if qd != 1:
        raise DnsGreska(f"podrzan je tocno jedan upit u paketu (qdcount={qd})")
    ime, poz = dekodiraj_ime(podaci, 12)
    if poz + 4 > len(podaci):
        raise DnsGreska("skraceno pitanje")
    tip, klasa = struct.unpack(">HH", podaci[poz:poz + 4])
    poz += 4
    opt = TIP_OPT in _tipovi_dodatnih(podaci, poz, an, ns, ar)
    return Upit(id_, zastavice, ime, tip, klasa, podaci, poz - 12, opt)


def _tipovi_dodatnih(podaci: bytes, poz: int, an: int, ns: int, ar: int) -> set[int]:
    """Tipovi zapisa iza pitanja. Neuspjeh citanja NIJE greska upita."""
    tipovi: set[int] = set()
    try:
        for _ in range(an + ns + ar):
            _ime, poz = dekodiraj_ime(podaci, poz)
            if poz + 10 > len(podaci):
                return tipovi
            tip, _klasa, _ttl, rdlen = struct.unpack(">HHIH", podaci[poz:poz + 10])
            tipovi.add(tip)
            poz += 10 + rdlen
    except DnsGreska:
        pass
    return tipovi


# =============================================================================
# Odgovori
# =============================================================================
def _zaglavlje(upit: Upit, rcode: int, an: int, aa: bool = True) -> bytes:
    zastavice = 0x8000 | (upit.zastavice & 0x0100) | (rcode & 0x0F)
    if aa:
        zastavice |= 0x0400                       # AA — dnkd je autoritativan za .dnk
    return struct.pack(">HHHHHH", upit.id, zastavice, 1, an, 0, 0)


def _pitanje(upit: Upit) -> bytes:
    return upit.sirovo[12:12 + upit.duzina_pitanja]


def _pokazivac_na_pitanje() -> bytes:
    return b"\xc0\x0c"                            # ime iz pitanja je na offsetu 12


def odgovor_a(upit: Upit, ip: str, ttl: int) -> bytes:
    okteti = [int(o) for o in ip.split(".")]
    if len(okteti) != 4 or any(not 0 <= o <= 255 for o in okteti):
        raise DnsGreska(f"nije IPv4 adresa: {ip!r}")
    rr = (_pokazivac_na_pitanje() + struct.pack(">HHIH", TIP_A, KLASA_IN, max(1, int(ttl)), 4)
          + bytes(okteti))
    return _zaglavlje(upit, RCODE_NOERROR, 1) + _pitanje(upit) + rr


def odgovor_txt(upit: Upit, dijelovi: list[str], ttl: int) -> bytes:
    rdata = bytearray()
    for dio in dijelovi:
        sirovo = dio.encode("utf-8")
        if len(sirovo) > 255:
            raise DnsGreska("TXT dio dulji od 255 bajtova — koristi Pelud.txt_dijelovi()")
        rdata.append(len(sirovo))
        rdata += sirovo
    rr = (_pokazivac_na_pitanje() + struct.pack(">HHIH", TIP_TXT, KLASA_IN,
                                               max(1, int(ttl)), len(rdata)) + bytes(rdata))
    paket = _zaglavlje(upit, RCODE_NOERROR, 1) + _pitanje(upit) + rr
    if len(paket) > MAX_UDP:
        # TC: klijent ponavlja preko TCP-a. Nikad okrnjeni zapis bez zastavice —
        # odrezan PELUD bi izgledao kao neispravan potpis (poruka bi imenovala
        # krivi uzrok).
        glava = bytearray(paket[:12])
        glava[2] |= 0x02
        return bytes(glava) + paket[12:]
    return paket


def odgovor_prazan(upit: Upit, rcode: int = RCODE_NOERROR) -> bytes:
    """NOERROR bez odgovora (NODATA) — ime postoji, taj tip ne."""
    return _zaglavlje(upit, rcode, 0) + _pitanje(upit)


def odgovor_greska(upit: Upit, rcode: int) -> bytes:
    return _zaglavlje(upit, rcode, 0, aa=(rcode == RCODE_NXDOMAIN)) + _pitanje(upit)


def odgovor_formerr(sirovo: bytes) -> bytes:
    """FORMERR na paket koji se nije dao procitati — zadrzi samo ID."""
    id_ = struct.unpack(">H", sirovo[:2])[0] if len(sirovo) >= 2 else 0
    return struct.pack(">HHHHHH", id_, 0x8001, 0, 0, 0, 0)


# =============================================================================
# Izlazni upit (za provjeru suglasnosti s javnim DNS-om)
# =============================================================================
def izgradi_upit(ime: str, tip: int, rd: bool = True) -> tuple[int, bytes]:
    id_ = random.SystemRandom().randrange(0, 0x10000)
    zastavice = 0x0100 if rd else 0
    return id_, (struct.pack(">HHHHHH", id_, zastavice, 1, 0, 0, 0)
                 + kodiraj_ime(ime) + struct.pack(">HH", tip, KLASA_IN))


def parsiraj_odgovor(podaci: bytes, ocekivani_id: int | None = None) -> dict:
    """{'rcode', 'tc', 'ime', 'tip', 'zapisi': [(tip, rdata_bytes)]}"""
    if len(podaci) < 12:
        raise DnsGreska("odgovor kraci od zaglavlja")
    id_, zastavice, qd, an, _ns, _ar = struct.unpack(">HHHHHH", podaci[:12])
    if not zastavice & 0x8000:
        raise DnsGreska("paket nije odgovor")
    if ocekivani_id is not None and id_ != ocekivani_id:
        raise DnsGreska("ID odgovora ne odgovara upitu — odbijeno")
    poz = 12
    ime, tip = "", 0
    for i in range(qd):
        ime_i, poz = dekodiraj_ime(podaci, poz)
        if poz + 4 > len(podaci):
            raise DnsGreska("skraceno pitanje u odgovoru")
        tip_i, _klasa = struct.unpack(">HH", podaci[poz:poz + 4])
        poz += 4
        if i == 0:
            ime, tip = ime_i, tip_i
    zapisi: list[tuple[int, bytes]] = []
    for _ in range(an):
        _ime, poz = dekodiraj_ime(podaci, poz)
        if poz + 10 > len(podaci):
            raise DnsGreska("skraceni zapis u odgovoru")
        tip_z, _klasa, _ttl, rdlen = struct.unpack(">HHIH", podaci[poz:poz + 10])
        poz += 10
        if poz + rdlen > len(podaci):
            raise DnsGreska("rdata izlazi izvan paketa")
        zapisi.append((tip_z, podaci[poz:poz + rdlen]))
        poz += rdlen
    return {"rcode": zastavice & 0x0F, "tc": bool(zastavice & 0x0200),
            "ime": ime, "tip": tip, "zapisi": zapisi}


def txt_iz_rdata(rdata: bytes) -> str:
    """Spoji <character-string> dijelove jednog TXT zapisa u jedan tekst."""
    out, poz = [], 0
    while poz < len(rdata):
        duzina = rdata[poz]
        poz += 1
        if poz + duzina > len(rdata):
            raise DnsGreska("TXT dio izlazi izvan rdata")
        out.append(rdata[poz:poz + duzina].decode("utf-8", "replace"))
        poz += duzina
    return "".join(out)


def a_iz_rdata(rdata: bytes) -> str:
    if len(rdata) != 4:
        raise DnsGreska("A rdata mora biti 4 bajta")
    return ".".join(str(b) for b in rdata)
