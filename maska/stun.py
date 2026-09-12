#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""STUN (RFC 5389 / RFC 8489) — klijent, posluzitelj i klasifikacija NAT-a. stdlib only.

Cemu ovdje: prije ikakvog proboda (F4) mora se IZMJERITI moze li se uopce
probiti. Ta mjera je **ponasanje mapiranja NAT-a**:

  EIM (endpoint-independent mapping) — NAT daje ISTU vanjsku adresu:port bez
      obzira s kime govoris. Tvoja vanjska adresa koju vidi sidro EU vrijedi i
      za peera na drugom kontinentu -> probod je moguc.
  EDM (endpoint-dependent mapping, "simetricni" NAT) — NAT daje NOVI port po
      odredistu. Adresa koju vidi EU ne vrijedi ni za koga drugog -> probod NIJE
      moguc i sidro ostaje relej. To nije kvar nego cinjenica o mrezi.

Mjerenje trazi DVIJE tocke gledanja na RAZLICITIM IP adresama. Upravo to je
dvo-sidrena postava iz F3 (EU + NEW): sidra vec postoje, pa MASKA ne ovisi ni o
Googleovom ni o Cloudflareovom STUN-u — sidro vozi svoj. Suverenost nije poza:
javni STUN vidi tko i kada trazi probod, a to je metapodatak koji ne mora
napustiti flotu.

Ogranicenje mjerenja, receno odmah: jedno sidro NIJE dovoljno. S jednom tockom
gledanja rezultat je NEPOZNATO, nikad "vjerojatno EIM".

Implementirano: Binding Request/Response, XOR-MAPPED-ADDRESS, MAPPED-ADDRESS,
SOFTWARE, ERROR-CODE, RESPONSE-ORIGIN, OTHER-ADDRESS, FINGERPRINT (CRC32),
MESSAGE-INTEGRITY (HMAC-SHA1, kratkotrajne vjerodajnice).
NIJE implementirano: TURN (RFC 5766), ICE-ova puna nominacija (RFC 8445),
dugotrajne vjerodajnice s REALM/NONCE. Gdje toga nema, nema ni tvrdnje.
"""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import secrets
import socket
import socketserver
import struct
import threading
import time
import zlib
from dataclasses import dataclass, field

MAGICNI_KEKS = 0x2112A442
_KEKS_BAJTOVI = MAGICNI_KEKS.to_bytes(4, "big")

# Tipovi poruka
ZAHTJEV_VEZIVANJA = 0x0001
ODGOVOR_VEZIVANJA = 0x0101
GRESKA_VEZIVANJA = 0x0111

# Atributi
A_MAPPED_ADDRESS = 0x0001
A_USERNAME = 0x0006
A_MESSAGE_INTEGRITY = 0x0008
A_ERROR_CODE = 0x0009
A_UNKNOWN_ATTRIBUTES = 0x000A
A_XOR_MAPPED_ADDRESS = 0x0020
A_SOFTWARE = 0x8022
A_ALTERNATE_SERVER = 0x8023
A_FINGERPRINT = 0x8028
A_RESPONSE_ORIGIN = 0x802B
A_OTHER_ADDRESS = 0x802C

IME_ATRIBUTA = {
    A_MAPPED_ADDRESS: "MAPPED-ADDRESS", A_USERNAME: "USERNAME",
    A_MESSAGE_INTEGRITY: "MESSAGE-INTEGRITY", A_ERROR_CODE: "ERROR-CODE",
    A_UNKNOWN_ATTRIBUTES: "UNKNOWN-ATTRIBUTES", A_XOR_MAPPED_ADDRESS: "XOR-MAPPED-ADDRESS",
    A_SOFTWARE: "SOFTWARE", A_ALTERNATE_SERVER: "ALTERNATE-SERVER",
    A_FINGERPRINT: "FINGERPRINT", A_RESPONSE_ORIGIN: "RESPONSE-ORIGIN",
    A_OTHER_ADDRESS: "OTHER-ADDRESS",
}

PORODICA_IPV4 = 0x01
PORODICA_IPV6 = 0x02

SOFTVER = "maska-stun/1.0"
MAX_PORUKA = 1500
_OTISAK_XOR = 0x5354554E        # "STUN"

# RFC 5389 sec. 7.2.1: RTO 500 ms, udvostrucenje, do 7 slanja. Za rubni uredjaj
# koji ceka na probod to je predugo; tri slanja u ~1,75 s daju isti zakljucak.
ZADANI_RTO_S = 0.25
ZADANA_SLANJA = 3


class StunGreska(ValueError):
    """Poruka se ne moze procitati ili ne prolazi provjeru. Nikad tiho None."""


def _padding(n: int) -> int:
    return (4 - n % 4) % 4


@dataclass
class Poruka:
    tip: int
    tid: bytes = field(default_factory=lambda: secrets.token_bytes(12))
    atributi: list[tuple[int, bytes]] = field(default_factory=list)

    # -- citanje -----------------------------------------------------------
    def prvi(self, tip: int) -> bytes | None:
        for t, v in self.atributi:
            if t == tip:
                return v
        return None

    @property
    def nerazumljivi_obavezni(self) -> list[int]:
        """Nepoznati atributi < 0x8000 — RFC 5389: poruka se ne smije obradjivati."""
        return [t for t, _v in self.atributi if t < 0x8000 and t not in IME_ATRIBUTA]

    # -- pisanje -----------------------------------------------------------
    def dodaj(self, tip: int, vrijednost: bytes) -> "Poruka":
        self.atributi.append((tip, vrijednost))
        return self

    def dodaj_tekst(self, tip: int, tekst: str) -> "Poruka":
        return self.dodaj(tip, tekst.encode("utf-8"))

    def dodaj_adresu(self, tip: int, ip: str, port: int, xor: bool = False) -> "Poruka":
        return self.dodaj(tip, kodiraj_adresu(ip, port, self.tid, xor))

    def _tijelo(self, atributi) -> bytes:
        out = bytearray()
        for tip, vrijednost in atributi:
            out += struct.pack(">HH", tip, len(vrijednost)) + vrijednost
            out += b"\x00" * _padding(len(vrijednost))
        return bytes(out)

    def kodiraj(self, kljuc: bytes | None = None, otisak: bool = False) -> bytes:
        """Serijaliziraj. kljuc -> MESSAGE-INTEGRITY, otisak -> FINGERPRINT (u tom redu)."""
        atributi = list(self.atributi)
        tijelo = self._tijelo(atributi)

        if kljuc is not None:
            # duzina u zaglavlju mora VEC uracunati MESSAGE-INTEGRITY (4+20)
            privremeno = struct.pack(">HHI12s", self.tip, len(tijelo) + 24,
                                     MAGICNI_KEKS, self.tid) + tijelo
            mac = hmac.new(kljuc, privremeno, hashlib.sha1).digest()
            atributi.append((A_MESSAGE_INTEGRITY, mac))
            tijelo = self._tijelo(atributi)

        if otisak:
            privremeno = struct.pack(">HHI12s", self.tip, len(tijelo) + 8,
                                     MAGICNI_KEKS, self.tid) + tijelo
            crc = (zlib.crc32(privremeno) & 0xFFFFFFFF) ^ _OTISAK_XOR
            atributi.append((A_FINGERPRINT, struct.pack(">I", crc)))
            tijelo = self._tijelo(atributi)

        return struct.pack(">HHI12s", self.tip, len(tijelo), MAGICNI_KEKS, self.tid) + tijelo

    # -- provjere ----------------------------------------------------------
    def provjeri_integritet(self, kljuc: bytes, sirovo: bytes) -> bool:
        """HMAC-SHA1 preko poruke DO atributa MESSAGE-INTEGRITY (RFC 5389 sec. 15.4)."""
        mac = self.prvi(A_MESSAGE_INTEGRITY)
        if mac is None or len(mac) != 20:
            return False
        poz = _pozicija_atributa(sirovo, A_MESSAGE_INTEGRITY)
        if poz is None:
            return False
        do_tu = bytearray(sirovo[:poz])
        struct.pack_into(">H", do_tu, 2, poz - 20 + 24)   # duzina uklj. MI, bez FINGERPRINT-a
        ocekivan = hmac.new(kljuc, bytes(do_tu), hashlib.sha1).digest()
        return hmac.compare_digest(mac, ocekivan)

    def provjeri_otisak(self, sirovo: bytes) -> bool:
        vrijednost = self.prvi(A_FINGERPRINT)
        if vrijednost is None or len(vrijednost) != 4:
            return False
        poz = _pozicija_atributa(sirovo, A_FINGERPRINT)
        if poz is None:
            return False
        do_tu = bytearray(sirovo[:poz])
        struct.pack_into(">H", do_tu, 2, poz - 20 + 8)
        crc = (zlib.crc32(bytes(do_tu)) & 0xFFFFFFFF) ^ _OTISAK_XOR
        return struct.unpack(">I", vrijednost)[0] == crc

    # -- parsiranje --------------------------------------------------------
    @classmethod
    def parsiraj(cls, podaci: bytes) -> "Poruka":
        if len(podaci) < 20:
            raise StunGreska("kraca od STUN zaglavlja")
        if podaci[0] & 0xC0:
            raise StunGreska("prva dva bita moraju biti 0 (nije STUN)")
        tip, duzina, keks, tid = struct.unpack(">HHI12s", podaci[:20])
        if keks != MAGICNI_KEKS:
            raise StunGreska("magicni keks ne odgovara (nije STUN, RFC 5389)")
        if duzina % 4:
            raise StunGreska("duzina tijela mora biti umnozak 4")
        if len(podaci) < 20 + duzina:
            raise StunGreska(f"tijelo skraceno ({len(podaci) - 20} < {duzina})")
        poruka = cls(tip=tip, tid=tid)
        poz, kraj = 20, 20 + duzina
        while poz < kraj:
            if poz + 4 > kraj:
                raise StunGreska("skraceno zaglavlje atributa")
            a_tip, a_duz = struct.unpack(">HH", podaci[poz:poz + 4])
            poz += 4
            if poz + a_duz > kraj:
                raise StunGreska(f"atribut {a_tip:#06x} izlazi izvan poruke")
            poruka.atributi.append((a_tip, podaci[poz:poz + a_duz]))
            poz += a_duz + _padding(a_duz)
        return poruka


def _pozicija_atributa(sirovo: bytes, tip: int) -> int | None:
    """Pozicija zaglavlja atributa u sirovim bajtovima (za HMAC/CRC preko prefiksa)."""
    if len(sirovo) < 20:
        return None
    duzina = struct.unpack(">H", sirovo[2:4])[0]
    poz, kraj = 20, min(len(sirovo), 20 + duzina)
    while poz + 4 <= kraj:
        a_tip, a_duz = struct.unpack(">HH", sirovo[poz:poz + 4])
        if a_tip == tip:
            return poz
        poz += 4 + a_duz + _padding(a_duz)
    return None


def kodiraj_adresu(ip: str, port: int, tid: bytes, xor: bool = False) -> bytes:
    adresa = ipaddress.ip_address(ip)
    if adresa.version == 4:
        sirovo = adresa.packed
        porodica = PORODICA_IPV4
        maska = _KEKS_BAJTOVI
    else:
        sirovo = adresa.packed
        porodica = PORODICA_IPV6
        maska = _KEKS_BAJTOVI + tid
    if xor:
        port ^= (MAGICNI_KEKS >> 16)
        sirovo = bytes(a ^ b for a, b in zip(sirovo, maska))
    return struct.pack(">BBH", 0, porodica, port) + sirovo


def dekodiraj_adresu(vrijednost: bytes, tid: bytes, xor: bool = False) -> tuple[str, int]:
    if len(vrijednost) < 8:
        raise StunGreska("atribut adrese kraci od 8 bajtova")
    _nula, porodica, port = struct.unpack(">BBH", vrijednost[:4])
    sirovo = vrijednost[4:]
    if porodica == PORODICA_IPV4:
        if len(sirovo) != 4:
            raise StunGreska("IPv4 adresa mora biti 4 bajta")
        maska = _KEKS_BAJTOVI
    elif porodica == PORODICA_IPV6:
        if len(sirovo) != 16:
            raise StunGreska("IPv6 adresa mora biti 16 bajtova")
        maska = _KEKS_BAJTOVI + tid
    else:
        raise StunGreska(f"nepoznata porodica adresa: {porodica:#04x}")
    if xor:
        port ^= (MAGICNI_KEKS >> 16)
        sirovo = bytes(a ^ b for a, b in zip(sirovo, maska))
    return str(ipaddress.ip_address(sirovo)), port


# =============================================================================
# Klijent
# =============================================================================
@dataclass
class Refleks:
    """Sto jedno sidro vidi kao nasu vanjsku adresu — tvrdnja jedne tocke gledanja."""
    server: tuple[str, int]
    ip: str
    port: int
    rtt_ms: int
    izvor_odgovora: tuple[str, int] | None = None

    @property
    def adresa(self) -> tuple[str, int]:
        return (self.ip, self.port)


def otkrij(server: tuple[str, int], utor: socket.socket | None = None,
           rto_s: float = ZADANI_RTO_S, slanja: int = ZADANA_SLANJA,
           kljuc: bytes | None = None) -> Refleks:
    """Jedan Binding Request. Vraca Refleks ili dize StunGreska.

    utor: ako je dan, koristi se TAJ socket — bitno, jer se mapiranje mjeri za
    port s kojeg ce se STVARNO probijati. Mjerenje s drugog porta mjeri drugu
    stvar (tipicna tiha greska u ovakvim alatima).
    """
    svoj_utor = utor is None
    if svoj_utor:
        utor = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    zahtjev = Poruka(ZAHTJEV_VEZIVANJA).dodaj_tekst(A_SOFTWARE, SOFTVER)
    paket = zahtjev.kodiraj(kljuc=kljuc, otisak=True)
    try:
        cekanje = rto_s
        for pokusaj in range(1, slanja + 1):
            poc = time.monotonic()
            utor.sendto(paket, server)
            utor.settimeout(cekanje)
            while True:
                try:
                    podaci, izvor = utor.recvfrom(MAX_PORUKA)
                except (socket.timeout, TimeoutError):
                    break
                try:
                    odgovor = Poruka.parsiraj(podaci)
                except StunGreska:
                    continue                       # tudji paket na istom portu
                if odgovor.tid != zahtjev.tid:
                    continue
                rtt = int((time.monotonic() - poc) * 1000)
                return _iz_odgovora(odgovor, podaci, server, izvor, rtt, kljuc)
            cekanje *= 2
        raise StunGreska(f"{server[0]}:{server[1]} ne odgovara nakon {slanja} slanja")
    finally:
        if svoj_utor:
            utor.close()


def _iz_odgovora(odgovor: Poruka, sirovo: bytes, server, izvor, rtt: int,
                 kljuc: bytes | None) -> Refleks:
    if odgovor.tip == GRESKA_VEZIVANJA:
        kod = odgovor.prvi(A_ERROR_CODE) or b""
        broj = (kod[2] * 100 + kod[3]) if len(kod) >= 4 else 0
        opis = kod[4:].decode("utf-8", "replace") if len(kod) > 4 else ""
        raise StunGreska(f"STUN greska {broj} {opis}".strip())
    if odgovor.tip != ODGOVOR_VEZIVANJA:
        raise StunGreska(f"neocekivan tip poruke {odgovor.tip:#06x}")
    if odgovor.prvi(A_FINGERPRINT) is not None and not odgovor.provjeri_otisak(sirovo):
        raise StunGreska("FINGERPRINT ne odgovara — poruka je izmijenjena ili nije STUN")
    if kljuc is not None and not odgovor.provjeri_integritet(kljuc, sirovo):
        raise StunGreska("MESSAGE-INTEGRITY ne odgovara")
    nerazumljivi = odgovor.nerazumljivi_obavezni
    if nerazumljivi:
        raise StunGreska(f"odgovor nosi nerazumljive obavezne atribute: "
                         f"{[hex(t) for t in nerazumljivi]}")

    vrijednost = odgovor.prvi(A_XOR_MAPPED_ADDRESS)
    if vrijednost is not None:
        ip, port = dekodiraj_adresu(vrijednost, odgovor.tid, xor=True)
    else:
        vrijednost = odgovor.prvi(A_MAPPED_ADDRESS)
        if vrijednost is None:
            raise StunGreska("odgovor bez (XOR-)MAPPED-ADDRESS")
        ip, port = dekodiraj_adresu(vrijednost, odgovor.tid, xor=False)
    return Refleks(server=server, ip=ip, port=port, rtt_ms=rtt, izvor_odgovora=izvor)


# =============================================================================
# Klasifikacija NAT-a
# =============================================================================
@dataclass
class NatNalaz:
    """Tri stanja, kao svugdje u MASKI: EIM | EDM | NEPOZNATO."""
    ponasanje: str
    razlog: str = ""
    refleksi: list[Refleks] = field(default_factory=list)
    lokalni_port: int | None = None

    @property
    def probod_moguc(self) -> bool:
        """Samo EIM daje adresu koja vrijedi za trecu stranu."""
        return self.ponasanje == "EIM"

    def kao_dict(self) -> dict:
        return {
            "ponasanje": self.ponasanje,
            "razlog": self.razlog,
            "probod_moguc": self.probod_moguc,
            "lokalni_port": self.lokalni_port,
            "refleksi": [{"server": f"{r.server[0]}:{r.server[1]}",
                          "vidi": f"{r.ip}:{r.port}", "rtt_ms": r.rtt_ms}
                         for r in self.refleksi],
        }


def klasificiraj(serveri: list[tuple[str, int]], utor: socket.socket | None = None,
                 rto_s: float = ZADANI_RTO_S, slanja: int = ZADANA_SLANJA) -> NatNalaz:
    """Izmjeri ponasanje mapiranja s ISTOG socketa prema VISE sidara.

    Zahtijeva bar dva sidra na RAZLICITIM IP adresama. S jednim sidrom rezultat
    je NEPOZNATO — "vjerojatno EIM" nije mjerenje.
    """
    svoj_utor = utor is None
    if svoj_utor:
        utor = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        utor.bind(("0.0.0.0", 0))
    try:
        lokalni_port = utor.getsockname()[1]
        refleksi: list[Refleks] = []
        greske: list[str] = []
        for server in serveri:
            try:
                refleksi.append(otkrij(server, utor=utor, rto_s=rto_s, slanja=slanja))
            except StunGreska as e:
                greske.append(f"{server[0]}:{server[1]}: {e}")

        razliciti_serveri = {r.server[0] for r in refleksi}
        if not refleksi:
            return NatNalaz("NEPOZNATO", "ni jedno sidro nije odgovorilo: " + "; ".join(greske),
                            refleksi, lokalni_port)
        if len(razliciti_serveri) < 2:
            return NatNalaz("NEPOZNATO",
                            "potrebna su DVA sidra na razlicitim IP adresama; "
                            + (f"odgovorilo samo {len(razliciti_serveri)} "
                               f"({'; '.join(greske)})" if greske
                               else "dano je samo jedno"),
                            refleksi, lokalni_port)

        adrese = {r.adresa for r in refleksi}
        if len(adrese) == 1:
            return NatNalaz("EIM", "", refleksi, lokalni_port)
        portovi = {r.port for r in refleksi}
        ipovi = {r.ip for r in refleksi}
        detalj = ("razlicit port po odredistu" if len(portovi) > 1 else "") \
            + (" i razlicita IP adresa (viseizlazni NAT)" if len(ipovi) > 1 else "")
        return NatNalaz("EDM", f"simetricni NAT: {detalj.strip()} — probod nije moguc, "
                               f"sidro ostaje relej", refleksi, lokalni_port)
    finally:
        if svoj_utor:
            utor.close()


# =============================================================================
# Posluzitelj (vozi se na sidru — bez ovisnosti o javnom STUN-u)
# =============================================================================
class _StunHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        podaci, utor = self.request
        posluzitelj = self.server
        posluzitelj.brojac_upita += 1
        try:
            zahtjev = Poruka.parsiraj(podaci)
        except StunGreska:
            posluzitelj.brojac_smeca += 1
            return                                    # na ne-STUN se ne odgovara
        if zahtjev.tip != ZAHTJEV_VEZIVANJA:
            return
        nerazumljivi = zahtjev.nerazumljivi_obavezni
        if nerazumljivi:
            odgovor = Poruka(GRESKA_VEZIVANJA, tid=zahtjev.tid)
            odgovor.dodaj(A_ERROR_CODE, struct.pack(">HBB", 0, 4, 20) + b"Unknown Attribute")
            odgovor.dodaj(A_UNKNOWN_ATTRIBUTES,
                          b"".join(struct.pack(">H", t) for t in nerazumljivi))
            utor.sendto(odgovor.kodiraj(otisak=True), self.client_address)
            return
        klijent_ip, klijent_port = self.client_address[0], self.client_address[1]
        odgovor = Poruka(ODGOVOR_VEZIVANJA, tid=zahtjev.tid)
        odgovor.dodaj_adresu(A_XOR_MAPPED_ADDRESS, klijent_ip, klijent_port, xor=True)
        moj_ip, moj_port = posluzitelj.server_address[0], posluzitelj.server_address[1]
        odgovor.dodaj_adresu(A_RESPONSE_ORIGIN, moj_ip, moj_port)
        odgovor.dodaj_tekst(A_SOFTWARE, SOFTVER)
        if posluzitelj.drugo_sidro:
            odgovor.dodaj_adresu(A_OTHER_ADDRESS, *posluzitelj.drugo_sidro)
        utor.sendto(odgovor.kodiraj(kljuc=posluzitelj.kljuc, otisak=True), self.client_address)


class Posluzitelj(socketserver.ThreadingUDPServer):
    """STUN Binding posluzitelj. Ne pamti nista o klijentima — samo im kaze sto vidi."""
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, adresa: tuple[str, int], kljuc: bytes | None = None,
                 drugo_sidro: tuple[str, int] | None = None):
        super().__init__(adresa, _StunHandler)
        self.kljuc = kljuc
        self.drugo_sidro = drugo_sidro          # OTHER-ADDRESS: gdje je druga tocka gledanja
        self.brojac_upita = 0
        self.brojac_smeca = 0

    def pokreni_u_niti(self) -> threading.Thread:
        nit = threading.Thread(target=self.serve_forever, kwargs={"poll_interval": 0.05},
                               name="stun", daemon=True)
        nit.start()
        return nit


def _cli(argv: list[str]) -> int:
    import argparse
    import json
    ap = argparse.ArgumentParser(prog="python3 -m maska.stun",
                                 description="STUN: izmjeri ponasanje NAT-a ili vozi posluzitelj")
    pod = ap.add_subparsers(dest="naredba", required=True)

    m = pod.add_parser("izmjeri", help="klasificiraj NAT preko dva ili vise sidara")
    m.add_argument("--sidro", action="append", required=True, metavar="HOST:PORT",
                   help="STUN sidro; navesti bar DVA na razlicitim IP adresama")
    m.add_argument("--port", type=int, default=0,
                   help="lokalni UDP port s kojeg se mjeri (0 = bilo koji)")

    s = pod.add_parser("posluzuj", help="vozi STUN posluzitelj (na sidru)")
    s.add_argument("--slusaj", default="0.0.0.0:3478")
    s.add_argument("--drugo-sidro", default=None, metavar="HOST:PORT",
                   help="adresa druge tocke gledanja (OTHER-ADDRESS)")

    a = ap.parse_args(argv)

    def razdvoji(spoj: str) -> tuple[str, int]:
        host, _, port = spoj.rpartition(":")
        return host, int(port)

    if a.naredba == "izmjeri":
        utor = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        utor.bind(("0.0.0.0", a.port))
        try:
            nalaz = klasificiraj([razdvoji(x) for x in a.sidro], utor=utor)
        finally:
            utor.close()
        print(json.dumps(nalaz.kao_dict(), ensure_ascii=False, indent=1))
        if nalaz.ponasanje == "EIM":
            print("# EIM — probod je moguc; sidro treba samo za susret, ne za prijenos")
        elif nalaz.ponasanje == "EDM":
            print("# EDM (simetricni NAT) — probod NIJE moguc s ovog uredjaja; sidro ostaje relej")
        else:
            print("# NEPOZNATO — mjerenje nije dovrseno; NE tvrdi da probod radi")
        return 0 if nalaz.ponasanje != "NEPOZNATO" else 2

    host, port = razdvoji(a.slusaj)
    drugo = razdvoji(a.drugo_sidro) if a.drugo_sidro else None
    posluzitelj = Posluzitelj((host, port), drugo_sidro=drugo)
    print(f"STUN posluzitelj na {host}:{port}"
          + (f", OTHER-ADDRESS {drugo[0]}:{drugo[1]}" if drugo else ""))
    try:
        posluzitelj.serve_forever()
    except KeyboardInterrupt:
        print("zaustavljam...")
    finally:
        posluzitelj.server_close()
    return 0


if __name__ == "__main__":
    import sys
    raise SystemExit(_cli(sys.argv[1:]))
