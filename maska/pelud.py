#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""PELUD — potpisani istekljivi locator zapis (MASKA faza F1).

Cemu: A-zapis je CINJENICA bez roka i bez autora — tko ga promijeni, promijenio
je istinu. PELUD je TVRDNJA s rokom i potpisom: "ime X je u trenutku visine
lanca H dosezljiv na lokatorima L, a ova tvrdnja vrijedi do exp". Statican
A-zapis ostaje samo kao jeftina, zamjenjiva ulaznica (Fasada, F-A) — stvarna
lokacija nikad nije u DNS-u (KLJUCNO_NACELO iz c1570).

Format je namjerno PROSIRENJE postojeceg Genesis Spore GENESIS1 DNS TXT zapisa
(c0967: "v=GENESIS1 ws=... gh=... ph=... ts=..."), dakle razmakom odvojeni
k=v parovi u jednom TXT stringu — ne novi binarni format:

  v=PELUD1 ime=<naziv.dnk> alg=ed25519 pk=<64hex> h=<visina> exp=<epoch>
  loc=<uri>|<uri> [ws=<32hex>] sig=<base64url-bez-padding>

Potpis pokriva TOCNO poznata polja u fiksnom redoslijedu (KANONSKI_RED), bez
sig. Nepoznata polja se ODBIJAJU (strogo), jer bi "ignoriraj nepoznato"
znacilo da napadac moze dodati polje koje citac buducnosti tumaci a potpis ga
ne pokriva.

STVARNA GRANICA OVE IMPLEMENTACIJE (ZAKON 46 — izraz mora odgovarati lancu):
alg=ed25519 je jedino sto ovdje postoji. ML-DSA-65 se u ovom stacku NE nalazi
(izmjereno grep-om po /var/www/genesis/core — nula pogodaka), pa je rezerviran
kao ime, a zapis s njim se ODBIJA s jasnim razlogom umjesto da se tiho
prihvati kao da je provjeren.
"""
from __future__ import annotations

import base64
import re
import time
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from . import kripto

VERZIJA = "PELUD1"
KANONSKI_RED = ("v", "ime", "alg", "pk", "h", "exp", "loc", "ws")
ALG_PODRZANI = ("ed25519",)
ALG_REZERVIRANI = ("ml-dsa-65", "ml-dsa-87")

PSEUDO_TLD = ".dnk"
LOC_ODVAJAC = "|"
LOC_SHEME = ("wg", "quic", "https", "http")
TXT_DIO_MAX = 255          # RFC 1035: jedan <character-string> u TXT rdata
MAX_VIJEK_S = 3600         # tvrdnja koja vrijedi dulje od sata nije "istekljiva"
DOPUSTENI_POMAK_S = 120    # tolerancija razilazenja satova izmedju cvorova
PREPORUCENI_TTL_S = 120

_RE_IME = re.compile(r"^(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+dnk\Z")
_RE_HEX64 = re.compile(r"^[0-9a-f]{64}\Z")
_RE_HEX32 = re.compile(r"^[0-9a-f]{32}\Z")


class PeludGreska(ValueError):
    """Zapis se ne moze procitati/izgraditi. Nikad tiho None."""


def _b64u(podaci: bytes) -> str:
    return base64.urlsafe_b64encode(podaci).decode().rstrip("=")


def _b64u_dekod(tekst: str) -> bytes:
    dopuna = "=" * (-len(tekst) % 4)
    try:
        return base64.urlsafe_b64decode(tekst + dopuna)
    except Exception as e:
        raise PeludGreska(f"sig nije valjan base64url: {e}") from e


def provjeri_ime(ime: str) -> str:
    ime = (ime or "").strip().lower()
    if not ime.endswith(PSEUDO_TLD):
        raise PeludGreska(f"ime mora zavrsavati na {PSEUDO_TLD}: {ime!r}")
    if not _RE_IME.match(ime):
        raise PeludGreska(f"ime nije valjano DNS ime pod {PSEUDO_TLD}: {ime!r}")
    return ime


def provjeri_lokator(lok: str) -> str:
    lok = (lok or "").strip()
    if not lok or " " in lok or LOC_ODVAJAC in lok:
        raise PeludGreska(f"lokator ne smije biti prazan ni sadrzavati razmak/'{LOC_ODVAJAC}': {lok!r}")
    dio = urlsplit(lok)
    if dio.scheme not in LOC_SHEME:
        raise PeludGreska(f"shema lokatora nije podrzana ({dio.scheme!r}); dopusteno: {LOC_SHEME}")
    if not dio.hostname:
        raise PeludGreska(f"lokator bez hosta: {lok!r}")
    try:
        port = dio.port
    except ValueError as e:
        raise PeludGreska(f"lokator ima neispravan port: {lok!r}") from e
    if dio.scheme in ("wg", "quic") and port is None:
        raise PeludGreska(f"{dio.scheme}:// lokator mora navesti port: {lok!r}")
    return lok


@dataclass
class Pelud:
    """Jedna potpisana tvrdnja o lokaciji jednog imena."""

    ime: str
    pk: str                                  # Ed25519 javni kljuc izdavatelja, 64 hex
    visina: int                              # visina Genesis lanca u trenutku izdavanja
    exp: int                                 # epoch sekunde — rok trajanja TVRDNJE
    lokatori: list[str] = field(default_factory=list)
    ws: str | None = None                    # weise3_id dokumenta koji tvrdnju objasnjava
    alg: str = "ed25519"
    sig: bytes | None = None

    # -- izgradnja ---------------------------------------------------------
    def __post_init__(self) -> None:
        self.ime = provjeri_ime(self.ime)
        self.alg = (self.alg or "").strip().lower()
        if self.alg in ALG_REZERVIRANI:
            raise PeludGreska(
                f"alg={self.alg} je REZERVIRAN, implementacija u ovom stacku ne postoji — "
                f"zapis se odbija umjesto da se tvrdi provjerenim")
        if self.alg not in ALG_PODRZANI:
            raise PeludGreska(f"alg nije podrzan: {self.alg!r}; podrzano: {ALG_PODRZANI}")
        self.pk = (self.pk or "").strip().lower()
        if not _RE_HEX64.match(self.pk):
            raise PeludGreska("pk mora biti 64 hex znaka (Ed25519 javni kljuc)")
        if not isinstance(self.visina, int) or self.visina < 0:
            raise PeludGreska("h (visina lanca) mora biti nenegativan cijeli broj")
        if not isinstance(self.exp, int) or self.exp <= 0:
            raise PeludGreska("exp mora biti epoch u sekundama")
        if not self.lokatori:
            raise PeludGreska("zapis bez lokatora nema smisla — loc mora imati bar jedan unos")
        self.lokatori = [provjeri_lokator(l) for l in self.lokatori]
        if self.ws is not None:
            self.ws = self.ws.strip().lower()
            if not _RE_HEX32.match(self.ws) and not _RE_HEX64.match(self.ws):
                raise PeludGreska("ws mora biti 32 ili 64 hex znaka (weise3_id)")

    @classmethod
    def izdaj(cls, ime: str, sk32: bytes, visina: int, lokatori: list[str],
              vijek_s: int = 600, ws: str | None = None, sada: float | None = None) -> "Pelud":
        """Napravi i POTPISE zapis. vijek_s je rok tvrdnje, ne DNS TTL."""
        if vijek_s <= 0 or vijek_s > MAX_VIJEK_S:
            raise PeludGreska(f"vijek_s mora biti u (0, {MAX_VIJEK_S}] — tvrdnja bez kratkog roka nije PELUD")
        sada = time.time() if sada is None else sada
        z = cls(ime=ime, pk=kripto.ed25519_pubkey(sk32).hex(), visina=int(visina),
                exp=int(sada) + int(vijek_s), lokatori=list(lokatori), ws=ws)
        z.potpisi(sk32)
        return z

    # -- kanonizacija i potpis --------------------------------------------
    def _polja(self) -> dict[str, str]:
        p = {
            "v": VERZIJA,
            "ime": self.ime,
            "alg": self.alg,
            "pk": self.pk,
            "h": str(self.visina),
            "exp": str(self.exp),
            "loc": LOC_ODVAJAC.join(self.lokatori),
        }
        if self.ws:
            p["ws"] = self.ws
        return p

    def kanonski(self) -> bytes:
        """Bajtovi koje potpis pokriva — fiksni red, jedan razmak, bez sig."""
        p = self._polja()
        return " ".join(f"{k}={p[k]}" for k in KANONSKI_RED if k in p).encode("utf-8")

    def potpisi(self, sk32: bytes) -> "Pelud":
        izveden = kripto.ed25519_pubkey(sk32).hex()
        if izveden != self.pk:
            raise PeludGreska("kljuc kojim potpisujes ne odgovara pk u zapisu")
        self.sig = kripto.ed25519_sign(sk32, self.kanonski())
        return self

    def txt(self) -> str:
        if self.sig is None:
            raise PeludGreska("zapis nije potpisan — nepotpisan PELUD se ne serijalizira")
        return self.kanonski().decode("utf-8") + " sig=" + _b64u(self.sig)

    def txt_dijelovi(self) -> list[str]:
        """TXT rdata u <=255-bajtnim dijelovima (RFC 1035). Spoji ih spoji_dijelove()."""
        sirovo = self.txt().encode("utf-8")
        return [sirovo[i:i + TXT_DIO_MAX].decode("utf-8")
                for i in range(0, len(sirovo), TXT_DIO_MAX)]

    # -- provjera ----------------------------------------------------------
    def provjeri(self, pinovani_pk: str | None, sada: float | None = None,
                 max_vijek_s: int = MAX_VIJEK_S,
                 dopusteni_pomak_s: int = DOPUSTENI_POMAK_S) -> tuple[bool, str]:
        """(valjan, razlog). razlog je "" samo kad je sve tocno.

        pinovani_pk je OBAVEZAN argument svijesti: potpis koji provjeravas
        kljucem IZ ISTOG zapisa ne dokazuje nista (napadac potpise svojim
        kljucem). None znaci izricito "bez pinovanja" i vraca razlog
        'pk_nije_pinovan' kao NEVALJAN — nikad tihi prolaz.
        """
        sada = time.time() if sada is None else sada
        if self.sig is None:
            return False, "nema_potpisa"
        if not pinovani_pk:
            return False, "pk_nije_pinovan"
        if (pinovani_pk or "").strip().lower() != self.pk:
            return False, "pk_ne_odgovara_pinovanom"
        if not kripto.ed25519_verify(bytes.fromhex(self.pk), self.sig, self.kanonski()):
            return False, "potpis_nevaljan"
        if self.exp <= sada - dopusteni_pomak_s:
            return False, f"istekao_prije_{int(sada - self.exp)}s"
        if self.exp > sada + max_vijek_s + dopusteni_pomak_s:
            return False, "exp_predaleko_u_buducnosti"
        return True, ""

    def preostalo_s(self, sada: float | None = None) -> int:
        sada = time.time() if sada is None else sada
        return int(self.exp - sada)

    def ttl_s(self, sada: float | None = None) -> int:
        """DNS TTL koji se smije posluziti: nikad dulji od ostatka tvrdnje."""
        return max(1, min(PREPORUCENI_TTL_S, self.preostalo_s(sada)))

    def lokatori_po_shemi(self, shema: str) -> list[str]:
        return [l for l in self.lokatori if urlsplit(l).scheme == shema]


def spoji_dijelove(dijelovi: list[str] | list[bytes]) -> str:
    """Spoji TXT <character-string> dijelove natrag u jedan zapis."""
    out = []
    for d in dijelovi:
        out.append(d.decode("utf-8", "strict") if isinstance(d, (bytes, bytearray)) else d)
    return "".join(out)


def parsiraj(tekst: str) -> Pelud:
    """Strogo citanje. Nepoznato polje, dvostruko polje ili visak razmaka = greska."""
    if not isinstance(tekst, str) or not tekst.strip():
        raise PeludGreska("prazan PELUD zapis")
    dijelovi = tekst.strip().split(" ")
    p: dict[str, str] = {}
    for d in dijelovi:
        if not d:
            raise PeludGreska("dvostruki razmak u zapisu — kanonski oblik ima tocno jedan")
        if "=" not in d:
            raise PeludGreska(f"dio zapisa nije k=v: {d!r}")
        k, v = d.split("=", 1)
        if k in p:
            raise PeludGreska(f"polje {k!r} ponovljeno — kanonski oblik ga ima tocno jednom")
        p[k] = v

    dopusteno = set(KANONSKI_RED) | {"sig"}
    nepoznata = sorted(set(p) - dopusteno)
    if nepoznata:
        raise PeludGreska(f"nepoznata polja odbijena (potpis ih ne pokriva): {nepoznata}")
    if p.get("v") != VERZIJA:
        raise PeludGreska(f"v mora biti {VERZIJA}, dobiveno {p.get('v')!r}")
    for obavezno in ("ime", "alg", "pk", "h", "exp", "loc", "sig"):
        if obavezno not in p:
            raise PeludGreska(f"nedostaje obavezno polje {obavezno!r}")
    try:
        visina = int(p["h"])
        exp = int(p["exp"])
    except ValueError as e:
        raise PeludGreska(f"h i exp moraju biti cijeli brojevi: {e}") from e

    z = Pelud(ime=p["ime"], pk=p["pk"], visina=visina, exp=exp,
              lokatori=p["loc"].split(LOC_ODVAJAC), ws=p.get("ws"), alg=p["alg"])
    z.sig = _b64u_dekod(p["sig"])
    if len(z.sig) != 64:
        raise PeludGreska(f"Ed25519 potpis mora biti 64 bajta, dobiveno {len(z.sig)}")
    # kanonizacija mora biti reverzibilna: tekst koji si dobio == tekst koji bi izdao
    if z.txt() != tekst.strip():
        raise PeludGreska("zapis nije u kanonskom obliku (redoslijed polja ili razmaci)")
    return z


# =============================================================================
# CLI — da se zapis moze izdati i provjeriti bez pisanja ijedne linije koda
# =============================================================================
def _cli(argv: list[str]) -> int:
    import argparse
    import pathlib

    ap = argparse.ArgumentParser(prog="python3 -m maska.pelud",
                                 description="PELUD zapis: izdaj / provjeri")
    pod = ap.add_subparsers(dest="naredba", required=True)

    i = pod.add_parser("izdaj", help="izdaj potpisani PELUD zapis")
    i.add_argument("--ime", required=True, help="npr. medijapos.dnk")
    i.add_argument("--kljuc", required=True, help="datoteka s 32-bajtnim Ed25519 tajnim kljucem")
    i.add_argument("--visina", required=True, type=int, help="visina Genesis lanca")
    i.add_argument("--loc", required=True, action="append",
                   help="lokator (moze se ponoviti), npr. wg://1.2.3.4:51820/<pk>")
    i.add_argument("--vijek", type=int, default=600, help=f"rok tvrdnje u s (max {MAX_VIJEK_S})")
    i.add_argument("--ws", default=None, help="weise3_id dokumenta (opcionalno)")

    v = pod.add_parser("provjeri", help="provjeri zapis protiv pinovanog kljuca")
    v.add_argument("--txt", required=True, help="cijeli PELUD zapis u jednom argumentu")
    v.add_argument("--pk", required=True, help="pinovani javni kljuc (64 hex)")

    a = ap.parse_args(argv)
    try:
        if a.naredba == "izdaj":
            sk = pathlib.Path(a.kljuc).read_bytes()[:32]
            if len(sk) != 32:
                print("GRESKA: kljuc mora imati tocno 32 bajta")
                return 2
            z = Pelud.izdaj(a.ime, sk, a.visina, a.loc, vijek_s=a.vijek, ws=a.ws)
            print(z.txt())
            for n, dio in enumerate(z.txt_dijelovi(), 1):
                print(f"# TXT dio {n}: {dio}")
            print(f"# vrijedi do {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(z.exp))}"
                  f" ({z.preostalo_s()} s), preporuceni DNS TTL {z.ttl_s()} s")
            return 0

        z = parsiraj(a.txt)
        valjan, razlog = z.provjeri(a.pk)
        print(f"{'VALJAN' if valjan else 'NEVALJAN'}: ime={z.ime} visina={z.visina} "
              f"lokatori={z.lokatori} preostalo={z.preostalo_s()}s"
              + (f" razlog={razlog}" if razlog else ""))
        return 0 if valjan else 1
    except PeludGreska as e:
        print(f"GRESKA: {e}")
        return 2


if __name__ == "__main__":
    import sys
    raise SystemExit(_cli(sys.argv[1:]))
