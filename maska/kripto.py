#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""MASKA kripto sloj — Ed25519 (potpis + VERIFIKACIJA) i X25519, stdlib only.

Zasto ovaj modul postoji odvojeno od eho6_node.py:
  eho6_node.py je namjerno JEDNA datoteka (curl | bash instalacija, Termux ARM)
  i ima samo sign+pubkey. dnkd (F2) mora VERIFICIRATI tudji potpis, a toga u
  postojecem kodu NEMA. Duplikacija je svjesna: eho6_node.py se ne prepisuje
  (ostaje njegov ugovor jedne datoteke), a ovaj modul je kanonski od sada.

Ed25519 je pisan po RFC 8032 referentnoj konstrukciji u prosirenim (extended)
koordinatama — bez modularne inverzije u petlji, jer afina varijanta iz
eho6_node.py radi dvije inverzije po sabiranju, sto verifikaciju (dva
skalarna mnozenja) cini ~3x skupljom nego sto treba za DNS put.

Dokaz ispravnosti: tests/test_kripto.py provjerava RFC 8032 sec. 7.1 vektore
(Ed25519) i RFC 7748 sec. 6.1 vektore (X25519), te medjuoperativnost s
potpisom koji generira eho6_node.ed25519_sign.

NIJE post-kvantno. ML-DSA-65 u ovom stacku NE POSTOJI (izmjereno: grep po
/var/www/genesis/core nema ni jedan pogodak). Zato PELUD zapis nosi polje
alg= i odbija sve osim poznatih vrijednosti — kad ML-DSA-65 stigne, mijenja se
implementacija ovdje i vrijednost alg=, ne format zapisa.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets

# =============================================================================
# Ed25519 (RFC 8032), prosirene koordinate
# =============================================================================
P = 2**255 - 19
Q = 2**252 + 27742317777372353535851937790883648493

_D = -121665 * pow(121666, P - 2, P) % P
_SQRT_M1 = pow(2, (P - 1) // 4, P)


def _inv(x: int) -> int:
    return pow(x, P - 2, P)


def _sha512(m: bytes) -> bytes:
    return hashlib.sha512(m).digest()


def _sha512_modq(m: bytes) -> int:
    return int.from_bytes(_sha512(m), "little") % Q


def _tocka_saberi(A, B):
    """Unificirano sabiranje u (X, Y, Z, T), T = XY/Z."""
    a = (A[1] - A[0]) * (B[1] - B[0]) % P
    b = (A[1] + A[0]) * (B[1] + B[0]) % P
    c = 2 * A[3] * B[3] * _D % P
    d = 2 * A[2] * B[2] % P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % P, g * h % P, f * g % P, e * h % P)


def _tocka_mnozi(s: int, A):
    R = (0, 1, 1, 0)  # neutralni element
    while s > 0:
        if s & 1:
            R = _tocka_saberi(R, A)
        A = _tocka_saberi(A, A)
        s >>= 1
    return R


def _tocka_jednake(A, B) -> bool:
    if (A[0] * B[2] - B[0] * A[2]) % P != 0:
        return False
    if (A[1] * B[2] - B[1] * A[2]) % P != 0:
        return False
    return True


def _g_tocka():
    y = 4 * _inv(5) % P
    x = _vrati_x(y, 0)
    return (x, y, 1, x * y % P)


def _vrati_x(y: int, predznak: int):
    if y >= P:
        return None
    x2 = (y * y - 1) * _inv(_D * y * y + 1) % P
    if x2 == 0:
        return None if predznak else 0
    x = pow(x2, (P + 3) // 8, P)
    if (x * x - x2) % P != 0:
        x = x * _SQRT_M1 % P
    if (x * x - x2) % P != 0:
        return None
    if (x & 1) != predznak:
        x = P - x
    return x


def _sazmi(A) -> bytes:
    zinv = _inv(A[2])
    x = A[0] * zinv % P
    y = A[1] * zinv % P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def _rasiri(s: bytes):
    if len(s) != 32:
        return None
    y = int.from_bytes(s, "little")
    predznak = y >> 255
    y &= (1 << 255) - 1
    x = _vrati_x(y, predznak)
    if x is None:
        return None
    return (x, y, 1, x * y % P)


_G = _g_tocka()


def _tajna_rasiri(sk32: bytes):
    if len(sk32) != 32:
        raise ValueError("Ed25519 tajni kljuc mora biti tocno 32 bajta")
    h = _sha512(sk32)
    a = bytearray(h[:32])
    a[0] &= 248
    a[31] &= 127
    a[31] |= 64
    return int.from_bytes(a, "little"), h[32:]


def ed25519_pubkey(sk32: bytes) -> bytes:
    a, _ = _tajna_rasiri(sk32)
    return _sazmi(_tocka_mnozi(a, _G))


def ed25519_sign(sk32: bytes, poruka: bytes) -> bytes:
    a, prefiks = _tajna_rasiri(sk32)
    A = _sazmi(_tocka_mnozi(a, _G))
    r = _sha512_modq(prefiks + poruka)
    R = _sazmi(_tocka_mnozi(r, _G))
    h = _sha512_modq(R + A + poruka)
    s = (r + h * a) % Q
    return R + s.to_bytes(32, "little")


def ed25519_verify(pk32: bytes, potpis: bytes, poruka: bytes) -> bool:
    """True samo za matematicki valjan potpis. Nikad iznimka — kvar je False.

    Odbija ne-kanonski S (>= Q) jer bi inace isti potpis imao vise valjanih
    kodiranja (malleability); PELUD zapis se hashira i broji u lanac, pa dva
    razlicita bajt-niza za istu tvrdnju nisu prihvatljiva.
    """
    if not isinstance(pk32, (bytes, bytearray)) or len(pk32) != 32:
        return False
    if not isinstance(potpis, (bytes, bytearray)) or len(potpis) != 64:
        return False
    A = _rasiri(bytes(pk32))
    if A is None:
        return False
    Rs = bytes(potpis[:32])
    R = _rasiri(Rs)
    if R is None:
        return False
    S = int.from_bytes(potpis[32:], "little")
    if S >= Q:
        return False
    h = _sha512_modq(Rs + bytes(pk32) + poruka)
    return _tocka_jednake(_tocka_mnozi(S, _G), _tocka_saberi(R, _tocka_mnozi(h, A)))


def ed25519_novi_kljuc() -> tuple[bytes, bytes]:
    sk = secrets.token_bytes(32)
    return sk, ed25519_pubkey(sk)


# =============================================================================
# X25519 (RFC 7748) — za WireGuard kljuceve u RIZOM generatoru (F3)
# =============================================================================
_A24 = 121665


def _cswap(zamijeni: int, x2: int, x3: int):
    """Uslovna zamjena bez grananja po tajnom bitu (zamijeni je 0 ili 1)."""
    lazni = (x2 - x3) * zamijeni % P
    return (x2 - lazni) % P, (x3 + lazni) % P


def x25519(skalar32: bytes, u32: bytes) -> bytes:
    """Montgomery ljestve. Vraca 32 bajta little-endian (WireGuard kodiranje)."""
    if len(skalar32) != 32 or len(u32) != 32:
        raise ValueError("X25519 trazi 32-bajtni skalar i 32-bajtnu u-koordinatu")
    k = bytearray(skalar32)
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    kk = int.from_bytes(k, "little")
    x1 = int.from_bytes(u32, "little") & ((1 << 255) - 1)

    x2, z2, x3, z3, zamijeni = 1, 0, x1, 1, 0
    for t in range(254, -1, -1):
        kt = (kk >> t) & 1
        zamijeni ^= kt
        x2, x3 = _cswap(zamijeni, x2, x3)
        z2, z3 = _cswap(zamijeni, z2, z3)
        zamijeni = kt

        a = (x2 + z2) % P
        aa = a * a % P
        b = (x2 - z2) % P
        bb = b * b % P
        e = (aa - bb) % P
        c = (x3 + z3) % P
        d = (x3 - z3) % P
        da = d * a % P
        cb = c * b % P
        x3 = pow((da + cb) % P, 2, P)
        z3 = x1 * pow((da - cb) % P, 2, P) % P
        x2 = aa * bb % P
        z2 = e * ((aa + _A24 * e) % P) % P

    x2, x3 = _cswap(zamijeni, x2, x3)
    z2, z3 = _cswap(zamijeni, z2, z3)
    return (x2 * _inv(z2) % P).to_bytes(32, "little")


_X25519_BAZA = (9).to_bytes(32, "little")


def x25519_pubkey(sk32: bytes) -> bytes:
    return x25519(sk32, _X25519_BAZA)


def x25519_novi_kljuc() -> tuple[bytes, bytes]:
    """WireGuard-kompatibilan par (privatni, javni). Isti izlaz kao `wg genkey`."""
    sk = bytearray(secrets.token_bytes(32))
    sk[0] &= 248
    sk[31] &= 127
    sk[31] |= 64
    sk = bytes(sk)
    return sk, x25519_pubkey(sk)


# =============================================================================
# Pomocno
# =============================================================================
def jednaki_bajtovi(a: bytes, b: bytes) -> bool:
    """Usporedba u konstantnom vremenu — potpisi i hashevi se ne uporedjuju s ==."""
    return hmac.compare_digest(bytes(a), bytes(b))


def sha3(podaci: bytes) -> str:
    """SHA3-256 hex — isti hash koji Genesis lanac koristi za body_sha."""
    return hashlib.sha3_256(podaci).hexdigest()
