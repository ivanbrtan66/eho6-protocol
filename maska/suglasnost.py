#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Provjera SUGLASNOSTI: kaze li javni DNS istu stvar kao PELUD (MASKA, ograda F2).

Nalaz koji ovo postoji da spriječi (pogled iza kulisa): cim dnkd pocne
razrjesavati imena, u sustavu postoje DVA imenika — javni DNS i PELUD iz sidra.
Onog dana kad kazu razlicitu stvar o istom imenu, dobio si tihi split-brain:
dio klijenata ide na staru lokaciju, dio na novu, oba puta vracaju HTTP 200, i
nijedan watchdog to ne vidi jer svaki mjeri svoj put. Isti razred kvara kao
a16 koji je 8 dana bio mrtav uz fasadu koja je vracala 200 (c2293).

Zato se suglasnost mjeri pri svakom razrjesenju, a ne "kasnije kad zatreba",
i razilazenje je ALARM — ne tiho preferiranje jednog izvora.

Cetiri stanja, nikad tiho True/False:
  SUGLASNO     — javno zrcalo nosi PELUD i tvrdi ISTO (pk + skup lokatora)
  NESUGLASNO   — zrcalo nosi PELUD i tvrdi DRUGO  -> ALARM
  NEMA_ZRCALA  — zrcalo nema _pelud TXT (DNS sloj iz c0967 je i dalje TODO) — nije kvar
  NEPOZNATO    — mjerenje samo nije uspjelo (timeout, nema nameservera)
"""
from __future__ import annotations

import socket
import struct
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

from . import dns_wire as dw
from .pelud import Pelud, PeludGreska, parsiraj

RESOLV_CONF = "/etc/resolv.conf"
PREFIKS_ZRCALA = "_pelud."
ZADANI_TIMEOUT_S = 3.0


@dataclass
class Nalaz:
    stanje: str                                # SUGLASNO | NESUGLASNO | NEMA_ZRCALA | NEPOZNATO
    razlog: str = ""
    zrcalo: str | None = None
    detalji: dict = field(default_factory=dict)

    @property
    def alarm(self) -> bool:
        return self.stanje == "NESUGLASNO"

    def kao_dict(self) -> dict:
        return {"stanje": self.stanje, "razlog": self.razlog,
                "zrcalo": self.zrcalo, "detalji": self.detalji}


def nameserveri(putanja: str = RESOLV_CONF) -> list[str]:
    """IPv4 nameserveri iz resolv.conf. Prazna lista je NEPOZNATO, ne greska."""
    out: list[str] = []
    try:
        for linija in Path(putanja).read_text(encoding="utf-8", errors="replace").splitlines():
            linija = linija.strip()
            if not linija.startswith("nameserver"):
                continue
            dijelovi = linija.split()
            if len(dijelovi) >= 2 and ":" not in dijelovi[1]:
                out.append(dijelovi[1])
    except OSError:
        return []
    return out


def _upit(ime: str, tip: int, ns: str, timeout: float) -> dict:
    """Jedan DNS upit prema jednom nameserveru. UDP, pa TCP ako je odgovor krnji."""
    id_, paket = dw.izgradi_upit(ime, tip)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        s.sendto(paket, (ns, 53))
        while True:
            podaci, izvor = s.recvfrom(4096)
            if izvor[0] == ns:                       # odbaci pakete s tudje adrese
                break
    odg = dw.parsiraj_odgovor(podaci, id_)
    if not odg["tc"]:
        return odg
    with socket.create_connection((ns, 53), timeout=timeout) as t:
        t.sendall(struct.pack(">H", len(paket)) + paket)
        glava = t.recv(2)
        if len(glava) < 2:
            raise dw.DnsGreska("TCP odgovor bez duzine")
        duzina = struct.unpack(">H", glava)[0]
        tijelo = b""
        while len(tijelo) < duzina:
            dio = t.recv(duzina - len(tijelo))
            if not dio:
                raise dw.DnsGreska("TCP odgovor prekinut")
            tijelo += dio
    return dw.parsiraj_odgovor(tijelo, id_)


def txt_zapisi(ime: str, ns_lista: list[str] | None = None,
               timeout: float = ZADANI_TIMEOUT_S) -> tuple[list[str] | None, str]:
    """(zapisi, razlog). None znaci NEPOZNATO — mjerenje palo, ne "nema zapisa"."""
    ns_lista = ns_lista or nameserveri()
    if not ns_lista:
        return None, "nema_nameservera_u_resolv_conf"
    zadnja_greska = ""
    for ns in ns_lista:
        try:
            odg = _upit(ime, dw.TIP_TXT, ns, timeout)
        except (OSError, socket.timeout, dw.DnsGreska) as e:
            zadnja_greska = f"{ns}: {type(e).__name__}: {e}"
            continue
        if odg["rcode"] == dw.RCODE_NXDOMAIN:
            return [], ""
        if odg["rcode"] != dw.RCODE_NOERROR:
            zadnja_greska = f"{ns}: {dw.IME_RCODE.get(odg['rcode'], odg['rcode'])}"
            continue
        return [dw.txt_iz_rdata(r) for t, r in odg["zapisi"] if t == dw.TIP_TXT], ""
    return None, zadnja_greska or "svi_nameserveri_pali"


def a_zapisi(ime: str, ns_lista: list[str] | None = None,
             timeout: float = ZADANI_TIMEOUT_S) -> tuple[list[str] | None, str]:
    ns_lista = ns_lista or nameserveri()
    if not ns_lista:
        return None, "nema_nameservera_u_resolv_conf"
    zadnja_greska = ""
    for ns in ns_lista:
        try:
            odg = _upit(ime, dw.TIP_A, ns, timeout)
        except (OSError, socket.timeout, dw.DnsGreska) as e:
            zadnja_greska = f"{ns}: {type(e).__name__}: {e}"
            continue
        if odg["rcode"] == dw.RCODE_NXDOMAIN:
            return [], ""
        if odg["rcode"] != dw.RCODE_NOERROR:
            zadnja_greska = f"{ns}: {dw.IME_RCODE.get(odg['rcode'], odg['rcode'])}"
            continue
        return [dw.a_iz_rdata(r) for t, r in odg["zapisi"] if t == dw.TIP_A], ""
    return None, zadnja_greska or "svi_nameserveri_pali"


def _hostovi(lokatori: list[str]) -> set[str]:
    return {(urlsplit(l).hostname or "").lower() for l in lokatori}


def provjeri(zapis: Pelud, javno_zrcalo: str | None,
             ns_lista: list[str] | None = None,
             timeout: float = ZADANI_TIMEOUT_S) -> Nalaz:
    """Usporedi PELUD iz sidra s onim sto javni DNS tvrdi o istom imenu."""
    if not javno_zrcalo:
        return Nalaz("NEMA_ZRCALA", "javno_zrcalo nije konfigurirano za ovo ime")

    ime_txt = PREFIKS_ZRCALA + javno_zrcalo.strip(".")
    zapisi, razlog = txt_zapisi(ime_txt, ns_lista, timeout)
    if zapisi is None:
        return Nalaz("NEPOZNATO", razlog or "txt_mjerenje_palo", javno_zrcalo)

    kandidati = [z for z in zapisi if z.strip().startswith("v=PELUD1 ")]
    if not kandidati:
        detalji = {"txt_nadjeno": len(zapisi)}
        a_lista, a_razlog = a_zapisi(javno_zrcalo, ns_lista, timeout)
        if a_lista is not None:
            detalji["a_zrcala"] = a_lista
            detalji["hostovi_lokatora"] = sorted(_hostovi(zapis.lokatori))
        elif a_razlog:
            detalji["a_razlog"] = a_razlog
        return Nalaz("NEMA_ZRCALA", f"{ime_txt} nema v=PELUD1 TXT zapis", javno_zrcalo, detalji)

    for tekst in kandidati:
        try:
            javni = parsiraj(tekst)
        except PeludGreska as e:
            return Nalaz("NESUGLASNO", f"javni PELUD se ne da procitati: {e}", javno_zrcalo,
                         {"sirovo": tekst[:300]})
        razlike = []
        if javni.ime != zapis.ime:
            razlike.append(f"ime {javni.ime} != {zapis.ime}")
        if javni.pk != zapis.pk:
            razlike.append("pk izdavatelja se razlikuje")
        if set(javni.lokatori) != set(zapis.lokatori):
            razlike.append("skup lokatora se razlikuje")
        if razlike:
            return Nalaz("NESUGLASNO", "; ".join(razlike), javno_zrcalo,
                         {"javni_loc": javni.lokatori, "sidro_loc": zapis.lokatori,
                          "javni_pk": javni.pk, "sidro_pk": zapis.pk,
                          "javna_visina": javni.visina, "sidro_visina": zapis.visina})
        return Nalaz("SUGLASNO", "", javno_zrcalo,
                     {"javna_visina": javni.visina, "sidro_visina": zapis.visina,
                      "javni_exp": javni.exp})
    return Nalaz("NEPOZNATO", "neocekivan tok provjere", javno_zrcalo)
