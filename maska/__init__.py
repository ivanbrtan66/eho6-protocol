# -*- coding: utf-8 -*-
"""MASKA — adresna indirekcija za suvereni internet (nastavak na c1570).

Moduli:
  kripto      Ed25519 (potpis + verifikacija) i X25519, stdlib only
  pelud       F1 — potpisani istekljivi locator zapis
  dns_wire    minimalni DNS kodek (RFC 1035), samo ono sto dnkd treba
  suglasnost  provjera razilazenja PELUD-a i javnog DNS-a (ograda protiv split-braina)
  godovi      dnevnik mjerenja lancan hashevima
  dnkd        F2 — lokalni razrjesitelj .dnk imena
  ui          upravljacka ploca dnkd-a

Faze F4 (direktan probod) i F5 (K-od-N oglasnik) NISU implementirane —
vidi docs/MASKA-FAZE.md.
"""
