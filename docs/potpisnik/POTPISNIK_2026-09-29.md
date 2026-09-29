# Potpisnik: nacrt modula za potpisivanje (29.09.2026.)

Javna, pročišćena verzija. Prezentacija: `potpisnik_2026-09-29.html` (isto na `/prez/` na EU i ES).

## Stanje modula bilježnik (korak nula)
- Napisano: predlošci (HR/DE), narudžba i plaćanje, PDF akta s vodenim i vremenskim žigom, knjiga upisa (samo dopisivanje) i digitalna oporuka.
- Nije u pogonu: modul nikad nije pokrenut.
- Nedostaje zadnji korak: pravno valjan potpis stranaka i bilježnika.

## Načelo
Nitko ne potpisuje za drugoga. Svaki potpisnik potpisuje sam, vlastitim ključem ili kvalificiranim certifikatom, na razini eIDAS koju dokument traži (jednostavni, napredni ili kvalificirani). Bilježnik ostaje zakonski autoritet.

## Tri nove inovacije
1. **Čuvar identiteta:** slika potpisa bez kriptografskog potpisa iste osobe nije potpis.
2. **Suvlasnički prag k od n:** svi potpisuju isti otisak, paralelno, svaki sa svog uređaja.
3. **Lanac pristanka:** dokazivo je da su svi potpisali bajt-identičnu verziju. Kad se dokument promijeni, raniji potpisi prelaze u NEPOZNATO.

## Plan
| faza | sadržaj |
|---|---|
| F0 | korak nula (gotovo) |
| F1 | testna instanca, n ≥ 30 |
| F2 | napredni potpis: passkey + PAdES + RFC 3161 |
| F3 | prag i lanac pristanka |
| F4 | kvalificirani potpis preko kvalificiranog pružatelja |
| F5 | priključak bilježnika uz pravni pregled |

Svaka faza ima vlastiti test i zaseban DA.
