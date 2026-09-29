# Analiza 10 dana rada flote Genesis (18.–28.09.2026.) — javna verzija

> Pročišćena verzija: bez tajni, bez osobnih i obiteljskih dokumenata i **bez pojedinosti otvorenih sigurnosnih nalaza** (oni su u privatnoj verziji kod vlasnika projekta). Ovo je **čitanje izvještaja, a ne mjerenje**: brojke su citirane s oznakom atoma lanca (`cNNNN`) iz kojeg potječu.

## Otvorene odluke vlasnika (WIP = 3)
1. **Klasa ključeva i tajni** — jedan registar potpisnih ključeva flote i odluka gdje žive tajni ključevi.
2. **Karantena krivih zapisa u replikama** — uzrok je nađen 26.9., a popravak čeka odobrenje.
3. **Rađanje potpisanih prstenova na računu (N1) u produkciji** — preporuka: tek nakon točke 1.

## 0. Opseg
| | |
|---|---|
| Izvještaja (`.md`) | 215, od toga **180 jedinstvenih** po sha256 |
| Korpus | 13.555 redaka, pročitan u cijelosti |
| Lanac u razdoblju | ~c6050 → c8611, **~2.560 atoma u 10 dana** |
| Paralelnih sesija-autora | najmanje 5 |

## 1. Vremenska crta
| Datum | Glavni događaji |
|---|---|
| 18.–19.9. | Registar uređaja; backup flote nije radio 7 dana → popravljen (c6060). Javna ploča napretka: 32 DOKAZANO, **U_POGONU 0** (c6132). |
| 20.9. | **EHO-9 v0** — deterministički sudac, dvije implementacije (c6190). Šira „Fuzija" zamrznuta. |
| 22.9. | **PZ-001** zbirni Merkle pečat lanca + RFC 3161 žig (c6264). Digigraf chat D0–D5 zatvoren. **EHO-9 sudi fiskalni račun u fenix-v4** (c6445), usklađivanje 7471/7471. |
| 23.9. | **PZ-003**: Zrno nosi presudu, replay bez baze 14/14 (c6534). |
| 24.9. | Verifikacija dva tjedna: 23 skupine DRŽE. EHOX: teorija idealnog sustava (Trgovac · Sudac · Pečat), pravila gubitka. Dijagnoza „sjekira i držalica". |
| 24.–25.9. | **DNK sloj D1–D5** (presude s hashom koda, kanon koda 2-od-3, tkanje segmenata, obnova 3-od-8 bez glavnog pružatelja). **Pečat replikacije P1–P8.** |
| 26.9. | Nađen uzrok krivih zapisa u replikama. Memio B0: 3 kopije na korisničkom hardveru (c8193). fenix-v4 chat popravljen (c8098). |
| 27.9. | 4D kod lab 7/8 (c8318); Rust jezgra; EHO v2 u fenix-v4; prvi pravi mobitel čita kod (c8472). Upute v2 → Protokol rada 30 pravila. |
| 28.9. | H12–H15 (c8500–c8561); **bankovna aplikacija složila nalog iz našeg koda**; popravak stranica iznajmljivača, 60 → 0 kvarova (c8554); zamjena procurjelih tokena (c8599). |

## 2. Što DRŽI
- EHO-9 sudi fiskalni račun u produkciji (c6445); golden `2df827b9…` 76/76, izmjereno ponovno 28.9.
- Zrno: replay bez baze; „potpis dokazuje TKO, determinizam ŠTO" (c6534).
- Zbirni pečat + žig (c6264); pečat replikacije, 50/50 podmetanja odbijeno.
- Kanon koda 2-od-3 prvi put u stvarnom radu zaustavio nepotpisanu promjenu (c7773).
- Domar: autonomni popravci; oluja alarma 1.072 → ~1 dnevno.
- Popravci produkcije uz puni protokol INTENT → .bak → test → produkcija → RACUN (c8098, c8554).
- 4D kod: bankovna aplikacija i opći čitač čitaju srce; naš čitač čita potpisani prsten s 0,1 % krivih bitova; podmetnuti IBAN → ALARM.
- **Kultura istine:** desetak tvrdnji povučeno ili ispravljeno, a presude nisu prekrojene (H9c 4,991× ostao PAD; H14a PAD upisan).

## 3. Što je PAD
- **Dodir sa stvarnim svijetom = 0:**
  - U_POGONU 0;
  - 0 stvarnih fiskalnih računa kroz sustav;
  - 0 stvarnih trgovina;
  - 0 dokumenata od stvarnog klijenta u arhivi;
  - pilot obitelji 0/20.
- Glavni lanac blokova je „šuma" (3.947 početaka); cNNNN atomi nisu ulančani hashom.
- Signal do čovjeka: kanal alarma nije isporučivao poruke 30 dana.
- EHO v2 integracija 5/10: nijedan ekran još ne prikazuje 4D kod.
- „NATO razina" kao šest mjerljivih stavki: 4 od 6 PAD → riječ se ne koristi dok ne prođu.
- **Sigurnosni dug:** 16 otvorenih stavki klase ključeva i tajni, najstarija od 5.9. (pojedinosti samo u privatnoj verziji).

## 4. Proturječja između sesija (izbor)
| Proturječje | Stanje |
|---|---|
| Plan EHO-10 pretpostavlja migraciju 0056, a produkcija je istog dana prešla na 0057 | po pravilu plana to je STOP, a nitko nije stao |
| „EHO v2 u produkciji" prema „0 ekrana ga koristi" | oboje točno; riječ precjenjuje |
| EHOX: „nikad ne drži tuđi novac" prema pričuvnom fondu; naknada u kodu ≠ naknada u prezentaciji | **otvoreno** |
| Dvije različite hipoteze pod oznakom H14 i dvije pod H15 | nema jedinstvenog brojača hipoteza |
| 20.9. upozorenje na Second-System Effect prema 28.9. širenju niza na 10 riječi | upozorenje nije opovrgnuto, nego zaboravljeno |
| Laboratorij: kocka od QR latica 9/9, pravi mobitel: 0 | novo pravilo: pravi mobitel je dio svakog kriterija |

## 5. Pet kutova
- **Ispod radara:** greške se ponavljaju u istoj klasi (mjerač mjeri prisutnost, a ne funkciju). Popravlja se pojedinačni slučaj, a klasa nikad. → Svaki novi mjerač mora imati protu-test.
- **U stranu:** prvi stvarni poslovni dokument u 10 dana nastao je izvan sustava, a upravo je on dao prvi stvarni dokaz. → Stvarni posao mora ići kroz sustav.
- **Dron:** ~2.560 atoma, 5 sesija i ~20 proizvoda, a dodir sa svijetom 0. → Strojni WIP i jedan brojač hipoteza.
- **Iza kulisa:** najslabiji sloj nisu algoritmi nego životni ciklus ključeva. → Preporuka ispod.
- **Druga strana medalje:** ova analiza čita dokumente koje su pisali isti agenti koji su radili posao. → Svaka stavka se prije akcije potvrđuje mjerenjem.

## 6. Preporuka
**Sedam dana samo ključevi:**
- nema nove serije hipoteza ni novog proizvoda dok klasa ključeva nije zatvorena dokazom;
- prvi korak je vlasnikov potpis kanona koda, treći glas u 2-od-3;
- zatim ide registar svih potpisnih ključeva flote.

Tek nakon toga dolazi prvi stvarni račun kroz sustav: **U_POGONU = 1**.

*Metoda: 180 jedinstvenih izvještaja, 18.–28.9.2026., pročitani u cijelosti. „Napisano", ne „testirano".*
