# QR4D — matematičko rješenje fizičkog ograničenja gustoće točkica

> Status: TEORIJA (pred-registracija hipoteza, pravilo 19). Nijedna brojka nije izmjerena u ovoj sesiji.
> Utemeljeno na lancu (git log atomi c8386–c8551, c8468, c8535), ne na otvaranju živog `qr4d` modula.
> Korak Nula nad kodom (dolje, §7) je uvjet prije bilo koje tvrdnje „radi / X× bolje".

---

## 1. Problem, precizno

Fizičko ograničenje QR4D-a nije „premalo mjesta", nego **kapacitet kanala po jedinici površine**:

```
C_ukupno  =  A · b_po_točki · r
   A            = broj točkica koje fizički stanu (papir, tinta, veličina modula)
   b_po_točki   = bita po točki (fizički kanal: prisutnost, veličina, praznina, položaj)
   r            = pouzdanost čitanja (kamera + tinta + pokret)
```

Lanac već napada `b_po_točki` fizički: točka/praznina (H12), velika/mala (T), 4 dimenzije u istoj površini. To je **fizički** put i ima strop — c8535 mjeri „srce usko grlo, 50 % optimum, oblik ne pomaže". Kad fizika stane, ostaje **matematika**.

Ključni uvid: **strop `C_ukupno` je informacijsko-teorijski i ne može se prevariti** — OSIM ako smanjiš koliko informacije uopće mora proći kroz fizički kanal. A upravo to nam offline verifikacija omogućuje.

## 2. Središnja teza — čitač NIJE prazna ploča

Offline verifikacija riješena znači: uređaj u ruci **već drži sidro** — javni ključ, lanac certifikata i **repliciran DokArh lanac** (Z3, Z17). To u teoriji informacija nije sitnica, to je **korelirana bočna informacija Y na strani dekodera**.

**Slepian–Wolf / Wyner–Ziv teorem (distribuirano kodiranje s bočnom informacijom):**
izvor X možeš komprimirati do **uvjetne entropije `H(X|Y)`**, gdje je Y ono što dekoder već ima — i to **bez da koder poznaje Y**. Dovoljno je da su X i Y korelirani.

Prevedeno na papir:

> Točkice ne moraju nositi **cijeli** sadržaj `H(X)`. Moraju nositi samo **sindrom** — razliku `H(X|Y)` između onoga što uređaj već može predvidjeti i istine.

Kad je sadržaj koda uvelike predvidljiv iz onoga što uređaj drži (predlošci, lanac, ključevi), `H(X|Y) ≪ H(X)`, pa broj nužnih točkica pada u istom omjeru — **bez ijedne fizičke promjene koda**.

To je jedini pravi matematički poluga protiv fizičkog stropa: ne guramo više bita kroz kanal, nego šaljemo manje bita jer dekoder ostalo zna sam.

## 3. Tri mehanizma (od najjačeg prema pomoćnom)

### 3.1 Sindromski sloj (Slepian–Wolf) — ruši broj točkica
- Koder računa sindrom `s = H·x` (paritetne provjere) umjesto punog `x`.
- Dekoder uzme svoju predikciju `y` (iz lanca/predloška) i traži najbliži `x` koji zadovoljava `s` — belief propagation nad LDPC matricom.
- Fizički se upisuje samo `s`, veličine ≈ `H(X|Y)` bita.
- **Ovo je matematički ekvivalent tvom „imamo offline verifikaciju" → pretvoreno u gustoću.**

### 3.2 Rateless (fountain) prstenovi — RaptorQ/LT
- Svaki prsten = fontanski kodirani simboli: **bilo kojih K od N** simbola rekonstruira cjelinu.
- Napada `r` (pouzdanost) i pokret izravno: svaki kadar kamere uhvati drugačiji šumni podskup, a **fuzija kadrova** (već postoji u lancu!) akumulira dovoljno **različitih** simbola. Ne trebaš pročitati SVE točke, nego BILO KOJIH K.
- „Na rate" (rast koda) postaje prirodan: dodaješ nove prstenove kao nove fontanske simbole — stari ostaju valjani, kapacitet/redundancija raste inkrementalno.

### 3.3 M-arni kanal po točki — optimum razina veličine/praznine
- Prisutnost = 1 bit; veličina s M razina = log₂M bita; praznina = dodatno stanje.
- Kapacitet M-arnog amplitudnog kanala uz IZMJERENI šum po razini bira **optimalni M** (previše razina → greške pojedu dobitak).
- Zahtijeva stvarnu krivulju greške po razini iz kamere (PSF, razlijevanje tinte — „hod po tinti" već postoji), ne pretpostavku.

## 4. Rješenje uskog grla „srce"

Srce (standardni QR / GiroCode) ima najveće module i fizički se ne može smanjiti ispod čitljivosti — zato je usko grlo. Matematički rez:

> Srce prestaje nositi sadržaj. Srce nosi **samo sjeme + commitment** (sidro): tko potpisuje, koje stanje lanca, hash. Sav ostatak nose **sindromski, fontanski prstenovi**.

Time se teret seli sa srca (fiksno, robusno, malo) na prstenove (skalabilno, tolerantno na djelomično čitanje). Usko grlo se rasterećuje po definiciji.

## 5. Pet kutova (pravilo 27)

- **Ispod radara:** uređaj već ima repliciran DokArh lanac — ogroman zajednički rječnik (Y) koji nitko ne koristi kao dekoderski codebook. Najveći dobitak leži u onome što već imamo.
- **U stranu:** ista matematika (Wyner–Ziv) vrti se u senzorskim mrežama i video-kompresiji desetljećima — dokazana drugdje, nova za tiskane kodove.
- **Dron:** strop je informacijsko-teorijski; nijedna dosjetka ne pobjeđuje `C = A·b·r`. Jedini izlaz je smanjiti `H(X)` koji mora proći — dakle bočna informacija. Sve ostalo je optimizacija konstante.
- **Iza kulisa:** `b_po_točki` i `r` diktira fizika kamere/tinte. Matematika mora biti hranjena IZMJERENIM greškama po razini, inače je optimum lažan (pravilo 5).
- **Druga strana medalje:** sindrom katastrofalno pada ako je Y kriv (uređaj nije u sinku s lancem). Zato obavezan graceful fallback: ako `H(X|Y)` dekod padne → traži još kadrova ili se vrati na mali samostalni jezgra-kod. Trostanje: nesklad = **NEPOZNATO**, nikad lažno prihvaćanje (pravilo 15).

## 6. Usporedba (mi naspram drugih) i jedinstvenost

| Pristup | Poluga | Koristi bočnu info dekodera? |
|---|---|---|
| Standardni QR | fiksni kapacitet | Ne |
| Boja/JAB kod, HCCB | više bita po ćeliji (fizički) | Ne |
| QR4D (sad) | 4 fizičke dimenzije po točki | Ne |
| **QR4D + sindrom (ovdje)** | **smanjuje `H(X)` koji mora proći** | **Da** |

**Jedinstvenost, vezana uz prošlo ograničenje:** prošlost je tjerala kod da nosi SVE, jer je čitač bio „glup i offline". To ograničenje **više ne vrijedi** — jer je offline verifikacija riješena, čitač je pametan i drži sidro. Upravo ograničenje koje je prije forsiralo puni sadržaj sada je nestalo. Nitko konkurentski to ne iskorištava, jer nitko drugi nema repliciran lanac u ruci čitača.

**Pošteno:** ako netko drugi već radi sindromski tiskani kod s bočnom informacijom — to ne znam i treba provjeriti prije tvrdnje o prvenstvu.

## 7. Korak Nula prije bilo koje tvrdnje (uvjet, pravilo 1/4)
Otvoriti živi `qr4d` modul na eu i izmjeriti:
1. čime točno srce i prstenovi kodiraju danas (polja, RS parametri) — grep u modul;
2. stvarnu krivulju greške po razini veličine/praznine iz postojećeg čitača (za §3.3);
3. `H(X)` naspram `H(X|Y)` na **n ≥ 30** stvarnih dokumenata, gdje je Y = trenutna glava lanca + predložak.

## 8. Najjeftiniji pokus (pred-registriran kriterij)
Na n ≥ 30 stvarnih payloada izračunati omjer `H(X|Y)/H(X)` (Y = glava lanca + predložak firme).
**Kriterij (fiksiran prije mjerenja):** ako je gornja granica ne prelazi, a **donja granica 95 % CI** omjera ≤ 0,40 → sindromski sloj daje **≥ 2,5×** efektivne gustoće bez ijedne fizičke promjene. Iznad 0,40 → teza pada za ovaj tip sadržaja i to se zapisuje kao rezultat, ne briše.

## 9. Deset riječi i horizont 2050
- **Dokazuje:** DOKAZIV (dokaz putuje bez mreže), PRENOSIV (radi offline, među uređajima), NEUNIŠTIV (djelomično čitanje i dalje rekonstruira — rateless).
- **Test:** stopa rekonstrukcije naspram udjela pročitanih točkica (rateless), i lažno-prihvaćanje = 0 na krivom Y (sindrom + trostanje).
- **2050:** papir postaje sićušan pečat-sidro (sjeme + commitment); „sadržaj" živi u zajedničkom repliciranom lancu; kod je pokazivač + sindrom koji dokazuje koje stanje lanca. **Sutra radimo:** izmjeriti `H(X|Y)` (§8) i, ako prođe, dodati sindromski prsten kao novi sloj uz postojeće.

---

# DODATAK — Korak Nula IZMJEREN (2026-09-28, iz živog koda)

> Izvor: `eu:/var/www/genesis/paketi/eho_v2/eho_v2/kod4d.py` + `qr_eho10_4dimenzije.py` (pročitano).
> Aritmetika kapaciteta izračunata deterministički iz konstanti (K=40, N0=16, RS 35 %, opis 24 B).
> Status i dalje TEORIJA za dobitak; ovo su izmjerene ULAZNE brojke, ne rezultat pokusa.

## Broj 1 — čime kodira danas (IZMJERENO)
- Geometrija: suncokretova spirala, pojas b ima `40·(2b+1)` točaka; **1 bit po točki** (R0=0,27 mala / R1=0,52 velika, ili točka/praznina). Nema više razina.
- Tijelo prstena = `tip(1) + len(2) + podaci(D) + potpis_Ed25519(64) + lanac[:8]` → **fiksna režija 75 B po prstenu neovisno o payloadu**.
- RS: podatkovni blokovi `nsym = ⌈0,35·bd⌉` (35 %), opis 8 B + 16 B RS = 24 B.

| podaci B | tijelo B | emit B | točaka | pojaseva | režija % |
|---:|---:|---:|---:|---:|---:|
| 16 | 91 | 147 | 1176 | 6 | 82 |
| 32 | 107 | 169 | 1352 | 6 | 70 |
| 50 | 125 | 193 | 1544 | 7 | 60 |
| 100 | 175 | 456 | 3648 | 10 | 43 |
| 300 | 375 | 672 | 5376 | 12 | 20 |

**Nalaz:** usko grlo nije payload nego **fiksna kriptografska režija po prstenu**. Potpis sam = 64 B = **512 točaka** (≈ 33 % prstena od 1544 točke). Prazan prsten (0 payloada) već traži 1008 točaka.

## Broj 2 — krivulja greške po razini (NE POSTOJI kao mjerenje)
Čitač je binaran (R0/R1), 1 bit po točki; Rust jezgra `_jezgra.abi3.so` je kompajlirana, izvor greške po razini se nigdje ne sprema. `_potroseno` mjeri samo utrošeni RS kapacitet `(2·greške+brisanja)/nsym`, ne po-razinsku vjerojatnost. **Zaključak: §3.3 (M-arni optimum) nema podatka — prije te tvrdnje treba pustiti čitač preko graduiranih uzoraka.**

## Broj 3 — H(X) vs H(X|Y) po polju (procjena, bez n≥30)
| polje | B | H(X)~b | H(X|Y) | uvjet |
|---|---:|---:|---|---|
| tip | 1 | 8 | ≈0 | iz konteksta |
| len | 2 | 16 | ≈0 | iz \|podaci\| |
| podaci | 50 | 400 | ≈0* | *ako je dokument u repliciranom lancu |
| **potpis** | **64** | **512** | **512 ILI ≈0** | **≈0 samo ako lokalna replika lanca već drži potpis; inače pun (pseudoslučajan — Slepian-Wolf NE pomaže)** |
| lanac8 | 8 | 64 | ≈0 | rekompatibilan iz tijela |

## Ispravak teze (istina prije elegancije)
Generički Slepian-Wolf nad **payloadom** daje malo — payload je već malen, a potpis je pseudoslučajan i **nestlačiv bočnom informacijom**. Pravi poluga je uža i jača:

> **Potpis (64 B) i lanac (8 B) — 75 B fiksne režije — postaju bočna informacija Y tek kad uređaj drži repliciran lanac (Z3/Z17).** Tada čitač ne treba potpis iz papira: već ga ima lokalno. Prstenovi nose samo indeks + dokaz vezanja/svježine. Srce već nosi 16-znakovnu adresu — to je taj indeks.

**Dvorežimski rateless kod (nova, konkretnija hipoteza):**
- **Režim A (dokument u lokalnoj replici):** prstenovi nose samo sindrom/indeks → čita se malo točaka, `H(X|Y)` ≈ adresa. Teorijski nestaje ≈ 75 B/prsten fiksne režije.
- **Režim B (hladan/nov dokument, stara replika):** prstenovi nose puni samostalni dokaz (kao danas).
- Rateless (RaptorQ) čini da **iste fizičke točke** služe oba: pročitaš malo za A, sve za B. „Na rate" (Structured Append, već postoji) je prirodni nosač.

**Druga strana medalje (mjerljiv rizik):** režim A vrijedi samo uz svježu repliku koja sadrži dokument. Stara/nesinkronizirana replika → obavezan pad na režim B, nikad lažni OK. Trostanje već to podržava (`presudi`: NEPOZNATO kad lanac nije provjerljiv).

## Sljedeći najjeftiniji pokus (revidiran, pred-registriran)
Ne mjeriti generički `H(X|Y)` nego **pokrivenost lokalne replike**: na n≥30 stvarnih skeniranja izmjeri udio dokumenata koji SU u lokalnoj replici lanca u trenutku čitanja.
**Kriterij (fiksiran):** ako je donja granica 95 % CI te pokrivenosti ≥ 0,80 → dvorežimski kod isplativ (režim A pokriva većinu), i tada prstenovi u prosjeku gube ≥ 75 B fiksne režije. Ispod 0,80 → režim A je rijedak, ostaje puni kod; teza pada i to se zapisuje.

---

# REŽIM A — q4d kao ŽIVI PROZOR U ATOM (konkretan nacrt, aditivan)

> Ivanov naglasak (28.09.): q4d već čita i prikazuje podatke IZ atoma, nije spremište. Srce je content-hash adresa → kod je već vezan za atom. Ne pišemo sve u točkice; proširujemo funkciju veze. Bez narušavanja ičega (Z0/pravilo 12, pravilo 9/20).
> Izmjereno iz koda: adresa = `base32(sha3-256("EHO10-4D::"+tip+podaci0))[:10]` (16 znakova); `presudi()` već provjerava da srce i prsten 0 pripadaju istom dokumentu; H11f/H11g već upisuju svako skeniranje. Dakle veza i zapis skeniranja POSTOJE — gradimo na njima.

## 0. Preokret okvira
Problem gustoće je krivo postavljen čim prihvatiš da je q4d **ručka na atom**. Papir ne mora rasti — **atom raste**. Fizika ostaje minimalna (srce-adresa + prstenovi kao offline dokaz), funkcionalnost raste u sloju atoma. Prstenovi prestaju biti „sve o dokumentu" i postaju **sidro vezanja** (srce↔atom↔verzija), a sadržaj/rast/status žive u atomu.

## 1. Što se NE dira (invarijanta izolacije)
- `kod4d.py` bitovi, `sastavi`/`dekodiraj`, Rust jezgra, zlatni testovi — **bit-identično, netaknuto**.
- `srce` (standardni QR) i postojeći čitač — netaknuti; stari kodovi čitaju se isto.
- Novi sloj je **isključivo aditivan**: novi resolver + novi endpoint + neobavezno polje u prstenu 0. Dokument bez novog polja radi kao danas (unatražna kompatibilnost).

## 2. Resolver adresa→atom (jezgra režima A), trostanje + offline-first
Redoslijed razrješenja (Z17 PULL, Z40, Z53):
1. **Lokalna replika lanca** (uređaj/rubni čvor) — traži atom po adresi. Pogodak → izvor istine, radi offline.
2. **Fleet pull** (ako ima mreže) — genesis EU `/borg/...` ili DokArh po adresi.
3. **Samo prstenovi** (režim B, hladno) — puni samostalni dokaz s papira.
Presuda uvijek trostanje: **DRŽI** (atom nađen i vezanje potvrđeno) / **ALARM** (vezanje ne valja — podmetnut atom/srce) / **NEPOZNATO** (replika stara ili atom nedostupan → padni na režim B, nikad lažni DRŽI).

## 3. Vezanje i anti-replay (jedini novi bit na papiru, minimalan)
Opasnost pokazivača: netko upre kod u drugi/noviji atom (rebind) ili vrati stari (replay/opozvano→valjano).
- **Srce↔atom** vezanje već postoji (adresa = hash prstena 0).
- Dodaje se **neobavezno polje u CBOR prstena 0**: `v` = visina/verzija atoma na koju je kod pečaćen (logički sat lanca, ne zidni — kao `intent.py`). Čitač: atom mora imati tu visinu u svojoj povijesti; **starija replika bez te visine → NEPOZNATO** (traži svježiju), **atom s drugom granom → ALARM**.
- Time je режим A jednako otporan na replay kao režim B, a ne troši više od nekoliko bajtova u prstenu koji ionako postoji.
- **Ništa staro se ne mijenja**: `v` je opcionalan ključ; dokument bez njega ponaša se kao danas (samo srce↔ring0 vezanje).

## 4. Nova funkcionalnost koju veza otključava (sve u sloju atoma, 0 novih točkica)
| Sposobnost | Kako | Dodiruje |
|---|---|---|
| **Živi prikaz** | resolver renderira TRENUTNO stanje atoma (faze, polja) | samo atom + prikaz |
| **Rast bez reprinta** | nove faze u atomu → isti kod pokazuje više („na rate" kroz vezu, ne kroz tisak) | samo atom |
| **Opoziv / status** | atom nosi `status` (valjan/opozvan/istekao); skeniranje pokazuje uživo | samo atom |
| **Selektivno otkrivanje** | atom drži polja s vidljivošću po ulozi; q4d renderira pogled po čitaču (javni/vlasnik) | atom + prikaz |
| **Akumulacija povijesti** | skeniranje dopisuje događaj u atom (H11f/H11g VEĆ to rade — poopćiti) | postojeći zapis |

Opoziv i živi status su najveći dobitak: **tiskani kod koji se može opozvati i koji sam raste** — papir to inače ne može.

## 5. Pet kutova
- **Ispod radara:** H11f/H11g već pišu skeniranja u zapis — infrastruktura „kod akumulira povijest" već postoji, samo je uska.
- **U stranu:** isto kao DNS/URL naspram ugrađenog sadržaja — pokazivač + živo razrješenje; mi dodajemo kriptografsko vezanje na verziju.
- **Dron:** granica sad nije gustoća nego **svježina replike**; mjerni cilj se seli s „koliko točaka" na „koliki udio čitanja ima atom lokalno".
- **Iza kulisa:** izvor istine mora biti atom (DokArh), ne demo sqlite `db()` — Korak Nula (§7) to mora potvrditi prije tvrdnje.
- **Druga strana medalje:** pokazivač bez atoma je prazan; zato prstenovi (režim B) OSTAJU obavezni kao offline dokaz. Režim A je ubrzanje i proširenje, ne zamjena.

## 6. Usporedba i jedinstvenost
Standardni QR/URL: pokazivač bez offline dokaza (mreža obavezna, nema kriptografskog vezanja). Ugrađeni potpisani kod (današnji q4d, režim B): offline dokaz ali statičan. **Režim A spaja oba: živ i vezan I offline-dokaziv** — jer imamo repliciran lanac + prstenove kao rezervu. To nitko drugi nema jer nitko nema repliciran DokArh u čitaču.

## 7. Korak Nula prije koda (jedan otvoreni)
Potvrditi izvor istine u produkciji: čita li `dokument(adr)` iz DokArh atoma ili iz demo sqlite `db()`. Ako je sqlite demo → prvi zadatak je resolver na atom, ne nova sposobnost.

## 8. Najjeftiniji pokus (pred-registriran)
Na n≥30 stvarnih skeniranja izmjeri: (a) udio s pogotkom u lokalnoj replici (režim A moguć), (b) 0 lažnih DRŽI na podmetnut/star atom uz polje `v`.
**Kriterij (fiksiran):** lažni DRŽI = 0 (tvrdo) I donja granica 95 % CI pokrivenosti ≥ 0,80 → režim A se pušta kao zadani, režim B kao fallback. Lažni DRŽI > 0 → vezanje `v` nije dovoljno, staje se.

## 9. Deset riječi / 2050
Dokazuje: **ŽIV** (kod raste s atomom), **SAMOISCJELJUJUĆ** (opoziv/ispravak u atomu bez reprinta), **DOKAZIV** (vezanje + prstenovi). 2050: papir je trajno sidro; sve živo je u lancu; isti otisnuti kod danas nosi dokument kakav bude za 11 godina.

---

# KORAK NULA — IZVOR ISTINE (izmjereno 28.09., presuda)

> Provjera na zahtjev: je li q4d izvor atom ili demo baza. Izmjereno iz živog koda, ne pretpostavljeno.

## Nalaz
1. **q4d danas čita iz demo sqlite**, ne iz lanca. `qr4d/app.py`: `BAZA=/var/lib/qr4d/qr4d.db`, `dokument(adr)` radi `SELECT … FROM dokument`, 3 hardkodirana `DEMO` dokumenta, testni ključ `kljuc_testa()`. grep `dokarh|lanac|atom` u app.py → 0. **Testna faza, namjerno odvojeno (Ivan potvrdio).**
2. **DokArh atom NIJE izvor poslovnog dokumenta.** `c8498_RACUN_qr4d_app_py.dok.json` = `{tip, putanja, hash_prije, hash_poslije, visina}` — notar IZMJENE KODA, ne dokument. „u lancu su SAMO putanja i hashevi — sadržaj nikad."
3. **Pravi izvor istine = arhiva-core** (`services/arhiva_core/models.py`, Postgres `arhiva_core_dokumenti`), ključ **`weise3_id`** (unique, index), pečat **`pecat_hash`** (Z3), vrijeme **`tsa_token`/`tsa_timestamp`**.

## Zašto to mijenja spoj nabolje
Sve sposobnosti režima A **već postoje kao stupci u arhiva-core** — ne grade se, samo se čitaju:
| Režim A sposobnost | Postojeći stupac arhiva-core |
|---|---|
| živi prikaz / rast | `faza` (draft…), `izmijenjen` |
| opoziv / zaborav po volji | `spaljivanje_status`, `faza`, `retain_until` |
| svježina / anti-replay | `pecat_hash`, `tsa_token`, `tsa_timestamp` |
| selektivno otkrivanje | `tenant_id`, `app_id`, `creator_weise3_id` (tenant gating već testiran) |
| fiskalno vezanje | `jir`, `zki`, `amount_gross` |

Znači: **ne treba nova funkcionalnost u arhiva-core.** Treba samo resolver koji q4d adresu preslika na `weise3_id` i renderira postojeće stanje.

## Preslikavanje adrese (jedina arhitektonska odluka) — preporuka
q4d `adresa` (16 zn, `base32(sha3-256("EHO10-4D::"+tip+podaci0))[:10]`) i arhiva `weise3_id` su **različiti content-hashevi** → nisu jednaki, treba eksplicitna veza.
- **Preporuka: zaseban q4d-vlastiti indeks `adresa → weise3_id`** (nova mala tablica u q4d bazi, puni se pri izdavanju). **Nula izmjena sheme arhiva-core** → maksimalna izolacija (Z0/pravilo 12), jer je arhiva-core dijeljena, višekorisnička produkcija koju ne smijemo dirati.
- Odbačeno: novi stupac u `arhiva_core_dokumenti` (traži migraciju dijeljene produkcijske tablice — nepotreban rizik) i upis u `semantic_payload` JSONB (neindeksirano, sporo).

## Spoj (aditivan, bez diranja bitova ni arhiva-core sheme)
```
qr4d/izvor.py  (nova datoteka)
  razrijesi(adr) -> (dokument|None, izvor)
    1. q4d indeks adresa->weise3_id  (nova tablica u qr4d.db)
    2. arhiva_core.verificiraj_dokument(weise3_id, kreator)  [postojeća funkcija]
    3. fallback: dokument(adr) iz sqlite  (današnje ponašanje, demo)
qr4d/app.py: _citaj_dokument dobije JEDAN redak — prvo izvor.razrijesi, pa fallback.
```
Trostanje: DRŽI (arhiva vratila + pečat/tsa svjež) / ALARM (pečat ne valja) / NEPOZNATO (nema veze ili arhiva nedostupna → demo/prstenovi). Stari kodovi i demo rade identično.

## Sljedeći korak (kad iz teorije u kod)
Prvi PR: `qr4d/izvor.py` + tablica indeksa + jedan redak u `_citaj_dokument`, iza značajke-zastavice (`QR4D_IZVOR=arhiva`), default ostaje demo dok se ne izmjeri. Test: n≥30 stvarnih izdanja → 0 lažnih DRŽI, pokrivenost indeksa ≥ 0,80 (95 % CI donja granica).

---

# SINTEZA — inovacija, je li riješeno, javni servis (28.09.)

## Što je inovativno (i što nije — pošteno)
- **Preokret okvira (naše):** fizička gustoća nije prava granica; granica je fiksna kripto-režija po prstenu (izmjereno 75 B, potpis = 512 točaka = 33 %). q4d nije spremište nego **živi, vezani prozor u izvor istine**; točke su sidro+pokazivač+offline-dokaz, ne skladište.
- **Dvorežimski kod:** A = indeks u živi izvor (arhiva-core), B = samostalni offline dokaz (prstenovi), iste fizičke točke.
- **Nije novo samo po sebi:** Slepian-Wolf, fountain kodovi, pokazivač-naspram-spremnika su poznati. **Novo je spoj:** tiskani znak koji je ISTOVREMENO offline-dokaziv I živ/opoziv, jer iza njega stoji repliciran lanac + arhiva-core. Nisam radio patentnu/literaturnu pretragu → ne tvrdim svjetsko prvenstvo (pravilo 7).

## Je li teorijski riješeno
- **Konceptualno DA:** pitanje „pobijedi gustoću matematikom" ima odgovor — ne pobjeđuje se, zaobiđe se pokazivačem na živi izvor uz prstenove kao offline rezervu.
- **Mjerno NE (još):** krivulja greške po razini ne postoji; H(X\|Y) i pokrivenost nisu izmjereni (pred-registrirano). Dakle: **napisano, ne testirano** (pravilo 1).

## Javni servis za q4d prikaz — moguće i treba li
- **Moguće:** tehnički da; `/q/skener` i `/api/v1/qr4d/citaj` su već javni; treba samo resolver + renderer kao javni servis.
- **Napetost sa CILJEM:** CLAUDE.md kaže „prvo javni verifikator". To znači: prvi javni artefakt = **verifikator** (dokaži autentičnost, prikaži javni pogled), NE platforma za autorstvo.
- **Tvrda istina o potrebi:** platforma za zajednicu ima smisla tek kad postoje izdavatelji q4d kodova. Sad postoje 3 demo dokumenta. Graditi autorsku platformu prije izdavatelja je naopako.
- **Središnji strateški rizik (tvoja odluka):** čitač je kompajlirana Rust jezgra (`_jezgra.abi3.so`, zatvorena). Kod koji čita samo NAŠ skener je ograđeni vrt. QR je pobijedio jer je otvoreni ISO standard. Vrijednost q4d ovisi o rasprostranjenosti našeg čitača → biraj: **SaaS verifikator (mi hostamo, moat = lanac+arhiva)** ili **otvoreni standard + otvoreni čitač (adopcija, bez moata)**.
- **Sigurnost (pravilo 12/16):** javni resolver izlaže čitanja arhiva-core svijetu → mora ići kroz postojeći tenant gating + selektivno otkrivanje; nova javna površina napada.

## Preporuka (jedna)
Prvi javni artefakt = **q4d VERIFIKATOR** (pročitaj → provjeri potpise/pečat → prikaži javni pogled + trostanje), ne autorska platforma. To je usklađeno s „prvo javni verifikator", malen je, i odmah je koristan (bilo tko provjeri je li kod pravi). Autorstvo/zajednica dolazi kad ima izdavatelja. Odluku otvoreni-standard vs SaaS donosi Ivan — to je arhitektura, ne trivijalnost.

## Deset riječi
Javni verifikator dokazuje: **DOKAZIV** (bilo tko provjeri offline/online), **SAMOSTALAN** (živi na internetu sam), **PRENOSIV** (bilo koji uređaj). Test: stranac skenira → DRŽI/PAD/NEPOZNATO bez ijednog našeg računa.
