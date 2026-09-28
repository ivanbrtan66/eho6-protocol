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
