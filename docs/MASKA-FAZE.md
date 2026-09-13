# MASKA — pet faza uklanjanja SPOF-a iz adresne indirekcije

> Status ovog dokumenta: **F1, F2, F4 i F5 izgrađeni i testirani. F3 izgrađen kao
> alat, pilot još nije pušten.** Gdje piše "nije izgrađeno", to znači
> da koda nema — ne da je "skoro gotovo". Gdje piše "dokazano", stoji test koji se
> može ponovno pokrenuti; gdje dokaza nema, piše što točno nedostaje.
> Nastavak na `c1570_maska_protokol_nacrt` (DRAFT, prior-art timestamp).

---

## 0. Izmjereno stanje prije gradnje

Nije pretpostavljeno — pročitano s EU čvora prije pisanja ijedne linije:

| Nalaz | Izvor |
|---|---|
| `medijapos` (X96:8093 → EU:18096) **nema rezervni put** | `tunel_watchdog_config.json`, `_biljeska_c2395` |
| 7 tunela pod nadzorom, `tonka` čeka prvo priključenje | isto |
| `v4.limit-connect.com` već ide s mrtvog MAR-a na NEW (`fenixv4-relay.service`, EU:8505 → NEW:8005) | `_biljeska_c3224` |
| `genesis-medijapos.limit-connect.com` → `217.160.71.124` (EU) | živi DNS upit; Fasada (F-A) je **u produkciji** |
| GENESIS1 TXT format: `v=GENESIS1 ws=… gh=… ph=… ts=…`, DNS sloj još TODO | `c0967` |
| **ML-DSA-65 ne postoji nigdje u stacku** | `grep` po `/var/www/genesis/core` → nula pogodaka |

Zaključak inventure: pitanje nije "kako početi" nego "kako maknuti SPOF Fasade i
statički A-zapis". Faza A (Fasada) radi u produkciji već sada.

---

## 1. Tvrda istina o A-zapisu

**A-zapis se ne može ukloniti** ako želiš da te otvori tuđi, nepromijenjen Chrome.
Preglednik zna tri stvari: DNS ime, IP adresu, BGP rutu. Sve alternative koje su
usporedene u c1570 (Tor, I2P, IPFS, ENS, mDNS) žrtvuju doseg. To stoji.

Ono što se **da** maknuti je da A-zapis pokazuje na **tvoj stroj**. A-zapis postaje
jeftina, zamjenjiva, višestruka ulaznica; stvarna lokacija nikad nije u DNS-u.

## 2. Zašto je ARPANET model točno ovaj model

ARPANET nije imao DNS. Postojao je `HOSTS.TXT` — jedna datoteka koju je ručno
održavao SRI-NIC, a svaki host ju je **povlačio FTP-om i držao lokalno**.
Razrješenje imena bilo je **lokalna funkcija hosta, ne mrežna usluga**. DNS je
nastao 1983. (Mockapetris, RFC 882/883) jer `HOSTS.TXT` nije skalirao preko ~1000
hostova — dakle iz **operativne nužde**, ne iz arhitektonskog uvjerenja.

Druga stvar: **IMP**. Host nije bio na mreži — IMP je bio, a host je visio iza
njega. Razdvojena je "stvar koja računa" od "stvari koja je adresirana". To je
Fasada, 55 godina ranije.

`dnkd` je povratak na taj model: PULL (ZAKON17) umjesto FTP-a, kriptografski
potpis umjesto centralnog NIC-a, rok trajanja umjesto ručnog ažuriranja.

---

## 3. Pet faza

### F1 — PELUD: potpisani istekljivi locator zapis ✅ izgrađeno

`maska/pelud.py`. Proširenje **postojećeg** GENESIS1 TXT formata, ne novi format:

```
v=PELUD1 ime=medijapos.dnk alg=ed25519 pk=<64hex> h=4287 exp=<epoch> \
loc=wg://217.160.71.124:51820/<kljuc>|https://genesis-medijapos.limit-connect.com \
[ws=<weise3_id>] sig=<base64url>
```

Odluke i njihovi razlozi:

- **Potpis pokriva točno poznata polja u fiksnom redoslijedu.** Nepoznato polje se
  **odbija**, ne ignorira: "ignoriraj nepoznato" znači da napadač može dodati polje
  koje budući čitač tumači, a potpis ga ne pokriva.
- **Zapis mora biti u kanonskom obliku.** Isti bajtovi ili ništa — jedna tvrdnja ne
  smije imati dva valjana kodiranja (isti razlog zbog kojeg se odbija ne-kanonski
  Ed25519 `S`).
- **`exp` je obavezan i ograničen na sat.** Tvrdnja bez kratkog roka nije PELUD nego
  A-zapis s potpisom.
- **`provjeri()` zahtijeva pinovani ključ.** Potpis provjeren ključem **iz istog
  zapisa** ne dokazuje ništa — napadač potpiše svojim. `provjeri(None)` vraća
  `(False, "pk_nije_pinovan")`, nikad tihi prolaz.
- **`alg=ml-dsa-65` se odbija s jasnim razlogom.** Implementacije nema u ovom
  stacku. Rezervirano ime koje tiho prođe kao "provjereno" gore je od greške.

### F2 — `dnkd`: lokalni razrješitelj ✅ izgrađeno

`maska/dnkd.py`. Systemd servis, sluša `127.0.0.53:5353` (UDP+TCP), odgovara samo na
`.dnk`. Put jednog upita: PULL sa svih sidara → Ed25519 verifikacija protiv
pinovanog ključa → provjera suglasnosti s javnim DNS-om → mapiranje na stabilnu
adresu iz `100.80.0.0/12` → GODOVI zapis.

Ograde koje nisu pregovorljive:

- **Nikad prosljeđivanje.** Sve izvan `.dnk` je `REFUSED`. Resolver koji
  prosljeđuje postaje proxy kroz koji ide sav korisnikov promet — nova dodirna
  točka, točno ono što MASKA uklanja.
- **Nikad vlastiti CA u sistemskom trust storeu.** Vidi §5.
- **Razlikuje "mjerenje palo" od "izmjeren kvar".** Sidro vraća 500 → `NEPOZNATO`.
  Sidro vraća zapis s neispravnim potpisom → `ALARM`. Poruka koja imenuje krivi
  uzrok gora je od nikakve.
- **Pad sidra ne ubija ime.** Zapis koji još vrijedi posluživa se dalje, uz vidljiv
  razlog `posluzujem zapis koji jos vrijedi`.
- **Podmetnut zapis se ne pamti.** Ne ulazi u predmemoriju ni na trenutak.

### F3 — RIZOM: dvo-sidreni WireGuard ✅ alat izgrađen, ⏳ pilot nije pušten

`rizom/rizom_konfig.py`, `rizom/deploy_sidro.sh`, `rizom/patch_watchdog.py`.

Zašto se `ssh -R` zamjenjuje, a ne popravlja: `ssh -R` je TCP sjednica u
user-spaceu; kad ISP-ov NAT tiho zaboravi mapiranje, sjednica ostane half-open —
uređaj ŽIV, tunel MRTAV, obje strane to ne znaju (c2397). Watchdog i dead-man su
**posljedica** tog razreda kvara, ne rješenje. WireGuard je u kernelu, handshake je
stateless, preživi promjenu IP-a i roaming, a `PersistentKeepalive = 25` drži NAT
mapiranje otvorenim jeftinije od svakog nadzora.

Zašto dva sidra: `medijapos` danas nema rezervni put. Jedan tunel prema jednom
sidru je jedna točka kvara.

### F4 — PROBOD: direktan probod NAT-a ✅ izgrađeno, ⏳ pilot na terenu nije pušten

`maska/stun.py`, `maska/susret.py`, `maska/probod.py`.

Ovo je faza koja **ukida** SPOF, a ne premješta ga: nakon proboda promet ide
peer-to-peer, sidro zna samo *tko postoji*, i njegov pad više ne ruši uspostavljenu
vezu.

**Redoslijed, i zašto baš takav:**

1. **Izmjeri prije nego probaš.** Ponašanje mapiranja NAT-a odlučuje je li probod
   uopće moguć:
   - **EIM** — isto vanjsko mapiranje bez obzira na odredište → adresa koju vidi
     sidro EU vrijedi i za peera → probod moguć.
   - **EDM (simetrični NAT)** — novi port po odredištu → adresa koju vidi sidro ne
     vrijedi ni za koga drugog → **probod nemoguć**, sidro ostaje relej.
   Mjerenje traži **dvije točke gledanja na različitim IP adresama** — a to je točno
   dvo-sidrena postava iz F3. S jednim sidrom rezultat je `NEPOZNATO`; "vjerojatno
   EIM" nije mjerenje. Sidro vozi **vlastiti STUN**: javni STUN vidio bi tko i kada
   traži probod, a taj metapodatak ne mora napustiti flotu.
2. **Oglas.** Svaka strana objavi potpisane kandidate (Ed25519, pinovani ključ,
   `ts` + `nonce` protiv ponavljanja). Sidro je **oglasna ploča, ne prolaz** — nema
   rutu koja prenosi teret, i test `test_nema_releja` to drži tako.
3. **Istovremeni probod** s istog socketa s kojeg je mjereno mapiranje. Izlazna
   proba otvara NAT mapiranje, tuđa proba ulazi kroz njega.
4. **Nominacija.** Par potvrđen **u oba smjera** s najmanjim RTT-om. Upravljačka
   strana je leksikografski manje ime — bez pregovora koji može zapeti.
5. **Predaja WireGuardu** (neobavezno): `wg set … endpoint`, pa provjera da se
   `latest-handshakes` **stvarno pomaknuo**. Ako se ne pomakne, endpoint se vraća na
   sidro i ishod je `RELEJ`. Uspjeh je pomak handshakea, nikad izostanak greške.

**Što sidro može, a što ne može slagati.** Sidro može objaviti lažan kandidat i time
**spriječiti** vezu, ali ne i ući u nju: WireGuard autentificira ključem a ne adresom,
a MASKA probe su potpisane Ed25519 ključem peera. Laž sidra je napad na dostupnost,
nikad na tajnost.

**Što je dokazano (`tests/test_probod.py`, NAT simulator po RFC 4787 razredima):**

| Postava | Očekivano | Dokazano |
|---|---|---|
| EIM + ADF ↔ EIM + ADF | probod uspijeva, par dvosmjerno potvrđen | ✅ |
| EIM + EIF ↔ EIM + EIF | uspijeva | ✅ |
| EDM na jednoj strani | `RELEJ` bez ijedne poslane probe (< 1 s) | ✅ |
| EDM, a kodu **slažemo** da je EIM | probod svejedno pada; presuda `RELEJ` | ✅ |
| EDM + potpuno otvoren filtar (EIF) | i dalje pada — potvrda stiže s **drugog** porta | ✅ |
| peer prima ali ne odgovara | `RELEJ`, nikad `NEPOSREDAN` | ✅ |
| krivotvorena proba (tuđi ključ) | ignorirana | ✅ |
| ponovljena proba (isti nonce) | ne broji se dvaput | ✅ |
| predaja WireGuardu bez pomaka handshakea | vraćanje na sidro + `RELEJ` | ✅ |

Peti red je najvažniji: bez njega bi "RELEJ kod simetričnog NAT-a" bio samo
poštovanje vlastite zastavice, a ne činjenica o mreži.

**Što NIJE dokazano:** da ISP-ov CGNAT kod tebe ima baš to ponašanje. Simulator
modelira razrede iz RFC 4787, ne konkretnu kutiju tvog operatera. To je pilot na
terenu, isto kao F3.

### F5 — OGLASNIK: K-od-N pultovi ✅ izgrađeno, ⏳ domene još nisu kupljene

`maska/oglasnik.py`.

**Ispravak ranije tvrdnje.** U c1570 i u prvoj verziji ovog dokumenta stajalo je da
F5 *"plaća SEO dosegom jer dijeli signal na tri domene"*, pa je faza bila uvjetna.
Ta tvrdnja vrijedi **samo ako pultovi poslužuju sadržaj** — tada su tri kopije iste
stranice i tražilica dijeli signal. Ako su pultovi ono što stvarno trebaju biti —
**`noindex` preusmjerivači** s `rel=canonical` na primarnu domenu — duplikata nema,
signal se ne dijeli, i cijena nestaje. Uvjet otpada; faza je izgrađena.

Mehanizam SEO-neutralnosti je u kodu i u testu, ne u obećanju: svaki odgovor nosi
`X-Robots-Tag: noindex, nofollow` i `Link: <primarna>; rel="canonical"`, a
`/robots.txt` zabranjuje cijeli pult. `test_svaki_odgovor_nosi_noindex_i_canonical`
provjerava to na svakoj ruti.

**Zašto K-od-N a ne "prvi koji odgovori":** jedan pult kojem je registrar oteo domenu
inače preusmjerava korisnike kamo hoće. Uz K-od-N pult preusmjerava tek kad **K
nezavisnih pultova drži istu potpisanu tvrdnju**. Napadač mora oteti K domena kod K
registrara u K jurisdikcija.

**Ustavno ograničenje koje konfiguracija provjerava: K mora biti stroga većina
(K > N/2).** Inače dvije razdvojene skupine mogu istovremeno imati po K glasova i
preusmjeravati na različita mjesta — a to nije konsenzus nego tihi split-brain, ista
bolest protiv koje F2 brani provjerom suglasnosti. `k=2` od `n=4` se **odbija**.

Ostale odluke i njihovi razlozi:

- **307, nikad 301.** Trajno preusmjeravanje prenosi težinu poveznica i kešira se
  zauvijek; pokazivač koji se mijenja svakih par minuta ne smije ostaviti trajan trag
  u tuđem kešu. `301` se odbija u konfiguraciji.
- **Glasovi se grupiraju po skupu lokatora, ne po visini lanca.** Pult koji kasni 30 s
  ima manju visinu ali isto odredište — to je slaganje, ne neslaganje. Unutar
  pobjedničke skupine uzima se najsvježiji potpis.
- **Bez `http(s)` lokatora nema preusmjeravanja.** Preglednik ne može slijediti
  `wg://`. Ako konsenzus postoji ali nijedan lokator nije web-adresa, pult to **kaže**
  (503 s razlogom) umjesto da izmišlja odredište.
- **Kad konsenzusa nema, pult ne pogađa.** Vraća 503 sa stranicom koja imenuje stanje
  (`NESUGLASNO` / `NEDOVOLJNO`), koliko glasova je trebalo i gdje se vidi stanje.

**Što je dokazano (`tests/test_oglasnik.py`, tri prava pulta na tri loopback adrese):**

| Postava | Očekivano | Dokazano |
|---|---|---|
| sva tri pulta složna | 307 na dogovoreni cilj | ✅ |
| **jedan pult otet** (njegovo sidro laže) | ostala dva nadglasaju ga; cilj se ne mijenja | ✅ |
| sva tri različita | 503 `NESUGLASNO`, bez preusmjeravanja | ✅ |
| dva pulta padnu | 503 `NEDOVOLJNO`, bez preusmjeravanja | ✅ |
| različita visina, isto odredište | slaganje, ne neslaganje | ✅ |
| samo `wg://` lokator | 503 s razlogom, bez izmišljenog cilja | ✅ |
| `k=2` od `n=4` u konfiguraciji | odbijeno (nije stroga većina) | ✅ |
| dva pulta na istoj domeni | odbijeno (nisu nezavisni izvori) | ✅ |
| svaka ruta | `noindex` + `canonical` | ✅ |

**Što NIJE napravljeno:** domene kod triju registrara u trima jurisdikcijama nisu
kupljene. Kod stoji i testiran je; tri domene su odluka i trošak, ne kod.

---

## 4. Granice ove implementacije (pročitaj prije nego povjeruješ)

| Što PELUD dokazuje | Što NE dokazuje |
|---|---|
| Tvrdnju je potpisao vlasnik pinovanog ključa | Da je pinovani ključ pravi — **prvi kontakt je trust-on-first-use** |
| Tvrdnja nije starija od `exp` | Da je lokacija u tvrdnji stvarno živa (to mjeri watchdog, ne potpis) |
| Zapis nije mijenjan nakon potpisa | Da `h=4287` odgovara stvarnoj visini Genesis lanca — **`h` se u ovoj verziji ne provjerava protiv lanca**, prenosi se i prikazuje |
| Da su sidra dala istu tvrdnju (ili nisu — razilaženje je ALARM) | Konsenzus. 2-od-2 suglasnost je **mjerenje**, ne K-od-N konsenzus (to je F5) |

Ostale poznate granice:

- **Kompromitiran ključ izdavatelja = kompromitirano ime.** Nema opoziva (revocation)
  u ovoj verziji. Kratak `exp` ograničava trajanje štete, ne i samu štetu.
- **`dnkd` nije post-kvantan.** Ed25519. Format nosi `alg=` da zamjena ne mijenja
  zapis, ali danas ML-DSA-65 u ovom stacku ne postoji.
- **GODOVI nisu usidreni u lanac.** Lanac hasheva otkriva naknadnu izmjenu lokalno;
  netko s pristupom datoteci može prepisati **cijeli** dnevnik od nule. Usidrenje
  posljednjeg hasha u Genesis lanac rješava to i nije izgrađeno.

Granice F4 posebno:

- **Nema TURN releja** (RFC 5766). "Relej" ovdje znači postojeći RIZOM tunel kroz
  sidro (F3), ne TURN.
- **Nije pun ICE** (RFC 8445): nema parova kandidata po prioritetu, agresivne
  nominacije ni IPv6 kandidata. ICE-lite s jednim pravilom nominacije.
- **MASKA-in socket za probod nije WireGuardov socket.** Mapiranje koje smo izmjerili
  vrijedi za naš port, a WireGuard ima svoj. Endpoint koji se predaje peeru je onaj
  koji **sidro opaža** za WireGuard peera — a to peer ne može kriptografski provjeriti
  (vidi gore: može spriječiti vezu, ne ući u nju). Zato se predaja dokazuje pomakom
  handshakea, ne vjerom u sidro.
- **Simetrični NAT nije riješen i ne može biti** ovom fazom — tu ostaje F3 relej.

---

## 5. Certifikati — i zašto ovdje nema vlastitog CA

Nijedan javni CA ne izdaje certifikat za `.dnk`. Očito rješenje ("napravi vlastiti
CA i ubaci ga u sistemski trust store") je **stvarna sigurnosna šteta za korisnika**:
taj ključ postaje ključ za **sve** stranice na tom uređaju, uključujući njegovu
banku. Jedan kompromitiran rubni uređaj tada nije izgubljen tunel nego izgubljen
uređaj.

Zato: TLS za `.dnk` imena terminira **aplikacija na loopbacku**. `dnkd` ne dira
trust store, a njegov systemd unit ima `CapabilityBoundingSet=` (prazan) i
`ProtectSystem=strict` da to ne može ni slučajno.

---

## 6. Adresni plan (disjunktan po konstrukciji, provjereno testom)

| Prostor | Namjena | Tko dodjeljuje |
|---|---|---|
| `100.64.0.0/12` | RIZOM mesh: `100.64.<sidro>.0/24`, sidro `.1`, rub deterministički oktet | `rizom_konfig.py` |
| `100.80.0.0/12` | `dnkd` mapiranje imena → stabilna adresa | `dnkd.Mapiranje` |

Oba su u RFC 6598 (`100.64.0.0/10`), namijenjenom operatorskom NAT-u — dakle neće se
sudariti s korisnikovim LAN-om (`192.168/16`, `10/8`) ni s Docker mostovima
(`172.17/16`). `test_rizom.py` i `test_dnkd.py` provjeravaju da se prostori ne
preklapaju; ako to ikad prestane biti istina, testovi padaju.

## 7. Nadzor: tri stanja, nikad tihi nula

`dnkd` izlaže `/borg/health.json` s poljima koja **postojeći** `tunel_watchdog.py`
već čita: `stanje` (`ok` / `alarm` / `NEPOZNATO`), `vatre[].razlog`,
`vatre[].ozbiljnost`, `vrijeme`. Razbijen GODOVI lanac gasi zeleno — dnevnik koji je
mijenjan ne smije izgledati zdravo.

Mjereno na ovom stroju: potpis 4 ms, verifikacija 4 ms, cijelo razrješenje s PULL-om
14 ms. Pure-Python kripto ovdje nije usko grlo. Cijeli paket: **215 testova**, samo
standardna biblioteka, bez izlaza na internet (sidra i NAT-ovi su na loopbacku
odnosno u simulatoru).

---

## 8. Runbook: pilot `medijapos` (jedan uređaj, dva sidra)

Svaki korak je reverzibilan, i **stari `ssh -R` put se ne gasi**.

```bash
# 1. generiraj (na radnoj stanici, ne na sidru)
python3 -m rizom.rizom_konfig --uredjaj x96 --ime-usluge medijapos \
    --usluga-port 8093 \
    --sidro eu:genesis.limit-connect.com:51820 \
    --sidro new:fina-connect.online:51820 \
    --izlaz ./izlaz-rizom
# bolje: --sidro-javni eu=<wg pubkey> ako sidro već ima svoj ključ

# 2. na svakom sidru
sudo ./rizom/deploy_sidro.sh --sidro eu --izvor ./izlaz-rizom/eu --usluga medijapos

# 3. na rubu (X96)
sudo ./izlaz-rizom/x96/instaliraj-rub.sh

# 4. dokaz puta (ne tvrdnja)
ping -c3 100.64.1.1                                  # s ruba
curl -sS --max-time 5 http://127.0.0.1:18196/health   # sa sidra

# 5. u nadzor
sudo python3 rizom/patch_watchdog.py --usluga medijapos --port 18196 --uredjaj X96
sudo -u www-data python3 /var/www/genesis/tools/tunel_watchdog.py

# vraćanje unatrag, bilo kada
sudo ./rizom/deploy_sidro.sh --vrati --sidro eu --usluga medijapos
python3 rizom/patch_watchdog.py --vrati
```

**Kriterij uspjeha pilota, postavljen prije mjerenja:** sedam dana bez
watchdog alarma na `medijapos-rizom`, uz oba puta mjerena paralelno. Prvo
očekivano stanje je `NEPOZNATO — ceka prvo prikljucenje`; watchdog sam briše tu
zastavicu na prvi OK (c2404). **Ako pilot preživi tjedan, tada ime. Prije toga
samo mjerenje.**

**F4 — probod (nakon što RIZOM stoji):**

```bash
# 1. na OBA sidra (dvije točke gledanja su uvjet za mjerenje NAT-a)
#    /var/lib/maska/susret.json: imena[<ime>].pk + drugo_sidro_stun = IP drugog sidra
sudo python3 -m maska.susret --provjeri-konfig
sudo python3 -m maska.susret

# 2. na rubu: izmjeri prije nego išta tvrdiš
python3 -m maska.stun izmjeri \
    --sidro genesis.limit-connect.com:3478 --sidro fina-connect.online:3478
#    EIM  -> probod je moguć
#    EDM  -> nije; sidro ostaje relej. Ovo je mjerenje, ne kvar.

# 3. probod prema peeru
python3 -m maska.probod --ime x96 --kljuc ~/.eho6/node.key \
    --peer tonka --peer-pk <64 hex> \
    --sidro https://genesis.limit-connect.com/susret \
    --sidro https://fina-connect.online/susret \
    --stun genesis.limit-connect.com:3478 --stun fina-connect.online:3478 \
    --wg-sucelje rizom-eu --wg-nas-pk <wg pubkey> --wg-relej 217.160.71.124:51820 \
    --godovi /var/lib/maska/godovi.jsonl
# izlaz 0 = NEPOSREDAN · 1 = RELEJ · 2 = NEPOZNATO (mjerenje nije dovršeno)
```

**F5 — pultovi (kad domene postoje):**

```bash
# na SVAKOM pultu, na njegovoj vlastitoj domeni i kod svog registrara:
#   /var/lib/maska/oglasnik.json — ploce[] su OSTALI pultovi, k je stroga vecina
sudo python3 -m maska.oglasnik --provjeri-konfig     # odbija k <= n/2
sudo python3 -m maska.oglasnik

# provjera odluke bez pokretanja servisa
python3 -m maska.oglasnik --odluka medijapos.dnk
# izlaz 0 = preusmjerava (konsenzus), 1 = ne preusmjerava (i kaze zasto)

# dokaz da se pult ne indeksira
curl -sI https://<pult>/medijapos.dnk | grep -i 'x-robots-tag\|location'
curl -sS https://<pult>/robots.txt
```

`dnkd` je odvojena instalacija i ne ovisi o F3:

```bash
sudo ./maska/instaliraj_dnkd.sh --ime medijapos.dnk --pk <64hex> \
     --sidro https://genesis.limit-connect.com/pelud \
     --sidro https://fina-connect.online/pelud \
     --zrcalo genesis-medijapos.limit-connect.com
dig @127.0.0.53 -p 5353 medijapos.dnk A
```

---

## 9. Tri pogleda

**Ispod radara.** Pravi neprijatelj nije NAT nego **ISP-ov TOS i CGNAT bez opcije
port-forwarda**. F4 (probod) je jedino što tu stvarno radi; F3 premješta ovisnost s
`ssh -R` na sidro, ne uklanja je.

**Iza kulisa.** F2 gradi **drugi imenik**. Onog dana kad `dnkd` i javni DNS kažu
različitu stvar o istom imenu, imaš tihi split-brain koji nijedan watchdog ne vidi —
svaki mjeri svoj put, oba vraćaju 200 (isti razred kvara kao a16 osam dana mrtav uz
fasadu 200, c2293). Zato je `maska/suglasnost.py` ugrađen u F2 **od prvog dana**, a
ne "kasnije kad zatreba", i zato je zadana politika `na_nesuglasje=odbij`: kad se
izvori razilaze, ime se **ne** posluživa. Dostupnost koja poslužuje pogrešnu lokaciju
lošija je od poštenog SERVFAIL-a.

**Druga strana medalje.** F1–F3 su SEO-neutralni: javni DNS ostaje netaknut, `.dnk`
je dodatni put. Za F5 sam tvrdio da nije neutralan — **to je bilo preusko**. Nije
neutralan samo ako pultovi poslužuju sadržaj; kao `noindex` preusmjerivači s
`canonical` na primarnu domenu ne dijele signal. Cijena F5 nije SEO nego **novac i
pravna izloženost**: tri domene kod tri registrara u tri jurisdikcije treba kupiti,
obnavljati i braniti.

---

## 10. Što bi ovo opovrglo

Tvrdnja bez uvjeta pod kojim pada je marketing. Ovi uvjeti ruše dio gradnje:

1. **Ako WireGuard s ruba padne ispod dostupnosti `ssh -R`** kroz tjedan paralelnog
   mjerenja → F3 je pogoršanje, vraća se `ssh -R` i traži se drugi uzrok.
2. **Ako CGNAT na X96 ne propušta ni izlazni UDP handshake** → F3 ne pomaže na tom
   uređaju i prije F4 nema smisla graditi dalje.
3. **Ako se `dnkd` i javni DNS razilaze češće nego mjesečno bez ljudske izmjene** →
   dva imenika su pregrešna za produkciju i PELUD ostaje samo objava, ne put.
4. **Ako `.dnk` ime traži instalaciju CA** da bi bilo iskoristivo → F2 je za
   korisnika neto šteta i staje.
5. **Ako na stvarnim rubnim uređajima mjerenje pokaže EDM** (simetrični NAT) →
   F4 na tom uređaju ne donosi ništa i sidro ostaje relej; gradnja staje dok se ne
   promijeni operater ili oprema.
6. **Ako probijena veza pada češće nego relej kroz sidro** kroz tjedan paralelnog
   mjerenja → F4 je pogoršanje i vraća se na F3 put.
7. **Ako tražilica unatoč `noindex` + `canonical` ipak podijeli signal** (mjerljivo:
   pad pozicija primarne domene ili pojava pulta u indeksu) → moj ispravak je bio
   kriv, c1570 je bio u pravu, i F5 se gasi.
8. **Ako K-od-N češće odbija preusmjeriti nego što spriječi otmicu** — to jest, ako
   je nedostupnost pultova češća od stvarnog napada — konsenzus košta više nego što
   donosi i K se spušta ili se faza gasi.

---

## 11. Niz

**PELUD** — adresa prestaje biti činjenica i postaje tvrdnja s rokom.
**RIZOM** — sidro postaje sastajalište, ne prolaz.
**GODOVI** — dostupnost prestaje biti tvrdnja i postaje povijest koju netko drugi
može provjeriti.

Imena su ovdje zato što mehanizmi postoje i imaju testove. `medijapos-rizom` još
nema ime jer još nema dokaz.
