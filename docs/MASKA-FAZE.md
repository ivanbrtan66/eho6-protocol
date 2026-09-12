# MASKA — pet faza uklanjanja SPOF-a iz adresne indirekcije

> Status ovog dokumenta: **F1 i F2 izgrađeni i testirani. F3 izgrađen kao alat, pilot
> još nije pušten. F4 i F5 nisu izgrađeni.** Gdje piše "nije izgrađeno", to znači
> da koda nema — ne da je "skoro gotovo".
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

### F4 — direktan probod (ICE/STUN rendezvous) ❌ nije izgrađeno

Ovo je faza koja **ubija SPOF**: sidro radi rendezvous, klijenti probiju NAT, promet
ide peer-to-peer. Sidro tada zna samo *tko postoji*, ne i *što se prenosi*, i pad
sidra ne ruši vezu. Tek tada Fasada prestaje biti jedina dodirna točka.

Nije izgrađeno i nije trivijalno: treba ICE kandidate, STUN, i fallback za simetrični
NAT (gdje probod ne radi i sidro ostaje relej). **F3 bez F4 samo premješta
ovisnost** — s `ssh -R` na WireGuard sidro. To je manje krhka ovisnost, ali je
ovisnost.

### F5 — K-od-N oglasnik ❌ nije izgrađeno, i možda se ne smije graditi

Tri registrara, tri TLD-a, tri jurisdikcije; 2-od-3 konsenzus prije preusmjeravanja
(obrazac iz c1496/c1497). Skupo, i **jedina faza koja plaća dosegom**: dijeli Google
signal na tri domene. Ako je SEO doseg i dalje zahtjev — a u c1570 je bio izričit —
**F5 se ne gradi.** Ovo je odluka, ne tehnički nedostatak.

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
14 ms. Pure-Python kripto ovdje nije usko grlo.

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
je dodatni put. F5 nije neutralan i zato je zadnji i uvjetan.

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

---

## 11. Niz

**PELUD** — adresa prestaje biti činjenica i postaje tvrdnja s rokom.
**RIZOM** — sidro postaje sastajalište, ne prolaz.
**GODOVI** — dostupnost prestaje biti tvrdnja i postaje povijest koju netko drugi
može provjeriti.

Imena su ovdje zato što mehanizmi postoje i imaju testove. `medijapos-rizom` još
nema ime jer još nema dokaz.
