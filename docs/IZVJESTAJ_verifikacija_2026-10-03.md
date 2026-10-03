# Verifikacija: prezentacija „DNK vs Krunica" + repozitorij eho6-protocol
Datum: 3.10.2026. · grana `claude/project-analysis-tests-3v00ko`

## Otvorene odluke (WIP = 3)
1. **Što s `eho6_node.py` prije javne objave:** popraviti 4 nalaza iz §3 (CORS/izlaganje tokena, TLS fallback, validacija iznosa, nepotpisan daemon) ili ga držati izvan javnog URL-a. Preporuka: popraviti, jer README tvrdi „Truth is proven".
2. **Poligon krug 3:** pred-registrirati H-BRZ-2 (manji blokovi unutar klasa) i H-RJ-2 (stupčani binarni zapis), ili prvo H-ZRNO-4 (rub piše), koji je pred-registriran u c10195, a nije ni mjeren ni naveden na stranici.
3. **Gdje živi poligon kod:** `poligon_krug2.py`, `poligon_zrno.py`, `dnk_zrno.py` nisu u ovom repozitoriju (vidi §1), pa ih nitko izvana ne može ponoviti.

## 1. Korak Nula: tri sloja

| sloj | što je izmjereno | naredba / izvor |
|---|---|---|
| **kod (ovaj repo)** | 4 datoteke, **0 testova prije ovog rada**. Poligon-skripte (`poligon_krug2.py`, `poligon_zrno.py`, `dnk_zrno.py`, `eho10_alat`) nisu u repozitoriju, nalaze se samo na NEW/EU (EU: `/var/www/genesis/protokol/poligon_kod/`, provjereno 3.10.). | `find . -type f` → README, eho6_node.py, install.sh, .gitignore |
| **lanac** | Atomi c10195, c10202, c10206, c10275, c10277 postoje i **svi brojevi sa stranice odgovaraju lancu** (vidi §2). | `mcp__MAX__read_file` nad `/var/www/genesis/schema_dokarh/genesis/c10{195,202,206,275,277}_*` |
| **dokument (stranica)** | HTTP 200, 17.642 B, tema/širina/konzola/4xx/vodoravni skrol provjereni (§2c). | `curl`, Playwright |

**Razlika među slojevima (prvi nalaz):** stanje flote, `flota_status` u ovoj sesiji: EU lanac_visina **10384**, ES/DE/NEW **10379**; dok_count EU 550.917, ES 550.916, NEW 550.858, DE 550.805; MAR i rubni NEPOZNATO (timeout / izvan dosega). Razlika od 5 blokova i 112 atoma na DE može biti obična replikacijska zaostalost, ali nije izmjereno koja. Vrijednost: **NEPOZNATO**; predlažem atom s presudom prije sljedećeg poligona.

## 2. Prezentacija: što drži, što ne

### 2a. Brojke sa stranice naspram lanca (provjereno čitanjem atoma)
| tvrdnja na stranici | izvor u lancu | stanje |
|---|---|---|
| H-ZRNO-2: 300/300, 150/150 NEPOZNATO, 500/500, 0/1000, 1000/1000 ×2, režija 1,4× | c10277 | podudara se |
| H-RJ-1 333 B/atom naspram 201,5; H-BRZ-1 p95 16,96 ms; 11,5×; 1,17×; ~75× | c10277 | podudara se |
| H-DNK-1 8/30, H-DNK-2 0/30, H-DNK-3 0/90 tihih krivih | c10202 | podudara se |
| 119,6 MB → 2,72 MB, 44×; 448 B = 14 hasheva; 19,9 mil. nt; 11 fg | c10206 | podudara se |
| Aritmetika (moj izračun): 119,6/2,72 = 43,97; 1609/139 = 11,58; 285/244 = 1,168; 8,21/0,11 = 74,6; 2,72 MB·8/1,09 = 19,96 M nt; 19,9 M nt · 330 g/mol / N_A ≈ 10,9 fg | — | točno |
| Kriteriji upisani prije mjerenja | c10195 (H-ZRNO-1..4) i c10275 (krug 2) prethode rezultatima c10206/c10277 | drži |

### 2b. Nalazi o samoj stranici (poredani po težini)
1. **„251 klasa" miješa dvije veličine klasa.** c10206: „korijen Rust=Python na 251 zrnu **(N=54)**". Ostatak stranice govori o klasima od **256** atoma (≈53 klasa). Čitatelj ne može znati da je 251 iz N=54. Popravak: napisati „251 klas (N=54)" ili ponoviti mjerenje za N=256.
2. **H-ZRNO-4 (rub piše, 0 izgubljenih / 0 dvostrukih) nedostaje na stranici.** Pred-registriran je u c10195, a u lancu nema rezultata. Po pravilu 19 mora stajati kao NEPOZNATO, a ne šutke izostati. Stranica navodi H-ZRNO-1…4 u izvorima, a prikazuje 1–3.
3. **Nule bez gornje granice (pravilo 5).** „0/1.000 prihvaćeno", „tihi krivi 0/90", „300/300", „10.000/10.000" treba pisati kao „≤ 3/N" (pravilo triju): 0/1000 → ≤ 0,3 %, **0/90 → ≤ 3,3 %** (to je najslabija brojka na stranici, a nosi presudu DRŽI za H-DNK-3), 0/150 → ≤ 2 %.
4. **Rječnik presuda je dvojak.** c10195 kaže „k−1 komada daje **glasni PAD**", c10275 to mijenja u „**NEPOZNATO**". Stranica koristi NEPOZNATO. Promjena je pred-registrirana prije krug-2 mjerenja, pa je legitimna, ali treba je imenovati („NEPOZNATO zamjenjuje glasni PAD, c10275").
5. **Uvjeti mjerenja brzine:** toplo, jedna mašina (NEW), nije mjereno hladno ni uz Postgres. Stranica to piše. Prijedlog: dodati i broj jezgri i kopiju izlaza (`ccc47102…e4d6`) uz link koji se može preuzeti.
6. **Harness 3 preglednika:** u ovoj sesiji pokrenut je samo **Chromium** (Firefox/WebKit nisu instalirani). Za pravilo 26 vrijedi „napisano", ne „testirano", za ostala dva.

### 2c. Harness nad stranicom (Chromium, 2 teme × 2 širine)
Naredba: `python3 h.py` (Playwright 1.x, Chromium 1194, `ignore_https_errors` jer sandbox proxy ponovno potpisuje TLS), exit 0.

| tema | širina | konzola | 4xx/5xx | vodoravni skrol (px) |
|---|---|---|---|---|
| tamna | 390 | **1 greška: `ERR_TOO_MANY_RETRIES`** (jedan resurs) | 0 | 0 |
| tamna | 1280 | 0 | 0 | 0 |
| svijetla | 390 | 0 | 0 | 0 |
| svijetla | 1280 | 0 | 0 | 0 |

Jedna greška pri prvom učitavanju nije ponovljena u ostalim trima prolazima; vjerojatno artefakt sandbox proxyja, ali bez ponavljanja n ≥ 30 presuda je **NEPOZNATO**, ne PAD. Test toka greške/potvrde nije primjenjiv: stranica nema forme. `curl -I`: `Strict-Transport-Security` postoji; **nema** `Content-Security-Policy`, `X-Content-Type-Options`, `X-Frame-Options`.

## 3. Novi testovi za `eho6_node.py`
`python3 -m pytest tests -q` → **15 passed, 6 xfailed, exit 0** (9,2 s).

Potvrđeno (prolaz):
- Ed25519 daje RFC 8032 vektore (TEST 1 potpis i ključ, TEST 2 ključ) i **0 razlika u 30 nasumičnih potpisa** naspram biblioteke `cryptography`.
- FraktalToken je 32 B, raspored `>BBHI8s16s`, anchor ne ovisi o redoslijedu ključeva, granice 100 / 10.000.
- HTTP: `/health` 200, `/eho6/verify` 400 bez `order`, 32-bajtni token, 404.

Nalazi (xfail strict, test će pasti čim se kod popravi pa se oznaka mora ukloniti):
| # | nalaz | težina | dokaz |
|---|---|---|---|
| 1 | `/eho6/login` vraća `session_token`, a server šalje `Access-Control-Allow-Origin: *` i sluša na `0.0.0.0` bez autentifikacije: bilo koja web-stranica u pregledniku vlasnika čvora (ili iz LAN-a) može ga dobiti | visoka | `test_no_wildcard_cors_on_login` (xfail) |
| 2 | `_http_request`: na **bilo koji** `URLError` (uključujući `HTTPError`, odnosno 4xx/5xx) ponovno pokušava s `CERT_NONE`, a `_api_call` zatim ide na `http://217.160.71.124` bez TLS-a. Login potpis i token putuju u čistom tekstu, a svaka greška servera isključuje provjeru certifikata | visoka | pročitano u kodu (`eho6_node.py:218-231, 244-252`), **nije pokrenuto**: napisano |
| 3 | `classify_organ`: iznos −5 → RIBOSOM, NaN → VM_JEZGRA, „abc" → `ValueError` → HTTP 500 umjesto 400 | srednja | 2 xfail testa, izlaz: `-5 1`, `nan 3`, `abc EXC ValueError` |
| 4 | README: `phi_t = … XOR F(32)`; kod: `PHI_XOR = 3524578` što je **F(33)**; F(32) = 2178309 | niska (dokument ≠ kod) | `test_phi_xor_matches_readme` (xfail) |
| 5 | `/eho6/verify` uvijek vraća `"verified": true`; token nije potpisan ključem čvora, anchor je prvih 8 B SHA-256 (64 bita). To je **otisak**, ne verifikacija | srednja | `build_fraktal_token` (kod) |
| 6 | `HTTPServer` je jednonitni: jedan `/eho6/login` s 2×30 s timeouta blokira `/health` | srednja | pročitano u kodu, nije izmjereno |
| 7 | `install.sh` preuzima `eho6_node.py` bez provjere potpisa ili hasha pa ga izvršava (`curl | bash` lanac). README tvrdi 2-of-2 sidra, ali daemon se ne provjerava ni jednim od njih | visoka | `install.sh:305-318` |
| 8 | Ključ se piše pa tek zatim `chmod 600`; mapa `~/.eho6` nije 0700 (pravilo 8) | niska | `install.sh:74, 128, 149` |
| 9 | `admit.json` se vjeruje kao lokalna datoteka; 2-of-2 potpisi se ne provjeravaju protiv ugrađenih ključeva sidara | srednja | `NodeState.load` |
| 10 | Čisti Python Ed25519: ~182 ms medijan po potpisu (p95 188,6 ms, n=30), nije konstantnog vremena | niska (izmjereno) | `sign ms median 182.3 p95 188.6` |

Pravilo 8–13: nijedna postojeća datoteka nije mijenjana. Dodani su samo `tests/test_eho6_node.py` i ovaj izvještaj. Produkcija: samo čitanje (`list_files`, `read_file`, `flota_status`), bez `exec_command` i `write_file`.

## 4. Preporuke i inovacije

### Deset riječi: koju dokazuje koji test
| riječ | današnji test | što nedostaje |
|---|---|---|
| ISTINIT, DOKAZIV | dokaz 448 B, 10.000/10.000, Rust = Python | gornja granica po pravilu 5 |
| NEUNIŠTIV, SAMOISCJELJUJUĆ | RS 5-od-7, 300/300, otrovan komad 500/500 | obnova na X96 (NEPOZNATO), H-ZRNO-4 |
| SVJEDOČEN | pred-registracija u lancu | javni verifikator koji ponavlja bez povjerenja |
| PRENOSIV | Rust → WASM | ponavljanje u pregledniku (Firefox/WebKit) |
| ŽIV, SAMOSTALAN | — | javni verifikator na internetu (prioritet po tvojoj uputi) |
| ZABORAVLJIV PO VOLJI | — | nijedan test; predlažem H-ZABORAV-1 (kriptografsko brisanje klasa, ostaje korijen) |
| DIGITALAN | — | — |

### Pet kutova (svaki mijenja odluku)
1. **Ispod radara (ono što nitko ne mjeri):** nedostaje test koji bi pao da netko tiho promijeni *kriterij*. Predlažem **kanarinac kriterija**: skripta koja svaki dan uspoređuje SHA-3 teksta kriterija iz PREDREG atoma s onim u kodu poligona, a razlika je NEPOZNATO s alarmom. *Odluka koju mijenja:* može li pravilo 19 postati strojno provjerljivo.
2. **U stranu (isti obrazac iz druge domene):** blokovi unutar klasa s pomakom u zaglavlju (kao bazeni oliga u DNK) rješavaju H-BRZ-1 PAD (jedan atom 8,2 ms, cilj ≤ 10 ms p95). Isti obrazac kao *Zarr/Parquet row-group* indeks. *Odluka:* idući poligon krug je H-BRZ-2, ne H-RJ-2, jer je rječnik grane već pao u mjerenju (333 naspram 201,5 B; lzma unutar klasa uči ponavljanja).
3. **Dron (prema 2050.):** javni verifikator kao jedna statična HTML + WASM datoteka koja prima atom i dokaz od 448 B, vraća DRŽI / PAD / NEPOZNATO bez ikakve mreže. Zajedno s **Merkle potpisom vremena** (tvoj arhivski žig, PQ hibrid: Ed25519 + ML-DSA) daje valjanost ≥ 11 g. *2050.:* netko izvadi DNK ili USB iz ladice, otvori jednu datoteku i dobije presudu. *Sutra:* sastaviti verifikator iz postojećeg Rust crate-a `eho10` (već ima Rust MMR; nalaz c10206: `_jezgra` ne izvozi MMR, treba WASM izvoz).
4. **Iza kulisa (što će se pokvariti):** (a) poligon kod nije u repozitoriju pa se ne može ponoviti izvana; (b) EU 10384 naspram 10379 na ostalima; (c) `eho6_node.py` §3 nalazi 1, 2, 7 postaju realan napad čim README ode van; (d) nema CSP zaglavlja na javnim stranicama. *Odluka:* prije javnog URL-a node popraviti.
5. **Druga strana medalje:** DNK-simulacija PAD 8/30 možda ne znači da je dekoder loš, nego da su parametri kanala (p = 0,5 %, ispad 10 %) pesimistični u odnosu na stvarnu sintezu. Pošteno je dodati **osjetljivost** (mreža p ∈ {0,1; 0,25; 0,5; 1} %) kao zasebnu pred-registriranu hipotezu, umjesto jedne točke. *Odluka:* L1 kriterij 30/30 mora biti definiran nad rasponom, ne nad jednom točkom, inače se „prolaz" može postići biranjem blagog kanala.

### Konkretne nadogradnje (poredano)
1. **Crveni tim koji ne spava:** dnevni `cron` nad testnom instancom koji generira napade (ispuštanje/umetanje/zamjena/zamjena komada) iz *fuzzera* sa zapisanom presudom prije pokretanja, rezultat kao atom. Postojeći test (1.000 ispuštanja) je jedan seed; fuzzer daje stotine tisuća uz isti kriterij, i tako 0 događaja prelazi u ≤ 3/10⁵.
2. **Svojstveni testovi (property-based, Hypothesis):** za RS i MMR: *za bilo koji podskup k od n komada, obnova je ili točna ili NEPOZNATO*. Zamjenjuje 300 ručnih kombinacija stotinama tisuća.
3. **Diferencijalni test Python ↔ Rust ↔ WASM** na istom korpusu, jedan JSON izlaz s hashem.
4. **`eho6_node.py`:** ukloniti `CERT_NONE` fallback, ograničiti CORS na `localhost`, vezati na `127.0.0.1`, potpisati daemon sidrima i provjeriti ih u `install.sh`, `ThreadingHTTPServer`, validirati `amount`.
5. **Stranica:** dodati preuzimanje sirovog izlaza koji odgovara hashu `ccc47102…e4d6`, popraviti §2b 1–4, dodati CSP.

## 5. Kako ovo izgleda 2050. i što od toga radimo sutra
- **2050.:** zapis nosi vlastiti verifikator i potpis vremena koji preživi kvantno računalo; kopije su u lancu, na papiru i u DNK; čvor na telefonu je isti kod kao verifikator u pregledniku.
- **Sutra:** (1) §3 popravci čvora uz zelene testove, (2) kanarinac kriterija, (3) WASM verifikator iz `eho10`, (4) H-ZRNO-4 mjerenje, (5) H-BRZ-2 pred-registracija.

## Što nije napravljeno
- Nije pokrenut nijedan poligon test, jer skripte nisu u repozitoriju i ne smijem pisati na produkciju. Sve brojke u §2a su **pročitane iz lanca**, ne ponovljene.
- Firefox i WebKit nisu pokrenuti.
- `grep` nad serverom za pretragu cijelog `/var/www/genesis` istekao je nakon 60 s; ciljana čitanja radila su.

## Dodatak: eho6 naspram eho_v2 (izmjereno na EU, samo čitanje)
- `paketi/eho_v2` (2.0.0a3) = EHO-10: `zapis` (kanonski CBOR + Ed25519 + Base45), `kod4d`, `presude`, `citac`, `qr_eho10_4dimenzije`, `mmr`, `glava`, `fuzija`, Rust jezgra (`_jezgra`, `_provjera`, WASM). Poligon skripte (`protokol/poligon_kod/poligon_krug2.py`, `poligon_zrno.py`) uvoze `eho_v2.mmr` i `eho_v2._jezgra`.
- `grep eho6|FraktalToken|RIBOSOM` nad `paketi/` = 0 pogodaka; nijedan atom u lancu ne sadrži oba imena (`eho6.{0,200}eho_v2` = 0). eho6 admisija/login/bridge živi odvojeno: `eho/eho6_engine.py`, `eho6_bootstrap.py`, `api/eho6_*.py`, `services/eho6_admit_service.py`.
- `eho_v2.zapis.potpisi` potpisuje kanonski CBOR polja, dok `eho6_node.genesis_login` potpisuje sirove bajtove `ts`. Poruke su različite pa izravna zamjena potpisa lomi provjeru na serveru bez izmjene servera.
