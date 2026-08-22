# Dispečerski tab „Rute" + OSRM auto-routing (tahograf-mvp)

Patch koji dispečeru daje formu za kreiranje multi-stop rute vozaču. Backend
`POST /api/v1/tahograf/rute` već postoji i radi — nedostajao je samo frontend
koji ga zove, plus izračun optimalnog redoslijeda stopova.

Ciljni projekt je `/var/www/genesis/tahograf-mvp` na Genesis EU nodeu, koji nije
dio ovog repozitorija. Ovdje živi samo patch i skripta za primjenu.

## Što patch dodaje

| Fajl | Izmjena |
|---|---|
| `api/tahograf_features.py` | `POST /api/v1/geo/route` — OSRM Trip proxy: optimalan redoslijed + km/min |
| `api/tahograf_features.py` | `/api/v1/geo/search` dodatno vraća `city/plz/country/admin` |
| `pwa/dispatcher.html` | tab gumb „📍 Rute", panel s formom, CSS |
| `pwa/dispatcher.js` | `RuteModule` — append na kraj, bez diranja postojećeg koda |

Nema migracije baze: `Ruta.destinacije` je `Column(JSON)` bez sheme, pa
`{naziv, adresa, lat, lon}` stane kakav jest. Nema registracije u `app.py` —
`feat_bp` je već registriran, ruta se pojavljuje sama.

## Primjena

```bash
cd /var/www/genesis/tahograf-mvp
python3 apply_rute_patch.py --dry-run    # provjeri anchore, ne piše ništa
python3 apply_rute_patch.py              # backup + primjena + chown www-data
```

Skripta radi `.bak_<timestamp>` kopiju svakog dirnutog fajla, provjerava da je
svaki anchor prisutan **točno jednom** (inače staje prije ijednog pisanja),
`compile()`-a patchani Python prije zapisa, i idempotentna je — drugi pokret
preskoči ono što je već primijenjeno.

Zatim restart backenda (frontend je statički):

```bash
systemctl list-units --type=service | grep -i tahograf
systemctl restart <stvarno-ime-servisa>
curl -s -o /dev/null -w "%{http_code}\n" https://digigraf.online/health
```

Rollback: vrati `.bak_<timestamp>` fajlove i restartaj servis.

## Nalazi iz čitanja stvarnog stanja

Sve niže je pročitano na živom nodeu, ne pretpostavljeno.

**Potvrđeno kako je i planirano**

- `geo_reverse()` blok se poklapa doslovno — anchor drži.
- `requests`, `_UA`, `logger`, `feat_bp`, `verify_token` već postoje u fajlu;
  nema dupliciranja importa.
- `POST /api/v1/tahograf/rute` prima `{driver_weise3, destinacije[], napomena,
  datum}` i vraća `{ok, ruta_id, datum}` (`api/rute_endpoints.py`).
- `pwa/routes.js` čita destinaciju kao `dest.naziv / dest.adresa / dest.lat /
  dest.lon` — točno oblik koji forma šalje, pa se ruta odmah prikaže vozaču.
- `DgGeocode.attachAutocomplete(input, {onSelect})` postoji, a `geocode.js` se
  učitava prije `dispatcher.js`.
- `switch-tab` delegacija u `dispatcher-events.js` zove globalni `switchTab` u
  trenutku klika, pa wrapper nad `window.switchTab` radi.

**Četiri stvari koje su ispale drukčije nego u planu**

1. **CSS panela ne postoji generički.** Plan je pretpostavio da `.on{display:block}`
   pokriva sve panele. U stvarnosti svaki panel ima vlastito id-pravilo
   (`#tab-burza-panel{…display:none}` + `#tab-burza-panel.on{display:block}`).
   Bez dodanog pravila za `#tab-rute-panel` novi bi panel bio trajno vidljiv
   ispod svakog drugog taba. Patch dodaje pravilo.

2. **Izmjena `enterDash()` nije potrebna.** Plan je tražio ubacivanje
   `window._fleetIdGlobal = _fleetId;` u postojeću funkciju. Nepotrebno:
   `fleet_id` je već u `localStorage["tg_disp_fleet_v2"]`, a `#chat-vozac-sel`
   svakih 30 s puni `loadStatus2()` istim popisom vozača. Modul čita ta dva
   izvora, pa je izmjena postojećeg JS-a **nula redaka** — čisti append.

3. **Autocomplete dropdown je bio prazan.** `pwa/geocode.js` crta retke iz
   `item.city / item.plz / item.country / item.admin`, ali `/api/v1/geo/search`
   vraća samo `display_name / lat / lon / lng / tip / adresa`. Ta polja su
   `undefined`, pa dropdown iscrtava prazne retke — a bez odabira adrese nema
   `lat/lon`, bez `lat/lon` nema OSRM poziva. To je blokiralo cijelu novu
   funkciju, i jednako pogađa postojeći dispo origin/dest i Ghost Driver.
   Patch aditivno podiže `city/plz/country/admin` iz Nominatimovog `address`
   objekta; stara polja ostaju netaknuta.

4. **Izračun je gubio destinacije.** Predložena `calc()` je nakon preuređivanja
   iscrtavala samo stopove s koordinatama, pa bi svaki ručno utipkani stop
   (bez odabira iz liste) nestao na klik. Ovdje se takvi stopovi zadržavaju i
   idu na kraj popisa, uz napomenu u zelenoj traci.

**Dvije stvari koje plan nije spomenuo, a mijenjaju postupak**

- `build.js` transpilira `pwa/*.js` **u mjestu** (esbuild → chrome60), pa je
  `pwa/dispatcher.js` ujedno i izvor i build output. Ručna izmjena je ispravna,
  ali dodani kod mora biti ES2017 (bez `?.`, `??`, `||=`) da ga `node build.js`
  ne mijenja. Dodani kod to poštuje.
- `sw.js` je network-first za sve osim `/v/`, i `dispatcher.js`/`dispatcher.html`
  idu kroz tu granu. Nije potrebno dizati `CACHE_NAME` ni `?v=` query — običan
  reload pokupi novu verziju.

## Provjere napravljene prije isporuke

- Svaki anchor grepan na živom fajlu → svaki se pojavljuje **točno jednom**
  (`geo/reverse pao` 1×, `out = [{"display_name"` 1×, `id="tab-burza" data-action`
  1×, `#tab-burza-panel.on{display:block}` 1×, `burza-empty">U` 1×).
- `RuteModule` i `geo/route` **ne postoje** u trenutnim fajlovima — patch se
  primjenjuje na čisto stanje.
- Applier pokrenut na fixture fajlovima izgrađenima od stvarnog sadržaja:
  dry-run → apply → ponovni apply (preskočeno svih 6 hunkova).
- Patchani backend prolazi `py_compile`; patchani `dispatcher.js` prolazi
  `node --check`.
- HTML parser potvrdio da je `#tab-rute-panel` na istoj dubini kao
  `#tab-burza-panel` (sibling unutar `dash-right`), stack uravnotežen.
- Logika redoslijeda provjerena na sintetičkom OSRM odgovoru: ulaz `[A,B,C,D]`
  s `waypoint_index [0,3,1,2]` → `redoslijed [0,2,3,1]` → obilazak `A,C,D,B`
  (start prvi, odredište zadnje, kako `source=first&destination=last` i traži).

## Što još nije provjereno

Ovo je pisano iz sesije koja ima **read-only** pristup nodeu, pa patch nije
primijenjen ni pokrenut na stvarnom sustavu. Neprovjereno ostaje:

- ponašanje `router.project-osrm.org` iz mreže nodea (demo server, javan, bez
  ključa — isti stil poziva kao postojeći Nominatim/Overpass proxy);
- klik-kroz u pregledniku (odabir vozača → 2+ adrese → izračun → kreiranje);
- da se nova ruta pojavi vozaču na `GET /api/v1/tahograf/rute/vozac/<w3>`.

Test nakon primjene:

1. Dispatcher panel → tab „📍 Rute", odaberi vozača.
2. Utipkaj 2+ adrese i **odaberi ih iz padajuće liste** (samo tako se pune
   `dataset.lat/lon`).
3. „🧭 Izračunaj optimalnu rutu" → zelena traka s km i minutama, redoslijed
   preuređen.
4. „✅ Kreiraj rutu" → zelena potvrda; provjera u bazi:
   ```bash
   sqlite3 /var/www/genesis/tahograf-mvp/data/tahograf.db \
     "select weise3_id,driver_weise3,status,destinacije from rute order by created_at desc limit 1;"
   ```
5. Vozačka strana (`app.html` → rute) mora prikazati novu rutu.
6. Namjerno oborena mreža → klik na izračun mora dati **crvenu traku u UI-ju**,
   a gumb „Kreiraj rutu" mora i dalje raditi (izračun je pomoć, ne uvjet).
