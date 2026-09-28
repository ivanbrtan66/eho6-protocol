# SPEC — `genesis-eu-write` (uski MCP kanal za pisanje u flotu)

> Izvor mjerenja: čitano s `eu:/var/www/genesis` i `eu:/etc/nginx` (2026-09-28), samo za čitanje.
> Ovaj dokument je specifikacija; ne dira eu čvor. Implementacija je Ivanov korak (SSH s Windows stroja).
> Nijedna tajna (token, ključ) nije u ovom dokumentu — namjerno (Z29, pravilo 8).

## 1. Zašto poseban kanal, a ne postojeći `mcp-full`

Izmjereno na eu:
- **`mcp_server_ro.py`** (port 8766) — 8 alata, **samo čitanje**; `write_file`/`exec_command`/`restart_service`/`query_db` **nisu registrirani** (strukturna granica, ne provjera). Ovo je kanal koji trenutno vidim iz cloud sesije (`Genesis_EU_read-only`).
- **`mcp_server_full.py`** (port 8767, ruta `/max/`) — 10 alata, uključ. `exec_command`, `write_file`, `restart_service`, `query_db`. Radi kao `www-data`; može čitati `.env` i pisati po kodu. Flota je EU-only jer `www-data` nema SSH ključeve.
- Vrata: `nginx` troprolazni gate (`conf.d/mcp_auth.conf`) — IP allow-lista **ili** Bearer header → puni 8765/8767; **samo `?token=` (claude.ai)** → read-only 8766. Zatvoreno c2122 baš zato što token stoji u URL-u u claude.ai postavkama i jednom je već procurio.

**Zaključak (istina, bez uljepšavanja):** dati cloud sesiji `/max/` znači `exec_command` kao `www-data` nad cijelim eu stablom kroz token koji živi u URL-u. To krši pravila 11, 12 i točku 16(d). Zato **novi, uži** kanal `genesis-eu-write` (port **8768**, ruta **`/write/`**) koji NE nudi `exec_command`, NE nudi `restart_service`, NE nudi `query_db`, i piše samo unutar bijele liste putanja.

## 2. Model prijetnji (NATO točka 16a)

| Protivnik | Sposobnost | Svojstvo koje jamčimo |
|---|---|---|
| Napadač koji je pročitao `?token=` iz claude.ai URL-a | šalje proizvoljne `write_file` pozive | ne može pisati izvan bijele liste; ne može pokrenuti kod; ne može čitati/pisati tajne; svaki upis je atom u lancu s hashem prije/poslije |
| Zlonamjeran ili pogrešan LLM poziv (moja strana) | traži pisanje po produkciji | odbijeno: dopušteno je samo testno stablo + izričito spojene mape; produkcija samo uz Ivanov `DA` flag |
| Kompromitirani `www-data` na eu | poseže za istim procesom | novi servis radi kao **zaseban** OS korisnik `genwrite` (ne `www-data`), s pristupom samo whitelist stablu i lancu preko `chain_upisi.sh` |

Ono što ovaj kanal **NE** rješava i mora se reći: token u URL-u ostaje slaba točka svih claude.ai konektora. Zato je jedina obrana uskost (mali skup alata + whitelist), ne povjerenje u token.

## 3. Alati (točno tri, ništa više)

### 3.1 `write_file(path, content, dopusti_produkciju=False)`
- **Whitelist korijena** (mjeri se `realpath -m`, kao u RO instanci):
  - `/var/www/genesis/_test/**` — testno stablo (default meta)
  - dodatne mape samo ako ih Ivan doda u `WRITE_WHITELIST` env varijablu servisa
- **Crna lista** = ista `_tajna()` logika kao RO (`.env`, `*.key`, `*.pem`, `.ssh`, `xmr_*`, `wallet.dat`, `.keys`…). Pisanje tajne je uvijek odbijeno.
- **Produkcija** (`/var/www/genesis/**` izvan `_test`) samo ako `dopusti_produkciju=True` **i** env `GENWRITE_PROD_OK=1` (Ivanov `DA` iz pravila 11). Bez oba → odbijeno.
- **Backup prije upisa**: `cp -a <f> <f>.bak_$(date -u +%Y%m%dT%H%M%SZ)` (pravilo 8 — UTC timestamp). Ako original ne postoji → `NEMA_ORIGINALA`, nastavlja se.
- **Dozvole novih datoteka/mapa**: `chown genwrite:www-data`, datoteke `0664`, mape `0775` (pravilo 8; www-data grupa da nginx može čitati statiku).
- **Readback dokaz (Z48)**: nakon upisa čita `wc -c` + `sha256sum`, uspoređuje s očekivanim; vraća `READBACK_MATCH: true/false`. Ako `false` → status **PAD**, ne tvrdnja o uspjehu.
- **Atom u lanac (pravilo 13)**: prije upisa INTENT atom (`putanja`, `baseline_hash`, `sesija`, `namjera`), poslije RACUN atom (`hash_prije`, `hash_poslije`, referenca na INTENT). Ide kroz **postojeći** `protokol/intent.py` → `chain_upisi.sh` (flock, jedan brojač na EU). Ne duplicira se numeracija (pravilo 20).
- **Trostanje izlaza (pravilo 15)**: `DRŽI` (upis + readback + oba atoma OK) / `PAD` (readback ne slaže ili atom odbijen) / `NEPOZNATO` (lanac nedostupan — upis se tada **ne** izvršava, jer bez traga nema pisanja).

### 3.2 `zivi_intenti(path)`
- Vraća tuđe otvorene INTENT-e na istoj putanji (OCC upozorenje, pravilo 12/kolizije). Read-only, poziva `intent.zivi_intenti`.

### 3.3 `visina_lanca()`
- Trenutna visina lanca (`intent.visina`). Za pred/post mjerenje pomaka (Z48). Read-only.

**Namjerno izostavljeno:** `exec_command`, `restart_service`, `query_db`, `delete_file`, `chmod`. Restart servisa i migracije ostaju Ivanov/CC SSH put — cloud sesija ih ne dobiva.

## 4. Infrastruktura (Ivanovi koraci na eu, preko SSH)

1. **OS korisnik**: `useradd -r -s /usr/sbin/nologin -g www-data genwrite`; `mkdir -p /var/www/genesis/_test && chown genwrite:www-data /var/www/genesis/_test && chmod 2775 /var/www/genesis/_test`.
2. **Servis** `genesis-mcp-write.service` (predložak niže) → port `127.0.0.1:8768`, `User=genwrite`, `ExecStartPre` import-gate (Z47/Z57, kao kod RO/full).
3. **nginx ruta** `/write/` u `sites-enabled/genesis-eu` — **vlastita mapa tokena**, odvojena od `mcp_auth.conf`, s **zasebnim** `$genwrite_ok` (novi token, novi ID, opoziv jednim retkom). Gate: `if ($genwrite_ok = 0) { return 403; }` → `proxy_pass http://127.0.0.1:8768/mcp/;`. Token se NE dijeli s `/mcp/` ni `/max/`.
4. **Audit**: `/var/log/genesis-mcp/audit_write.log`, red po pozivu (alat, putanja, rc, readback, cNNNN atoma).
5. **claude.ai konektor**: dodati kao custom SSE konektor `https://genesis.limit-connect.com/write/sse?token=…` na https://claude.ai/customize/connectors; token upisati **tamo**, nikad u chat; nova sesija ga učita.

### Predložak `genesis-mcp-write.service`
```ini
[Unit]
Description=Genesis MCP WRITE (EU) — uski whitelist kanal, port 8768
After=network.target
StartLimitIntervalSec=300
StartLimitBurst=10

[Service]
Type=simple
User=genwrite
Group=www-data
WorkingDirectory=/var/www/genesis
Environment=WRITE_WHITELIST=/var/www/genesis/_test
# GENWRITE_PROD_OK ostaje NEPOSTAVLJEN dok Ivan izričito ne dopusti produkciju
ExecStartPre=/var/www/genesis/.venv/bin/python -c "import importlib.util,sys; s=importlib.util.spec_from_file_location('m','/var/www/genesis/mcp_server_write.py'); m=importlib.util.module_from_spec(s); s.loader.exec_module(m)"
ExecStart=/var/www/genesis/.venv/bin/python /var/www/genesis/mcp_server_write.py
Restart=always
RestartSec=3
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

## 5. Kako ovo izgleda 2050 (pravilo — horizont dizajna)
Token u URL-u nestaje: konektor se veže na **potpisani capability** (kratkoživući, vezan uz sesiju i uređaj, opoziv jednim atomom). `genesis-eu-write` je tada samo izvršitelj politike koju lanac potpisuje. Ono što gradimo sutra: whitelist + zaseban korisnik + atom po upisu — jer to su isti gradivni blokovi koje capability model kasnije samo pooštri.

## 6. Deset riječi — što ovaj modul dokazuje
**SVJEDOČEN** (svaki upis je atom s hashem prije/poslije) i **DOKAZIV** (readback + trostanje). Test u `TEST.md` mjeri upravo to.
