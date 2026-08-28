# CLAUDE.md — EHO6 / Genesis kontekst

Ovaj repo je dio Genesis ekosustava. Radni jezik je hrvatski.

## Što je EHO6

Kriptografski membership protokol za distribuiranu edge mrežu. Pristup traži uplatu
(0.001 XMR) i 2-of-2 Ed25519 konsenzus dvaju sidara (EU + DE) — nema centralnog
autoriteta. Detalji u `README.md`.

## Struktura repoa

| Datoteka | Uloga |
|---|---|
| `eho6_node.py` | edge daemon, HTTP server na portu 8091 |
| `install.sh` | instalater (Linux / macOS / Termux), generira Ed25519 par u `~/.eho6/node.key` |
| `README.md` | protokol, API, kriptografija, sidra |

Ključna mjesta u `eho6_node.py`:

- `_handle_health` (~red 474) — `GET /health`, BORG JSON s 13 polja
- `_handle_status` (~red 493) — `GET /eho6/status`
- `make_fraktal_token` (~red 364) — 32-bajtni binarni format
  `[organ:1][intent:1][flags:2][phi_t:4][anchor:8][payload:16]`
- `ed25519_sign` / `ed25519_pubkey` (~red 87) — čisti Python Ed25519, stdlib only (Termux-safe)

`phi_t` je Fibonacci-modulirani timestamp: `(time_ns//1000 XOR F(32)) & 0xFFFFFFFF`.

## Flota

Pet glavnih čvorova: **EU** (Hetzner Frankfurt, sidro), **DE** (IONOS Berlin, sidro),
**ES**, **NEW**, **MAR**. Uz njih rubni čvorovi X96 Mini klase, bez javne domene
(health-only, EU-only doktrina).

Zdravlje se čita HTTP pullom s `/borg/health.json` — kanonski Z17 PULL, bez ključa.
Konsenzus se provjerava tako da svi čvorovi imaju **istu `lanac_visina`**.

Produkcijski kod flote NIJE u ovom repou. Živi na čvorovima pod `/var/www/genesis`,
npr. `services/health_writer.py` i `services/borg_health_writer.py`.

### Pristup floti iz Claude Codea

EU čvor vrti vlastiti MCP server kao systemd servis `genesis-mcp-ro` (read-only)
uz `genesis-mcp` (puni). Read-only varijanta izlaže: `flota_status`, `system_status`,
`list_files`, `read_file`, `grep`, `get_logs`, `dokarh_stats`. Odbija ključni
materijal (`.env`, SSH ključevi, `*.pem`, shadow).

Lokalno se dodaje s `claude mcp add --transport http <ime> <url>`.

## Projekt ZMAJ

Plan gradnje (25.8.2026.) za komunikaciju i sigurnost bez vlastitog izvora energije
ili pohranjenog ključa. Analogija: jedrilica leti bez motora jer crpi energiju koja
već postoji u atmosferi.

- **Komponenta A** — 868 MHz ISM sloj na Semtech SX1262, ETSI EN 300 220, 1% duty-cycle.
  Poznato ograničenje: SX1262 nema RF front-end za pravi pasivni backscatter, pa je
  ovo realno aktivan LoRa beacon. Ne uljepšavati u dokumentaciji.
- **Komponenta B** — LoRa CSS procesno pojačanje, `PG(dB) = 10·log₁₀(2^SF)`.
- **Komponenta C** — PLS izvedeni ključ (Maurer 1993 / Ahlswede-Csiszár 1993):
  information reconciliation + privacy amplification nad koreliranim mjerenjima
  zajedničkog kanala. Poznato ograničenje: LoRa je jednonositeljski CSS sustav,
  nema podnositelje pa nema pravi CSI. Za Fazu 1 se ide na RSSI-based key generation.

Faze: 0 validacija → 1 hardverski prototip → 2 RSSI key derivation →
3 integracija s Ed25519 (fallback, **ne** zamjena) i EHO7 relayem → 4 rollout na flotu.

### Otvoreno pitanje za Fazu 0

BORG health JSON iz `_handle_health` je ~320 bajtova. To ne stane u LoRa paket
(max 255 B) i skupo je po airtimeu: 320 B na SF9/125 kHz traje 1,25 s, što uz
1% duty-cycle znači jedan heartbeat svake ~2 minute; na SF12 je 9 s po paketu i
razmak ~15 minuta. Kompaktan 32-bajtni paket na SF9 traje 247 ms → heartbeat
svakih ~25 s.

Prijedlog: MESH-RF heartbeat graditi na postojećem 32-bajtnom `FraktalToken`
formatu umjesto na JSON-u, uz dokumentirano mapiranje BORG polja.

## Konvencije

- **ZAKON 47/48 — nulti slučaj tihog neuspjeha.** Svaki neuspjeh mora dati eksplicitan
  status. Vrijedi za EHO8CP, a plan ZMAJ ga preuzima kao metriku za key agreement.
  U kodu se to vidi kao `last_error` u health odgovoru.
- **Trostanje (Z53)** umjesto boolean zdravlja: `ok` / `ALARM` / `NEPOZNATO`.
  `NEPOZNATO` znači da izvor ne zna, i to se ne smije prijaviti kao ALARM.
- Poznata ograničenja se pišu u dokumentaciju bez uljepšavanja.
- `eho6_node.py` mora ostati stdlib-only (Termux-safe) — bez vanjskih ovisnosti.

## Poznati rizici

- Kotva + asembler timer je identificiran kao SPOF na EU čvoru (EHO8CP dokumentacija).
  Isti rizik vrijedi ako Komponenta C ovisi o jednom koordinacijskom čvoru.
- RSSI-izvedeni ključevi imaju nisku entropijsku stopu — dovoljno za periodično
  osvježavanje sesijskog ključa, nedovoljno kao jedini izvor dugoročnog identiteta.
- Realan doseg je 20–40% teoretskog LOS maksimuma (Test 02, MESH-RF prezentacija).
  Ne obećavati domet timu bez terenskog mjerenja.
