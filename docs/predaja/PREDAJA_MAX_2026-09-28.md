# PREDAJA → staza MAX · 28.09.2026.

> Kopirati u `Downloads/` na laptopu. Otvoriti u Claude Code sesiji na laptopu (Remote Control ili lokalno) i reći:
> **„Pročitaj Downloads/PREDAJA_MAX_2026-09-28.md i nastavi temu *trojstvo na djelu*."**

## 0. Tko predaje i što
- **Izvor:** cloud sesija (Pro staza), repo `ivanbrtan66/eho6-protocol`, grana `ccr-0e439cd8-geof9p`.
- **Cilj:** staza MAX (laptop) preuzima rad s punim lokalnim pristupom (Downloads, SSH root, flota).
- **Iskreno:** ova cloud sesija **nije vodila** razgovor o temi *trojstvo na djelu*. Taj razgovor je na tvojoj strani ili u drugoj sesiji. Ovaj dokument predaje **činjenice iz ove sesije**, ne izmišlja sadržaj te teme.

## 1. Što je danas napravljeno u ovoj sesiji
| # | Radnja | Ishod |
|---|---|---|
| 1 | Provjera ovlasti repozitorija | `ivanbrtan66` = **admin**, jedini suradnik; čitanje ✅; push na radnu granu ✅ (dry-run) |
| 2 | Provjera kontejnera | `root` (uid 0); datoteke 644 `root:root`; nijedna world-writable |
| 3 | Provjera konektora | `Genesis-eu-full` **aktivan** (exec/write/restart/query_db); `Genesis_EU_read-only` **nije autoriziran** |
| 4 | Pregled `install.sh` | 3 nalaza (§2) — **ništa nije mijenjano** (Ivanova odluka: „ostavljamo ovako") |
| 5 | Pristup mapi Downloads | Cloud **ne može** doći do laptopa → rješenje: `claude remote-control` na laptopu (§3) |
| 6 | Ova predaja + prezentacija | `docs/predaja/` u repou + `/prez/predaja_max_2026-09-28.html` na EU |

## 2. Otvoreni nalazi u `install.sh` (nisu popravljeni — čekaju „DA")
1. **L149 — tajni ključ kratko čitljiv:** `chmod 600` ide *nakon* zapisa → prozor s 644. Popravak: `umask 077` prije `gen_keypair` + `chmod 700 "$EHO6_DIR"`.
2. **~L300 — predvidljiv `/tmp/_eho6_w3id`:** symlink/podmetanje W3ID-a. Popravak: `mktemp` unutar `$EHO6_DIR`.
3. **L374 — systemd servis radi kao root:** nema `User=`. Popravak: sistemski korisnik `eho6` + `chown -R` + `NoNewPrivileges=yes`, `ProtectSystem=strict`, `ReadWritePaths=`.

## 3. Kako MAX dobiva Downloads (jednom)
```bash
# Windows (PowerShell):  irm https://claude.ai/install.ps1 | iex
# macOS / Linux:          curl -fsSL https://claude.ai/install.sh | bash
cd ~/Downloads
claude remote-control
```
Sesija se pojavi u Claude Code aplikaciji → rad izravno nad lokalnim datotekama.
⚠️ **Ne pushati cijeli Downloads na GitHub** (osobni dokumenti, ključevi; limit 100 MB po datoteci).

## 4. Kontekst flote (pročitano danas, samo čitanje)
- Grana `claude/prikaz-uputa-promptu-b3d2h1` (druga sesija, danas): `docs/qr4d/` teorija + prezentacija, `docs/pristup/PUNI_PRISTUP_CC_RUNBOOK.md`.
- Soba za prezentacije: `/var/www/genesis/public/prez/` → `genesis.limit-connect.com/prez/` i `no-limit.world/prez/` (ES zrcalo).
- „Trojstvo" u kanonu ima tri značenja — **MAX mora potvrditi koje je tema**:
  - **ZAKON 27 — Model Trinity:** `weise3_id` + `bunker_seal_id` + `created_at` na svakom modelu.
  - **Trojstvo 2/3 — spaljivanje** (`arhiva_core`): inicijator + suglasnik + hlađenje; R3: 41 test-dokument u `trojstvo_ceka`.
  - **EHO Exchange trojstvo** (`/prez/ehoexchange.html`): krug Zaradi–Plati–Sačuvaj–Dokaži.

## 5. Prvi koraci za MAX
1. Potvrditi koje „trojstvo" je tema i pokazati stanje iz izvora (ne iz ovog dokumenta).
2. Autorizirati `Genesis_EU_read-only` (claude.ai → Settings → Connectors) — pregled bez rizika.
3. Odluka o 3 nalaza iz §2: „DA" → `.bak` + ciljane izmjene + PR.
4. Dodati prezentaciju u indeks `/prez/` i ES zrcalo ako je Ivan želi javno popisanu.

## 6. Guardraili (vrijede i na MAX-u)
`.bak` prije svake izmjene · `chown www-data` · nikad `cat >` preko postojećeg modula · produkcija samo uz izričit „DA" · trostanje DRŽI/PAD/NEPOZNATO, nikad lažni OK.
