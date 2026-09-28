# Puni pristup za Pro (cloud) sesiju — što CC/Ivan mora napraviti

> Cilj (Ivan, laptop, 28.09.): Pro staza (ova cloud sesija) dobiva ravnopravan, puni pristup — ne samo verifikacija nego i izvršenje popravka. Kraj pregovaranja.
> Pisano iskreno: jedan strop se NE može ukloniti iz clouda, i to je jasno navedeno (§0).

## 0. Tvrda istina o stropu (izmjereno u ovoj sesiji)
- Ovaj cloud kontejner izlazi van **samo preko HTTPS proxyja**. Izmjereno: TCP na `genesis.limit-connect.com:22` → **timeout** (SSH nedostupan), HTTPS → prolazi (403 bez tokena).
- Zato **SSH root** (kako radi tvoja lokalna CC) iz ove sesije **nije moguć** — to je fizička granica clouda, ne dozvola.
- **Maksimum koji Pro cloud sesija fizički može dobiti = puni HTTPS MCP** (`/max/`, `genesis-mcp-full`, radi kao `www-data`): `exec_command`, `write_file`, `restart_service`, `query_db` nad flotom. To je paritet s Max stazom preko MCP-a; SSH-superset ostaje samo na tvom lokalnom stroju.

## 1. Konektor — puni MCP na claude.ai (glavni korak)
Ova sesija sada ima samo `Genesis_EU_read-only` (routiran na RO jer ide `?token=` u URL-u, po c2122).
Za puni pristup treba konektor koji nginx routira na **puni** upstream. Po `mcp_auth.conf`: **Bearer header → puni 8765/8767**, dok `?token=` query → RO. Dakle:

1. Na **https://claude.ai/customize/connectors** dodaj *custom MCP (SSE)* konektor:
   - URL: `https://genesis.limit-connect.com/max/sse` (puni, 8767) — ili `/mcp/sse` s Bearerom (puni 8765).
   - Autentikacija: **Authorization: Bearer <PUNI token>** (postojeći „full" token iz `eu:/etc/nginx/conf.d/mcp_auth.conf`, mapa `$mcp_token_ok`). **Token se upisuje u postavke konektora, nikad u chat.**
   - Ime npr. `genesis-eu-full`.
2. **Pokreni novu sesiju** (konektori se učitavaju na startu sesije). Nova sesija tada dobiva `exec_command/write_file/restart_service/query_db`.

> Zašto Bearer, ne query token: query token je javno u URL-u postavki (procurio jednom, c2122) i namjerno ide na RO. Bearer header ide na puni upstream i ne stoji u URL-u.

## 2. Permission mode sesije — da izvršim, ne samo predložim
Da mogu odraditi popravak bez zaustavljanja na svakom koraku, nova Pro sesija treba krenuti u autonomnijem modu:
- pri pokretanju sesije postavi permission mode na **acceptEdits** (ili **dontAsk**), umjesto default „pitaj za sve".
- to je postavka pokretanja cloud sesije (claude.ai/code), nije nešto što ja sam mogu podići.

## 3. GitHub — već imam, provjeri opseg
- Push na `ivanbrtan66/eho6-protocol` i otvaranje draft PR-ova **već radi** (radim to cijelu sesiju).
- Ako želiš da smijem i **mergeati** i raditi na drugim repoima flote, dodaj ih preko `add_repo` / GitHub App instalacije; reci koji repoi ulaze u opseg.

## 4. Mreža (samo ako 403 ostane)
Ako i s Bearerom dobijem 403/407 od proxyja prema `genesis.limit-connect.com`, tada environment network policy blokira host → u postavkama okruženja (cloud environment meni u naslovnoj traci → Edit → Network access) dodaj `genesis.limit-connect.com` u dopuštene domene ili podigni razinu pristupa.

## 5. Guardraili koji OSTAJU i s punim rukama (moja obveza)
Puni pristup ≠ bezobzirno. Nastavljam po protokolu (CLAUDE.md):
- Produkcija samo uz tvoj izričit „DA" (11); rad na test-stablu inače.
- Prije svake izmjene: `.bak` s UTC pečatom + `chown www-data`, ključevi 0600 (8).
- Izolacija: provjera da modul ne dira druge domene/baze/tajne (12).
- INTENT atom prije, RACUN atom poslije, hash prije/poslije (13).
- Trostanje DRŽI/PAD/NEPOZNATO; nikad lažni OK (15).
- Nikad ne brišem/gasim test da bih „zazelenio"; nikad prazan commit; ne prepisujem tuđu povijest.
Ovo nije kočnica na brzinu — to je ono što razlikuje „trezne glave i odriješene ruke" od štete.

## 6. Alternativa (ako ipak želiš uže) — jedan redak
`genesis-eu-write` (uski, samo write u whitelist + atomi) iz `docs/genesis-eu-write/SPEC.md` daje manje moći uz manju površinu napada. Ti si tražio PUNI/ravnopravni pristup → preporuka je §1 (puni), a uski ostaje kao opcija ako se predomisliš.

## 7. Što se mijenja čim dobijem §1+§2
Prelazim s „predloži" na „napravi + priloži dokaz": `qr4d/izvor.py` spoj na arhiva-core, deploy `/prez/`, pokretanje harnessa, i sustavno pegланje nagomilanog koda — svaki popravak s tripletom i chain atomom.
