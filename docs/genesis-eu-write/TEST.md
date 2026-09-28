# TEST — `genesis-eu-write` (trajni gate, po uzoru na `tools_test_mcp_ro.py`)

> Pred-registrirani kriterij (pravilo 19): kriterij se ne mijenja nakon mjerenja; PAD je rezultat kao i PROLAZ.
> Test se izvodi na eu, protiv `mcp_server_write.py`, prije prvog spajanja konektora i pri svakom restartu (ExecStartPre-import + ovaj gate).
> `n ≥ 30` ne vrijedi za granične testove (deterministički su, 1 poziv = 1 presuda); vrijedi za mjerenje kašnjenja upisa ako se ono ikad tvrdi (pravilo 5).

## A. STRUKTURA ALATA — MORA BITI TOČNO TRI
```
registrirano == {write_file, zivi_intenti, visina_lanca}
exec_command NE POSTOJI · restart_service NE POSTOJI · query_db NE POSTOJI · delete_file NE POSTOJI
```
Presuda: bilo koji zabranjeni alat registriran → **PAD**.

## B. WHITELIST — MORA PASTI (izvan dopuštenog korijena)
Očekivano: svaki poziv `write_file` vraća odbijeno, na disku se NIŠTA ne mijenja.
```
/var/www/genesis/api/genesis_auth.py         (produkcijski kod, bez prod-flaga)
/var/www/genesis/mcp_server_ro.py            (produkcijski kod)
/etc/nginx/sites-enabled/genesis-eu          (izvan stabla)
/root/notes.txt                              (izvan stabla)
/var/www/fenix-v4/manage.py                  (drugi projekt — Z0 izolacija)
/tmp/x.txt                                    (tmp-leak brana, pravilo 13 + detektor_tmp_leak)
```

## C. TAJNE — MORAJU PASTI (i unutar whitelistа imenom)
Očekivano: `_tajna()` hvata prije ikakvog upisa.
```
/var/www/genesis/_test/.env
/var/www/genesis/_test/id_ed25519
/var/www/genesis/_test/admit_wallet.keys
/var/www/genesis/_test/server.pem
/var/www/genesis/_test/wallet.dat
```
Presuda: bilo koja od gornjih prođe → **PAD** (rupa).

## D. PRODUKCIJA BEZ DOZVOLE — MORA PASTI
```
write_file("/var/www/genesis/public/prez/index.html", "...", dopusti_produkciju=True)
  uz GENWRITE_PROD_OK NEpostavljen  ->  odbijeno (treba i flag i env)
```
Presuda: prođe bez `GENWRITE_PROD_OK=1` → **PAD**.

## E. DOPUŠTEN UPIS — MORA PROĆI, S DOKAZOM (Z48)
```
write_file("/var/www/genesis/_test/dokaz_<pid>.txt", "sadržaj-<utc>")
Očekivano u odgovoru:
  READBACK_MATCH == True
  sha256_na_disku == sha256_očekivan
  backup korak == BACKUP_OK ili NEMA_ORIGINALA
  novi INTENT atom cNNNN  I  novi RACUN atom cMMMM (MMMM referencira INTENT)
  dozvole: datoteka 0664, vlasnik genwrite:www-data
```
Presuda: `READBACK_MATCH=False` ILI nedostaje neki atom → **PAD**.
Kad je lanac nedostupan → status **NEPOZNATO** i upis se NE izvršava (nema traga = nema pisanja).

## F. IZOLACIJA (pravilo 12) — MJERENJE, NE TVRDNJA
Prije/poslije testa E, otisak drugih domena mora biti identičan:
```
sha256 nginx conf-a nepromijenjen · nijedan servis restartan (audit bez restart_service, jer alat ne postoji)
`ps -u genwrite` pokazuje samo mcp_server_write.py · genwrite NEMA shell (nologin)
```

## Skica gate skripte (`tools_test_mcp_write.py`)
```python
# -*- coding: utf-8 -*-
"""Trajni gate za WRITE MCP: tri alata, whitelist drži, tajne padaju, produkcija zaključana,
dopušten upis prolazi s readbackom + dva atoma. Po uzoru na tools_test_mcp_ro.py."""
import asyncio, importlib.util, os, sys, hashlib

spec = importlib.util.spec_from_file_location("w", "/var/www/genesis/mcp_server_write.py")
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
pao = 0

# A) alati
alati = set(t.name for t in asyncio.run(m.mcp.list_tools()))
if alati != {"write_file", "zivi_intenti", "visina_lanca"}:
    print("X A: skup alata nije točno tri:", sorted(alati)); pao += 1
for z in ("exec_command", "restart_service", "query_db", "delete_file"):
    if z in alati:
        print("X A: zabranjeni alat registriran:", z); pao += 1

# B) whitelist — _dozvoljena_putanja mora vratiti False izvan korijena
for p in ["/var/www/genesis/api/genesis_auth.py", "/etc/nginx/sites-enabled/genesis-eu",
          "/root/notes.txt", "/var/www/fenix-v4/manage.py", "/tmp/x.txt"]:
    if m._dozvoljeno(p, prod=False):
        print("X B: whitelist propustio:", p); pao += 1

# C) tajne — _tajna mora uhvatiti i unutar _test
for p in ["/var/www/genesis/_test/.env", "/var/www/genesis/_test/id_ed25519",
          "/var/www/genesis/_test/admit_wallet.keys", "/var/www/genesis/_test/wallet.dat"]:
    if m._tajna(p) is None:
        print("X C: tajna propuštena:", p); pao += 1

# D) produkcija bez flaga
os.environ.pop("GENWRITE_PROD_OK", None)
if m._dozvoljeno("/var/www/genesis/public/prez/index.html", prod=True):
    print("X D: produkcija prošla bez GENWRITE_PROD_OK"); pao += 1

# E) dopušten upis + readback (poziva stvarni alat; piše samo u _test)
tp = "/var/www/genesis/_test/dokaz_%d.txt" % os.getpid()
sad = "dokaz-%d" % os.getpid()
rez = asyncio.run(m.write_file(tp, sad))  # ovisno o potpisu; sync varijanta ako nije async
import json as _j; r = _j.loads(rez) if isinstance(rez, str) else rez
if not r.get("READBACK_MATCH"):
    print("X E: READBACK_MATCH nije True:", r); pao += 1
if r.get("sha256_na_disku") != hashlib.sha256(sad.encode()).hexdigest():
    print("X E: sha256 se ne slaže"); pao += 1
if not (r.get("intent_c") and r.get("racun_c")):
    print("X E: nedostaje INTENT ili RACUN atom:", r.get("intent_c"), r.get("racun_c")); pao += 1

print("REZULTAT:", "PAO — %d rupa" % pao if pao else "PROŠAO — 0 rupa")
sys.exit(1 if pao else 0)
```
> Skica je namjerno usklađena s imenima koja SPEC traži (`_dozvoljeno`, `_tajna`, `write_file` vraća JSON s `READBACK_MATCH`, `sha256_na_disku`, `intent_c`, `racun_c`). Pri implementaciji imena moraju stvarno postojati — inače test pada na `AttributeError`, što je ispravno (pravilo 4: ne pretpostavljaj, mjeri).

## Presuda gate-a
- **PROŠAO — 0 rupa** → kanal se smije spojiti na claude.ai.
- **PAO — N rupa** → kanal se NE spaja; svaka rupa je nalaz, ne upozorenje.
