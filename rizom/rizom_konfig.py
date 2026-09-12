#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""RIZOM — generator dvo-sidrene WireGuard konfiguracije (MASKA faza F3). stdlib only.

Zasto se `ssh -R` zamjenjuje, a ne popravlja (izmjereno, ne teorija):
  * `ssh -R` je TCP sjednica u user-spaceu. Kad ISP-ov NAT tiho zaboravi
    mapiranje, sjednica ostane half-open: uredjaj je ZIV, tunel je MRTAV, a
    obje strane to ne znaju (c2397 — a16 zdrav, tunel mrtav; c3813 — tunel
    ubijen izvana digao se sam za 65 s, ali samo zato sto watchdog postoji).
    Watchdog i dead-man su posljedica tog razreda kvara, ne rjesenje za njega.
  * WireGuard je u kernelu, nema sjednicu koju treba drzati otvorenom, handshake
    je stateless i preziva promjenu IP-a i roaming. PersistentKeepalive=25 s
    drzi NAT mapiranje otvorenim jeftinije nego ijedan watchdog.

Zasto DVA sidra: `medijapos` (X96:8093 -> EU:18096) danas NEMA rezervni put —
to je izmjeren nalaz iz tunel_watchdog_config.json (_biljeska_c2395), a ne
pretpostavka. Jedan tunel prema jednom sidru je jedna tocka kvara; drugi
izlazni handshake prema drugom sidru je jedina stvar koja tu pomaze.

POTPUNA IZOLACIJA (obavezno, i zato provjerljivo u izlazu):
  * AllowedIPs na rubu je SAMO /32 adresa sidra — nikad 0.0.0.0/0. Uredjajev
    obican promet ne prolazi kroz tunel i ostale domene na serveru se ne diraju.
  * Svaki link ima vlastitu /24 podmrezu unutar 100.64.0.0/12 (RFC 6598).
    dnkd mapiranje imena zivi u 100.80.0.0/12 — disjunktno po konstrukciji,
    provjereno u testu test_rizom.py.
  * Na sidru se NE dira ni jedan postojeci nginx site: generira se NOVA
    datoteka s NOVIM portom (127.0.0.1:18196), pa stari `ssh -R` put (18096)
    ostaje ziv i mjeren cijelo vrijeme pilota. Dva puta, ne zamjena.

Privatni kljucevi: pisu se s 0600 u izlazni direktorij. Kljuc sidra generiran
na trecem stroju je stvarni rizik rukovanja — zato je preferirani put
--sidro-javni (sidro generira svoj kljuc kod sebe s `wg genkey`), a generirani
kljuc sidra izlaz izricito oznaci kao "premjesti i izbrisi".
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import stat
import sys
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from maska import kripto  # noqa: E402

RIZOM_MREZA = "100.64.0.0/12"          # RFC 6598; dnkd koristi 100.80.0.0/12
ZADANI_WG_PORT = 51820
KEEPALIVE_S = 25                       # ISP NAT mapiranja padaju tipicno na 30-60 s
ZADANI_NGINX_PORT = 18196              # NOVI port; stari ssh -R put (18096) ostaje ziv


def wg_kodiraj(kljuc: bytes) -> str:
    return base64.b64encode(kljuc).decode()


def wg_dekodiraj(tekst: str) -> bytes:
    sirovo = base64.b64decode(tekst.strip() + "=" * (-len(tekst.strip()) % 4))
    if len(sirovo) != 32:
        raise ValueError(f"WireGuard kljuc mora biti 32 bajta (base64), dobiveno {len(sirovo)}")
    return sirovo


def oktet_uredjaja(ime: str) -> int:
    """Deterministican host-oktet 2..250 iz imena uredjaja (sidro drzi .1)."""
    h = int(hashlib.sha3_256(ime.encode("utf-8")).hexdigest()[:8], 16)
    return 2 + (h % 249)


@dataclass
class Sidro:
    ime: str
    host: str
    port: int = ZADANI_WG_PORT
    treci_oktet: int = 1
    javni_kljuc: str | None = None          # ako je dan, kljuc sidra se NE generira
    privatni_kljuc: str | None = field(default=None, repr=False)

    @property
    def mreza(self) -> str:
        return f"100.64.{self.treci_oktet}.0/24"

    @property
    def adresa(self) -> str:
        return f"100.64.{self.treci_oktet}.1"

    def adresa_ruba(self, oktet: int) -> str:
        return f"100.64.{self.treci_oktet}.{oktet}"


def _zapisi(putanja: Path, sadrzaj: str, tajno: bool = False) -> Path:
    putanja.parent.mkdir(parents=True, exist_ok=True)
    if putanja.exists():                     # nikad tihi prepis — uvijek .bak
        kopija = putanja.with_suffix(putanja.suffix + ".bak")
        n = 1
        while kopija.exists():
            kopija = putanja.with_suffix(putanja.suffix + f".bak{n}")
            n += 1
        kopija.write_bytes(putanja.read_bytes())
    putanja.write_text(sadrzaj, encoding="utf-8")
    os.chmod(putanja, stat.S_IRUSR | stat.S_IWUSR if tajno else 0o644)
    return putanja


def konf_ruba(sidro: Sidro, uredjaj: str, oktet: int, privatni_rub: str,
              javni_sidra: str, usluga_port: int) -> str:
    return f"""# RIZOM {sidro.ime} — rubni uredjaj '{uredjaj}' (MASKA F3)
# Generirano: rizom_konfig.py. Instalirati kao /etc/wireguard/rizom-{sidro.ime}.conf (0600).
#
# AllowedIPs je NAMJERNO samo /32 sidra: kroz tunel ide iskljucivo promet prema
# sidru. Obican promet uredjaja (i sve ostalo na njemu) ostaje netaknut.
# Rubni uredjaj NE otvara ni jedan ulazni port — handshake je izlazni, pa CGNAT
# i ISP-ov TOS bez port-forwarda nisu prepreka.
[Interface]
PrivateKey = {privatni_rub}
Address = {sidro.adresa_ruba(oktet)}/32
# Bez DNS= : dnkd (MASKA F2) je lokalni razrjesitelj i ne smije se mijenjati odavde.

[Peer]
# sidro {sidro.ime} ({sidro.host})
PublicKey = {javni_sidra}
AllowedIPs = {sidro.adresa}/32
Endpoint = {sidro.host}:{sidro.port}
PersistentKeepalive = {KEEPALIVE_S}

# Usluga koju sidro dohvaca preko ovog tunela: http://{sidro.adresa_ruba(oktet)}:{usluga_port}/
# (isti proces koji danas visi na ssh -R 18096 — taj put ostaje ziv paralelno.)
"""


def konf_sidra(sidro: Sidro, uredjaj: str, oktet: int, privatni_sidra: str | None,
               javni_rub: str, usluga_port: int) -> str:
    zaglavlje = f"""# RIZOM {sidro.ime} — strana SIDRA (MASKA F3)
# Instalirati kao /etc/wireguard/rizom-{sidro.ime}.conf (0600) na sidru {sidro.host}.
# Ako datoteka VEC postoji, dodaj SAMO [Peer] blok na kraj — nikad ne prepisuj.
"""
    if privatni_sidra:
        zaglavlje += f"""
[Interface]
PrivateKey = {privatni_sidra}
Address = {sidro.adresa}/24
ListenPort = {sidro.port}
# Firewall: potreban je SAMO ulazni UDP {sidro.port}. Nista drugo se ne otvara.
"""
    else:
        zaglavlje += f"""
# [Interface] blok NIJE generiran jer je javni kljuc sidra dan izvana
# (--sidro-javni {sidro.ime}=...). Sidro zadrzava svoj postojeci privatni kljuc.
# Provjeri da [Interface] na sidru ima: Address = {sidro.adresa}/24, ListenPort = {sidro.port}
"""
    return zaglavlje + f"""
[Peer]
# rubni uredjaj '{uredjaj}'
PublicKey = {javni_rub}
AllowedIPs = {sidro.adresa_ruba(oktet)}/32
# Bez Endpoint= : rub je za NAT-om i sam se javlja. Bez keepalivea na ovoj strani.

# Nakon `wg-quick up rizom-{sidro.ime}`, usluga ruba je dosezljiva na
#   http://{sidro.adresa_ruba(oktet)}:{usluga_port}/
"""


def nginx_snippet(sidro: Sidro, uredjaj: str, oktet: int, usluga_port: int,
                  nginx_port: int, ime_usluge: str) -> str:
    return f"""# RIZOM drugi put za '{ime_usluge}' preko sidra {sidro.ime} (MASKA F3)
# NOVA datoteka, NOVI port — ni jedan postojeci server blok se ne dira, pa
# nijedna druga domena na ovom serveru ne moze biti pogodjena ovom izmjenom.
# Stari put (ssh -R, port 18096) ostaje ziv i mjeren paralelno tijekom pilota.
server {{
    listen 127.0.0.1:{nginx_port};
    server_name {ime_usluge}-rizom.local;

    access_log /var/log/nginx/{ime_usluge}-rizom.access.log;
    error_log  /var/log/nginx/{ime_usluge}-rizom.error.log;

    # Kratki timeouti: mjerenje mora pasti brzo i glasno, ne visjeti 60 s.
    proxy_connect_timeout 5s;
    proxy_read_timeout 10s;
    proxy_send_timeout 10s;

    location / {{
        proxy_pass http://{sidro.adresa_ruba(oktet)}:{usluga_port};
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Rizom-Sidro "{sidro.ime}";
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        # Bez kesiranja: fasada koja vraca zadnji-dobar odgovor lagala bi
        # watchdogu da je rub ziv (isti razred kvara kao c2293).
        proxy_buffering off;
    }}
}}
"""


def instaliraj_rub_sh(sidra: list[Sidro], uredjaj: str) -> str:
    imena = " ".join(s.ime for s in sidra)
    return f"""#!/usr/bin/env bash
# RIZOM — instalacija na rubnom uredjaju '{uredjaj}' (MASKA F3). Pokrenuti kao root.
set -euo pipefail
G='\\033[32m'; Y='\\033[33m'; R='\\033[31m'; RST='\\033[0m'
ok(){{ printf "${{G}}[OK]${{RST}}  %s\\n" "$*"; }}
upozori(){{ printf "${{Y}}[!!]${{RST}}  %s\\n" "$*"; }}
umri(){{ printf "${{R}}[ERR]${{RST}} %s\\n" "$*" >&2; exit 1; }}

[[ $EUID -eq 0 ]] || umri "pokreni kao root (wg-quick i /etc/wireguard trebaju root)"
command -v wg >/dev/null || umri "wireguard-tools nije instaliran (apt install wireguard-tools)"
command -v wg-quick >/dev/null || umri "wg-quick nedostupan"
ZAPIS="$(date +%Y%m%d%H%M%S)"

for IME in {imena}; do
  IZVOR="$(dirname "$0")/rizom-$IME.conf"
  [[ -f "$IZVOR" ]] || umri "nema $IZVOR"
  CILJ="/etc/wireguard/rizom-$IME.conf"
  if [[ -f "$CILJ" ]]; then
    cp -a "$CILJ" "$CILJ.bak_$ZAPIS"
    ok "backup postojece konfiguracije: $CILJ.bak_$ZAPIS"
  fi
  install -o root -g root -m 600 "$IZVOR" "$CILJ"
  ok "instalirano $CILJ (root:root 0600)"
done

for IME in {imena}; do
  systemctl enable --now "wg-quick@rizom-$IME" \\
    && ok "wg-quick@rizom-$IME pokrenut i ukljucen u boot" \\
    || upozori "wg-quick@rizom-$IME nije startao — provjeri: journalctl -u wg-quick@rizom-$IME -n 30"
done

echo
echo "— stanje tunela —"
wg show || upozori "wg show nije uspio"
echo
echo "Sljedeci korak (na SIDRU, ne ovdje): instaliraj peer blok i podigni sucelje,"
echo "pa s ruba provjeri:  ping -c3 100.64.1.1   (i 100.64.2.1 za drugo sidro)"
echo "Vracanje unatrag:    systemctl disable --now wg-quick@rizom-<ime>"
"""


def generiraj(uredjaj: str, sidra: list[Sidro], usluga_port: int, ime_usluge: str,
              nginx_port: int, izlaz: Path) -> dict:
    oktet = oktet_uredjaja(uredjaj)
    izlaz = izlaz.expanduser().resolve()
    sk_rub, pk_rub = kripto.x25519_novi_kljuc()
    privatni_rub, javni_rub = wg_kodiraj(sk_rub), wg_kodiraj(pk_rub)

    manifest = {
        "uredjaj": uredjaj,
        "ime_usluge": ime_usluge,
        "usluga_port": usluga_port,
        "oktet": oktet,
        "rizom_mreza": RIZOM_MREZA,
        "javni_kljuc_ruba": javni_rub,
        "sidra": [],
        "napomena": ("Manifest sadrzi SAMO javne kljuceve. Privatni kljucevi su u "
                     "datotekama s dozvolom 0600 i ne smiju u git."),
    }

    dir_rub = izlaz / uredjaj
    _zapisi(dir_rub / "kljucevi" / "rub.privatni", privatni_rub + "\n", tajno=True)
    _zapisi(dir_rub / "kljucevi" / "rub.javni", javni_rub + "\n")

    for sidro in sidra:
        if sidro.javni_kljuc:
            javni_sidra, privatni_sidra = sidro.javni_kljuc, None
        else:
            sk_s, pk_s = kripto.x25519_novi_kljuc()
            privatni_sidra, javni_sidra = wg_kodiraj(sk_s), wg_kodiraj(pk_s)
            _zapisi(izlaz / sidro.ime / "kljucevi" / "sidro.privatni.PREMJESTI_I_IZBRISI",
                    privatni_sidra + "\n", tajno=True)
        _zapisi(izlaz / sidro.ime / "kljucevi" / "sidro.javni", javni_sidra + "\n")

        _zapisi(dir_rub / f"rizom-{sidro.ime}.conf",
                konf_ruba(sidro, uredjaj, oktet, privatni_rub, javni_sidra, usluga_port),
                tajno=True)
        _zapisi(izlaz / sidro.ime / f"rizom-{sidro.ime}.conf",
                konf_sidra(sidro, uredjaj, oktet, privatni_sidra, javni_rub, usluga_port),
                tajno=True)
        _zapisi(izlaz / sidro.ime / f"nginx-{ime_usluge}-rizom.conf",
                nginx_snippet(sidro, uredjaj, oktet, usluga_port, nginx_port, ime_usluge))
        nginx_port_sidra = nginx_port

        manifest["sidra"].append({
            "ime": sidro.ime, "host": sidro.host, "port": sidro.port,
            "mreza": sidro.mreza, "adresa_sidra": sidro.adresa,
            "adresa_ruba": sidro.adresa_ruba(oktet),
            "javni_kljuc_sidra": javni_sidra,
            "kljuc_sidra_generiran_ovdje": bool(not sidro.javni_kljuc),
            "nginx_port_na_sidru": nginx_port_sidra,
        })
        nginx_port += 1                     # drugo sidro dobiva svoj port, nikad isti

    skripta = _zapisi(dir_rub / "instaliraj-rub.sh", instaliraj_rub_sh(sidra, uredjaj))
    os.chmod(skripta, 0o750)
    _zapisi(izlaz / "manifest.json", json.dumps(manifest, ensure_ascii=False, indent=1))
    return manifest


def _cli(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(
        prog="python3 -m rizom.rizom_konfig",
        description="RIZOM: generiraj dvo-sidrenu WireGuard konfiguraciju (MASKA F3)")
    ap.add_argument("--uredjaj", required=True, help="ime rubnog uredjaja, npr. x96")
    ap.add_argument("--ime-usluge", default=None, help="ime usluge (zadano = ime uredjaja)")
    ap.add_argument("--usluga-port", required=True, type=int,
                    help="port aplikacije na rubu (npr. 8093 za medijapos)")
    ap.add_argument("--sidro", action="append", required=True, metavar="IME:HOST[:PORT]",
                    help="sidro; navesti DVA puta (dva sidra su cijela svrha F3)")
    ap.add_argument("--sidro-javni", action="append", default=[], metavar="IME=BASE64",
                    help="postojeci javni WG kljuc sidra (preferirano: sidro drzi svoj kljuc)")
    ap.add_argument("--nginx-port", type=int, default=ZADANI_NGINX_PORT,
                    help=f"prvi lokalni port na sidru za novi put (zadano {ZADANI_NGINX_PORT})")
    ap.add_argument("--izlaz", default="./izlaz-rizom", help="izlazni direktorij")
    a = ap.parse_args(argv)

    dani_kljucevi: dict[str, str] = {}
    for par in a.sidro_javni:
        if "=" not in par:
            print(f"GRESKA: --sidro-javni ocekuje IME=BASE64, dobiveno {par!r}")
            return 2
        ime, kljuc = par.split("=", 1)
        try:
            wg_dekodiraj(kljuc)
        except ValueError as e:
            print(f"GRESKA: javni kljuc sidra {ime!r}: {e}")
            return 2
        dani_kljucevi[ime.strip()] = kljuc.strip()

    sidra: list[Sidro] = []
    for i, spec in enumerate(a.sidro, start=1):
        dijelovi = spec.split(":")
        if len(dijelovi) not in (2, 3):
            print(f"GRESKA: --sidro ocekuje IME:HOST[:PORT], dobiveno {spec!r}")
            return 2
        ime, host = dijelovi[0].strip(), dijelovi[1].strip()
        port = int(dijelovi[2]) if len(dijelovi) == 3 else ZADANI_WG_PORT
        if not ime or not host:
            print(f"GRESKA: --sidro {spec!r} ima prazno ime ili host")
            return 2
        sidra.append(Sidro(ime=ime, host=host, port=port, treci_oktet=i,
                           javni_kljuc=dani_kljucevi.get(ime)))

    if len(sidra) < 2:
        print("GRESKA: F3 trazi DVA sidra. Jedno sidro je jedna tocka kvara — tocno ono "
              "stanje u kojem medijapos danas jest (_biljeska_c2395). Navedi --sidro dvaput.")
        return 2
    if len({s.ime for s in sidra}) != len(sidra):
        print("GRESKA: sidra moraju imati razlicita imena")
        return 2

    ime_usluge = a.ime_usluge or a.uredjaj
    manifest = generiraj(a.uredjaj, sidra, a.usluga_port, ime_usluge,
                         a.nginx_port, Path(a.izlaz))

    print(f"RIZOM konfiguracija generirana u {Path(a.izlaz).expanduser().resolve()}\n")
    print(f"  uredjaj '{manifest['uredjaj']}' -> host-oktet {manifest['oktet']} "
          f"(deterministican iz imena)")
    for s in manifest["sidra"]:
        print(f"  sidro {s['ime']:<5} {s['host']}:{s['port']}  "
              f"{s['adresa_ruba']} <-> {s['adresa_sidra']}  (mreza {s['mreza']}, "
              f"nginx 127.0.0.1:{s['nginx_port_na_sidru']})")
        if s["kljuc_sidra_generiran_ovdje"]:
            print(f"     ! privatni kljuc sidra {s['ime']} generiran OVDJE — premjesti ga na "
                  f"sidro i izbrisi lokalnu kopiju (ili ponovi s --sidro-javni {s['ime']}=...)")
    print(f"""
Redoslijed koraka (svaki je reverzibilan):
  1. SIDRA: prenesi {a.izlaz}/<sidro>/rizom-<sidro>.conf u /etc/wireguard/ (0600),
     otvori SAMO ulazni UDP port sidra, `systemctl enable --now wg-quick@rizom-<sidro>`.
  2. RUB ({manifest['uredjaj']}): prenesi cijeli direktorij {a.izlaz}/{manifest['uredjaj']}/ i
     pokreni `sudo ./instaliraj-rub.sh`.
  3. DOKAZ PUTA: s ruba `ping -c3 {manifest['sidra'][0]['adresa_sidra']}`, sa sidra
     `curl -sS http://{manifest['sidra'][0]['adresa_ruba']}:{manifest['usluga_port']}/health`.
  4. SVAKO SIDRO: instaliraj svoj nginx-{ime_usluge}-rizom.conf (nova datoteka, novi port —
     {", ".join(f"{s['ime']}:{s['nginx_port_na_sidru']}" for s in manifest["sidra"])}) i `nginx -t` PRIJE reloada.
  5. NADZOR na EU: `sudo python3 rizom/patch_watchdog.py --usluga {ime_usluge} --port {manifest['sidra'][0]['nginx_port_na_sidru']} --uredjaj {manifest['uredjaj'].upper()}`
     — dodaje '{ime_usluge}-rizom' u tunel_watchdog_config.json s ceka_prvo_prikljucenje.
  6. Stari `ssh -R` put se NE gasi. Gasi se tek kad RIZOM prezivi tjedan bez alarma —
     tada ime, prije toga samo mjerenje.""")
    return 0


if __name__ == "__main__":
    raise SystemExit(_cli(sys.argv[1:]))
