#!/usr/bin/env bash
# ============================================================================
# dnkd instalacija (MASKA F2). Pokrenuti kao root na rubnom uredjaju ili sidru.
#
#   sudo ./maska/instaliraj_dnkd.sh \
#        --ime medijapos.dnk --pk <64hex pinovani kljuc izdavatelja> \
#        --sidro https://genesis.limit-connect.com/pelud \
#        --sidro https://fina-connect.online/pelud \
#        --zrcalo genesis-medijapos.limit-connect.com
#
# Odbija zavrsiti s poluvaljanom konfiguracijom: bez pinovanog kljuca dnkd ne
# moze nikoga verificirati, a razrjesitelj koji ne verificira je gori od
# nikakvog — daje osjecaj sigurnosti bez sigurnosti.
#
# Deinstalacija:  sudo ./maska/instaliraj_dnkd.sh --ukloni
# ============================================================================
set -euo pipefail

G='\033[32m'; Y='\033[33m'; R='\033[31m'; B='\033[1m'; RST='\033[0m'
ok()      { printf "${G}[OK]${RST}  %s\n" "$*"; }
upozori() { printf "${Y}[!!]${RST}  %s\n" "$*"; }
umri()    { printf "${R}[ERR]${RST} %s\n" "$*" >&2; exit 1; }
info()    { printf "      %s\n" "$*"; }

KORIJEN="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
KORISNIK="maska"
STANJE="/var/lib/maska"
UNIT="/etc/systemd/system/dnkd.service"
IME=""; PK=""; ZRCALO=""; UKLONI=0; DNS_ADRESA="127.0.0.53:5353"; HTTP_ADRESA="127.0.0.1:8099"
SIDRA=()
ZAPIS="$(date +%Y%m%d%H%M%S)"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --ime)     IME="${2:-}"; shift 2 ;;
    --pk)      PK="${2:-}"; shift 2 ;;
    --sidro)   SIDRA+=("${2:-}"); shift 2 ;;
    --zrcalo)  ZRCALO="${2:-}"; shift 2 ;;
    --dns)     DNS_ADRESA="${2:-}"; shift 2 ;;
    --http)    HTTP_ADRESA="${2:-}"; shift 2 ;;
    --ukloni)  UKLONI=1; shift ;;
    -h|--help) sed -n '3,20p' "${BASH_SOURCE[0]}"; exit 0 ;;
    *) umri "nepoznata zastavica: $1" ;;
  esac
done

[[ $EUID -eq 0 ]] || umri "pokreni kao root (systemd unit i /var/lib/maska trebaju root)"

if [[ $UKLONI -eq 1 ]]; then
  systemctl disable --now dnkd 2>/dev/null && ok "dnkd zaustavljen i iskljucen" || upozori "dnkd nije bio aktivan"
  [[ -f "$UNIT" ]] && mv "$UNIT" "${UNIT}.uklonjen_${ZAPIS}" && ok "unit premjesten u ${UNIT}.uklonjen_${ZAPIS}"
  systemctl daemon-reload
  ok "stanje i godovi ostavljeni u ${STANJE} (mjerenja se ne brisu deinstalacijom)"
  info "za potpuno brisanje: rm -rf ${STANJE}   — time gubis dnevnik mjerenja"
  exit 0
fi

# --- provjere prije ikakve izmjene -----------------------------------------
PYTHON=""
for kandidat in python3.13 python3.12 python3.11 python3; do
  if command -v "$kandidat" >/dev/null; then
    v="$("$kandidat" -c 'import sys; print(sys.version_info.major*100+sys.version_info.minor)')"
    [[ "$v" -ge 311 ]] && { PYTHON="$(command -v "$kandidat")"; break; }
  fi
done
[[ -n "$PYTHON" ]] || umri "potreban Python 3.11+ (dnkd koristi samo standardnu biblioteku)"
ok "Python: $($PYTHON --version) ($PYTHON)"

[[ -f "${KORIJEN}/maska/dnkd.py" ]] || umri "ne vidim ${KORIJEN}/maska/dnkd.py — pokreni skriptu iz repozitorija"
[[ -n "$IME" ]] || umri "obavezno --ime <ime.dnk>"
[[ "$IME" == *.dnk ]] || umri "ime mora zavrsavati na .dnk (dobiveno: $IME)"
[[ -n "$PK" ]] || umri "obavezno --pk <64 hex> — bez pinovanog kljuca dnkd ne verificira nista"
[[ "${#PK}" -eq 64 ]] || umri "--pk mora imati tocno 64 hex znaka (dobiveno ${#PK})"
[[ "$PK" =~ ^[0-9a-fA-F]{64}$ ]] || umri "--pk nije heksadecimalan"
[[ "${#SIDRA[@]}" -ge 1 ]] || umri "obavezno bar jedno --sidro <url> (dva su bolje: pad jednog tada nije pad imena)"
[[ "${#SIDRA[@]}" -ge 2 ]] || upozori "samo JEDNO sidro — to je jedna tocka kvara; dodaj drugo kad mozes"

# --- korisnik i direktoriji -------------------------------------------------
if ! id -u "$KORISNIK" >/dev/null 2>&1; then
  useradd --system --no-create-home --shell /usr/sbin/nologin "$KORISNIK"
  ok "sistemski korisnik '$KORISNIK' kreiran (bez shella, bez doma)"
else
  ok "korisnik '$KORISNIK' vec postoji"
fi
install -d -o "$KORISNIK" -g "$KORISNIK" -m 750 "$STANJE"
ok "direktorij $STANJE ($KORISNIK:$KORISNIK 0750)"

# --- konfiguracija ----------------------------------------------------------
KONFIG="${STANJE}/dnkd.json"
if [[ -f "$KONFIG" ]]; then
  cp -a "$KONFIG" "${KONFIG}.bak_${ZAPIS}"
  ok "backup postojece konfiguracije: ${KONFIG}.bak_${ZAPIS}"
fi

SIDRA_JSON="$(printf '"%s",' "${SIDRA[@]}")"; SIDRA_JSON="[${SIDRA_JSON%,}]"
ZRCALO_JSON=""
[[ -n "$ZRCALO" ]] && ZRCALO_JSON=", \"javno_zrcalo\": \"${ZRCALO}\""

cat > "${KONFIG}.novo" <<KONF
{
 "_biljeska": "dnkd (MASKA F2). PELUD se PULL-a sa sidara i verificira protiv pinovanog kljuca. na_nesuglasje=odbij znaci: kad javni DNS i PELUD tvrde razlicito, ime se NE posluzuje nego se digne alarm — tiho preferiranje jednog izvora je split-brain koji nijedan watchdog ne vidi.",
 "slusaj_dns": "${DNS_ADRESA}",
 "slusaj_http": "${HTTP_ADRESA}",
 "mapiranje_mreza": "100.80.0.0/12",
 "sidra": ${SIDRA_JSON},
 "imena": { "${IME}": { "pk": "${PK}"${ZRCALO_JSON} } },
 "na_nesuglasje": "odbij",
 "ttl_s": 120,
 "osvjezavanje_s": 60,
 "http_timeout_s": 5,
 "godovi": "${STANJE}/godovi.jsonl",
 "mapiranje_datoteka": "${STANJE}/mapiranje.json"
}
KONF

if ! (cd "$KORIJEN" && "$PYTHON" -m maska.dnkd --konfig "${KONFIG}.novo" --provjeri-konfig >/dev/null); then
  rm -f "${KONFIG}.novo"
  umri "generirana konfiguracija nije prosla vlastitu provjeru — nista nije instalirano"
fi
mv "${KONFIG}.novo" "$KONFIG"
chown "$KORISNIK:$KORISNIK" "$KONFIG"
chmod 640 "$KONFIG"
ok "konfiguracija $KONFIG (provjerena, $KORISNIK:$KORISNIK 0640)"

# --- systemd unit -----------------------------------------------------------
[[ -f "$UNIT" ]] && { cp -a "$UNIT" "${UNIT}.bak_${ZAPIS}"; ok "backup unita: ${UNIT}.bak_${ZAPIS}"; }
sed -e "s|__KORIJEN__|${KORIJEN}|g" -e "s|__KORISNIK__|${KORISNIK}|g" \
    -e "s|__STANJE__|${STANJE}|g" -e "s|__PYTHON__|${PYTHON}|g" \
    "${KORIJEN}/maska/systemd/dnkd.service" > "$UNIT"
chmod 644 "$UNIT"
systemctl daemon-reload
ok "unit instaliran: $UNIT"

systemctl enable --now dnkd
sleep 2
if systemctl is-active --quiet dnkd; then
  ok "dnkd radi"
else
  upozori "dnkd nije aktivan — zadnjih 20 linija dnevnika:"
  journalctl -u dnkd -n 20 --no-pager | sed 's/^/      /'
  umri "instalacija je na disku, ali servis ne radi. Nista nije 'skoro u redu' — popravi pa ponovi."
fi

# --- dokaz ------------------------------------------------------------------
DNS_HOST="${DNS_ADRESA%:*}"; DNS_PORT="${DNS_ADRESA##*:}"
echo
printf "${B}— dokaz, ne tvrdnja —${RST}\n"
if command -v dig >/dev/null; then
  dig "@${DNS_HOST}" -p "${DNS_PORT}" "$IME" A +short +timeout=3 | sed 's/^/      /' \
    || upozori "dig nije dobio odgovor — provjeri journalctl -u dnkd"
else
  info "dig nije instaliran; provjeri plocom: curl -sS http://${HTTP_ADRESA}/borg/health.json"
fi
curl -sS --max-time 5 "http://${HTTP_ADRESA}/borg/health.json" \
  | "$PYTHON" -c 'import json,sys; z=json.load(sys.stdin); print("      zdravlje:", z["stanje"], "| imena:", [(i["ime"], i["stanje"]) for i in z["imena"]])' \
  || upozori "ploca ne odgovara na http://${HTTP_ADRESA}/"
echo
info "upravljacka ploca:  http://${HTTP_ADRESA}/"
info "dnevnik mjerenja:   ${STANJE}/godovi.jsonl  (provjera lanca: $PYTHON -m maska.godovi ${STANJE}/godovi.jsonl)"
info "sistemski resolver NIJE mijenjan — .dnk imena idu kroz ${DNS_ADRESA} dok ga sam ne ukljucis"
info "deinstalacija:      sudo $0 --ukloni"
