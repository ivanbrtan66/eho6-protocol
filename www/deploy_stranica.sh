#!/usr/bin/env bash
# ============================================================================
# Pustanje nadopunjene EHO6 prezentacijske stranice. Pokrenuti kao root NA CVORU
# koji stvarno posluzuje /quantum/eho6/.
#
# Putanju NE POGADJA. Trazi --cilj i prije ikakve izmjene provjerava da je to
# stvarno ta stranica (mora sadrzavati njezin naslov). Razlog: putanja stranice
# nije utvrdjena read-only alatom — nije u /var/www/genesis/quantum ni
# /var/www/html, pa je vjerojatno posluzena kroz masku s drugog cvora, kao
# v4.limit-connect.com. Pisati na slijepo znaci prepisati nesto drugo.
#
#   Nadji je:  grep -rl "Get Running in 30 Seconds" /var/www /srv /usr/share/nginx 2>/dev/null
#              nginx -T | grep -B8 -A8 "quantum"
#
#   sudo www/deploy_stranica.sh --cilj /put/do/index.html --izvor www/eho6/index.html
#   sudo www/deploy_stranica.sh --vrati --cilj /put/do/index.html
# ============================================================================
set -euo pipefail

G='\033[32m'; Y='\033[33m'; R='\033[31m'; B='\033[1m'; RST='\033[0m'
ok()      { printf "${G}[OK]${RST}  %s\n" "$*"; }
upozori() { printf "${Y}[!!]${RST}  %s\n" "$*"; }
umri()    { printf "${R}[ERR]${RST} %s\n" "$*" >&2; exit 1; }
info()    { printf "      %s\n" "$*"; }

CILJ=""; IZVOR="www/eho6/index.html"; VRATI=0
PROVJERA_URL="https://genesis.limit-connect.com/quantum/eho6/"
OTISAK="Get Running in 30 Seconds"     # postoji na zivoj stranici prije nadopune
OZNAKA="MASKA (F1-F5)"                 # postoji tek nakon nadopune
VLASNIK="www-data"
ZAPIS="$(date +%Y%m%d%H%M%S)"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --cilj)  CILJ="${2:-}"; shift 2 ;;
    --izvor) IZVOR="${2:-}"; shift 2 ;;
    --vrati) VRATI=1; shift ;;
    --url)   PROVJERA_URL="${2:-}"; shift 2 ;;
    -h|--help) sed -n '3,20p' "${BASH_SOURCE[0]}"; exit 0 ;;
    *) umri "nepoznata zastavica: $1" ;;
  esac
done

[[ -n "$CILJ" ]] || umri "obavezno --cilj <putanja/index.html> (putanja se ne pogadja)"
[[ $EUID -eq 0 ]] || umri "pokreni kao root (pisanje u docroot i chown $VLASNIK)"

# --- vracanje ---------------------------------------------------------------
if [[ $VRATI -eq 1 ]]; then
  zadnji="$(ls -1t "${CILJ}.bak_maska_"* 2>/dev/null | head -1 || true)"
  [[ -n "$zadnji" ]] || umri "nema ni jednog ${CILJ}.bak_maska_* backupa"
  cp -a "$CILJ" "${CILJ}.prije_vracanja_${ZAPIS}"
  install -o "$VLASNIK" -g "$VLASNIK" -m 644 "$zadnji" "$CILJ"
  ok "vraceno iz $(basename "$zadnji")"
  info "stanje prije vracanja: ${CILJ}.prije_vracanja_${ZAPIS}"
  exit 0
fi

# --- provjere prije ikakve izmjene -----------------------------------------
[[ -f "$IZVOR" ]] || umri "nema $IZVOR (pokreni prvo: python3 www/nadopuni_stranicu.py --preuzmi --izlaz $IZVOR)"
[[ -f "$CILJ" ]]  || umri "$CILJ ne postoji — to nije stranica koju trazis, ne pisem na slijepo"

grep -q "$OTISAK" "$CILJ" || umri "$CILJ ne sadrzi \"$OTISAK\" — to NIJE EHO6 prezentacijska stranica; odbijam pisati"
grep -q "$OZNAKA" "$IZVOR" || umri "$IZVOR nema MASKA blok — nadopuna nije napravljena"

if grep -q "$OZNAKA" "$CILJ"; then
  upozori "ciljna stranica VEC ima MASKA blok — instaliram noviju verziju preko nje"
fi

STARA="$(wc -c < "$CILJ")"; NOVA="$(wc -c < "$IZVOR")"
printf "\n${B}Pustanje EHO6 stranice${RST}\n"
info "cilj:  $CILJ   ($STARA B)"
info "izvor: $IZVOR  ($NOVA B)"
echo

# --- backup i instalacija ---------------------------------------------------
cp -a "$CILJ" "${CILJ}.bak_maska_${ZAPIS}"
ok "backup: ${CILJ}.bak_maska_${ZAPIS}"

TMP="${CILJ}.tmp_${ZAPIS}"
install -o "$VLASNIK" -g "$VLASNIK" -m 644 "$IZVOR" "$TMP"
mv -f "$TMP" "$CILJ"                      # atomarno: posjetitelj nikad ne vidi pola stranice
ok "instalirano $CILJ ($VLASNIK:$VLASNIK 0644)"

# --- dokaz, ne tvrdnja ------------------------------------------------------
if command -v curl >/dev/null; then
  if curl -sS --max-time 15 "$PROVJERA_URL" | grep -q "$OZNAKA"; then
    ok "javna stranica posluzuje MASKA blok: $PROVJERA_URL"
  else
    upozori "javna stranica jos NE posluzuje MASKA blok"
    info "moguci uzroci: kes (CDN/nginx proxy_cache), maska prema drugom cvoru, ili drugi docroot"
    info "vracanje: sudo $0 --vrati --cilj $CILJ"
  fi
else
  upozori "curl nije dostupan — provjeri rucno: $PROVJERA_URL"
fi
echo
info "vracanje unatrag u svakom trenutku: sudo $0 --vrati --cilj $CILJ"
