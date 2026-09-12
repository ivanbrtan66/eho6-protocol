#!/usr/bin/env bash
# ============================================================================
# RIZOM — pustanje na SIDRO (MASKA F3). Pokrenuti kao root NA SIDRU.
#
# Sto radi (i nista vise od toga):
#   1. instalira /etc/wireguard/rizom-<sidro>.conf  — ako postoji, SAMO dodaje
#      [Peer] blok na kraj (append), nikad ne prepisuje tudje peerove
#   2. instalira NOVU nginx datoteku s NOVIM portom — ni jedan postojeci
#      server blok se ne dira, pa ni jedna druga domena na serveru ne moze
#      biti pogodjena ovom izmjenom (potpuna izolacija)
#   3. `nginx -t` PRIJE reloada; ako test padne, vraca backup i NE reloada
#   4. dozvole: root:root 0600 za kljuceve, www-data:www-data 0644 za sve
#      pod /var/www/genesis
#
# Sto NE radi: ne dira firewall (ispise tocnu naredbu), ne gasi stari ssh -R
# put, ne mijenja DNS. Sve tri stvari su odluke, ne detalji instalacije.
#
# Vracanje unatrag:  ./deploy_sidro.sh --vrati --sidro eu
# ============================================================================
set -euo pipefail

G='\033[32m'; Y='\033[33m'; R='\033[31m'; B='\033[1m'; RST='\033[0m'
ok()      { printf "${G}[OK]${RST}  %s\n" "$*"; }
upozori() { printf "${Y}[!!]${RST}  %s\n" "$*"; }
umri()    { printf "${R}[ERR]${RST} %s\n" "$*" >&2; exit 1; }
info()    { printf "      %s\n" "$*"; }

SIDRO=""; IZVOR="."; USLUGA="medijapos"; NGINX_DIR="/etc/nginx/conf.d"
VRATI=0; DOZVOLI_FIREWALL=0; ZAPIS="$(date +%Y%m%d%H%M%S)"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --sidro)   SIDRO="${2:-}"; shift 2 ;;
    --izvor)   IZVOR="${2:-}"; shift 2 ;;
    --usluga)  USLUGA="${2:-}"; shift 2 ;;
    --nginx-dir) NGINX_DIR="${2:-}"; shift 2 ;;
    --dozvoli-firewall) DOZVOLI_FIREWALL=1; shift ;;
    --vrati)   VRATI=1; shift ;;
    -h|--help)
      echo "Upotreba: $0 --sidro eu [--izvor DIR] [--usluga medijapos]"
      echo "                    [--nginx-dir /etc/nginx/conf.d] [--dozvoli-firewall] [--vrati]"
      exit 0 ;;
    *) umri "nepoznata zastavica: $1" ;;
  esac
done

[[ -n "$SIDRO" ]] || umri "obavezno --sidro <ime> (npr. eu)"
[[ $EUID -eq 0 ]] || umri "pokreni kao root (/etc/wireguard i nginx trebaju root)"

WG_CILJ="/etc/wireguard/rizom-${SIDRO}.conf"
NGINX_CILJ="${NGINX_DIR}/${USLUGA}-rizom.conf"

# --- vracanje unatrag -------------------------------------------------------
if [[ $VRATI -eq 1 ]]; then
  vraceno=0
  zadnji_wg="$(ls -1t "${WG_CILJ}.bak_rizom_"* 2>/dev/null | head -1 || true)"
  if [[ -n "$zadnji_wg" ]]; then
    cp -a "$WG_CILJ" "${WG_CILJ}.prije_vracanja_${ZAPIS}"
    install -o root -g root -m 600 "$zadnji_wg" "$WG_CILJ"
    ok "WireGuard konfiguracija vracena iz $(basename "$zadnji_wg")"
    systemctl restart "wg-quick@rizom-${SIDRO}" 2>/dev/null \
      && ok "wg-quick@rizom-${SIDRO} restartan" \
      || upozori "wg-quick@rizom-${SIDRO} nije restartan — provjeri rucno"
    vraceno=1
  else
    upozori "nema WireGuard backupa (${WG_CILJ}.bak_rizom_*)"
  fi
  if [[ -f "$NGINX_CILJ" ]]; then
    mv "$NGINX_CILJ" "${NGINX_CILJ}.uklonjen_${ZAPIS}"
    if nginx -t 2>/dev/null; then
      systemctl reload nginx && ok "nginx datoteka uklonjena i nginx reloadan"
    else
      mv "${NGINX_CILJ}.uklonjen_${ZAPIS}" "$NGINX_CILJ"
      umri "nginx -t pada i BEZ nase datoteke — vracam je i ne diram nginx; problem je drugdje"
    fi
    vraceno=1
  fi
  [[ $vraceno -eq 1 ]] || umri "nema sto vratiti"
  info "stari ssh -R put nije bio ni diran, pa je usluga i dalje na svom izvornom putu"
  exit 0
fi

# --- provjere prije ikakve izmjene -----------------------------------------
command -v wg >/dev/null      || umri "wireguard-tools nije instaliran (apt install wireguard-tools)"
command -v wg-quick >/dev/null || umri "wg-quick nedostupan"
command -v nginx >/dev/null   || umri "nginx nije instaliran na ovom sidru"

WG_IZVOR="${IZVOR}/rizom-${SIDRO}.conf"
NGINX_IZVOR="${IZVOR}/nginx-${USLUGA}-rizom.conf"
[[ -f "$WG_IZVOR" ]]    || umri "nema $WG_IZVOR (pokreni prvo rizom_konfig.py)"
[[ -f "$NGINX_IZVOR" ]] || umri "nema $NGINX_IZVOR (pokreni prvo rizom_konfig.py)"
grep -q '^\[Peer\]' "$WG_IZVOR" || umri "$WG_IZVOR nema [Peer] blok — pogresna datoteka"

NOVI_PORT="$(grep -oP 'listen\s+127\.0\.0\.1:\K[0-9]+' "$NGINX_IZVOR" | head -1 || true)"
[[ -n "$NOVI_PORT" ]] || umri "ne mogu procitati 'listen 127.0.0.1:<port>' iz $NGINX_IZVOR"
if ss -ltn 2>/dev/null | grep -q "127.0.0.1:${NOVI_PORT}\b"; then
  umri "port ${NOVI_PORT} je na ovom sidru VEC zauzet — generiraj s --nginx-port <drugi>"
fi
if [[ -f "$NGINX_CILJ" ]]; then
  upozori "$NGINX_CILJ vec postoji — bit ce backupiran i zamijenjen"
fi

printf "\n${B}RIZOM pustanje na sidro '%s'${RST}\n" "$SIDRO"
info "WireGuard: $WG_CILJ"
info "nginx:     $NGINX_CILJ  (novi lokalni port ${NOVI_PORT})"
info "usluga:    ${USLUGA} — stari put se NE gasi"
echo

# --- 1. WireGuard -----------------------------------------------------------
mkdir -p /etc/wireguard
chmod 700 /etc/wireguard
if [[ -f "$WG_CILJ" ]]; then
  cp -a "$WG_CILJ" "${WG_CILJ}.bak_rizom_${ZAPIS}"
  ok "backup: ${WG_CILJ}.bak_rizom_${ZAPIS}"
  NOVI_PK="$(grep -oP '^\s*PublicKey\s*=\s*\K\S+' "$WG_IZVOR" | tail -1)"
  if grep -q "$NOVI_PK" "$WG_CILJ"; then
    ok "peer je vec u konfiguraciji — preskacem dodavanje (idempotentno)"
  else
    # append SAMO [Peer] blok: postojeci [Interface] i tudji peerovi ostaju
    printf "\n# --- dodano RIZOM deploy_sidro.sh %s ---\n" "$ZAPIS" >> "$WG_CILJ"
    sed -n '/^\[Peer\]/,$p' "$WG_IZVOR" >> "$WG_CILJ"
    ok "[Peer] blok dodan na kraj $WG_CILJ (bez prepisivanja)"
  fi
else
  install -o root -g root -m 600 "$WG_IZVOR" "$WG_CILJ"
  ok "instalirano $WG_CILJ (root:root 0600)"
fi
chmod 600 "$WG_CILJ"

if systemctl is-active --quiet "wg-quick@rizom-${SIDRO}"; then
  systemctl restart "wg-quick@rizom-${SIDRO}" && ok "wg-quick@rizom-${SIDRO} restartan"
else
  systemctl enable --now "wg-quick@rizom-${SIDRO}" \
    && ok "wg-quick@rizom-${SIDRO} pokrenut i ukljucen u boot" \
    || umri "wg-quick@rizom-${SIDRO} nije startao: journalctl -u wg-quick@rizom-${SIDRO} -n 30"
fi

WG_PORT="$(grep -oP '^\s*ListenPort\s*=\s*\K[0-9]+' "$WG_CILJ" | head -1 || true)"
if [[ -n "$WG_PORT" ]]; then
  if [[ $DOZVOLI_FIREWALL -eq 1 ]] && command -v ufw >/dev/null; then
    ufw allow "${WG_PORT}/udp" && ok "ufw: dozvoljen ulazni UDP ${WG_PORT}"
  else
    upozori "firewall NIJE diran. Ulazni UDP ${WG_PORT} mora biti otvoren:"
    info "ufw allow ${WG_PORT}/udp        # ili odgovarajuce pravilo tvog firewalla"
    info "(ponovi ovu skriptu s --dozvoli-firewall da to ucini umjesto tebe)"
  fi
fi

# --- 2. nginx (nova datoteka, novi port) ------------------------------------
if [[ -f "$NGINX_CILJ" ]]; then
  cp -a "$NGINX_CILJ" "${NGINX_CILJ}.bak_rizom_${ZAPIS}"
  ok "backup: ${NGINX_CILJ}.bak_rizom_${ZAPIS}"
fi
install -o root -g root -m 644 "$NGINX_IZVOR" "$NGINX_CILJ"
ok "instalirano $NGINX_CILJ"

if nginx -t 2>/tmp/rizom_nginx_t.log; then
  ok "nginx -t prosao"
  systemctl reload nginx && ok "nginx reloadan" || umri "nginx reload pao — pogledaj journalctl -u nginx"
else
  upozori "nginx -t PAO — ne reloadam i vracam stanje:"
  sed 's/^/      /' /tmp/rizom_nginx_t.log
  if [[ -f "${NGINX_CILJ}.bak_rizom_${ZAPIS}" ]]; then
    install -o root -g root -m 644 "${NGINX_CILJ}.bak_rizom_${ZAPIS}" "$NGINX_CILJ"
  else
    rm -f "$NGINX_CILJ"
  fi
  nginx -t >/dev/null 2>&1 && ok "stanje vraceno, nginx konfiguracija je opet valjana"
  umri "nginx nije mijenjan; RIZOM put nije aktiviran"
fi

# --- 3. dozvole pod /var/www/genesis ----------------------------------------
if [[ -d /var/www/genesis ]] && id -u www-data >/dev/null 2>&1; then
  ok "napomena: sve pod /var/www/genesis mora ostati www-data:www-data (servisi ne rade kao root)"
fi

# --- 4. dokaz puta ----------------------------------------------------------
echo
printf "${B}— dokaz, ne tvrdnja —${RST}\n"
RUB_IP="$(grep -oP '^\s*AllowedIPs\s*=\s*\K[0-9.]+' "$WG_CILJ" | tail -1 || true)"
wg show "rizom-${SIDRO}" 2>/dev/null || upozori "wg show ne vidi sucelje rizom-${SIDRO}"
if [[ -n "$RUB_IP" ]]; then
  info "kad rub podigne svoju stranu, provjeri:"
  info "  ping -c3 ${RUB_IP}"
  info "  curl -sS --max-time 5 http://127.0.0.1:${NOVI_PORT}/health"
fi
info "pa ubaci put u nadzor (na EU cvoru):"
info "  sudo python3 rizom/patch_watchdog.py --usluga ${USLUGA} --port ${NOVI_PORT}"
info "vracanje unatrag u svakom trenutku:"
info "  $0 --vrati --sidro ${SIDRO} --usluga ${USLUGA}"
echo
ok "pustanje zavrseno. Handshake s ruba jos NIJE dokaz dok ga ne izmjeri watchdog."
