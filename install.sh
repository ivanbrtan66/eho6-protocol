#!/usr/bin/env bash
# ============================================================================
# EHO6 Node Installer v1.0
# Decentralized verification protocol — edge node bootstrap
# stdlib only, works on Termux (Android ARM), macOS, Linux
# ============================================================================
set -euo pipefail

# --- Colors ------------------------------------------------------------------
G='\033[32m'; Y='\033[33m'; R='\033[31m'; B='\033[1m'; RST='\033[0m'
ok()   { printf "${G}[OK]${RST}  %s\n" "$*"; }
warn() { printf "${Y}[!!]${RST}  %s\n" "$*"; }
die()  { printf "${R}[ERR]${RST} %s\n" "$*" >&2; exit 1; }
info() { printf "     %s\n" "$*"; }

# --- Defaults ----------------------------------------------------------------
EHO6_DIR="$HOME/.eho6"
EU_HTTPS="https://genesis.limit-connect.com"
EU_HTTP="http://217.160.71.124"
NODE_PORT=8091
AGENT_ID=""
WORD=""
FORCE_TERMUX=0
POLL_INTERVAL=10
POLL_MAX=200

# --- Parse flags -------------------------------------------------------------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --termux)     FORCE_TERMUX=1; shift ;;
    --agent-id)   AGENT_ID="$2"; shift 2 ;;
    --word)       WORD="$2"; shift 2 ;;
    --port)       NODE_PORT="$2"; shift 2 ;;
    -h|--help)
      echo "Usage: install.sh [--termux] [--agent-id NAME] [--word WORD] [--port PORT]"
      exit 0 ;;
    *) die "Unknown flag: $1" ;;
  esac
done

# --- Banner ------------------------------------------------------------------
printf "\n${B}╔══════════════════════════════════════════╗${RST}\n"
printf "${B}║${RST}   ${G}EHO6 Node Installer v1.0${RST}               ${B}║${RST}\n"
printf "${B}║${RST}   Decentralized Verification Protocol   ${B}║${RST}\n"
printf "${B}╚══════════════════════════════════════════╝${RST}\n\n"

# --- Platform detection ------------------------------------------------------
PLATFORM="linux"
if [[ $FORCE_TERMUX -eq 1 ]] || [[ -n "${PREFIX:-}" ]] || (uname -o 2>/dev/null | grep -qi android); then
  PLATFORM="termux"
elif [[ "$(uname -s)" == "Darwin" ]]; then
  PLATFORM="macos"
fi
ok "Platform: ${B}${PLATFORM}${RST}"

# --- Python 3.11+ check -----------------------------------------------------
PYTHON=""
for candidate in python3.13 python3.12 python3.11 python3 python; do
  if command -v "$candidate" &>/dev/null; then
    ver=$("$candidate" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>/dev/null || true)
    major="${ver%%.*}"
    minor="${ver##*.}"
    if [[ "$major" -ge 3 ]] && [[ "$minor" -ge 11 ]]; then
      PYTHON="$candidate"
      break
    fi
  fi
done
[[ -z "$PYTHON" ]] && die "Python 3.11+ required. Found none."
PYVER=$("$PYTHON" --version)
ok "Python: ${B}${PYVER}${RST} ($(command -v "$PYTHON"))"

# --- Create ~/.eho6/ --------------------------------------------------------
mkdir -p "$EHO6_DIR"
ok "Directory: $EHO6_DIR"

# --- Ed25519 keypair generation ----------------------------------------------
KEY_FILE="$EHO6_DIR/node.key"
PUB_FILE="$EHO6_DIR/node.pub"

gen_keypair() {
  $PYTHON -c "
import secrets, hashlib, sys

P = 2**255 - 19
Q = 2**252 + 27742317777372353535851937790883648493
_d = (-121665 * pow(121666, P-2, P)) % P

def _base_point():
    y = 4 * pow(5, P-2, P) % P
    x2 = ((y*y - 1) * pow(_d*y*y + 1, P-2, P)) % P
    x = pow(x2, (P+3)//8, P)
    if (x*x - x2) % P != 0:
        x = x * pow(2, (P-1)//4, P) % P
    if x & 1: x = P - x
    return (x, y)

_B = _base_point()

def _add(A, B):
    x1, y1 = A; x2, y2 = B
    dxy = _d * x1 * x2 * y1 * y2
    x3 = ((x1*y2 + x2*y1) * pow(1 + dxy, P-2, P)) % P
    y3 = ((y1*y2 + x1*x2) * pow(1 - dxy, P-2, P)) % P
    return (x3, y3)

def _scalarmult(s, Pt):
    R = (0, 1)
    while s > 0:
        if s & 1: R = _add(R, Pt)
        Pt = _add(Pt, Pt)
        s >>= 1
    return R

def _encode(Pt):
    x, y = Pt
    return (y | ((x & 1) << 255)).to_bytes(32, 'little')

sk = secrets.token_bytes(32)
h = hashlib.sha512(sk).digest()
ab = bytearray(h[:32]); ab[0] &= 248; ab[31] &= 127; ab[31] |= 64
a = int.from_bytes(ab, 'little')
pk = _encode(_scalarmult(a, _B))

key_path = sys.argv[1]
pub_path = sys.argv[2]

with open(key_path, 'wb') as f: f.write(sk)
with open(pub_path, 'w') as f: f.write(pk.hex())
print(pk.hex())
" "$KEY_FILE" "$PUB_FILE"
}

if [[ -f "$KEY_FILE" ]]; then
  warn "Key already exists: $KEY_FILE"
  printf "     Overwrite? [y/${B}N${RST}] "
  read -r ans
  if [[ "${ans,,}" == "y" || "${ans,,}" == "yes" ]]; then
    PUBKEY=$(gen_keypair)
    ok "Keypair regenerated"
  else
    PUBKEY=$(cat "$PUB_FILE")
    ok "Keeping existing keypair"
  fi
else
  PUBKEY=$(gen_keypair)
  ok "Keypair generated"
fi
chmod 600 "$KEY_FILE"
info "Public key: ${PUBKEY:0:16}...${PUBKEY: -8}"

# --- Agent ID ----------------------------------------------------------------
validate_agent_id() {
  local id="$1"
  if [[ ${#id} -lt 3 || ${#id} -gt 64 ]]; then return 1; fi
  if [[ ! "$id" =~ ^[a-zA-Z0-9_]+$ ]]; then return 1; fi
  return 0
}

if [[ -z "$AGENT_ID" ]]; then
  while true; do
    printf "\n  Enter agent_id (alphanum + underscore, 3-64 chars): "
    read -r AGENT_ID
    if validate_agent_id "$AGENT_ID"; then break; fi
    warn "Invalid agent_id. Use 3-64 alphanumeric/underscore characters."
  done
fi
validate_agent_id "$AGENT_ID" || die "Invalid agent_id: $AGENT_ID"
ok "Agent ID: ${B}${AGENT_ID}${RST}"

# --- Word --------------------------------------------------------------------
if [[ -z "$WORD" ]]; then
  printf "  Enter word [${B}pilot${RST}]: "
  read -r WORD
  [[ -z "$WORD" ]] && WORD="pilot"
fi
ok "Word: ${B}${WORD}${RST}"

# --- Save config.json --------------------------------------------------------
CONFIG_FILE="$EHO6_DIR/config.json"
cat > "$CONFIG_FILE" <<JSONEOF
{
  "agent_id": "${AGENT_ID}",
  "word": "${WORD}",
  "eu_https": "${EU_HTTPS}",
  "eu_http": "${EU_HTTP}",
  "node_port": ${NODE_PORT}
}
JSONEOF
ok "Config saved: $CONFIG_FILE"

# --- Determine curl flags ----------------------------------------------------
CURL_FLAGS=("-s" "-S" "--max-time" "30")
if [[ "$PLATFORM" == "termux" ]]; then
  CURL_FLAGS+=("--insecure")
  EU_BASE="$EU_HTTP"
  warn "Termux: using HTTP fallback + --insecure"
else
  EU_BASE="$EU_HTTPS"
fi

# --- Admit request -----------------------------------------------------------
printf "\n${B}--- Requesting admission ---${RST}\n"
ADMIT_URL="${EU_BASE}/api/v1/eho6/admit/request"
ADMIT_BODY="{\"candidate_pk\":\"${PUBKEY}\",\"agent_id\":\"${AGENT_ID}\",\"word\":\"${WORD}\"}"

ADMIT_RESP=$(curl "${CURL_FLAGS[@]}" -X POST \
  -H "Content-Type: application/json" \
  -d "$ADMIT_BODY" \
  "$ADMIT_URL" 2>&1) || die "Admit request failed. Is EU reachable?\n  URL: $ADMIT_URL\n  Response: $ADMIT_RESP"

# Parse response
ADMIT_STATUS=$(echo "$ADMIT_RESP" | $PYTHON -c "import sys,json; d=json.load(sys.stdin); print(d.get('status',''))" 2>/dev/null || echo "")
ADMIT_ADDR=$(echo "$ADMIT_RESP" | $PYTHON -c "import sys,json; d=json.load(sys.stdin); print(d.get('admit_address',''))" 2>/dev/null || echo "")
ADMIT_XMR=$(echo "$ADMIT_RESP" | $PYTHON -c "import sys,json; d=json.load(sys.stdin); print(d.get('amount_xmr',''))" 2>/dev/null || echo "")
ADMIT_MSG=$(echo "$ADMIT_RESP" | $PYTHON -c "import sys,json; d=json.load(sys.stdin); print(d.get('message',''))" 2>/dev/null || echo "")

if [[ -z "$ADMIT_STATUS" ]]; then
  die "Unexpected response from admit API:\n  $ADMIT_RESP"
fi

# Already admitted?
if [[ "$ADMIT_STATUS" == "ADMITTED" ]]; then
  ok "Already ADMITTED!"
else
  ok "Admission status: ${B}${ADMIT_STATUS}${RST}"
  [[ -n "$ADMIT_MSG" ]] && info "$ADMIT_MSG"

  # Check simulation vs mainnet
  IS_SIM=0
  if echo "$ADMIT_RESP" | grep -qi "simulation"; then
    IS_SIM=1
    printf "\n  ${Y}SIMULATION MODE${RST} — payment will auto-confirm in ~60 seconds\n"
  else
    if [[ -n "$ADMIT_ADDR" ]] && [[ -n "$ADMIT_XMR" ]]; then
      printf "\n  ${B}Send exactly ${G}${ADMIT_XMR} XMR${RST} to:\n"
      printf "  ${B}${ADMIT_ADDR}${RST}\n\n"
      info "Waiting for 10 confirmations (can take 20+ minutes)..."
    fi
  fi

  # --- Poll for ADMITTED status -----------------------------------------------
  printf "\n${B}--- Waiting for admission ---${RST}\n"
  STATUS_URL="${EU_BASE}/api/v1/eho6/admit/status/${AGENT_ID}"
  SPINNER=('|' '/' '-' '\')
  ELAPSED=0

  for i in $(seq 1 $POLL_MAX); do
    S_IDX=$(( (i - 1) % 4 ))
    MINS=$(( ELAPSED / 60 ))
    SECS=$(( ELAPSED % 60 ))
    printf "\r  ${SPINNER[$S_IDX]} Polling... %02d:%02d elapsed (attempt %d/%d)  " "$MINS" "$SECS" "$i" "$POLL_MAX"

    POLL_RESP=$(curl "${CURL_FLAGS[@]}" "$STATUS_URL" 2>/dev/null || echo "{}")
    POLL_STATUS=$(echo "$POLL_RESP" | $PYTHON -c "import sys,json; d=json.load(sys.stdin); print(d.get('status',''))" 2>/dev/null || echo "")

    case "$POLL_STATUS" in
      ADMITTED)
        printf "\r                                                               \r"
        ok "ADMITTED after ${MINS}m ${SECS}s!"
        break
        ;;
      FAILED|EXPIRED)
        printf "\n"
        FAIL_MSG=$(echo "$POLL_RESP" | $PYTHON -c "import sys,json; d=json.load(sys.stdin); print(d.get('message','Unknown error'))" 2>/dev/null || echo "Unknown error")
        die "Admission ${POLL_STATUS}: ${FAIL_MSG}"
        ;;
    esac

    sleep "$POLL_INTERVAL"
    ELAPSED=$(( ELAPSED + POLL_INTERVAL ))
  done

  if [[ "$POLL_STATUS" != "ADMITTED" ]]; then
    die "Timed out after $(( POLL_MAX * POLL_INTERVAL / 60 )) minutes. Run installer again to resume polling."
  fi
fi

# --- Save admit.json ---------------------------------------------------------
ADMIT_FILE="$EHO6_DIR/admit.json"
# Fetch final status and save as admit.json
STATUS_URL="${EU_BASE}/api/v1/eho6/admit/status/${AGENT_ID}"
FINAL_RESP=$(curl "${CURL_FLAGS[@]}" "$STATUS_URL" 2>/dev/null || echo "{}")
echo "$FINAL_RESP" | $PYTHON -c "
import sys, json
d = json.load(sys.stdin)
admit = {
    'agent_id': d.get('agent_id', ''),
    'status': d.get('status', ''),
    'admit_address': d.get('admit_address', ''),
    'xmr_amount': d.get('xmr_amount', ''),
    'weise3_id': d.get('weise3_id', ''),
    'admitted_at': d.get('admitted_at', ''),
    'word': d.get('word', ''),
    'candidate_pk': d.get('candidate_pk', '')
}
json.dump(admit, open(sys.argv[1], 'w'), indent=2)
print(admit.get('weise3_id', 'unknown'))
" "$ADMIT_FILE" > /tmp/_eho6_w3id 2>/dev/null || true
W3ID=$(cat /tmp/_eho6_w3id 2>/dev/null || echo "unknown")
rm -f /tmp/_eho6_w3id
ok "Admit data saved: $ADMIT_FILE"
[[ "$W3ID" != "unknown" ]] && info "WeisE3 ID: $W3ID"

# --- Download eho6_node.py ---------------------------------------------------
printf "\n${B}--- Downloading node daemon ---${RST}\n"
NODE_PY="$EHO6_DIR/eho6_node.py"
NODE_URL="${EU_BASE}/quantum/eho6/eho6_node.py"
HTTP_CODE=$(curl "${CURL_FLAGS[@]}" -w "%{http_code}" -o "$NODE_PY" "$NODE_URL" 2>/dev/null || echo "000")

if [[ "$HTTP_CODE" == "200" ]]; then
  chmod +x "$NODE_PY"
  ok "Downloaded eho6_node.py ($HTTP_CODE)"
else
  warn "Download returned HTTP $HTTP_CODE — node.py may need manual placement"
  info "Expected URL: $NODE_URL"
  info "Place file at: $NODE_PY"
fi

# --- Autostart setup ---------------------------------------------------------
printf "\n${B}--- Setting up autostart ---${RST}\n"
PYTHON_ABS=$(command -v "$PYTHON")

case "$PLATFORM" in
  termux)
    BOOT_DIR="$HOME/.termux/boot"
    mkdir -p "$BOOT_DIR"
    cat > "$BOOT_DIR/start-eho6.sh" <<BOOTEOF
#!/data/data/com.termux/files/usr/bin/bash
# EHO6 node autostart (Termux:Boot)
termux-wake-lock
$PYTHON_ABS $NODE_PY >> $EHO6_DIR/node.log 2>&1 &
BOOTEOF
    chmod +x "$BOOT_DIR/start-eho6.sh"
    ok "Termux:Boot script: $BOOT_DIR/start-eho6.sh"
    warn "Install 'Termux:Boot' from F-Droid for auto-start on boot"
    ;;

  macos)
    PLIST_DIR="$HOME/Library/LaunchAgents"
    PLIST_FILE="$PLIST_DIR/com.eho6.node.plist"
    mkdir -p "$PLIST_DIR"
    cat > "$PLIST_FILE" <<PLISTEOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.eho6.node</string>
    <key>ProgramArguments</key>
    <array>
        <string>${PYTHON_ABS}</string>
        <string>${NODE_PY}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>${EHO6_DIR}/node.log</string>
    <key>StandardErrorPath</key>
    <string>${EHO6_DIR}/node.err</string>
    <key>WorkingDirectory</key>
    <string>${EHO6_DIR}</string>
</dict>
</plist>
PLISTEOF
    ok "LaunchAgent: $PLIST_FILE"
    info "Load now:  launchctl load $PLIST_FILE"
    info "Unload:    launchctl unload $PLIST_FILE"
    ;;

  linux)
    if command -v systemctl &>/dev/null && [[ $(id -u) -eq 0 ]]; then
      # System-wide systemd
      UNIT_FILE="/etc/systemd/system/eho6.service"
      cat > "$UNIT_FILE" <<UNITEOF
[Unit]
Description=EHO6 Decentralized Verification Node
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${PYTHON_ABS} ${NODE_PY}
WorkingDirectory=${EHO6_DIR}
Restart=always
RestartSec=10
StandardOutput=append:${EHO6_DIR}/node.log
StandardError=append:${EHO6_DIR}/node.err

[Install]
WantedBy=multi-user.target
UNITEOF
      systemctl daemon-reload
      systemctl enable eho6.service
      ok "Systemd service (system): $UNIT_FILE"
      info "Control:   systemctl {start|stop|status} eho6"

    elif command -v systemctl &>/dev/null; then
      # User-level systemd (no root)
      USER_UNIT_DIR="$HOME/.config/systemd/user"
      mkdir -p "$USER_UNIT_DIR"
      UNIT_FILE="$USER_UNIT_DIR/eho6.service"
      cat > "$UNIT_FILE" <<UNITEOF
[Unit]
Description=EHO6 Decentralized Verification Node
After=network-online.target

[Service]
Type=simple
ExecStart=${PYTHON_ABS} ${NODE_PY}
WorkingDirectory=${EHO6_DIR}
Restart=always
RestartSec=10
StandardOutput=append:${EHO6_DIR}/node.log
StandardError=append:${EHO6_DIR}/node.err

[Install]
WantedBy=default.target
UNITEOF
      systemctl --user daemon-reload
      systemctl --user enable eho6.service
      ok "Systemd service (user): $UNIT_FILE"
      info "Control:   systemctl --user {start|stop|status} eho6"
    else
      warn "No systemd found. Start manually: $PYTHON_ABS $NODE_PY &"
    fi
    ;;
esac

# --- Start node now ----------------------------------------------------------
printf "\n${B}--- Starting EHO6 node ---${RST}\n"
if [[ -f "$NODE_PY" ]] && [[ -s "$NODE_PY" ]]; then
  nohup "$PYTHON_ABS" "$NODE_PY" >> "$EHO6_DIR/node.log" 2>&1 &
  NODE_PID=$!
  sleep 2

  if kill -0 "$NODE_PID" 2>/dev/null; then
    ok "Node started (PID: $NODE_PID)"
  else
    warn "Node process exited. Check $EHO6_DIR/node.log"
  fi
else
  warn "eho6_node.py not found or empty — skipping start"
  info "Place the file at $NODE_PY and run: $PYTHON_ABS $NODE_PY"
fi

# --- Final summary -----------------------------------------------------------
printf "\n${B}╔══════════════════════════════════════════╗${RST}\n"
printf "${B}║${RST}   ${G}EHO6 Node Installation Complete${RST}       ${B}║${RST}\n"
printf "${B}╚══════════════════════════════════════════╝${RST}\n\n"
info "Agent ID:    $AGENT_ID"
info "Public key:  ${PUBKEY:0:16}...${PUBKEY: -8}"
info "Node port:   $NODE_PORT"
info "Config:      $CONFIG_FILE"
info "Logs:        $EHO6_DIR/node.log"
printf "\n"
info "Health:      http://localhost:${NODE_PORT}/health"
info "Status:      http://localhost:${NODE_PORT}/eho6/status"
info "Verify:      curl -X POST http://localhost:${NODE_PORT}/eho6/verify -d '{\"order\":{...}}'"
printf "\n"
info "Login token (for API calls):"
info "  curl -X POST http://localhost:${NODE_PORT}/eho6/login"
info "  # Returns: {\"session_token\": \"...\", \"weise3_id\": \"...\"}"
printf "\n"
ok "Done. Your node is part of the EHO6 mesh."
