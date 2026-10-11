#!/usr/bin/env python3
"""
EHO6 Edge Node Daemon v1.0
Decentralized verification protocol — stdlib only.
Works on Android ARM (Termux), Ubuntu, macOS.
"""

import base64
import math
import ssl
import hashlib
import json
import os
import struct
import sys
import threading
import time
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.error import HTTPError

# =============================================================================
# Constants
# =============================================================================
VERSION = "1.0.0"
EHO6_DIR = Path.home() / ".eho6"
DEFAULT_PORT = 8091
DEFAULT_BIND = "127.0.0.1"  # loopback only; set "bind" in config.json to expose on LAN
SESSION_REFRESH_INTERVAL = 50 * 60  # 50 minutes

# Admission anchors (Ed25519). Same set the server verifier accepts
# (services/haveno_admission.KNOWN_ANCHORS: ustav c1487 + AMANDMAN-2; MAR retired by c4176).
# A rotation needs a new node release: the node does not walk the amendment chain itself.
ANCHOR_PKS = {
    "4d628b9cfeac2912faee20c9421cea91c227075a39105bb12c713483a4f46b13": "genesis-eu",
    "d210246f0f45cb256315c44d97f4c1a7ae95342e695fbc4a5f5b3fbef421dc8f": "genesis-de",
    "a70db7eda9a83318ca031196e7abe8c0f54665c7c3c5d3285c79149d2e6fd707": "genesis-es",
}
ADMIT_REQUIRED_SIGS = 2

# Verdicts (three-state, never bool)
DRZI = "DRZI"
PAD = "PAD"
NEPOZNATO = "NEPOZNATO"

# Organ types
RIBOSOM = 1
REGULACIJA = 2
VM_JEZGRA = 3

# FraktalToken XOR constant = F(33)
PHI_XOR = 3524578

# =============================================================================
# Pure Python Ed25519 (stdlib only, Termux-safe)
# =============================================================================
P = 2**255 - 19
Q = 2**252 + 27742317777372353535851937790883648493
_d = (-121665 * pow(121666, P - 2, P)) % P


def _base_point():
    y = 4 * pow(5, P - 2, P) % P
    x2 = ((y * y - 1) * pow(_d * y * y + 1, P - 2, P)) % P
    x = pow(x2, (P + 3) // 8, P)
    if (x * x - x2) % P != 0:
        x = x * pow(2, (P - 1) // 4, P) % P
    if x & 1:
        x = P - x
    return (x, y)


_B = _base_point()


def _add(A, B):
    x1, y1 = A
    x2, y2 = B
    dxy = _d * x1 * x2 * y1 * y2
    x3 = ((x1 * y2 + x2 * y1) * pow(1 + dxy, P - 2, P)) % P
    y3 = ((y1 * y2 + x1 * x2) * pow(1 - dxy, P - 2, P)) % P
    return (x3, y3)


def _scalarmult(s, Pt):
    R = (0, 1)
    while s > 0:
        if s & 1:
            R = _add(R, Pt)
        Pt = _add(Pt, Pt)
        s >>= 1
    return R


def _encode(Pt):
    x, y = Pt
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def _sha512(m):
    return hashlib.sha512(m).digest()


def ed25519_sign(sk32: bytes, msg: bytes) -> bytes:
    h = _sha512(sk32)
    ab = bytearray(h[:32])
    ab[0] &= 248
    ab[31] &= 127
    ab[31] |= 64
    a = int.from_bytes(ab, "little")
    A = _encode(_scalarmult(a, _B))
    r = int.from_bytes(_sha512(h[32:] + msg), "little") % Q
    R = _encode(_scalarmult(r, _B))
    S = (r + int.from_bytes(_sha512(R + A + msg), "little") * a) % Q
    return R + S.to_bytes(32, "little")


def ed25519_pubkey(sk32: bytes) -> bytes:
    h = _sha512(sk32)
    ab = bytearray(h[:32])
    ab[0] &= 248
    ab[31] &= 127
    ab[31] |= 64
    a = int.from_bytes(ab, "little")
    return _encode(_scalarmult(a, _B))


_SQRT_M1 = pow(2, (P - 1) // 4, P)


def _decode(s32: bytes):
    """Decode a 32-byte point encoding; None if not a canonical curve point."""
    if len(s32) != 32:
        return None
    n = int.from_bytes(s32, "little")
    y, sign = n & ((1 << 255) - 1), n >> 255
    if y >= P:
        return None
    x2 = ((y * y - 1) * pow(_d * y * y + 1, P - 2, P)) % P
    x = pow(x2, (P + 3) // 8, P)
    if (x * x - x2) % P != 0:
        x = x * _SQRT_M1 % P
    if (x * x - x2) % P != 0:
        return None
    if x == 0 and sign:
        return None
    if x & 1 != sign:
        x = P - x
    return (x, y)


def ed25519_verify(pk32: bytes, sig64: bytes, msg: bytes) -> bool:
    """RFC 8032 verification (cofactorless, rejects S >= L and non-canonical points)."""
    if len(pk32) != 32 or len(sig64) != 64:
        return False
    A, R = _decode(pk32), _decode(sig64[:32])
    S = int.from_bytes(sig64[32:], "little")
    if A is None or R is None or S >= Q:
        return False
    k = int.from_bytes(_sha512(sig64[:32] + pk32 + msg), "little") % Q
    return _scalarmult(S, _B) == _add(R, _scalarmult(k, A))


def verify_admit(admit, node_pk_hex: str = "") -> tuple:
    """Check admit.json the way services/haveno_admission.verify_admit_json does, but stricter.

    Returns (DRZI | PAD | NEPOZNATO, reason). Malformed input is NEPOZNATO; a readable
    document that fails a check is PAD. Signatures count once per DISTINCT known anchor.
    """
    if not isinstance(admit, dict):
        return NEPOZNATO, "admit is not a JSON object"
    for key in ("candidate_pk", "agent_id", "word", "nastao", "threshold", "body_sha", "signatures", "status"):
        if key not in admit:
            return NEPOZNATO, f"missing field: {key}"
    if not isinstance(admit["signatures"], list):
        return NEPOZNATO, "signatures is not a list"
    if admit["status"] != "ADMITTED":
        return PAD, f"status is {admit['status']!r}, not ADMITTED"
    if node_pk_hex and str(admit["candidate_pk"]).lower() != node_pk_hex.lower():
        return PAD, "candidate_pk is not this node's public key"

    body = {k: admit[k] for k in ("candidate_pk", "agent_id", "word", "nastao", "threshold")}
    canonical = json.dumps(body, sort_keys=True, ensure_ascii=False).encode()
    if hashlib.sha3_256(canonical).hexdigest() != admit["body_sha"]:
        return PAD, "body_sha does not match the signed body"

    valid = set()
    for entry in admit["signatures"]:
        if not isinstance(entry, dict):
            continue
        pk_hex = str(entry.get("anchor_pk", "")).lower()
        if pk_hex not in ANCHOR_PKS or pk_hex in valid:
            continue
        try:
            sig = base64.b64decode(entry.get("sig", ""), validate=True)
        except (ValueError, TypeError):
            continue
        if ed25519_verify(bytes.fromhex(pk_hex), sig, canonical):
            valid.add(pk_hex)
    if len(valid) < ADMIT_REQUIRED_SIGS:
        return PAD, f"{len(valid)} valid distinct anchor signatures, need {ADMIT_REQUIRED_SIGS}"
    return DRZI, "anchors: " + ", ".join(sorted(ANCHOR_PKS[pk] for pk in valid))


# =============================================================================
# Node State (global singleton)
# =============================================================================
class NodeState:
    def __init__(self):
        self.agent_id = ""
        self.word = ""
        self.eu_https = ""
        self.eu_http = ""
        self.node_port = DEFAULT_PORT
        self.bind = DEFAULT_BIND
        self.allow_insecure_http = False
        self.sk = b""
        self.pk = b""
        self.pk_hex = ""
        self.session_token = ""
        self.weise3_id = ""
        self.phi_t_login = ""
        self.admit_status = "UNKNOWN"
        self.admit_verdict = NEPOZNATO
        self.admit_reason = "not loaded"
        self.start_time = time.time()
        self.request_count = 0
        self.verify_count = 0
        self.last_error = ""
        self.lock = threading.Lock()

    def load(self):
        """Load config, keypair, and admit data."""
        # Config
        config_path = EHO6_DIR / "config.json"
        if not config_path.exists():
            raise FileNotFoundError(f"Config not found: {config_path}")
        with open(config_path) as f:
            cfg = json.load(f)
        self.agent_id = cfg["agent_id"]
        self.word = cfg.get("word", "pilot")
        self.eu_https = cfg.get("eu_https", "https://genesis.limit-connect.com")
        self.eu_http = cfg.get("eu_http", "http://217.160.71.124")
        self.node_port = int(cfg.get("node_port", DEFAULT_PORT))
        self.bind = cfg.get("bind", DEFAULT_BIND)
        # Plain-HTTP fallback sends the login signature and token in cleartext: opt-in only
        self.allow_insecure_http = cfg.get("allow_insecure_http") is True

        # Override port from env
        env_port = os.environ.get("EHO6_PORT")
        if env_port:
            self.node_port = int(env_port)
        env_bind = os.environ.get("EHO6_BIND")
        if env_bind:
            self.bind = env_bind

        # Keypair
        key_path = EHO6_DIR / "node.key"
        if not key_path.exists():
            raise FileNotFoundError(f"Key not found: {key_path}")
        with open(key_path, "rb") as f:
            self.sk = f.read(32)
        if len(self.sk) != 32:
            raise ValueError("node.key must be exactly 32 bytes")
        self.pk = ed25519_pubkey(self.sk)
        self.pk_hex = self.pk.hex()

        # Admit
        admit_path = EHO6_DIR / "admit.json"
        if admit_path.exists():
            try:
                with open(admit_path) as f:
                    admit = json.load(f)
            except (OSError, ValueError) as e:
                admit = None
                log_err(f"admit.json unreadable: {e}")
            # The file's own "status" is never trusted: ADMITTED only with 2 valid anchor signatures
            self.admit_verdict, self.admit_reason = verify_admit(admit, self.pk_hex)
            self.admit_status = "ADMITTED" if self.admit_verdict == DRZI else "ADMIT_" + self.admit_verdict
            if isinstance(admit, dict):
                self.weise3_id = admit.get("weise3_id", "")
            log(f"Admit verification: {self.admit_verdict} ({self.admit_reason})")
        else:
            self.admit_status = "NO_ADMIT_FILE"

        log(f"Loaded: agent={self.agent_id}, pk={self.pk_hex[:16]}..., admit={self.admit_status}")

    def eu_base(self) -> str:
        """Pick HTTPS first, fall back to HTTP."""
        return self.eu_https

    def eu_base_fallback(self) -> str:
        return self.eu_http

    def uptime(self) -> float:
        return time.time() - self.start_time


STATE = NodeState()


# =============================================================================
# Logging
# =============================================================================
def log(msg: str):
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{ts}] {msg}", flush=True)


def log_err(msg: str):
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{ts}] ERROR: {msg}", file=sys.stderr, flush=True)


# =============================================================================
# HTTP Client Helpers (stdlib)
# =============================================================================
def _http_request(url: str, data=None, headers=None, method="GET", timeout=30):
    """Make HTTP request, return (status_code, response_dict)."""
    hdrs = {"Content-Type": "application/json", "User-Agent": f"EHO6-Node/{VERSION}"}
    if headers:
        hdrs.update(headers)

    body = None
    if data is not None:
        body = json.dumps(data).encode()

    req = Request(url, data=body, headers=hdrs, method=method)

    # Certificate verification is never disabled: a TLS failure is an error, not a downgrade
    resp = urlopen(req, timeout=timeout, context=ssl.create_default_context())

    raw = resp.read().decode()
    try:
        return resp.status, json.loads(raw)
    except json.JSONDecodeError:
        return resp.status, {"raw": raw}


def _api_call(path: str, data=None, method="GET", headers=None, timeout=30):
    """Call EU API, try HTTPS then HTTP fallback."""
    url = STATE.eu_base().rstrip("/") + path
    try:
        return _http_request(url, data=data, headers=headers, method=method, timeout=timeout)
    except HTTPError:
        # Server answered over verified TLS; a 4xx/5xx is not a reason to change transport
        raise
    except Exception as e1:
        if not STATE.allow_insecure_http:
            log_err(f"API call failed: {path} — HTTPS: {e1} (HTTP fallback disabled)")
            raise
        log_err(f"WARNING: HTTPS failed ({e1}); using cleartext HTTP fallback (allow_insecure_http)")
        url2 = STATE.eu_base_fallback().rstrip("/") + path
        try:
            return _http_request(url2, data=data, headers=headers, method=method, timeout=timeout)
        except Exception as e2:
            log_err(f"API call failed: {path} — HTTPS: {e1}, HTTP: {e2}")
            raise


# =============================================================================
# Genesis Session Management
# =============================================================================
def genesis_login() -> dict:
    """
    Call EU login endpoint with signed timestamp.
    Returns {token, phi_t, word, ...}
    """
    ts = str(int(time.time()))
    msg = ts.encode()
    sig = ed25519_sign(STATE.sk, msg)
    sig_b64 = base64.b64encode(sig).decode()

    status, resp = _api_call(
        "/api/v1/eho6/login",
        data={"agent_id": STATE.agent_id, "ts": ts, "sig": sig_b64},
        method="POST",
    )
    if status != 200:
        raise RuntimeError(f"Login failed ({status}): {resp}")
    return resp


def genesis_bridge(token: str) -> dict:
    """
    Call EU bridge endpoint with login token.
    Returns {session_token, weise3_id, tier}
    """
    status, resp = _api_call(
        "/api/v1/eho6/bridge",
        data={"token": token},
        method="POST",
    )
    if status != 200:
        raise RuntimeError(f"Bridge failed ({status}): {resp}")
    return resp


def refresh_session():
    """Full login + bridge flow. Updates STATE."""
    try:
        login_resp = genesis_login()
        token = login_resp.get("token", "")
        if not token:
            raise RuntimeError(f"No token in login response: {login_resp}")

        STATE.phi_t_login = login_resp.get("phi_t", "")

        bridge_resp = genesis_bridge(token)
        with STATE.lock:
            STATE.session_token = bridge_resp.get("session_token", "")
            STATE.weise3_id = bridge_resp.get("weise3_id", STATE.weise3_id)

        log(f"Session refreshed: weise3={STATE.weise3_id}, phi_t={STATE.phi_t_login}")
    except Exception as e:
        log_err(f"Session refresh failed: {e}")
        with STATE.lock:
            STATE.last_error = str(e)


def session_refresh_loop():
    """Background thread: refresh genesis session every 50 minutes."""
    while True:
        try:
            refresh_session()
        except Exception as e:
            log_err(f"Session refresh loop error: {e}")
        time.sleep(SESSION_REFRESH_INTERVAL)


# =============================================================================
# EHO6 Mini-Pipeline (FraktalToken generation)
# =============================================================================
def classify_organ(order: dict) -> int:
    """Classify order into organ type based on amount range.

    Raises ValueError for anything that is not a finite, non-negative number.
    """
    amount = order.get("amount", order.get("value", 0))
    if isinstance(amount, bool) or not isinstance(amount, (int, float)):
        raise ValueError(f"amount must be a number, got {type(amount).__name__}")
    amount = float(amount)
    if not math.isfinite(amount) or amount < 0:
        raise ValueError(f"amount must be finite and >= 0, got {amount}")
    if amount < 100:
        return RIBOSOM
    elif amount < 10000:
        return REGULACIJA
    else:
        return VM_JEZGRA


def _uint_field(order: dict, name: str, default: int, maximum: int) -> int:
    """Read an unsigned integer field that must fit its token slot (no silent truncation)."""
    value = order.get(name, default)
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= maximum:
        raise ValueError(f"{name} must be an integer in 0..{maximum}, got {value!r}")
    return value


def compute_phi_t() -> int:
    """Compute phi_t: (time_us XOR 3524578) & 0xFFFFFFFF"""
    time_us = int(time.time_ns() // 1000)
    return (time_us ^ PHI_XOR) & 0xFFFFFFFF


def compute_anchor(order_bytes: bytes) -> bytes:
    """SHA-256 of order bytes, first 8 bytes."""
    return hashlib.sha256(order_bytes).digest()[:8]


def compress_payload(order_bytes: bytes) -> bytes:
    """First 16 bytes of order bytes as compressed payload."""
    payload = order_bytes[:16]
    if len(payload) < 16:
        payload = payload + b"\x00" * (16 - len(payload))
    return payload


def build_fraktal_token(order: dict) -> tuple:
    """
    Full EHO6 mini-pipeline:
    1. Classify organ
    2. Compute phi_t
    3. Compute anchor (SHA-256[:8])
    4. Pack FraktalToken: struct.pack(">BBHI8s16s", organ, intent, flags, phi_t, anchor, payload)
    Returns (token_b64, metadata_dict)
    """
    organ = classify_organ(order)
    intent = _uint_field(order, "intent", 1, 0xFF)  # 1 = default verification
    flags = _uint_field(order, "flags", 0, 0xFFFF)
    phi_t = compute_phi_t()

    # Serialize order for hashing
    order_bytes = json.dumps(order, sort_keys=True, separators=(",", ":")).encode()

    anchor = compute_anchor(order_bytes)
    payload = compress_payload(order_bytes)

    # Pack 32-byte FraktalToken
    # >BBHI8s16s = 1+1+2+4+8+16 = 32 bytes
    token_raw = struct.pack(
        ">BBHI8s16s",
        organ,
        intent,
        flags,
        phi_t,
        anchor,
        payload,
    )

    token_b64 = base64.b64encode(token_raw).decode()

    metadata = {
        "organ": organ,
        "organ_name": {RIBOSOM: "RIBOSOM", REGULACIJA: "REGULACIJA", VM_JEZGRA: "VM_JEZGRA"}.get(organ, "UNKNOWN"),
        "intent": intent,
        "flags": flags,
        "phi_t": phi_t,
        "anchor_hex": anchor.hex(),
        "token_size": len(token_raw),
        "agent_id": STATE.agent_id,
        "timestamp": time.time(),
    }

    return token_b64, metadata


# =============================================================================
# Local-only access checks
# =============================================================================
_LOCAL_HOSTNAMES = ("localhost", "127.0.0.1", "[::1]")


def _strip_port(hostport: str) -> str:
    if hostport.startswith("["):
        return hostport.split("]")[0] + "]"
    return hostport.rsplit(":", 1)[0] if ":" in hostport else hostport


def _is_local_host(host: str) -> bool:
    """True if the Host header names this machine (blocks DNS rebinding)."""
    return _strip_port(host.strip().lower()) in _LOCAL_HOSTNAMES


def _is_local_origin(origin: str) -> bool:
    """True for http(s)://localhost|127.0.0.1|[::1][:port] origins."""
    origin = origin.strip().lower()
    for scheme in ("http://", "https://"):
        if origin.startswith(scheme):
            return _is_local_host(origin[len(scheme):])
    return False


# =============================================================================
# HTTP Request Handler
# =============================================================================
class EHO6Handler(BaseHTTPRequestHandler):
    """HTTP handler for EHO6 node endpoints."""

    server_version = f"EHO6-Node/{VERSION}"

    def log_message(self, format, *args):
        """Override to use our logger."""
        log(f"HTTP {args[0] if args else ''}")

    def _send_json(self, data: dict, status: int = 200):
        body = json.dumps(data, indent=2).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Krunica-Hash", hashlib.sha256(body).hexdigest()[:16])
        self._send_cors_headers()
        self.end_headers()
        self.wfile.write(body)

    def _send_cors_headers(self):
        """Allow only browser pages served from this machine; never a wildcard."""
        origin = self.headers.get("Origin", "")
        if _is_local_origin(origin):
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")

    def _send_error(self, status: int, message: str):
        self._send_json({"error": message, "status": status}, status)

    def _read_body(self) -> dict:
        length = int(self.headers.get("Content-Length", 0))
        if length == 0:
            return {}
        raw = self.rfile.read(length)
        try:
            return json.loads(raw.decode())
        except (json.JSONDecodeError, UnicodeDecodeError):
            return {}

    def do_OPTIONS(self):
        """Handle CORS preflight."""
        self.send_response(204)
        self._send_cors_headers()
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.end_headers()

    def do_GET(self):
        with STATE.lock:
            STATE.request_count += 1
        path = self.path.split("?")[0].rstrip("/")

        if path == "/health":
            self._handle_health()
        elif path == "/eho6/status":
            self._handle_status()
        else:
            self._send_error(404, f"Not found: {path}")

    def do_POST(self):
        with STATE.lock:
            STATE.request_count += 1
        path = self.path.split("?")[0].rstrip("/")

        if path == "/eho6/verify":
            self._handle_verify()
        elif path == "/eho6/login":
            # Login returns the session token: refuse DNS-rebinding hosts and foreign origins
            if not _is_local_host(self.headers.get("Host", "")):
                self._send_error(403, "Login is only available via localhost")
                return
            origin = self.headers.get("Origin")
            if origin is not None and not _is_local_origin(origin):
                self._send_error(403, "Login is not allowed from a foreign origin")
                return
            self._handle_login()
        else:
            self._send_error(404, f"Not found: {path}")

    # --- Endpoint handlers ---------------------------------------------------

    def _handle_health(self):
        """GET /health — BORG-format health JSON."""
        uptime = STATE.uptime()
        self._send_json({
            "agent_id": STATE.agent_id,
            "url": f"http://localhost:{STATE.node_port}",
            "vrijeme": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "stanje": "ok" if STATE.admit_status == "ADMITTED" else "degraded",
            "dok_count": STATE.verify_count,
            "uptime_sec": round(uptime, 1),
            "phi_t": STATE.phi_t_login,
            "admit_status": STATE.admit_status,
            "version": VERSION,
            "request_count": STATE.request_count,
            "last_error": STATE.last_error,
            "session_active": bool(STATE.session_token),
            "weise3_id": STATE.weise3_id,
        })

    def _handle_status(self):
        """GET /eho6/status — detailed node status."""
        self._send_json({
            "agent_id": STATE.agent_id,
            "public_key": STATE.pk_hex,
            "admit_status": STATE.admit_status,
            "admit_verdict": STATE.admit_verdict,
            "admit_reason": STATE.admit_reason,
            "weise3_id": STATE.weise3_id,
            "session_active": bool(STATE.session_token),
            "phi_t": STATE.phi_t_login,
            "node_port": STATE.node_port,
            "uptime_sec": round(STATE.uptime(), 1),
            "verify_count": STATE.verify_count,
            "request_count": STATE.request_count,
            "version": VERSION,
            "eu_https": STATE.eu_https,
            "eu_http": STATE.eu_http,
        })

    def _handle_verify(self):
        """POST /eho6/verify — EHO6 verification pipeline."""
        body = self._read_body()
        order = body.get("order")

        if not order or not isinstance(order, dict):
            self._send_error(400, "Missing or invalid 'order' object in body")
            return

        try:
            token_b64, metadata = build_fraktal_token(order)
        except ValueError as e:
            self._send_error(400, f"Invalid order: {e}")
            return

        try:
            with STATE.lock:
                STATE.verify_count += 1

            self._send_json({
                "fraktal_token": token_b64,
                "token_size_bytes": 32,
                "metadata": metadata,
                "verified": True,
                "agent_id": STATE.agent_id,
            })
        except Exception as e:
            log_err(f"Verify failed: {e}")
            STATE.last_error = str(e)
            self._send_error(500, f"Verification failed: {e}")

    def _handle_login(self):
        """POST /eho6/login — refresh genesis session and return tokens."""
        try:
            login_resp = genesis_login()
            token = login_resp.get("token", "")

            if not token:
                self._send_error(502, "Login returned no token")
                return

            bridge_resp = genesis_bridge(token)

            with STATE.lock:
                STATE.session_token = bridge_resp.get("session_token", "")
                STATE.weise3_id = bridge_resp.get("weise3_id", STATE.weise3_id)
                STATE.phi_t_login = login_resp.get("phi_t", "")

            self._send_json({
                "session_token": STATE.session_token,
                "weise3_id": STATE.weise3_id,
                "phi_t": STATE.phi_t_login,
                "tier": bridge_resp.get("tier", ""),
                "word": login_resp.get("word", ""),
                "agent_id": STATE.agent_id,
            })

        except Exception as e:
            log_err(f"Login endpoint failed: {e}")
            STATE.last_error = str(e)
            self._send_error(502, f"Login failed: {e}")


# =============================================================================
# Server
# =============================================================================
def run_server():
    """Main entry point."""
    log(f"EHO6 Node v{VERSION} starting...")

    # Load state
    try:
        STATE.load()
    except Exception as e:
        log_err(f"Failed to load node state: {e}")
        log_err(f"Run install.sh first to set up ~/.eho6/")
        sys.exit(1)

    # Verify admit
    if STATE.admit_status != "ADMITTED":
        log(f"WARNING: Node not ADMITTED (status={STATE.admit_status}). Some features disabled.")

    # Initial session refresh (non-blocking — in thread)
    log("Starting initial session refresh...")
    session_thread = threading.Thread(target=session_refresh_loop, daemon=True)
    session_thread.start()

    # HTTP server
    port = STATE.node_port
    server = ThreadingHTTPServer((STATE.bind, port), EHO6Handler)
    server.daemon_threads = True
    log(f"Listening on {STATE.bind}:{port}")
    log(f"Health:  http://localhost:{port}/health")
    log(f"Status:  http://localhost:{port}/eho6/status")
    log(f"Verify:  POST http://localhost:{port}/eho6/verify")
    log(f"Login:   POST http://localhost:{port}/eho6/login")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log("Shutting down...")
        server.shutdown()
        log("Goodbye.")


if __name__ == "__main__":
    run_server()
