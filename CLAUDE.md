# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this repo is

EHO6 is a decentralized membership/verification protocol for edge nodes. This repo contains the **edge node deliverables only** — the daemon that runs on a member's machine and the installer that bootstraps it. The EU/DE anchor servers (the admission and consensus backend at `genesis.limit-connect.com`) are a separate, external service this code talks to over HTTP(S) — they are not part of this repository.

The repo is intentionally minimal:
- `eho6_node.py` — the edge node HTTP daemon (single file, Python stdlib only)
- `install.sh` — bootstrap installer (bash, POSIX-ish, targets Linux/macOS/Termux)
- `README.md` — protocol overview, API examples, cryptography/anchor reference

There is no build system, package manager, dependency file, test suite, or linter configured in this repo — both deliverables are self-contained scripts by design (see "stdlib-only" below).

## Running the node

```bash
# Requires ~/.eho6/config.json, node.key, admit.json (created by install.sh)
python3 eho6_node.py

# Override the listen port without editing config.json
EHO6_PORT=9091 python3 eho6_node.py
```

The daemon reads its identity/config from `~/.eho6/` on startup (`NodeState.load()` in `eho6_node.py`) and exits immediately if `config.json` or `node.key` is missing — it does not scaffold that directory itself. To get a working `~/.eho6/`, run the installer first:

```bash
bash install.sh --agent-id your_node_name --word yourword [--port 8091] [--termux]
```

There are no automated tests in this repo. Verify changes by exercising the running daemon's HTTP endpoints:

```bash
curl http://localhost:8091/health
curl http://localhost:8091/eho6/status
curl -X POST http://localhost:8091/eho6/verify \
  -H "Content-Type: application/json" \
  -d '{"order": {"symbol": "BTC/USDT", "side": "buy", "qty": 1.0}}'
curl -X POST http://localhost:8091/eho6/login
```

## Architecture

### `eho6_node.py` — single-file daemon, four concerns in one process

1. **Pure-Python Ed25519** (`ed25519_sign`, `ed25519_pubkey`, and the low-level `_add`/`_scalarmult`/`_encode` field-arithmetic helpers). This exists so the node has zero third-party dependencies and runs unmodified on Termux/Android ARM, where compiling `pynacl`/`cryptography` is often impractical. **Do not replace this with a `pip`-installed crypto library** — that would break the stdlib-only/Termux guarantee that is the whole point of this design. If you touch this section, preserve exact wire-compatibility with the anchor servers' Ed25519 verification.

2. **`NodeState`** (global singleton `STATE`) — holds the loaded keypair, agent config, admission status, and session token, guarded by `STATE.lock` since it's mutated both by the HTTP handler thread(s) and the background session-refresh thread. Any new field that's read/written from more than one thread must go through this same lock.

3. **Genesis session management** (`genesis_login`, `genesis_bridge`, `refresh_session`, `session_refresh_loop`) — a background daemon thread re-authenticates with the EU anchor every `SESSION_REFRESH_INTERVAL` (50 min) by signing the current timestamp with the node's private key. `_api_call` always tries `eu_https` first and falls back to `eu_http` on failure — preserve this fallback when adding new anchor calls, since Termux TLS is unreliable (see `install.sh`'s `--insecure` handling for the same reason).

4. **EHO6 mini-pipeline / FraktalToken** (`classify_organ`, `compute_phi_t`, `compute_anchor`, `compress_payload`, `build_fraktal_token`) — turns an arbitrary `order` dict into a fixed 32-byte binary token: `struct.pack(">BBHI8s16s", organ, intent, flags, phi_t, anchor, payload)`. Field widths and byte order are part of the wire format consumed elsewhere in the EHO6 ecosystem — changing the struct format, the `phi_t` XOR constant (`PHI_XOR`), or the organ/intent value meanings is a breaking protocol change, not a local refactor.

HTTP routing is a hand-rolled dispatcher on `BaseHTTPRequestHandler` (`EHO6Handler.do_GET`/`do_POST` switching on `self.path`), not a framework. Endpoints:

| Method | Path | Handler |
|---|---|---|
| GET | `/health` | `_handle_health` — BORG-format health JSON |
| GET | `/eho6/status` | `_handle_status` — detailed node status |
| POST | `/eho6/verify` | `_handle_verify` — runs the FraktalToken pipeline on `{"order": {...}}` |
| POST | `/eho6/login` | `_handle_login` — forces an immediate session refresh |

All responses go through `_send_json`, which also stamps an `X-Krunica-Hash` header (SHA-256 of the response body, truncated) and permissive CORS headers — keep new endpoints consistent with this.

### `install.sh` — installer/bootstrapper

Single bash script, no external tooling beyond `curl` and a Python 3.11+ interpreter (auto-detected by probing `python3.13` → `python3.12` → `python3.11` → `python3` → `python`). Responsibilities, in order: detect platform (Linux/macOS/Termux), generate an Ed25519 keypair (a **duplicate, inline copy** of the same field-arithmetic used in `eho6_node.py` — if you change the curve math in one place, mirror it in the other), collect `agent_id`/`word`, write `~/.eho6/config.json`, POST an admission request to the EU anchor, poll `/api/v1/eho6/admit/status/<agent_id>` until `ADMITTED`/`FAILED`/`EXPIRED`, write `~/.eho6/admit.json`, download `eho6_node.py` from the anchor, wire up autostart (systemd unit — system or `--user` — on Linux, a LaunchAgent plist on macOS, a Termux:Boot script on Android), and finally launches the node.

Note the installer *downloads* `eho6_node.py` from the anchor server at install time rather than using the copy checked into this repo — this repo's `eho6_node.py` is the source of truth that gets published to `${EU_BASE}/quantum/eho6/eho6_node.py`; keep that in mind when reasoning about "what code actually runs on a node."

## Conventions specific to this codebase

- **Zero third-party dependencies, on purpose.** Both files must keep working with nothing beyond the Python standard library and `curl`/bash — this is what makes Termux/Android support possible. Don't introduce a `requirements.txt`, `pip install`, or bash dependency on tools not already used (`curl`, `python3`, `systemctl`/`launchctl` where applicable).
- **HTTPS-then-HTTP fallback** is a deliberate pattern (`_api_call` in the daemon, `CURL_FLAGS`/`EU_BASE` selection in the installer) to work around flaky TLS on some Termux setups. Preserve it rather than "simplifying" to HTTPS-only.
- Croatian/mixed-language identifiers appear intentionally in the protocol vocabulary (organ types `RIBOSOM`, `REGULACIJA`, `VM_JEZGRA`; the `stanje`/`vrijeme`/`dok_count` fields in the BORG-format `/health` response; `weise3_id`). These are protocol/wire terms shared with the external anchor services — do not translate or rename them.
- Binary formats (`FraktalToken`'s `struct.pack` layout, the raw 32-byte Ed25519 key file at `~/.eho6/node.key`) are fixed wire/storage contracts with the anchor servers and other EHO6 tooling outside this repo. Treat any change to byte layout, field order, or sizes as a breaking protocol change.
