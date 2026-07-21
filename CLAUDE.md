# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository Overview

EHO6 is a decentralized cryptographic membership/verification protocol for edge nodes. This repo contains the **edge node daemon** and its **installer** — not the anchor servers (EU/DE) that the node talks to; those live elsewhere and are only reachable over the network (`genesis.limit-connect.com`).

The repo is intentionally minimal: two runnable scripts and a README. There is no build system, package manifest, or test suite.

- `eho6_node.py` — the edge node daemon (stdlib-only Python 3.11+). Runs an HTTP server, manages the node's Ed25519 identity, maintains a session with the EU anchor, and exposes the local verification API.
- `install.sh` — bash bootstrap script. Detects the platform, generates the node's keypair, requests admission from the EU anchor (paid in Monero), polls until admitted, downloads/places `eho6_node.py` into `~/.eho6/`, wires up autostart (systemd/LaunchAgent/Termux:Boot), and starts the node.
- `README.md` — protocol description, install one-liners, API examples, and the FraktalToken wire format. Read it for the "why"; this file covers the "how to work on the code."

## Running / Testing Locally

There is no test suite, linter, or build step configured. To exercise changes:

```bash
# Syntax/sanity check the daemon
python3 -c "import ast; ast.parse(open('eho6_node.py').read())"

# Run the daemon directly (requires ~/.eho6/config.json and ~/.eho6/node.key to exist first — see install.sh)
python3 eho6_node.py

# Exercise the installer's bash syntax without running it
bash -n install.sh
```

`eho6_node.py` refuses to start without `~/.eho6/config.json` and `~/.eho6/node.key` (it exits with instructions to run `install.sh` first). To test the daemon standalone without going through the full paid-admission flow, hand-create those files:

```bash
mkdir -p ~/.eho6
python3 -c "import secrets,pathlib; pathlib.Path.home().joinpath('.eho6/node.key').write_bytes(secrets.token_bytes(32))"
cat > ~/.eho6/config.json <<'EOF'
{"agent_id": "test_agent", "word": "pilot", "node_port": 8091}
EOF
python3 eho6_node.py
```

Then hit the local API:

```bash
curl http://localhost:8091/health
curl -X POST http://localhost:8091/eho6/verify -H "Content-Type: application/json" \
  -d '{"order": {"symbol": "BTC/USDT", "side": "buy", "qty": 1.0}}'
```

Note: without a real `admit.json` (issued by the EU anchor after payment), `/eho6/login` and the background session-refresh loop will fail against the live anchor — this is expected when testing offline. `/eho6/verify` works fully offline since FraktalToken generation is local-only.

## Architecture

### Two independent artifacts, one deployment flow

`install.sh` and `eho6_node.py` are decoupled: the installer's only jobs are identity generation, paid admission, and process supervision. Once `~/.eho6/{config.json,node.key,admit.json}` exist, `eho6_node.py` is fully self-sufficient and re-runnable on its own. Keep this separation when adding features — install-time/one-shot logic belongs in `install.sh`; runtime logic belongs in `eho6_node.py`.

### `~/.eho6/` is the node's persistent state directory

Both scripts read/write the same layout:
- `node.key` — 32-byte raw Ed25519 private key (mode 600)
- `node.pub` — hex-encoded public key (installer convenience copy)
- `config.json` — `agent_id`, `word`, `eu_https`, `eu_http`, `node_port`
- `admit.json` — admission record returned by the EU anchor once ADMITTED (status, weise3_id, etc.)
- `node.log` / `node.err` — daemon output (used by all three autostart mechanisms)

### Pure-Python Ed25519 (no third-party deps, deliberately)

Both `eho6_node.py` and the keygen step embedded in `install.sh` implement Ed25519 sign/keygen from scratch using only `hashlib`/`secrets`/big-int math (`_add`, `_scalarmult`, `_encode` over curve25519). This is intentional — the project targets Termux/Android ARM where installing `cryptography` or `pynacl` is often impractical. **The same Ed25519 implementation is duplicated in both files.** If you fix a bug or change behavior in one copy, update the other to match.

### Node runtime (`eho6_node.py`) is single-file, three concerns in one process

1. **`NodeState`** (global singleton `STATE`) — loads `~/.eho6/*` on startup, holds the keypair, admit status, and live session token behind a `threading.Lock`.
2. **Genesis session management** (`genesis_login`, `genesis_bridge`, `refresh_session`) — signs a timestamp with the node key, exchanges it for a session token via the EU anchor's `/api/v1/eho6/login` and `/api/v1/eho6/bridge`. Runs on a daemon thread (`session_refresh_loop`) every `SESSION_REFRESH_INTERVAL` (50 min), independent of incoming HTTP traffic. All outbound anchor calls (`_api_call`) try HTTPS first and silently fall back to the plain-HTTP anchor address (`eu_http`) — this fallback exists for Termux environments with broken TLS trust stores.
3. **HTTP server** (`EHO6Handler`, stdlib `http.server`) — serves the local node API on `node_port` (default 8091). Routes are dispatched by literal path match in `do_GET`/`do_POST`; add new endpoints there.

### FraktalToken pipeline (`build_fraktal_token`)

The core "verification" logic is a fixed 4-step, fully local pipeline with no network calls:
1. `classify_organ` — buckets an order into RIBOSOM/REGULACIJA/VM_JEZGRA by amount.
2. `compute_phi_t` — Fibonacci-XOR-modulated microsecond timestamp (`PHI_XOR = 3524578`).
3. `compute_anchor` — SHA-256(order_bytes)[:8].
4. `compress_payload` — first 16 bytes of the canonical JSON-serialized order, zero-padded.

These are packed via `struct.pack(">BBHI8s16s", ...)` into an exact 32-byte token (see README's FraktalToken Format section for the byte layout). Preserve this struct format exactly — anchors and other consumers parse it by fixed offsets, not by any schema/version field.

### Endpoints (kept in sync between code and README)

- `GET /health` — BORG-format health JSON (Croatian field names: `stanje`, `vrijeme`, `dok_count` — this is intentional, not a bug, matching an external monitoring convention).
- `GET /eho6/status` — detailed node status.
- `POST /eho6/verify` — runs the FraktalToken pipeline, fully offline.
- `POST /eho6/login` — forces an immediate genesis login+bridge refresh (network call to the anchor).

If you add/change an endpoint, update both the handler dispatch and the README's "Edge Node API" section.

## Conventions

- Stdlib-only. Do not add third-party Python dependencies (`requests`, `pynacl`, etc.) — the whole point is that this runs unmodified on Termux/Android ARM with just a stock Python 3.11+ install.
- Bash installer targets `set -euo pipefail` and must remain POSIX-ish/portable across Linux, macOS, and Termux — avoid GNU-only flags without checking availability first (see the existing platform-detection pattern at the top of `install.sh`).
- Never commit real key material — `.gitignore` already excludes `*.key`, `*.sk`, `*.pw`, `.wallet_pw`, `*.env`.
- Secrets/keys directory is `~/.eho6/`, not anything inside the repo.
