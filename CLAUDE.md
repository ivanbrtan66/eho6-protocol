# CLAUDE.md

Guidance for AI assistants working in this repository.

## What this repo is

EHO6 is a decentralized verification protocol for edge nodes. This repository holds the
**client side only**: the bootstrap installer and the edge-node daemon that users run on
their own machines. The server side (the "EU anchor" at `genesis.limit-connect.com` and the
"DE anchor") lives elsewhere and is **not** in this repo — you cannot read, test, or change
anchor behavior from here.

Admission to the mesh requires a Monero payment plus a 2-of-2 Ed25519 signature from both
anchors. The node daemon is a small HTTP server that mints 32-byte `FraktalToken`s and keeps
a Genesis session alive.

## Layout

The entire project is five files at the repository root. There are no packages, subdirectories,
build system, or CI.

| File | Role |
|---|---|
| `eho6_node.py` | The edge-node daemon. 610 lines, single file, stdlib only. |
| `install.sh` | Bootstrap: keygen → admission → download daemon → autostart. Bash, `set -euo pipefail`. |
| `README.md` | User-facing protocol overview and install instructions. |
| `CLAUDE.md` | This file. Repo-local guidance; not shipped to users. |
| `.gitignore` | Guards secrets (`*.key`, `*.sk`, `*.pw`, `.wallet_pw`, `*.env`). |

Only `eho6_node.py` and `install.sh` are deployed (see **Publishing**). The two Markdown files
stay in the repo.

`eho6_node.py` is organized as banner-commented sections in this order: constants → pure-Python
Ed25519 → `NodeState` → logging → HTTP client helpers → Genesis session management → FraktalToken
pipeline → `EHO6Handler` → `run_server()`. Keep new code in the section it belongs to and match
the existing `# ===...===` banner style.

## Hard constraints

These are not stylistic preferences — violating them breaks the product.

1. **Python standard library only.** No `pip install`, no `requirements.txt`, no third-party
   imports in `eho6_node.py`. The daemon must run on Termux/Android ARM where compiling
   native extensions (including `cryptography`/`PyNaCl`) is unreliable. This is why Ed25519
   is hand-rolled in pure Python. Do not "improve" it by swapping in a library.
2. **Python 3.11+.** `install.sh` searches `python3.13 → python3.12 → python3.11 → python3 → python`
   and hard-fails below 3.11.
3. **Three platforms.** Linux (systemd, system-wide if root, else user unit), macOS (LaunchAgent),
   Termux/Android (Termux:Boot script). Any change to install or autostart must handle all three.
4. **Single-file daemon.** `install.sh` downloads exactly one file (`eho6_node.py`) from
   `$EU_BASE/quantum/eho6/eho6_node.py`. Splitting the daemon into modules breaks installation
   for every existing user. If you must add code, add it to `eho6_node.py`.
5. **Never commit secrets.** `node.key` is a raw 32-byte Ed25519 seed. It stays in `~/.eho6/`,
   `chmod 600`, and never enters the repo, logs, or API responses. Log and print public keys
   truncated (`${PUBKEY:0:16}...`), as the existing code does.

## Runtime layout (`~/.eho6/`)

Created by `install.sh`, read by the daemon at startup. Not in the repo.

- `config.json` — `agent_id`, `word`, `eu_https`, `eu_http`, `node_port`
- `node.key` — 32-byte Ed25519 seed (mode 600)
- `node.pub` — hex public key
- `admit.json` — admission record; the daemon reads `status` and `weise3_id`
- `node.log` / `node.err` — daemon output

`STATE.load()` raises if `config.json` or `node.key` is missing, and `run_server()` exits 1.
A missing `admit.json` is tolerated: status becomes `NO_ADMIT_FILE` and the node runs degraded.
`EHO6_PORT` in the environment overrides `node_port` from config.

## Running and testing locally

There is no test suite and no CI. Verification is manual. Do not fabricate a test-passing claim;
run the checks below and report what they actually printed.

The daemon needs a `~/.eho6/` that does not exist in a fresh checkout, so point `HOME` at a
scratch directory rather than running `install.sh` (which would make real network calls and
request a real Monero payment):

```bash
export SCRATCH=/tmp/eho6-dev
mkdir -p "$SCRATCH/.eho6"
python3 -c "import secrets;open('$SCRATCH/.eho6/node.key','wb').write(secrets.token_bytes(32))"
cat > "$SCRATCH/.eho6/config.json" <<'EOF'
{"agent_id":"dev_test","word":"pilot",
 "eu_https":"https://genesis.limit-connect.com",
 "eu_http":"http://217.160.71.124","node_port":8099}
EOF
echo '{"status":"ADMITTED","weise3_id":"w3_dev"}' > "$SCRATCH/.eho6/admit.json"

HOME="$SCRATCH" EHO6_PORT=8099 python3 eho6_node.py
```

Then exercise the endpoints:

```bash
curl -s http://localhost:8099/health
curl -s http://localhost:8099/eho6/status
curl -s -X POST http://localhost:8099/eho6/verify \
  -H 'Content-Type: application/json' \
  -d '{"order":{"symbol":"BTC/USDT","side":"buy","qty":1.0}}'
```

`/health`, `/eho6/status`, and `/eho6/verify` all work fully offline. Only `/eho6/login` and the
background session thread need the EU anchor; without valid credentials they fail with
`401 Unauthorized`, which surfaces in `last_error` and in the log. That is expected in a dev
environment and is not a regression to chase.

**Regression check for the crypto.** Any edit near the Ed25519 code must be validated against
RFC 8032 test vector 1 before committing:

```bash
python3 -c "
import importlib.util
s=importlib.util.spec_from_file_location('n','eho6_node.py')
m=importlib.util.module_from_spec(s); s.loader.exec_module(m)
sk=bytes.fromhex('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60')
assert m.ed25519_pubkey(sk).hex()=='d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a'
assert m.ed25519_sign(sk,b'').hex()=='e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b'
print('ed25519 OK')"
```

The current implementation passes this. Note it is **sign-and-derive only** — there is no
verify function, because the node never checks anchor signatures locally.

For `install.sh`, `bash -n install.sh` catches syntax errors. Running it end-to-end is not
something to do casually: it contacts the live EU anchor, requests real admission, and installs
autostart units on the machine it runs on.

## The two subsystems

### Genesis session (needs network)

`genesis_login()` signs the current Unix timestamp with the node key and POSTs
`{agent_id, ts, sig}` to `/api/v1/eho6/login`. The returned `token` is exchanged via
`genesis_bridge()` at `/api/v1/eho6/bridge` for a `session_token` and `weise3_id`.
`session_refresh_loop()` runs this in a daemon thread every 50 minutes; `POST /eho6/login`
triggers it on demand. Both paths mutate `STATE` under `STATE.lock`.

All anchor calls go through `_api_call()`, which tries `eu_https` and falls back to `eu_http`.

### FraktalToken pipeline (offline)

`build_fraktal_token()` produces a 32-byte token:

```
struct.pack(">BBHI8s16s", organ, intent, flags, phi_t, anchor, payload)
 organ:1  intent:1  flags:2  phi_t:4  anchor:8  payload:16  = 32 bytes
```

- `organ` — from `classify_organ()`: `<100` → `RIBOSOM` (1), `<10000` → `REGULACIJA` (2),
  else `VM_JEZGRA` (3)
- `phi_t` — `(time_ns//1000 XOR 3524578) & 0xFFFFFFFF`, where `3524578` is Fibonacci F(32)
- `anchor` — `sha256(order_bytes)[:8]`
- `payload` — `order_bytes[:16]`, zero-padded

`order_bytes` is `json.dumps(order, sort_keys=True, separators=(",", ":"))`. That canonical
form is load-bearing: changing serialization changes every `anchor` and `payload`, so treat
it as a wire format, not an implementation detail.

## Node HTTP API

Served on `0.0.0.0:<node_port>` with `Access-Control-Allow-Origin: *`. Every response carries
`X-Krunica-Hash` (first 16 hex chars of the body's SHA-256).

| Method | Path | Notes |
|---|---|---|
| GET | `/health` | BORG-format health. Croatian keys: `vrijeme`, `stanje`, `dok_count`. |
| GET | `/eho6/status` | Detailed status, includes full public key. |
| POST | `/eho6/verify` | Requires `{"order": {...}}`; 400 if absent or not an object. |
| POST | `/eho6/login` | Refreshes the Genesis session; 502 on anchor failure. |
| OPTIONS | any | CORS preflight, 204. |

`stanje` is `"ok"` only when `admit_status == "ADMITTED"`, otherwise `"degraded"`.

## Conventions

- **Bilingual naming is intentional.** Croatian terms appear in the domain vocabulary
  (`RIBOSOM`, `REGULACIJA`, `VM_JEZGRA`, `vrijeme`, `stanje`, `dok_count`, `krunica`) alongside
  English code. These are part of the wire format — do not translate them.
- Log through `log()` / `log_err()`, never bare `print`. They prepend `[YYYY-MM-DD HH:MM:SS]`
  and flush, which matters because output is appended to `node.log` by systemd/launchd.
- Handlers are `_handle_<name>` methods on `EHO6Handler`, responding via `_send_json()` /
  `_send_error()`. Route by adding a branch in `do_GET` / `do_POST`; paths are normalized with
  `.split("?")[0].rstrip("/")`.
- Endpoint handlers catch broadly, record `STATE.last_error`, and return a JSON error rather
  than letting the exception escape. Keep that pattern — a crashed handler is worse than a 500.
- In `install.sh`, use the `ok` / `warn` / `die` / `info` helpers instead of raw `echo`, and
  quote all path expansions.
- Commit messages in this repo's history are short and imperative (`add eho6_node.py`).

## Known rough edges

Real, verified behaviors. Do not "fix" these as drive-by changes — they touch the protocol or
the anchor contract, so raise them before changing them.

- **Non-2xx anchor responses raise instead of returning.** `urlopen` raises `HTTPError` for
  4xx/5xx, and `HTTPError` subclasses `URLError`, so `_http_request`'s `except (ImportError, URLError)`
  swallows it, retries with a permissive SSL context, and finally propagates. The
  `if status != 200` checks in `genesis_login()` / `genesis_bridge()` are therefore unreachable;
  errors arrive as exceptions and land in `last_error`. Confirmed: a 401 from the anchor produces
  `last_error: "HTTP Error 401: Unauthorized"`, never a status-code branch.
- **The TLS fallback disables verification.** When the first `urlopen` fails, the retry sets
  `check_hostname = False` and `verify_mode = CERT_NONE`. This is deliberate for broken Termux
  cert stores, and `install.sh` likewise passes `--insecure` and prefers `EU_HTTP` on Termux.
  It is a real MITM exposure on the login path — treat any change here as a security decision.
- **`classify_organ()` reads `amount` or `value`, not `qty`.** The README's example order uses
  `qty`, so it classifies as `RIBOSOM` via the `0` default rather than by size. Verified.
- **README says SHA3-256; the code uses SHA-256.** `compute_anchor()` and `X-Krunica-Hash` both
  call `hashlib.sha256`. The docs are wrong, not the code — but the code is the deployed wire
  format, so fix the README rather than the hash.
- **`STATE.request_count` and `verify_count` are incremented without the lock** from
  `BaseHTTPRequestHandler` threads. Counters only; no correctness impact today.
- **`eu_base()` always returns HTTPS** despite its "pick HTTPS first, fall back" docstring;
  the actual fallback lives in `_api_call()`.

## Publishing

`install.sh` fetches the daemon from `$EU_BASE/quantum/eho6/eho6_node.py`, and the README's
one-liner fetches `install.sh` from the same host. Changes merged here do **not** reach users
until those files are deployed to `genesis.limit-connect.com`. That deployment step happens
outside this repository — say so plainly rather than implying a merge ships the change.

## Git workflow

Develop on the assigned feature branch, never commit directly to `main`, and push with
`git push -u origin <branch>`. Open pull requests as drafts.
