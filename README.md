# EHO6 — Decentralized Verification Protocol

> **"Truth is proven, not claimed."**

EHO6 is a cryptographic membership protocol for distributed edge networks. Admission requires payment and dual-anchor Ed25519 consensus — no central authority.

## How It Works

```
Edge Node                EU Anchor              DE Anchor
    │                        │                      │
    ├─ POST /admit/request ──►│                      │
    │◄─ XMR address ─────────┤                      │
    │                        │                      │
    ├─ [Send 0.001 XMR] ─────────────────────────── ─►
    │                        │                      │
    │              [Detect payment]                  │
    │                [EU signs body]                 │
    │                        ├─ POST /anchor/sign ──►│
    │                        │◄─ DE signature ───────┤
    │                        │                      │
    │◄─ admit.json (2/2 sigs)─┤                      │
    │                        │                      │
    ├─ POST /login ──────────►│                      │
    │◄─ EHO6 token (φ-time) ─┤                      │
```

## One-Command Install

```bash
# Linux / macOS
curl -fsSL https://genesis.limit-connect.com/quantum/eho6/install.sh | bash

# Termux (Android)
curl -fsSL https://genesis.limit-connect.com/quantum/eho6/install.sh | bash -s -- --termux

# With custom agent ID
curl -fsSL https://genesis.limit-connect.com/quantum/eho6/install.sh | bash -s -- \
  --agent-id your_node_name --word yourword
```

## What the Installer Does

1. Detects platform (Linux / macOS / Termux/Android)
2. Generates Ed25519 keypair locally (`~/.eho6/node.key`)
3. Requests admission — returns Monero address
4. Polls status every 10s until `ADMITTED`
5. Downloads `eho6_node.py` edge daemon
6. Configures autostart (systemd / LaunchAgent / Termux:Boot)
7. Starts node — available at `http://localhost:8091`

## Edge Node API

```bash
# Health (BORG format)
curl http://localhost:8091/health

# EHO6 mini-pipeline (classify + FraktalToken)
curl -X POST http://localhost:8091/eho6/verify \
  -H "Content-Type: application/json" \
  -d '{"order": {"symbol": "BTC/USDT", "side": "buy", "qty": 1.0}}'

# Genesis session refresh
curl -X POST http://localhost:8091/eho6/login
```

## Cryptography

| Component | Algorithm |
|-----------|-----------|
| Node identity | Ed25519 keypair |
| Admission signature | Ed25519 (EU anchor) |
| Consensus | 2-of-2 threshold (EU + DE) |
| Payment | Monero (XMR) — subaddress per agent |
| Token | Ed25519-signed JWT-like (3-part base64) |
| Hash | SHA3-256 (body_sha) |

## Anchors

| Node | Jurisdiction | Public Key |
|------|-------------|------------|
| genesis-eu | Hetzner EU (Frankfurt) | `4d628b9c...a4f46b13` |
| genesis-de | IONOS DE (Berlin) | `d210246f...f421dc8f` |

## Admission Requirements

- **Fee**: 0.001 XMR (~$0.15)
- **Payment window**: 24 hours
- **Confirmations**: 10 blocks (~20 min)
- **Consensus**: Both anchors must sign

## Technical Paper

[EHO6 Whitepaper (PDF)](https://genesis.limit-connect.com/quantum/eho6/whitepaper.pdf) — June 2026

## FraktalToken Format

Every verified order becomes a 32-byte `FraktalToken`:

```
[organ:1][intent:1][flags:2][phi_t:4][anchor:8][payload:16] = 32 bytes
```

Where `phi_t` is a Fibonacci-modulated timestamp: `(time_ns//1000 XOR F(32)) & 0xFFFFFFFF`

## License

MIT — use freely, attribution appreciated.

## Chain

Built on the Genesis chain (`genesis.limit-connect.com`). Every admission is a permanent cryptographic record.

---

*EHO6 Research Collective — 2026*

---

## MASKA — Address Indirection Layer (`maska/`, `rizom/`)

A second layer on top of EHO6: separating **where people find you** (public,
DNS-indexed, stable) from **where you actually live** (physical, hidden, changing).
Continues the `c1570` draft. Full engineering document (Croatian, with measured
state, known limits and falsification criteria): [`docs/MASKA-FAZE.md`](docs/MASKA-FAZE.md).

| Phase | What it is | Status |
|-------|-----------|--------|
| **F1 PELUD** | Signed, expiring locator record — extends the existing GENESIS1 DNS TXT format | **built** (`maska/pelud.py`) |
| **F2 `dnkd`** | Local `.dnk` resolver: PULL + Ed25519 verify + split-brain check + stable RFC 6598 address | **built** (`maska/dnkd.py`) |
| **F3 RIZOM** | Dual-anchor WireGuard replacing single `ssh -R` reverse tunnels | **tooling built**, pilot not yet deployed |
| **F4 Direct punch** | ICE/STUN rendezvous, peer-to-peer traffic — the phase that actually removes the SPOF | **not built** |
| **F5 K-of-N board** | N registrars / TLDs / jurisdictions, K-of-N consensus | **not built** (costs SEO reach — conditional) |

### PELUD record

```
v=PELUD1 ime=medijapos.dnk alg=ed25519 pk=<64hex> h=<chain height> exp=<epoch> \
loc=wg://host:51820/<key>|https://mirror.example sig=<base64url>
```

Unknown fields, non-canonical spelling, a missing pin, an expired claim, or a
reserved-but-unimplemented `alg` (e.g. `ml-dsa-65`) are all **rejected** — never
silently accepted.

```bash
python3 -m maska.pelud izdaj --ime medijapos.dnk --kljuc ~/.eho6/node.key \
        --visina 4287 --loc wg://217.160.71.124:51820/<wgkey> --vijek 600
python3 -m maska.pelud provjeri --txt "v=PELUD1 …" --pk <64hex>
```

### `dnkd` local resolver

```bash
sudo ./maska/instaliraj_dnkd.sh --ime medijapos.dnk --pk <64hex> \
     --sidro https://genesis.limit-connect.com/pelud \
     --sidro https://fina-connect.online/pelud \
     --zrcalo genesis-medijapos.limit-connect.com

dig @127.0.0.53 -p 5353 medijapos.dnk A     # mapped 100.80.0.0/12 address
dig @127.0.0.53 -p 5353 medijapos.dnk TXT   # the PELUD record itself
curl -sS http://127.0.0.1:8099/borg/health.json
```

Everything outside `.dnk` gets `REFUSED` — `dnkd` is a stub resolver, never a
forwarder. It installs **no CA** into the system trust store: TLS for `.dnk` is
terminated by the application on loopback. See `docs/MASKA-FAZE.md` §5.

Control panel at `http://127.0.0.1:8099/` — every action shows a loading state,
every failure shows a translated readable message, every success is confirmed, and
a lost connection to the daemon shows a persistent banner instead of frozen numbers.

### RIZOM dual-anchor WireGuard

```bash
python3 -m rizom.rizom_konfig --uredjaj x96 --ime-usluge medijapos \
        --usluga-port 8093 \
        --sidro eu:genesis.limit-connect.com:51820 \
        --sidro new:fina-connect.online:51820 --izlaz ./izlaz-rizom

sudo ./rizom/deploy_sidro.sh --sidro eu --izvor ./izlaz-rizom/eu --usluga medijapos
sudo ./izlaz-rizom/x96/instaliraj-rub.sh
sudo python3 rizom/patch_watchdog.py --usluga medijapos --port 18196 --uredjaj X96
```

`AllowedIPs` is always the anchor's `/32` — never `0.0.0.0/0`, so the device's
normal traffic is untouched. The anchor side gets a **new** nginx file on a **new**
port, so no existing site (and no other domain on that server) is modified, and the
old `ssh -R` path keeps running and being measured in parallel. Every script backs
up before it writes and has a documented one-command rollback.

### GODOVI measurement ledger

Every resolution — successful, failed, or unmeasurable — is appended as a
hash-chained JSONL line, so availability becomes a history a third party can check:

```bash
python3 -m maska.godovi /var/lib/maska/godovi.jsonl
```

### Tests

134 tests, standard library only, no network egress (anchors run on loopback).
Ed25519 is checked against RFC 8032 §7.1 vectors, X25519 against RFC 7748 §5.2 and
cross-checked against `openssl`, and interoperability with `eho6_node.py` signatures
is asserted:

```bash
./tests/pokreni_sve.sh
```
