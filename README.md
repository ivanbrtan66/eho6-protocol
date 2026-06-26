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
