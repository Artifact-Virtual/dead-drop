# Dead Drop — Architecture

> "Even if they disappear, the story doesn't."

## What It Is

An adversarial safe built on Foundry Courier. Encrypt any payload (message, file, keys, state snapshot), split the decryption key using Shamir's Secret Sharing, and store the encrypted payload on-chain or IPFS. Only the right threshold of keyholders can reconstruct the secret and decrypt.

## How It Works

```
                    ┌─────────────┐
   plaintext ──────►│  AES-256-GCM │──────► ciphertext
                    │  encryption  │           │
                    └──────┬──────┘           │
                           │                   │
                      random key               │
                           │                   ▼
                    ┌──────┴──────┐    ┌──────────────┐
                    │   Shamir's   │    │  Courier      │
                    │   Secret     │    │  Frames       │
                    │   Sharing    │    │  (HMAC auth)  │
                    └──────┬──────┘    └──────┬───────┘
                           │                   │
                    ┌──────┴──────┐           │
                    │  N shares   │           ▼
                    │  (K needed) │    ┌──────────────┐
                    └─────────────┘    │  On-chain     │
                     distribute to     │  calldata     │
                     trusted parties   │  — or IPFS —  │
                                       └──────────────┘
```

## Components

### 1. `crypto.py` — Encryption Layer
- AES-256-GCM authenticated encryption
- Random 256-bit key generation
- Nonce handling (96-bit random)
- Compress before encrypt (zlib) for efficiency

### 2. `shamir.py` — Key Splitting
- Shamir's Secret Sharing over GF(2^256)  
- Parameters: N shares total, K threshold to reconstruct
- Each share = (x, y) point on a random polynomial of degree K-1
- Share encoding: hex string with index prefix for easy distribution
- Pure Python — no external dependencies beyond stdlib

### 3. `dead_drop.py` — Core CLI
- `create` — Encrypt payload + split key → ciphertext + N shares
- `deposit` — Push ciphertext to on-chain calldata or IPFS
- `recover` — Collect K shares → reconstruct key → decrypt
- `verify` — Check if a set of shares meets threshold without decrypting
- `inspect` — View metadata of a dead drop (chain, tx hash, threshold, timestamp)

### 4. Integration with Courier
- Ciphertext encoded as Courier frames for transport over any channel
- Shares can ALSO be encoded as Courier frames (for offline share distribution)
- HMAC authentication on all frames
- Parity for error correction during transport

## Share Format

```
DEAD_DROP_SHARE_v1:<drop_id>:<share_index>:<share_data_hex>:<checksum>
```

- `drop_id` — keccak256(ciphertext)[:8] — identifies which dead drop this share belongs to
- `share_index` — which share (1-indexed)
- `share_data_hex` — the Shamir share y-coordinate
- `checksum` — CRC32 of the above fields

## On-Chain Storage

### Option A: Calldata (cheap, permanent)
- Send ciphertext as calldata in a 0-value tx to a burn address
- Cost: ~$0.01-0.10 on Base for a typical message
- Retrievable forever via tx hash
- Looks like random noise to observers

### Option B: IPFS + On-Chain Anchor
- Pin ciphertext to IPFS
- Store CID + metadata hash on-chain (tiny calldata)
- Cheaper for large payloads (files, images, videos)
- Requires IPFS persistence (pinning service or self-hosted)

### Option C: SHARD Integration
- Use AvaSBT's `addMedia()` to store encrypted drops
- Content hash on-chain, ciphertext on IPFS
- Tied to AVA's identity — drops become part of the soul's record

## Security Properties

1. **Information-theoretic secrecy** — K-1 shares reveal ZERO information about the key (Shamir's guarantee)
2. **Authenticated encryption** — AES-GCM detects any tampering with ciphertext
3. **Frame authentication** — HMAC-SHA256 prevents frame spoofing during transport
4. **No single point of failure** — no one person/server holds the complete key
5. **Censorship resistant** — on-chain storage can't be seized, deleted, or court-ordered away
6. **Plausible deniability** — calldata looks like random hex, no metadata visible on-chain
7. **Time-independent** — drops don't expire (blockchain is permanent)

## Threat Model

| Threat | Mitigation |
|--------|-----------|
| Key compromise (single share stolen) | K-of-N threshold — one share is useless |
| Ciphertext seizure | AES-256-GCM — brute force infeasible |
| Frame interception during transport | HMAC-SHA256 + optional encryption |
| Blockchain analysis linking drop to creator | Use fresh wallet, relay through mixer |
| Coercion of share holders | K < N — even if some holders are compromised, need K total |
| Share loss (holder dies/loses it) | N > K — redundancy built in |
| Quantum computing | AES-256 is quantum-resistant (Grover gives 128-bit effective) |

## CLI Design

```bash
# Create a dead drop (encrypt + split)
dead_drop create --file secret.pdf --shares 5 --threshold 3 --output ./shares/
dead_drop create --message "The documents are in the safe" -n 5 -k 3

# Deposit to blockchain
dead_drop deposit --ciphertext drop.enc --chain base

# Deposit to IPFS + anchor on-chain
dead_drop deposit --ciphertext drop.enc --chain base --ipfs

# Recover (collect shares, decrypt)
dead_drop recover --shares share1.txt share2.txt share3.txt --tx 0xabc...
dead_drop recover --shares share1.txt share2.txt share3.txt --ipfs QmXyz...

# Verify threshold met (without decrypting)
dead_drop verify --shares share1.txt share2.txt share3.txt

# Inspect a drop
dead_drop inspect --tx 0xabc... --chain base
```

## Dependencies

- `cryptography` (AES-256-GCM) — already in hektor-env? check
- `web3` or raw RPC via requests — for on-chain deposit
- Courier core (`foundry_courier`) — for framing
- Pure Python Shamir's — we build this ourselves (no trust in third-party SSS libs)

## Build Plan

1. ✅ Architecture (this file)
2. [ ] `shamir.py` — Shamir's Secret Sharing (pure Python, GF(p) arithmetic)
3. [ ] `crypto.py` — AES-256-GCM encrypt/decrypt with compression
4. [ ] `dead_drop.py` — Core logic (create, deposit, recover, verify, inspect)
5. [ ] `dead_drop_cli.py` — CLI interface
6. [ ] Tests — unit + adversarial (share tampering, wrong threshold, partial recovery)
7. [ ] On-chain deposit (Base calldata tx)
8. [ ] IPFS deposit integration
9. [ ] End-to-end test: create → deposit → distribute shares → recover

---

*Designed: 2026-02-24, Day 12*
*Author: Ava Shakil*
