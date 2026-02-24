# Dead Drop

**Encrypt anything. Split the key. Trust no one.**

<p align="center">
  <img src="dead_drop/assets/header.png" alt="Dead Drop" width="100%">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/crypto-AES--256--GCM-blue?style=flat-square" alt="Crypto">
  <img src="https://img.shields.io/badge/key_split-Shamir's_SSS-purple?style=flat-square" alt="SSS">
  <img src="https://img.shields.io/badge/tests-25%2F25-brightgreen?style=flat-square" alt="Tests">
  <img src="https://img.shields.io/badge/SSS_deps-zero-orange?style=flat-square" alt="Deps">
  <img src="https://img.shields.io/badge/license-MIT-green?style=flat-square" alt="License">
</p>

---

Dead Drop encrypts any payload with **AES-256-GCM**, then splits the encryption key into **N shares** using **Shamir's Secret Sharing**. Any **K shares** reconstruct the key. **K−1 shares** reveal *nothing* — not probabilistically, not computationally, but **information-theoretically**. An adversary with infinite computing power and K−1 shares learns exactly zero bits about your secret.

Store the ciphertext wherever you want — on a blockchain, IPFS, a USB stick, a QR code under a park bench. Without the threshold of shares, it's noise.

## How It Works

```
                         Your Data
                        (any bytes)
                            │
                     ┌──────▼──────┐
                     │  AES-256    │
                     │  -GCM       │──────────────┐
                     │  Encrypt    │              │
                     └──────┬──────┘              │
                            │                     │
                     ┌──────▼──────┐       ┌──────▼──────┐
                     │   Shamir    │       │  Ciphertext  │
                     │   Split     │       │  (on-chain / │
                     │   Key → N   │       │   IPFS / USB)│
                     └──────┬──────┘       └─────────────┘
                            │
               ┌────────────┼────────────┐
               ▼            ▼            ▼
          Share 1      Share 2      Share N
          (Alice)      (Bob)        (...)

     Any K shares → key → decrypt      K−1 shares → nothing
```

## Install

```bash
git clone https://github.com/Artifact-Virtual/dead-drop.git
cd dead-drop
pip install -e .
```

Requires Python 3.8+ and `cryptography` (or `pycryptodome`). Shamir's implementation has **zero dependencies** — pure Python, pure math.

## Usage

### Create a dead drop

```bash
# Text payload, 3-of-5 threshold
python cli.py create -m "The evidence is in building 7, third floor." -n 5 -k 3 --output ./drops/

# File payload (any binary — PDFs, images, databases, private keys)
python cli.py create -f evidence.pdf -n 5 -k 3 --output ./drops/

# From stdin
cat wallet.key | python cli.py create -n 3 -k 2 --output ./drops/
```

Output:
```
Creating dead drop: 52 bytes, 3-of-5 threshold
Crypto backend: cryptography
Drop ID: a1b2c3d4e5f67890
Ciphertext: 97 bytes

Drop saved to: ./drops/a1b2c3d4e5f67890/
  Metadata:    drop.json
  Ciphertext:  ciphertext.bin
  Shares:      shares/ (5 files)

============================================================
⚠️  DISTRIBUTE SHARES TO TRUSTED PARTIES NOW
⚠️  Need 3 of 5 shares to recover
⚠️  DELETE local shares after distribution!
============================================================
```

### Recover

Any 3 of the 5 share holders come together:

```bash
python cli.py recover \
  --shares share_001.txt share_003.txt share_005.txt \
  --ciphertext ciphertext.bin \
  -k 3
```

```
Recovery successful! Payload: 52 bytes

--- Payload ---
The evidence is in building 7, third floor.
--- End ---
```

### Verify shares

Check validity without decrypting:

```bash
python cli.py verify --shares share_001.txt share_002.txt share_003.txt
```

```
Valid:       True
Drop ID:     a1b2c3d4e5f67890
Shares:      3
Indices:     [1, 2, 3]
```

### Inspect a drop

```bash
python cli.py inspect --drop ./drops/a1b2c3d4e5f67890/
```

## The Math

The encryption key `S` becomes the constant term of a random polynomial of degree `k−1`:

```
f(x) = S + a₁x + a₂x² + ... + aₖ₋₁xᵏ⁻¹   (mod p)
```

Each share is a point `(i, f(i))` on this curve. Given `k` points, [Lagrange interpolation](https://en.wikipedia.org/wiki/Lagrange_polynomial) uniquely determines `f` and recovers `f(0) = S`. Given `k−1` points, every possible value of `S` is equally consistent with the data. This is **information-theoretic security** — it doesn't depend on computational hardness assumptions. It holds against quantum computers. It holds against God.

**Field:** GF(p) where `p` is the secp256k1 curve order — a 256-bit prime. The shares speak Ethereum natively.

**Implementation:** Pure Python. Extended Euclidean Algorithm for modular inverse. Horner's method for polynomial evaluation. `secrets.randbelow()` for cryptographically secure coefficients. **~120 lines. No imports beyond stdlib.** Audit it in 10 minutes.

### Encryption

- **AES-256-GCM**: 256-bit random key, 96-bit random nonce, authenticated encryption
- **zlib compression** before encryption (configurable)
- Tampered ciphertext → authentication failure → immediate rejection

### Share Format

```
DEAD_DROP_SHARE_v1:<drop_id>:<index>:<share_hex>:<crc32>
```

One line of text. Send it over Signal, write it on paper, encode it in a QR code. The CRC32 detects corruption before you waste time trying a bad share.

## Threat Model

### Protected

| Threat | How |
|--------|-----|
| Single point of compromise | Key is split — no single share reveals anything |
| Laptop seizure | Ciphertext without K shares is indistinguishable from random |
| Coerced share holder | K−1 shares = zero information (proven, not assumed) |
| Server takedown | Ciphertext lives on-chain — immutable, uncensorable |
| Ransomware | Offline shares can't be encrypted by malware |
| Tampered shares | CRC32 on shares, GCM auth tag on ciphertext |
| Share/ciphertext mix-up | Drop ID binds shares to their specific ciphertext |

### Not Protected

| Threat | Why |
|--------|-----|
| K+ colluding holders | By definition — that's the threshold |
| Physical coercion of K holders | Out of scope for cryptography |
| Side channels on the encrypting machine | Use an air-gapped machine for high-value drops |

**Post-quantum:** AES-256 retains ~128-bit security under Grover's algorithm. Shamir's SSS is information-theoretic — quantum computers don't help.

## Architecture

```
dead_drop/
├── shamir.py       Shamir's Secret Sharing (pure Python, GF(p), ~120 lines)
├── crypto.py       AES-256-GCM encryption (cryptography or PyCryptodome)
├── dead_drop.py    Core: create, recover, verify, save/load
├── __init__.py     Public API
└── assets/
    └── header.png

cli.py              CLI: create, recover, verify, inspect
tests/
└── test_dead_drop.py   25 tests: Shamir math, crypto, full pipeline, adversarial
```

## Use Cases

**Whistleblower protection** — Encrypt documents, store ciphertext as Ethereum calldata (immutable, uncensorable), distribute shares to journalists, lawyers, and press freedom organizations.

**Dead man's switch** — If K holders don't hear from you by a certain date, they combine shares and release the payload.

**Emergency credentials** — Split master passwords across trusted family members. 3-of-5: any three can recover if something happens to you.

**Journalist source protection** — Source material encrypted, key split between editor, lawyer, and international press org. No single raid compromises the source.

**AI agent state backup** — Encrypt agent keys, memory snapshots, or wallet credentials. Split across geographically distributed nodes. Survives any single point of failure.

**Disaster recovery** — Backup encryption keys split across continents. No single natural disaster, government action, or infrastructure failure can destroy access.

## API

```python
from dead_drop import create, recover, verify_shares

# Create
drop, shares = create(b"secret payload", n=5, k=3, label="evidence")

# Recover
plaintext = recover(shares[:3], drop.ciphertext, k=3)

# Verify
result = verify_shares(shares)
# {'valid': True, 'drop_id': 'a1b2c3d4', 'share_count': 5, 'indices': [1,2,3,4,5]}
```

## Tests

```bash
python tests/test_dead_drop.py
```

25 tests covering:
- Shamir split/reconstruct with various thresholds (2-of-2, 3-of-5, all-of-N)
- Different share subsets all reconstruct correctly  
- Insufficient shares fail
- Known-value reconstruction
- Share format parsing and CRC validation
- Tampered share detection
- AES encrypt/decrypt roundtrip
- Wrong key rejection
- Tampered ciphertext rejection
- Large payload handling
- Full pipeline: create → save → load → recover
- Cross-drop share rejection (can't mix shares from different drops)
- JSON serialization roundtrip

## License

MIT — Use it. Fork it. Save someone's life with it.

---

<p align="center">
Built by <a href="https://github.com/Artifact-Virtual">Artifact Virtual</a><br>
<em>"The only safe that gets stronger when you give away the keys."</em>
</p>
