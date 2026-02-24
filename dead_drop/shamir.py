"""
Shamir's Secret Sharing — Pure Python implementation.

Splits a secret into N shares where any K shares can reconstruct
the original, but K-1 shares reveal zero information (information-theoretic security).

Operates over a prime field GF(p) where p is a 256-bit prime
(larger than any AES-256 key).

No external dependencies. No trust in third-party SSS libraries.

Author: Ava Shakil
Date: 2026-02-24
"""

import os
import secrets
import hashlib
import struct


# A 256-bit prime (NIST P-256 curve order, well-audited, larger than any 256-bit secret)
# This is the order of the secp256k1 curve used by Bitcoin/Ethereum
PRIME = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


def _mod_inv(a: int, p: int) -> int:
    """Modular multiplicative inverse using extended Euclidean algorithm."""
    if a < 0:
        a = a % p
    g, x, _ = _extended_gcd(a, p)
    if g != 1:
        raise ValueError(f"No modular inverse for {a} mod {p}")
    return x % p


def _extended_gcd(a: int, b: int) -> tuple:
    """Extended Euclidean Algorithm. Returns (gcd, x, y) where ax + by = gcd."""
    if a == 0:
        return b, 0, 1
    g, x, y = _extended_gcd(b % a, a)
    return g, y - (b // a) * x, x


def _eval_poly(coeffs: list, x: int, prime: int) -> int:
    """Evaluate polynomial at x using Horner's method in GF(prime)."""
    result = 0
    for coeff in reversed(coeffs):
        result = (result * x + coeff) % prime
    return result


def split_secret(secret: bytes, n: int, k: int, prime: int = PRIME) -> list:
    """
    Split a secret into n shares, requiring k to reconstruct.
    
    Args:
        secret: The secret bytes to split (max 32 bytes / 256 bits)
        n: Total number of shares to generate
        k: Minimum shares needed to reconstruct (threshold)
        prime: The prime field modulus
    
    Returns:
        List of (index, share_hex) tuples. Index is 1-based.
    
    Raises:
        ValueError: If parameters are invalid
    """
    if k < 2:
        raise ValueError("Threshold k must be >= 2")
    if n < k:
        raise ValueError("Total shares n must be >= threshold k")
    if k > 255:
        raise ValueError("Threshold k must be <= 255")
    if n > 255:
        raise ValueError("Total shares n must be <= 255")
    if len(secret) > 32:
        raise ValueError("Secret must be <= 32 bytes (256 bits)")
    if len(secret) == 0:
        raise ValueError("Secret must not be empty")
    
    # Convert secret bytes to integer
    secret_int = int.from_bytes(secret, 'big')
    
    if secret_int >= prime:
        raise ValueError("Secret value exceeds prime field")
    
    # Generate random polynomial coefficients: a_0 = secret, a_1..a_{k-1} = random
    coeffs = [secret_int]
    for _ in range(k - 1):
        coeffs.append(secrets.randbelow(prime))
    
    # Evaluate polynomial at x = 1, 2, ..., n
    shares = []
    for i in range(1, n + 1):
        y = _eval_poly(coeffs, i, prime)
        # Encode y as 32-byte hex
        y_hex = format(y, '064x')
        shares.append((i, y_hex))
    
    return shares


def reconstruct_secret(shares: list, k: int, prime: int = PRIME) -> bytes:
    """
    Reconstruct the secret from k or more shares using Lagrange interpolation.
    
    Args:
        shares: List of (index, share_hex) tuples
        k: The threshold (must match the original split)
        prime: The prime field modulus
    
    Returns:
        The original secret bytes
    
    Raises:
        ValueError: If not enough shares or shares are invalid
    """
    if len(shares) < k:
        raise ValueError(f"Need at least {k} shares, got {len(shares)}")
    
    # Use only k shares (first k provided)
    points = []
    for idx, y_hex in shares[:k]:
        x = idx
        y = int(y_hex, 16)
        points.append((x, y))
    
    # Check for duplicate x values
    x_vals = [p[0] for p in points]
    if len(set(x_vals)) != len(x_vals):
        raise ValueError("Duplicate share indices detected")
    
    # Lagrange interpolation at x = 0 to recover the secret
    secret_int = 0
    for i, (xi, yi) in enumerate(points):
        # Compute Lagrange basis polynomial L_i(0)
        numerator = 1
        denominator = 1
        for j, (xj, _) in enumerate(points):
            if i == j:
                continue
            numerator = (numerator * (0 - xj)) % prime
            denominator = (denominator * (xi - xj)) % prime
        
        # L_i(0) = numerator / denominator mod prime
        lagrange = (numerator * _mod_inv(denominator, prime)) % prime
        secret_int = (secret_int + yi * lagrange) % prime
    
    # Convert back to bytes (32 bytes, big-endian)
    secret_bytes = secret_int.to_bytes(32, 'big')
    
    # Strip leading zeros to match original length
    # We don't know original length, so return full 32 bytes
    # Caller must know expected length or we prepend length in the secret
    return secret_bytes


def format_share(drop_id: str, index: int, share_hex: str) -> str:
    """
    Format a share as a portable string.
    
    Format: DEAD_DROP_SHARE_v1:<drop_id>:<index>:<share_hex>:<crc32>
    """
    payload = f"DEAD_DROP_SHARE_v1:{drop_id}:{index:03d}:{share_hex}"
    crc = struct.pack('>I', _crc32(payload.encode()))
    checksum = crc.hex()
    return f"{payload}:{checksum}"


def parse_share(share_str: str) -> tuple:
    """
    Parse a formatted share string.
    
    Returns: (drop_id, index, share_hex)
    Raises ValueError if format or checksum is invalid.
    """
    parts = share_str.strip().split(':')
    if len(parts) != 5:
        raise ValueError(f"Invalid share format: expected 5 parts, got {len(parts)}")
    
    if parts[0] != 'DEAD_DROP_SHARE_v1':
        raise ValueError(f"Unknown share version: {parts[0]}")
    
    drop_id = parts[1]
    index = int(parts[2])
    share_hex = parts[3]
    checksum = parts[4]
    
    # Verify checksum
    payload = f"DEAD_DROP_SHARE_v1:{drop_id}:{index:03d}:{share_hex}"
    expected_crc = struct.pack('>I', _crc32(payload.encode())).hex()
    
    if checksum != expected_crc:
        raise ValueError(f"Share checksum mismatch (corrupted or tampered)")
    
    return drop_id, index, share_hex


def _crc32(data: bytes) -> int:
    """CRC32 checksum (unsigned)."""
    import binascii
    return binascii.crc32(data) & 0xFFFFFFFF
