"""
Dead Drop Encryption Layer — AES-256-GCM authenticated encryption.

Handles: compression → encryption → framing-ready output.
And reverse: deframing → decryption → decompression.

No external crypto dependencies — uses Python's cryptography library
(already in most environments) or falls back to PyCryptodome.

Author: Ava Shakil
Date: 2026-02-24
"""

import os
import zlib
import struct
import hashlib

# Try cryptography first (preferred), fall back to PyCryptodome
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    _BACKEND = 'cryptography'
except ImportError:
    try:
        from Crypto.Cipher import AES
        _BACKEND = 'pycryptodome'
    except ImportError:
        _BACKEND = None


def generate_key() -> bytes:
    """Generate a cryptographically secure 256-bit key."""
    return os.urandom(32)


def encrypt(plaintext: bytes, key: bytes, compress: bool = True) -> bytes:
    """
    Encrypt plaintext with AES-256-GCM.
    
    Args:
        plaintext: Data to encrypt
        key: 32-byte encryption key
        compress: Whether to zlib-compress before encrypting (default True)
    
    Returns:
        Encrypted blob: flags(1) + nonce(12) + ciphertext + tag(16)
    
    The flags byte encodes:
        bit 0: compression enabled
        bits 1-7: reserved (zero)
    """
    if len(key) != 32:
        raise ValueError(f"Key must be 32 bytes, got {len(key)}")
    
    # Flags byte
    flags = 0x01 if compress else 0x00
    
    # Optional compression
    data = zlib.compress(plaintext, level=9) if compress else plaintext
    
    # 96-bit random nonce (recommended for AES-GCM)
    nonce = os.urandom(12)
    
    if _BACKEND == 'cryptography':
        aesgcm = AESGCM(key)
        # Returns ciphertext + 16-byte tag appended
        ct_with_tag = aesgcm.encrypt(nonce, data, None)
    elif _BACKEND == 'pycryptodome':
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        ct_with_tag = ciphertext + tag
    else:
        raise RuntimeError(
            "No AES backend available. Install 'cryptography' or 'pycryptodome':\n"
            "  pip install cryptography"
        )
    
    # Pack: flags(1) + nonce(12) + ciphertext_with_tag
    return struct.pack('B', flags) + nonce + ct_with_tag


def decrypt(blob: bytes, key: bytes) -> bytes:
    """
    Decrypt an AES-256-GCM encrypted blob.
    
    Args:
        blob: The encrypted blob from encrypt()
        key: 32-byte encryption key
    
    Returns:
        Original plaintext
    
    Raises:
        ValueError: If decryption fails (wrong key, tampered data)
    """
    if len(key) != 32:
        raise ValueError(f"Key must be 32 bytes, got {len(key)}")
    
    if len(blob) < 1 + 12 + 16:  # flags + nonce + minimum tag
        raise ValueError("Blob too short to be valid")
    
    # Unpack
    flags = blob[0]
    nonce = blob[1:13]
    ct_with_tag = blob[13:]
    compressed = bool(flags & 0x01)
    
    try:
        if _BACKEND == 'cryptography':
            aesgcm = AESGCM(key)
            data = aesgcm.decrypt(nonce, ct_with_tag, None)
        elif _BACKEND == 'pycryptodome':
            ciphertext = ct_with_tag[:-16]
            tag = ct_with_tag[-16:]
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            data = cipher.decrypt_and_verify(ciphertext, tag)
        else:
            raise RuntimeError("No AES backend available")
    except Exception as e:
        raise ValueError(f"Decryption failed (wrong key or tampered data): {e}")
    
    # Decompress if needed
    if compressed:
        data = zlib.decompress(data)
    
    return data


def drop_id(ciphertext: bytes) -> str:
    """
    Generate a drop ID from ciphertext.
    keccak256(ciphertext)[:8] — 8 hex chars, identifies the drop.
    """
    # Use SHA-256 since keccak256 needs an extra dep
    # (keccak would be more Ethereum-native, but SHA-256 is fine for IDs)
    h = hashlib.sha256(ciphertext).hexdigest()[:16]
    return h


def get_backend() -> str:
    """Return the active crypto backend name."""
    return _BACKEND or 'none'
