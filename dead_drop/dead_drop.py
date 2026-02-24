"""
Dead Drop — Core logic.

Create, deposit, recover, verify, and inspect adversarial safes.

A dead drop is:
1. A payload encrypted with AES-256-GCM
2. The encryption key split via Shamir's Secret Sharing into N shares (K threshold)
3. The ciphertext stored on-chain (calldata) or IPFS
4. Shares distributed to trusted parties

Only K share holders cooperating can reconstruct the key and decrypt.
K-1 shares reveal zero information about the secret.

Author: Ava Shakil
Date: 2026-02-24
"""

import json
import time
import hashlib
import os
from pathlib import Path
from typing import Optional

from . import crypto
from . import shamir


class DeadDrop:
    """Represents a single dead drop instance."""
    
    def __init__(self, drop_id: str, ciphertext: bytes, n: int, k: int,
                 created_at: float = None, metadata: dict = None):
        self.drop_id = drop_id
        self.ciphertext = ciphertext
        self.n = n
        self.k = k
        self.created_at = created_at or time.time()
        self.metadata = metadata or {}
    
    def to_dict(self) -> dict:
        return {
            'version': 'dead_drop_v1',
            'drop_id': self.drop_id,
            'n': self.n,
            'k': self.k,
            'ciphertext_hex': self.ciphertext.hex(),
            'ciphertext_size': len(self.ciphertext),
            'created_at': self.created_at,
            'metadata': self.metadata,
        }
    
    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)


def create(payload: bytes, n: int, k: int,
           label: str = None) -> tuple:
    """
    Create a dead drop.
    
    Args:
        payload: The secret data to protect (any bytes — message, file, keys)
        n: Total shares to generate
        k: Threshold shares needed to reconstruct
        label: Optional human-readable label (stored in metadata, NOT encrypted)
    
    Returns:
        (DeadDrop, shares_list)
        - DeadDrop object with ciphertext and metadata
        - List of formatted share strings
    """
    # Generate random encryption key
    key = crypto.generate_key()
    
    # Encrypt the payload
    ciphertext = crypto.encrypt(payload, key, compress=True)
    
    # Generate drop ID from ciphertext
    did = crypto.drop_id(ciphertext)
    
    # Split the key using Shamir's Secret Sharing
    raw_shares = shamir.split_secret(key, n, k)
    
    # Format shares with drop ID and checksums
    formatted_shares = []
    for index, share_hex in raw_shares:
        share_str = shamir.format_share(did, index, share_hex)
        formatted_shares.append(share_str)
    
    # Build metadata
    metadata = {
        'payload_size': len(payload),
        'compressed_encrypted_size': len(ciphertext),
        'crypto_backend': crypto.get_backend(),
        'payload_hash': hashlib.sha256(payload).hexdigest(),
    }
    if label:
        metadata['label'] = label
    
    drop = DeadDrop(
        drop_id=did,
        ciphertext=ciphertext,
        n=n,
        k=k,
        metadata=metadata,
    )
    
    return drop, formatted_shares


def recover(shares: list, ciphertext: bytes, k: int) -> bytes:
    """
    Recover the original payload from shares and ciphertext.
    
    Args:
        shares: List of formatted share strings (at least k)
        ciphertext: The encrypted payload
        k: Threshold
    
    Returns:
        The original plaintext payload
    
    Raises:
        ValueError: If shares are invalid, threshold not met, or decryption fails
    """
    if len(shares) < k:
        raise ValueError(f"Need at least {k} shares, got {len(shares)}")
    
    # Parse all shares
    parsed = []
    expected_drop_id = None
    for share_str in shares:
        did, index, share_hex = shamir.parse_share(share_str)
        
        # Verify all shares belong to the same drop
        if expected_drop_id is None:
            expected_drop_id = did
        elif did != expected_drop_id:
            raise ValueError(
                f"Share {index} belongs to drop {did}, expected {expected_drop_id}. "
                "Cannot mix shares from different drops."
            )
        
        parsed.append((index, share_hex))
    
    # Verify drop ID matches ciphertext
    actual_did = crypto.drop_id(ciphertext)
    if actual_did != expected_drop_id:
        raise ValueError(
            f"Ciphertext drop ID {actual_did} doesn't match shares drop ID {expected_drop_id}. "
            "Wrong ciphertext or tampered data."
        )
    
    # Reconstruct the encryption key
    key_bytes = shamir.reconstruct_secret(parsed, k)
    
    # Decrypt
    plaintext = crypto.decrypt(ciphertext, key_bytes)
    
    return plaintext


def verify_shares(shares: list) -> dict:
    """
    Verify a set of shares without decrypting.
    
    Returns dict with:
        - valid: bool (all shares parse and checksums match)
        - drop_id: the common drop ID
        - share_count: how many valid shares
        - indices: list of share indices
        - errors: list of error messages for invalid shares
    """
    result = {
        'valid': True,
        'drop_id': None,
        'share_count': 0,
        'indices': [],
        'errors': [],
    }
    
    for i, share_str in enumerate(shares):
        try:
            did, index, share_hex = shamir.parse_share(share_str)
            
            if result['drop_id'] is None:
                result['drop_id'] = did
            elif did != result['drop_id']:
                result['errors'].append(
                    f"Share {i+1}: drop ID mismatch ({did} vs {result['drop_id']})"
                )
                result['valid'] = False
                continue
            
            result['indices'].append(index)
            result['share_count'] += 1
            
        except ValueError as e:
            result['errors'].append(f"Share {i+1}: {e}")
            result['valid'] = False
    
    return result


def save_drop(drop: DeadDrop, output_dir: str) -> dict:
    """
    Save a dead drop to disk.
    
    Creates:
        <output_dir>/<drop_id>/drop.json — metadata
        <output_dir>/<drop_id>/ciphertext.bin — encrypted payload
    
    Returns dict with file paths.
    """
    drop_dir = Path(output_dir) / drop.drop_id
    drop_dir.mkdir(parents=True, exist_ok=True)
    
    # Save metadata
    meta_path = drop_dir / 'drop.json'
    meta_path.write_text(drop.to_json())
    
    # Save ciphertext
    ct_path = drop_dir / 'ciphertext.bin'
    ct_path.write_bytes(drop.ciphertext)
    
    return {
        'metadata': str(meta_path),
        'ciphertext': str(ct_path),
        'directory': str(drop_dir),
    }


def save_shares(shares: list, output_dir: str, drop_id: str) -> list:
    """
    Save individual shares to separate files.
    
    Creates: <output_dir>/share_001.txt, share_002.txt, etc.
    Each file contains exactly one share string.
    
    Returns list of file paths.
    """
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    
    paths = []
    for i, share_str in enumerate(shares, 1):
        path = out / f"share_{i:03d}.txt"
        path.write_text(share_str + '\n')
        paths.append(str(path))
    
    return paths


def load_ciphertext(path: str) -> bytes:
    """Load ciphertext from a file."""
    return Path(path).read_bytes()


def load_shares(paths: list) -> list:
    """Load shares from files. Each file contains one share string."""
    shares = []
    for p in paths:
        share_str = Path(p).read_text().strip()
        shares.append(share_str)
    return shares
