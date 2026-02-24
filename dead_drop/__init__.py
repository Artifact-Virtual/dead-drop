"""Dead Drop — Adversarial safe. AES-256-GCM + Shamir's Secret Sharing."""

from .dead_drop import create, recover, verify_shares, save_drop, save_shares
from .dead_drop import load_ciphertext, load_shares, DeadDrop
from .crypto import encrypt, decrypt, generate_key, get_backend
from .shamir import split_secret, reconstruct_secret, format_share, parse_share

__all__ = [
    'create', 'recover', 'verify_shares', 'save_drop', 'save_shares',
    'load_ciphertext', 'load_shares', 'DeadDrop',
    'encrypt', 'decrypt', 'generate_key', 'get_backend',
    'split_secret', 'reconstruct_secret', 'format_share', 'parse_share',
]
