"""
Dead Drop — Test Suite

Tests Shamir's Secret Sharing, AES-256-GCM encryption,
and the full create/recover pipeline.

Author: Ava Shakil
Date: 2026-02-24
"""

import os
import sys
import tempfile

# Add parent to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from dead_drop import shamir, crypto
from dead_drop import dead_drop


# ==========================================================================
# Shamir's Secret Sharing Tests
# ==========================================================================

def test_shamir_basic_3_of_5():
    """Split and reconstruct with exact threshold."""
    secret = os.urandom(32)
    shares = shamir.split_secret(secret, n=5, k=3)
    assert len(shares) == 5
    
    # Use first 3 shares
    recovered = shamir.reconstruct_secret(shares[:3], k=3)
    assert recovered == secret


def test_shamir_all_shares():
    """Reconstruct using all N shares (more than threshold)."""
    secret = os.urandom(32)
    shares = shamir.split_secret(secret, n=5, k=3)
    
    # reconstruct_secret uses first k shares, so pass all but it only uses 3
    recovered = shamir.reconstruct_secret(shares, k=3)
    assert recovered == secret


def test_shamir_different_subsets():
    """Any K shares should work, not just the first K."""
    secret = os.urandom(32)
    shares = shamir.split_secret(secret, n=5, k=3)
    
    # Try different subsets of 3
    subsets = [
        [shares[0], shares[1], shares[2]],
        [shares[0], shares[2], shares[4]],
        [shares[1], shares[3], shares[4]],
        [shares[2], shares[3], shares[4]],
    ]
    for subset in subsets:
        recovered = shamir.reconstruct_secret(subset, k=3)
        assert recovered == secret, f"Failed with subset indices {[s[0] for s in subset]}"


def test_shamir_2_of_2():
    """Minimum possible threshold."""
    secret = os.urandom(32)
    shares = shamir.split_secret(secret, n=2, k=2)
    recovered = shamir.reconstruct_secret(shares, k=2)
    assert recovered == secret


def test_shamir_insufficient_shares():
    """K-1 shares must NOT reconstruct the secret."""
    secret = os.urandom(32)
    shares = shamir.split_secret(secret, n=5, k=3)
    
    # Only 2 shares (below threshold of 3)
    try:
        shamir.reconstruct_secret(shares[:2], k=3)
        assert False, "Should have raised ValueError"
    except ValueError:
        pass  # Expected


def test_shamir_known_value():
    """Test with a known secret value."""
    secret = b'\x00' * 31 + b'\x42'  # 0x42 as 32-byte big-endian
    shares = shamir.split_secret(secret, n=3, k=2)
    recovered = shamir.reconstruct_secret(shares, k=2)
    assert recovered == secret


def test_shamir_share_format():
    """Test share formatting and parsing round-trip."""
    secret = os.urandom(32)
    shares = shamir.split_secret(secret, n=3, k=2)
    
    for index, share_hex in shares:
        formatted = shamir.format_share("deadbeef01234567", index, share_hex)
        did, parsed_idx, parsed_hex = shamir.parse_share(formatted)
        assert did == "deadbeef01234567"
        assert parsed_idx == index
        assert parsed_hex == share_hex


def test_shamir_tampered_share_checksum():
    """Tampered share should fail checksum."""
    secret = os.urandom(32)
    shares = shamir.split_secret(secret, n=3, k=2)
    formatted = shamir.format_share("abcd1234abcd1234", 1, shares[0][1])
    
    # Tamper with the share data
    parts = formatted.split(':')
    parts[3] = 'ff' + parts[3][2:]  # Flip first byte
    tampered = ':'.join(parts)
    
    try:
        shamir.parse_share(tampered)
        assert False, "Should have raised ValueError for tampered share"
    except ValueError as e:
        assert "checksum" in str(e).lower()


# ==========================================================================
# Crypto Tests
# ==========================================================================

def test_crypto_encrypt_decrypt():
    """Basic encrypt/decrypt round-trip."""
    key = crypto.generate_key()
    plaintext = b"The documents are in the safe."
    
    blob = crypto.encrypt(plaintext, key)
    recovered = crypto.decrypt(blob, key)
    assert recovered == plaintext


def test_crypto_wrong_key():
    """Wrong key must fail decryption."""
    key1 = crypto.generate_key()
    key2 = crypto.generate_key()
    plaintext = b"Secret message"
    
    blob = crypto.encrypt(plaintext, key1)
    try:
        crypto.decrypt(blob, key2)
        assert False, "Should have raised ValueError"
    except ValueError:
        pass


def test_crypto_no_compression():
    """Encryption without compression."""
    key = crypto.generate_key()
    plaintext = b"Short message"
    
    blob = crypto.encrypt(plaintext, key, compress=False)
    recovered = crypto.decrypt(blob, key)
    assert recovered == plaintext


def test_crypto_large_payload():
    """Test with a large payload (~1MB)."""
    key = crypto.generate_key()
    plaintext = os.urandom(1024 * 1024)  # 1MB of random data
    
    blob = crypto.encrypt(plaintext, key)
    recovered = crypto.decrypt(blob, key)
    assert recovered == plaintext


def test_crypto_empty_after_compression():
    """Empty-ish content that compresses well."""
    key = crypto.generate_key()
    plaintext = b'\x00' * 10000
    
    blob = crypto.encrypt(plaintext, key)
    assert len(blob) < 100  # Should compress dramatically
    recovered = crypto.decrypt(blob, key)
    assert recovered == plaintext


def test_crypto_tampered_ciphertext():
    """Tampered ciphertext must fail authentication."""
    key = crypto.generate_key()
    blob = crypto.encrypt(b"Secret", key)
    
    # Flip a byte in the ciphertext portion
    tampered = bytearray(blob)
    tampered[20] ^= 0xFF
    tampered = bytes(tampered)
    
    try:
        crypto.decrypt(tampered, key)
        assert False, "Should have raised ValueError for tampered data"
    except ValueError:
        pass


def test_crypto_drop_id_deterministic():
    """Same ciphertext should produce same drop ID."""
    ct = b"some ciphertext bytes"
    id1 = crypto.drop_id(ct)
    id2 = crypto.drop_id(ct)
    assert id1 == id2
    assert len(id1) == 16  # 16 hex chars


def test_crypto_drop_id_unique():
    """Different ciphertexts should produce different drop IDs."""
    id1 = crypto.drop_id(b"ciphertext A")
    id2 = crypto.drop_id(b"ciphertext B")
    assert id1 != id2


# ==========================================================================
# Full Pipeline Tests
# ==========================================================================

def test_pipeline_basic():
    """Create and recover a dead drop."""
    message = b"The truth is in building 7, third floor, locked cabinet."
    
    drop, shares = dead_drop.create(message, n=5, k=3)
    
    assert drop.n == 5
    assert drop.k == 3
    assert len(shares) == 5
    assert drop.metadata['payload_size'] == len(message)
    
    # Recover with first 3 shares
    recovered = dead_drop.recover(shares[:3], drop.ciphertext, k=3)
    assert recovered == message


def test_pipeline_any_3_of_5():
    """Any 3 of 5 shares should recover the message."""
    message = b"Evidence of corruption: account 7731-B, transfers March 2025"
    
    drop, shares = dead_drop.create(message, n=5, k=3)
    
    import itertools
    for combo in itertools.combinations(range(5), 3):
        subset = [shares[i] for i in combo]
        recovered = dead_drop.recover(subset, drop.ciphertext, k=3)
        assert recovered == message, f"Failed with combination {combo}"


def test_pipeline_file_payload():
    """Dead drop with a binary file payload."""
    # Simulate a PDF or image
    payload = os.urandom(50000)
    
    drop, shares = dead_drop.create(payload, n=3, k=2, label="leaked-document.pdf")
    assert drop.metadata['label'] == "leaked-document.pdf"
    
    recovered = dead_drop.recover(shares[:2], drop.ciphertext, k=2)
    assert recovered == payload


def test_pipeline_insufficient_shares_fails():
    """Below-threshold shares must not decrypt."""
    message = b"This should stay secret"
    drop, shares = dead_drop.create(message, n=5, k=3)
    
    try:
        dead_drop.recover(shares[:2], drop.ciphertext, k=3)
        assert False, "Should have raised ValueError"
    except ValueError:
        pass


def test_pipeline_wrong_ciphertext_fails():
    """Shares from one drop can't decrypt another drop's ciphertext."""
    drop1, shares1 = dead_drop.create(b"Message A", n=3, k=2)
    drop2, shares2 = dead_drop.create(b"Message B", n=3, k=2)
    
    try:
        dead_drop.recover(shares1[:2], drop2.ciphertext, k=2)
        assert False, "Should have raised ValueError (drop ID mismatch)"
    except ValueError as e:
        assert "drop ID" in str(e).lower() or "doesn't match" in str(e).lower()


def test_pipeline_mixed_shares_rejected():
    """Shares from different drops cannot be mixed."""
    drop1, shares1 = dead_drop.create(b"Drop A", n=3, k=2)
    drop2, shares2 = dead_drop.create(b"Drop B", n=3, k=2)
    
    try:
        dead_drop.recover([shares1[0], shares2[1]], drop1.ciphertext, k=2)
        assert False, "Should have raised ValueError (mixed shares)"
    except ValueError as e:
        assert "mix" in str(e).lower() or "drop" in str(e).lower()


def test_pipeline_verify_shares():
    """Verify shares without decrypting."""
    drop, shares = dead_drop.create(b"Verify me", n=5, k=3)
    
    result = dead_drop.verify_shares(shares)
    assert result['valid'] is True
    assert result['share_count'] == 5
    assert result['drop_id'] == drop.drop_id
    assert sorted(result['indices']) == [1, 2, 3, 4, 5]


def test_pipeline_save_and_load():
    """Save drop and shares to disk, then recover."""
    message = b"Persisted dead drop test"
    drop, shares = dead_drop.create(message, n=3, k=2)
    
    with tempfile.TemporaryDirectory() as tmpdir:
        # Save
        drop_files = dead_drop.save_drop(drop, tmpdir)
        share_files = dead_drop.save_shares(shares, os.path.join(tmpdir, 'shares'), drop.drop_id)
        
        # Load
        ct = dead_drop.load_ciphertext(drop_files['ciphertext'])
        loaded_shares = dead_drop.load_shares(share_files[:2])
        
        # Recover
        recovered = dead_drop.recover(loaded_shares, ct, k=2)
        assert recovered == message


def test_pipeline_json_serialization():
    """Drop metadata should serialize cleanly."""
    drop, _ = dead_drop.create(b"JSON test", n=3, k=2, label="test-label")
    
    j = drop.to_json()
    import json
    data = json.loads(j)
    assert data['version'] == 'dead_drop_v1'
    assert data['drop_id'] == drop.drop_id
    assert data['n'] == 3
    assert data['k'] == 2
    assert data['metadata']['label'] == 'test-label'


# ==========================================================================
# Runner
# ==========================================================================

def run_all():
    tests = [
        # Shamir
        test_shamir_basic_3_of_5,
        test_shamir_all_shares,
        test_shamir_different_subsets,
        test_shamir_2_of_2,
        test_shamir_insufficient_shares,
        test_shamir_known_value,
        test_shamir_share_format,
        test_shamir_tampered_share_checksum,
        # Crypto
        test_crypto_encrypt_decrypt,
        test_crypto_wrong_key,
        test_crypto_no_compression,
        test_crypto_large_payload,
        test_crypto_empty_after_compression,
        test_crypto_tampered_ciphertext,
        test_crypto_drop_id_deterministic,
        test_crypto_drop_id_unique,
        # Pipeline
        test_pipeline_basic,
        test_pipeline_any_3_of_5,
        test_pipeline_file_payload,
        test_pipeline_insufficient_shares_fails,
        test_pipeline_wrong_ciphertext_fails,
        test_pipeline_mixed_shares_rejected,
        test_pipeline_verify_shares,
        test_pipeline_save_and_load,
        test_pipeline_json_serialization,
    ]
    
    passed = 0
    failed = 0
    for t in tests:
        try:
            t()
            print(f"[PASS] {t.__name__}")
            passed += 1
        except Exception as e:
            print(f"[FAIL] {t.__name__}: {e}")
            import traceback
            traceback.print_exc()
            failed += 1
    
    print(f"\n--- Dead Drop tests: {passed} passed, {failed} failed ---")
    return failed == 0


if __name__ == "__main__":
    sys.exit(0 if run_all() else 1)
