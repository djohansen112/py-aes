import pytest
from aes_assignment import (
    sub_bytes, inv_sub_bytes, shift_rows, inv_shift_rows,
    mix_columns, inv_mix_columns, add_round_key,
    encrypt_block, decrypt_block, xtime
)

@pytest.fixture
def nist_vector():
    """Standard NIST FIPS 197 Test Vector."""
    return {
        "key": bytes.fromhex('2b7e151628aed2a6abf7158809cf4f3c'),
        "plaintext": bytes.fromhex('6bc1bee22e409f96e93d7e117393172a'),
        "ciphertext": bytes.fromhex('3ad77bb40d7a3660a89ecaf32466ef97')
    }

def test_xtime():
    assert xtime(0x57) == 0xae
    assert xtime(0xae) == 0x47  # (0xae << 1) ^ 0x1b = 0x15c ^ 0x1b = 0x5c ^ 0x1b = 0x47
    assert xtime(0x47) == 0x8e
    assert xtime(0x8e) == 0x07  # (0x8e << 1) ^ 0x1b = 0x11c ^ 0x1b = 0x1c ^ 0x1b = 0x07

def test_sub_bytes():
    state = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f]
    expected = [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76]
    assert sub_bytes(state) == expected
    assert inv_sub_bytes(expected) == state

def test_shift_rows():
    state = list(range(16))
    # Row 0: 0, 4, 8, 12 -> 0, 4, 8, 12
    # Row 1: 1, 5, 9, 13 -> 5, 9, 13, 1
    # Row 2: 2, 6, 10, 14 -> 10, 14, 2, 6
    # Row 3: 3, 7, 11, 15 -> 15, 3, 7, 11
    expected = [
        0, 5, 10, 15,
        4, 9, 14, 3,
        8, 13, 2, 7,
        12, 1, 6, 11
    ]
    shifted = shift_rows(state)
    assert shifted == expected
    assert inv_shift_rows(shifted) == state

def test_add_round_key():
    state = [0x00] * 16
    key = [0xff] * 16
    assert add_round_key(state, key) == key
    assert add_round_key(key, key) == state

def test_full_encryption_decryption(nist_vector):
    # Test full block encryption
    encrypted = encrypt_block(nist_vector["plaintext"], nist_vector["key"])
    assert encrypted == nist_vector["ciphertext"]

    # Test full block decryption
    decrypted = decrypt_block(nist_vector["ciphertext"], nist_vector["key"])
    assert decrypted == nist_vector["plaintext"]

def test_mix_columns():
    # A simple test case for MixColumns
    state = [0xdb, 0x13, 0x53, 0x45] + [0x00] * 12
    expected = [0x8e, 0x4d, 0xa1, 0xbc] + [0x00] * 12
    mixed = mix_columns(state)
    assert mixed[:4] == expected[:4]
    assert inv_mix_columns(mixed)[:4] == state[:4]
