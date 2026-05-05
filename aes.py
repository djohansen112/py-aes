import os

"""
AES-128 Implementation
----------------------
This script implements the Advanced Encryption Standard (AES) with a 128-bit key.
It is designed for educational purposes, breaking down each step of the cipher
to demonstrate how data is transformed at each layer.
"""

# =============================================================================
# AES S-Boxes (Substitution Tables)
# =============================================================================

# The S-BOX (Substitution Box) is a non-linear substitution table.
# It provides 'confusion' by replacing each byte with another according to a
# fixed mathematical formula in GF(2^8).
S_BOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
]

# The INV_S_BOX (Inverse Substitution Box) reverses the S_BOX substitution.
# It is used exclusively during the decryption process.
INV_S_BOX = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d]

# RCON (Round Constants) are used in the Key Expansion process to break symmetry.
RCON = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]

# =============================================================================
# AES Transformation Functions
# =============================================================================

def sub_bytes(state):
    """
    SubBytes: Applies the S-Box substitution to every byte in the 4x4 state.
    This provides non-linearity to the cipher.
    """
    for i in range(16):
        state[i] = S_BOX[state[i]]

def inv_sub_bytes(state):
    """
    InvSubBytes: Reverses the SubBytes step using the Inverse S-Box.
    Used only in decryption.
    """
    for i in range(16):
        state[i] = INV_S_BOX[state[i]]

def shift_rows(state):
    """
    ShiftRows: Cyclically shifts the rows of the state matrix.
    Row 0: No shift
    Row 1: Shifts left by 1 byte
    Row 2: Shifts left by 2 bytes
    Row 3: Shifts left by 3 bytes
    This provides diffusion by spreading data across columns.
    """
    state[1], state[5], state[9], state[13] = state[5], state[9], state[13], state[1]
    state[2], state[6], state[10], state[14] = state[10], state[14], state[2], state[6]
    state[3], state[7], state[11], state[15] = state[15], state[3], state[7], state[11]

def inv_shift_rows(state):
    """
    InvShiftRows: Reverses ShiftRows by shifting rows to the right.
    """
    state[1], state[5], state[9], state[13] = state[13], state[1], state[5], state[9]
    state[2], state[6], state[10], state[14] = state[10], state[14], state[2], state[6]
    state[3], state[7], state[11], state[15] = state[7], state[11], state[15], state[3]

def gf_mul(a, b):
    """
    Galois Field Multiplication in GF(2^8).
    This handles multiplication while ensuring the result stays within a single byte
    by XORing with the irreducible polynomial 0x1B if an overflow occurs.
    """
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi_bit_set = a & 0x80
        a <<= 1
        a &= 0xFF
        if hi_bit_set:
            a ^= 0x1B
        b >>= 1
    return p

def mix_columns(state):
    """
    MixColumns: Treats each column as a polynomial and multiplies it with a
    fixed matrix in GF(2^8). This provides further diffusion.
    """
    for i in range(0, 16, 4):
        s0, s1, s2, s3 = state[i:i+4]
        state[i]   = gf_mul(s0, 2) ^ gf_mul(s1, 3) ^ s2 ^ s3
        state[i+1] = s0 ^ gf_mul(s1, 2) ^ gf_mul(s2, 3) ^ s3
        state[i+2] = s0 ^ s1 ^ gf_mul(s2, 2) ^ gf_mul(s3, 3)
        state[i+3] = gf_mul(s0, 3) ^ s1 ^ s2 ^ gf_mul(s3, 2)

def inv_mix_columns(state):
    """
    InvMixColumns: Reverses MixColumns using the inverse matrix coefficients.
    """
    for i in range(0, 16, 4):
        s0, s1, s2, s3 = state[i:i+4]
        state[i]   = gf_mul(s0, 0x0e) ^ gf_mul(s1, 0x0b) ^ gf_mul(s2, 0x0d) ^ gf_mul(s3, 0x09)
        state[i+1] = gf_mul(s0, 0x09) ^ gf_mul(s1, 0x0e) ^ gf_mul(s2, 0x0b) ^ gf_mul(s3, 0x0d)
        state[i+2] = gf_mul(s0, 0x0d) ^ gf_mul(s1, 0x09) ^ gf_mul(s2, 0x0e) ^ gf_mul(s3, 0x0b)
        state[i+3] = gf_mul(s0, 0x0b) ^ gf_mul(s1, 0x0d) ^ gf_mul(s2, 0x09) ^ gf_mul(s3, 0x0e)

def add_round_key(state, round_key):
    """
    AddRoundKey: XORs the state with the current round key.
    This is the only step that incorporates the secret key.
    """
    for i in range(16):
        state[i] ^= round_key[i]

# =============================================================================
# Key Expansion
# =============================================================================

def key_expansion(key):
    """
    Expands a 128-bit secret key into a series of 11 round keys (176 bytes).
    Each round of AES uses a unique key derived from the original.
    """
    expanded_key = list(key)
    for i in range(4, 44):
        temp = expanded_key[(i-1)*4 : i*4]
        if i % 4 == 0:
            # RotWord: cyclic shift left
            temp = temp[1:] + temp[:1]
            # SubWord: S-Box substitution
            temp = [S_BOX[b] for b in temp]
            # XOR with Round Constant
            temp[0] ^= RCON[i // 4]
        
        # XOR with the word from 4 positions back
        prev_word = expanded_key[(i-4)*4 : (i-3)*4]
        new_word = [temp[j] ^ prev_word[j] for j in range(4)]
        expanded_key.extend(new_word)
    
    # Slice the expanded key into 16-byte blocks
    return [expanded_key[i:i+16] for i in range(0, len(expanded_key), 16)]

# =============================================================================
# AES Main Logic (128-bit)
# =============================================================================

def aes_encrypt_block(block, round_keys):
    """
    Encrypts a single 16-byte block of data through 10 rounds of transformations.
    """
    state = list(block)
    
    # Initial Round
    add_round_key(state, round_keys[0])
    
    # 9 Rounds of full transformations
    for i in range(1, 10):
        sub_bytes(state)
        shift_rows(state)
        mix_columns(state)
        add_round_key(state, round_keys[i])
    
    # Final Round (MixColumns is omitted)
    sub_bytes(state)
    shift_rows(state)
    add_round_key(state, round_keys[10])
    
    return bytes(state)

def aes_decrypt_block(block, round_keys):
    """
    Decrypts a single 16-byte block by reversing the encryption steps.
    Note: Round keys are applied in reverse order.
    """
    state = list(block)
    
    # Initial Round (decryption starts with the final round key)
    add_round_key(state, round_keys[10])
    
    # 9 Rounds of inverse transformations
    for i in range(9, 0, -1):
        inv_shift_rows(state)
        inv_sub_bytes(state)
        add_round_key(state, round_keys[i])
        inv_mix_columns(state)
    
    # Final Round
    inv_shift_rows(state)
    inv_sub_bytes(state)
    add_round_key(state, round_keys[0])
    
    return bytes(state)

# =============================================================================
# Padding (PKCS#5 / PKCS#7)
# =============================================================================

def pkcs5_pad(data):
    """
    Pads the input data to a multiple of 16 bytes (AES block size).
    Note: For AES, PKCS#5 and PKCS#7 are the same thing.
    """
    pad_len = 16 - (len(data) % 16)
    # Append pad_len bytes, each with the value of pad_len
    return data + bytes([pad_len] * pad_len)

def pkcs5_unpad(data):
    """
    Removes the PKCS#5/7 padding after decryption.
    """
    pad_len = data[-1]
    # Check if padding is valid (1-16)
    if pad_len < 1 or pad_len > 16:
        return data
    return data[:-pad_len]

# =============================================================================
# File Operations & Main Loop
# =============================================================================

def process_aes(mode):
    """
    Main controller for reading files, processing AES, and saving results.
    """
    key_file = "key.txt"
    input_file = "input.txt"
    output_file = "output.txt"

    # Load the secret key
    if not os.path.exists(key_file):
        print(f"Error: {key_file} not found.")
        return

    with open(key_file, "r") as f:
        key_raw = f.read().strip()
        
    # Handle Key Format: 128-bit key can be 32 Hex chars OR 16 Text chars
    try:
        if len(key_raw) == 32:
            # Assume Hexadecimal (e.g. 2b7e1516...)
            key = bytes.fromhex(key_raw)
        elif len(key_raw) == 16:
            # Assume Plain Text (e.g. YELLOW SUBMARINE)
            key = key_raw.encode('utf-8')
        else:
            print(f"Error: Key must be 128-bit.")
            print(f"- If Hex: 32 characters (0-9, a-f)")
            print(f"- If Text: 16 characters")
            return
    except ValueError:
        # If fromhex fails, try treating as 16-byte text
        if len(key_raw) == 16:
            key = key_raw.encode('utf-8')
        else:
            print("Error: Invalid key format. Use 32 hex characters.")
            return

    # Generate round keys for AES-128
    round_keys = key_expansion(key)

    # Load input data
    if not os.path.exists(input_file):
        print(f"Error: {input_file} not found.")
        return

    if mode == 'encrypt':
        # Encrypt: Read text -> Pad -> Process -> Save as Hex
        with open(input_file, "r", encoding='utf-8') as f:
            data = f.read().encode('utf-8')
        
        data_padded = pkcs5_pad(data)
        ciphertext = b""
        for i in range(0, len(data_padded), 16):
            ciphertext += aes_encrypt_block(data_padded[i:i+16], round_keys)
        
        with open(output_file, "w") as f:
            f.write(ciphertext.hex())
        print(f"Encryption complete (Mode: ECB, Padding: PKCS5).")
        print(f"Hex result saved to {output_file}")

    elif mode == 'decrypt':
        # Decrypt: Read Hex -> Process -> Unpad -> Save as Text
        with open(input_file, "r") as f:
            data_hex = f.read().strip()
        
        try:
            data = bytes.fromhex(data_hex)
        except ValueError:
            print(f"Error: {input_file} must contain a valid hexadecimal string for decryption.")
            print("Hint: If you just want to test, run 'python aes.py encrypt' first to generate valid hex input.")
            return
        
        decrypted_padded = b""
        for i in range(0, len(data), 16):
            decrypted_padded += aes_decrypt_block(data[i:i+16], round_keys)
        
        plaintext = pkcs5_unpad(decrypted_padded)
        try:
            result = plaintext.decode('utf-8')
            with open(output_file, "w", encoding='utf-8') as f:
                f.write(result)
            print(f"Decryption complete (Mode: ECB, Padding: PKCS5).")
            print(f"Plaintext saved to {output_file}")
        except UnicodeDecodeError:
            print("Error: Decrypted data is not valid text. Check your key/padding.")

if __name__ == "__main__":
    import sys
    # Command line handling: python aes.py [encrypt|decrypt]
    if len(sys.argv) > 1 and sys.argv[1] in ['encrypt', 'decrypt']:
        process_aes(sys.argv[1])
    else:
        print("Usage: python aes.py [encrypt|decrypt]")
        # Setup sample files if they don't exist
        if not os.path.exists("key.txt"):
            with open("key.txt", "w") as f: f.write("2b7e151628aed2a6abf7158809cf4f3c")
        
        # Create a helpful sample message if input.txt is empty or missing
        if not os.path.exists("input.txt"):
            with open("input.txt", "w") as f: f.write("Hello University Assignment!")
        
        print("\nReady to test!")
        print("1. Run 'python aes.py encrypt' to turn input.txt into hex.")
        print("2. Copy the result from output.txt back to input.txt.")
        print("3. Run 'python aes.py decrypt' to get your message back.")
