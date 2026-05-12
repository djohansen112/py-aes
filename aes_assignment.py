#!/usr/bin/env python3

# =========================
# Functional AES-128 Implementation
# Group 2
# =========================

# S-Box and Inverse S-Box
S_BOX = (
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
)

INV_S_BOX = (
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
)

# Round Constants
R_CON = (
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
    0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A,
)

# Finite Field Multiplication by 2
def xtime(a):
    """Finite Field multiplication by 2 in GF(2^8)."""
    # Shift left by 1
    res = a << 1
    # If the MSB was 1, XOR with 0x1B (AES polynomial)
    if (a & 0x80):
        res = res ^ 0x1B
    # Ensure it stays within 8 bits
    return res & 0xFF

# Basic Operations on Flat 16-Byte State
def add_round_key(state, key):
    """XOR the state with the round key."""
    new_state = []
    for i in range(16):
        state_byte = state[i]
        key_byte = key[i]
        xor_result = state_byte ^ key_byte
        new_state.append(xor_result)
    return new_state

def sub_bytes(state):
    """Apply S-BOX substitution to each byte of the state."""
    new_state = []
    for b in state:
        substituted_byte = S_BOX[b]
        new_state.append(substituted_byte)
    return new_state

def inv_sub_bytes(state):
    """Apply Inverse S-BOX substitution to each byte of the state."""
    new_state = []
    for b in state:
        substituted_byte = INV_S_BOX[b]
        new_state.append(substituted_byte)
    return new_state

def shift_rows(s):
    # Explicit reordering of indices for left shift
    return [
        s[0], s[5], s[10], s[15],  # Column 0
        s[4], s[9], s[14], s[3],   # Column 1
        s[8], s[13], s[2], s[7],   # Column 2
        s[12], s[1], s[6], s[11]   # Column 3
    ]

def inv_shift_rows(s):
    # Explicit reordering of indices for right shift
    return [
        s[0], s[13], s[10], s[7],  # Column 0
        s[4], s[1], s[14], s[11],  # Column 1
        s[8], s[5], s[2], s[15],   # Column 2
        s[12], s[9], s[6], s[3]    # Column 3
    ]

def mix_column(column):
    """Mixes a single 4-byte column using the AES polynomial."""
    # Pre-calculate XOR of all elements in the column
    total_xor = column[0] ^ column[1] ^ column[2] ^ column[3]
    
    # Calculate each byte of the resulting column
    # Formula (e.g., for row 0): res0 = (2 * c0) ^ (3 * c1) ^ (1 * c2) ^ (1 * c3)
    # Re-written as: res0 = c0 ^ total_xor ^ (2 * (c0 ^ c1))
    
    res0 = column[0] ^ total_xor ^ xtime(column[0] ^ column[1])
    res1 = column[1] ^ total_xor ^ xtime(column[1] ^ column[2])
    res2 = column[2] ^ total_xor ^ xtime(column[2] ^ column[3])
    res3 = column[3] ^ total_xor ^ xtime(column[3] ^ column[0])
    
    return [res0, res1, res2, res3]

def mix_columns(state):
    """Split the state into columns and apply mix_column to each."""
    # Column 0
    col0_in = [state[0], state[1], state[2], state[3]]
    col0_out = mix_column(col0_in)
    
    # Column 1
    col1_in = [state[4], state[5], state[6], state[7]]
    col1_out = mix_column(col1_in)
    
    # Column 2
    col2_in = [state[8], state[9], state[10], state[11]]
    col2_out = mix_column(col2_in)
    
    # Column 3
    col3_in = [state[12], state[13], state[14], state[15]]
    col3_out = mix_column(col3_in)
    
    # Combine columns back into a flat state
    new_state = col0_out + col1_out + col2_out + col3_out
    return new_state

def inv_mix_column(column):
    """Inverse MixColumn for a single column."""
    # Multiply by 0x0e, 0x0b, 0x0d, 0x09
    # This can be simplified by using the xtime results
    u = xtime(xtime(column[0] ^ column[2]))
    v = xtime(xtime(column[1] ^ column[3]))
    
    # XOR original column bytes with u and v
    temp_col = [
        column[0] ^ u,
        column[1] ^ v,
        column[2] ^ u,
        column[3] ^ v
    ]
    
    # Apply standard mix_column to the result
    return mix_column(temp_col)

def inv_mix_columns(state):
    """Split the state into columns and apply inv_mix_column to each."""
    col0_out = inv_mix_column(state[0:4])
    col1_out = inv_mix_column(state[4:8])
    col2_out = inv_mix_column(state[8:12])
    col3_out = inv_mix_column(state[12:16])
    
    return col0_out + col1_out + col2_out + col3_out

# =========================
# Key Expansion
# =========================
def expand_key(master_key):
    """Expand 128-bit master key into 11 round keys (176 bytes)."""
    # 1. Start with the master key as the first 4 words
    words = []
    for i in range(0, 16, 4):
        word = [master_key[i], master_key[i+1], master_key[i+2], master_key[i+3]]
        words.append(word)
    
    rcon_index = 1
    while len(words) < 44:
        # Take the previous word
        temp = words[-1][:]
        
        # Every 4th word undergoes transformation
        if len(words) % 4 == 0:
            # a) RotWord: Rotate left [b0, b1, b2, b3] -> [b1, b2, b3, b0]
            rotated = [temp[1], temp[2], temp[3], temp[0]]
            
            # b) SubWord: Substitute each byte using S-BOX
            substituted = []
            for b in rotated:
                substituted.append(S_BOX[b])
            
            # c) XOR with Round Constant (only first byte)
            substituted[0] = substituted[0] ^ R_CON[rcon_index]
            
            temp = substituted
            rcon_index += 1
        
        # XOR with the word 4 positions back
        four_back = words[-4]
        new_word = []
        for j in range(4):
            new_word.append(temp[j] ^ four_back[j])
        
        words.append(new_word)
        
    # Group the 44 words into 11 round keys (16 bytes each)
    round_keys = []
    for i in range(11):
        rk = []
        for j in range(4):
            word = words[i*4 + j]
            rk.extend(word)
        round_keys.append(rk)
        
    return round_keys

# =========================
# Main Encryption Flow
# =========================
def encrypt_block(plaintext, key):
    round_keys = expand_key(key)
    
    # Initial Round
    state = add_round_key(list(plaintext), round_keys[0])
    
    # Rounds 1 to 9
    for i in range(1, 10):
        state = sub_bytes(state)
        state = shift_rows(state)
        state = mix_columns(state)
        state = add_round_key(state, round_keys[i])
        
    # Final Round (No MixColumns)
    state = sub_bytes(state)
    state = shift_rows(state)
    state = add_round_key(state, round_keys[10])
    
    return bytes(state)

# Main Decryption Flow
def decrypt_block(ciphertext, key):
    round_keys = expand_key(key)
    
    # Initial Round (Reverse order of keys)
    state = add_round_key(list(ciphertext), round_keys[10])
    state = inv_shift_rows(state)
    state = inv_sub_bytes(state)
    
    # Rounds 9 down to 1
    for i in range(9, 0, -1):
        state = add_round_key(state, round_keys[i])
        state = inv_mix_columns(state)
        state = inv_shift_rows(state)
        state = inv_sub_bytes(state)
        
    # Final Round
    state = add_round_key(state, round_keys[0])
    
    return bytes(state)

def main():
    import sys

    print("Functional AES-128 Implementation")
    print("-" * 35)

    try:
        if len(sys.argv) >= 4:
            mode = sys.argv[1].lower()
            key_hex = sys.argv[2]
            # Join remaining args if space-separated string provided
            data_input = " ".join(sys.argv[3:])
        else:
            print("Usage: python aes.py [encrypt|decrypt] [key_hex] [data_hex_or_string]")
            print("Example: python aes.py encrypt 2b7e151628aed2a6abf7158809cf4f3c 6bc1bee22e409f96e93d7e117393172a")
            print("\nEntering interactive mode...")
            mode = input("Mode (encrypt/decrypt): ").strip().lower()
            key_hex = input("Key (hex, 32 chars): ").strip()
            data_input = input("Data (hex or 16-char string): ").strip()

        # Handle Key (Must be Hex)
        key = bytes.fromhex(key_hex)
        if len(key) != 16:
            raise ValueError("Key must be exactly 128 bits (32 hex characters / 16 bytes).")

        # Handle Data
        try:
            # Try parsing as hex first
            data = bytes.fromhex(data_input)
        except ValueError:
            # If not hex, treat as string and pad/truncate to 16 bytes
            print("Note: Data was not valid hex. Treating as ASCII string (padded/truncated to 16 bytes).")
            data = data_input.encode('ascii', errors='ignore')[:16].ljust(16, b'\0')

        if len(data) != 16:
            raise ValueError(f"Data must be exactly 128 bits (16 bytes). Got {len(data)} bytes.")

        if mode == 'encrypt':
            result = encrypt_block(data, key)
            print(f"\nPlaintext (hex):  {data.hex()}")
            print(f"Key (hex):        {key.hex()}")
            print(f"Ciphertext (hex): {result.hex()}")
        elif mode == 'decrypt':
            result = decrypt_block(data, key)
            print(f"\nCiphertext (hex): {data.hex()}")
            print(f"Key (hex):        {key.hex()}")
            print(f"Plaintext (hex):  {result.hex()}")
            try:
                print(f"Plaintext (txt):  {result.decode('ascii', errors='replace')}")
            except:
                pass
        else:
            print("Error: Mode must be 'encrypt' or 'decrypt'.")

    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
