# AES-128 Implementation (Educational)

This project provides a clean, "from-scratch" implementation of the Advanced Encryption Standard (AES) with a 128-bit key. It was developed for educational purposes to demonstrate the core mathematical transformations of the AES algorithm.

## Features

- **Core AES Transformations:** Detailed implementation of `SubBytes`, `ShiftRows`, `MixColumns`, and `AddRoundKey`.
- **Key Expansion:** Expands a 128-bit key into 11 round keys.
- **Padding:** Uses PKCS#7 padding to handle messages of arbitrary lengths.
- **Mode of Operation:** Implements Electronic Codebook (ECB) mode for block-by-block processing.
- **File-Based I/O:** Reads from `key.txt` and `input.txt`, and writes to `output.txt`.

## Project Structure

- `aes.py`: The main Python script containing the AES implementation and CLI logic.
- `key.txt`: A text file containing the 128-bit key as a 32-character hexadecimal string.
- `input.txt`: The input file (plain text for encryption, hex string for decryption).
- `output.txt`: The resulting output file.

## Usage

### 1. Setup Files
Ensure you have `key.txt` and `input.txt` in the same directory as `aes.py`.

- **key.txt**: `2b7e151628aed2a6abf7158809cf4f3c` (32 hex characters)
- **input.txt**: Your message (e.g., `Hello AES!`)

### 2. Run Encryption
```bash
python aes.py encrypt
```
The encrypted result (in hexadecimal) will be saved to `output.txt`.

### 3. Run Decryption
Move the encrypted hex string from `output.txt` to `input.txt`, then run:
```bash
python aes.py decrypt
```
The decrypted plain text will be saved back to `output.txt`.

## Educational Breakdown

The implementation follows the standard AES-128 round structure:
1. **Initial Round:** `AddRoundKey`
2. **Main Rounds (1-9):** `SubBytes` -> `ShiftRows` -> `MixColumns` -> `AddRoundKey`
3. **Final Round (10):** `SubBytes` -> `ShiftRows` -> `AddRoundKey`

Each function in `aes.py` is heavily commented to explain the mathematical rationale behind these steps.
