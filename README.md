# AES-128 Architectural Analysis & Avalanche Effect Study

This project contains a specialized implementation of AES-128 designed to study the impact of its individual mathematical layers. By selectively disabling layers like `SubBytes` or `MixColumns`, we can empirically measure how "chaos" (diffusion and confusion) spreads through the 128-bit state.

## 1. The Block Lifecycle (Step-by-Step)
When you call `encrypt_block_custom(plaintext)`, the 128-bit block follows this exact chronological path:

1.  **Input:** Plaintext (16 bytes) is converted to a 4x4 Matrix via `bytes2matrix`.
2.  **Round 0 (Initialization):**
    *   `add_round_key` is called using the original master key.
3.  **Rounds 1 through 9 (The Main Loop):**
    *   `sub_bytes`: Non-linear replacement.
    *   `shift_rows`: Vertical transposition.
    *   `mix_columns`: Horizontal matrix math.
    *   `add_round_key`: XOR with the round's unique sub-key.
4.  **Round 10 (The Final Round):**
    *   `sub_bytes`
    *   `shift_rows`
    *   `add_round_key` (XOR with the 11th sub-key).
    *   *Note: `mix_columns` is omitted here to allow for decryption math.*
5.  **Output:** The matrix is converted back to 16 bytes via `matrix2bytes`.

---

## 2. Detailed Function Mechanics

### `sub_bytes(s)` (The Lookup)
*   **Internal Action:** It iterates through all 16 cells of the matrix. For every byte (e.g., `0xFF`), it looks up the value at that index in the `s_box` table.
*   **Result:** The byte is replaced. If `0x00` goes in, `0x63` comes out.
*   **Why:** This provides **Confusion**. It breaks the mathematical patterns of the bits.

### `shift_rows(s)` (The Slide)
*   **Internal Action:**
    *   Row 0: No change.
    *   Row 1: `[1, 2, 3, 0]` (Elements slide left by 1).
    *   Row 2: `[2, 3, 0, 1]` (Elements slide left by 2).
    *   Row 3: `[3, 0, 1, 2]` (Elements slide left by 3).
*   **Why:** This provides **Vertical Diffusion**. It ensures bytes that were in the same column are now in different columns.

### `mix_columns(s)` (The Matrix Multiplication)
*   **Internal Action:** It takes each column of 4 bytes and treats them as a mathematical vector. It multiplies this vector by a fixed matrix (using GF(2^8) arithmetic).
*   **Result:** Each new byte in the column is a combination of all 4 original bytes in that column.
*   **Why:** This provides **Horizontal Diffusion**. A 1-bit change in a single byte "explodes" to affect all 4 bytes of the column.

### `_expand_key(master_key)` (The Key Generator)
*   **Internal Action:** AES-128 needs 11 unique keys (one for Round 0, ten for Rounds 1-10). This function takes your 16-byte key and uses the `s_box` and `r_con` (round constants) to "stretch" it into 176 bytes.
*   **Why:** If we used the same key for every round, the cipher would be vulnerable to simple frequency analysis.

---

## 3. Simulation Methodology
The program performs **129 iterations** to calculate averages:
*   **Trial 0:** All-zero plaintext baseline.
*   **Trials 1-128:** A single bit `1` is flipped through every possible position (0 to 127).
*   **Metric:** **Hamming Distance** - we count exactly how many bits in the modified variants (AES1-AES4) differ from the standard **AES0** result.

---

## 4. How to Review the Results Table
When you run the program, the table shows the **Average Bit Difference**.

*   **Target:** **64.0**. In a 128-bit block, a perfectly randomized state should differ by exactly 50% of its bits (64 bits) compared to another state.
*   **Key Finding:** You will notice that even if you remove a layer (like `MixColumns`), the average difference hits **~64.0** by Round 02. This proves that AES is "over-engineered" for safety; the remaining layers pick up the slack to randomize the state almost immediately.
