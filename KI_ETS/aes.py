"""
aes.py — Implementasi Manual AES-128
AES-128: kunci 128-bit (16 byte), 10 putaran (rounds).

Referensi: FIPS 197 — Advanced Encryption Standard (AES)
"""

# S-Box dan Inverse S-Box (substitution table)
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
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
]

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
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
]

# Round constants (RCON) — untuk key schedule
RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]


# Operasi GF(2^8) — Galois Field arithmetic

def xtime(a: int) -> int:
    """Perkalian dengan 2 di GF(2^8): shift kiri 1 bit, XOR 0x1B jika bit 7 aktif."""
    if a & 0x80:
        return ((a << 1) ^ 0x1B) & 0xFF
    return (a << 1) & 0xFF


def gmul(a: int, b: int) -> int:
    """
    Perkalian dua byte di GF(2^8) menggunakan Russian Peasant Multiplication.
    Digunakan di MixColumns dan InvMixColumns.
    """
    result = 0
    for _ in range(8):
        if b & 1:
            result ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return result


# State helpers — konversi bytes <-> state 4×4

def bytes_to_state(b: bytes) -> list:
    """Ubah 16 bytes menjadi state 4×4 (kolom-mayor / column-major)."""
    return [[b[r + 4 * c] for c in range(4)] for r in range(4)]


def state_to_bytes(state: list) -> bytes:
    """Ubah state 4×4 kembali ke 16 bytes."""
    return bytes(state[r][c] for c in range(4) for r in range(4))


# AES Transformations

def sub_bytes(state: list) -> list:
    """SubBytes: substitusi setiap byte menggunakan S-Box."""
    return [[S_BOX[state[r][c]] for c in range(4)] for r in range(4)]


def inv_sub_bytes(state: list) -> list:
    """InvSubBytes: substitusi terbalik menggunakan Inverse S-Box."""
    return [[INV_S_BOX[state[r][c]] for c in range(4)] for r in range(4)]


def shift_rows(state: list) -> list:
    """
    ShiftRows: geser setiap baris ke kiri.
    Baris 0: tidak digeser
    Baris 1: geser 1 ke kiri
    Baris 2: geser 2 ke kiri
    Baris 3: geser 3 ke kiri
    """
    new_state = [row[:] for row in state]
    for r in range(1, 4):
        new_state[r] = state[r][r:] + state[r][:r]
    return new_state


def inv_shift_rows(state: list) -> list:
    """InvShiftRows: geser setiap baris ke kanan."""
    new_state = [row[:] for row in state]
    for r in range(1, 4):
        new_state[r] = state[r][4 - r:] + state[r][:4 - r]
    return new_state


def mix_columns(state: list) -> list:
    """
    MixColumns: kalikan setiap kolom dengan matriks tetap di GF(2^8).
    Matriks: [[2,3,1,1],[1,2,3,1],[1,1,2,3],[3,1,1,2]]
    """
    new_state = [[0] * 4 for _ in range(4)]
    for c in range(4):
        col = [state[r][c] for r in range(4)]
        new_state[0][c] = gmul(col[0], 2) ^ gmul(col[1], 3) ^ col[2] ^ col[3]
        new_state[1][c] = col[0] ^ gmul(col[1], 2) ^ gmul(col[2], 3) ^ col[3]
        new_state[2][c] = col[0] ^ col[1] ^ gmul(col[2], 2) ^ gmul(col[3], 3)
        new_state[3][c] = gmul(col[0], 3) ^ col[1] ^ col[2] ^ gmul(col[3], 2)
    return new_state


def inv_mix_columns(state: list) -> list:
    """
    InvMixColumns: kalikan setiap kolom dengan matriks invers di GF(2^8).
    Matriks: [[14,11,13,9],[9,14,11,13],[13,9,14,11],[11,13,9,14]]
    """
    new_state = [[0] * 4 for _ in range(4)]
    for c in range(4):
        col = [state[r][c] for r in range(4)]
        new_state[0][c] = gmul(col[0], 14) ^ gmul(col[1], 11) ^ gmul(col[2], 13) ^ gmul(col[3], 9)
        new_state[1][c] = gmul(col[0], 9) ^ gmul(col[1], 14) ^ gmul(col[2], 11) ^ gmul(col[3], 13)
        new_state[2][c] = gmul(col[0], 13) ^ gmul(col[1], 9) ^ gmul(col[2], 14) ^ gmul(col[3], 11)
        new_state[3][c] = gmul(col[0], 11) ^ gmul(col[1], 13) ^ gmul(col[2], 9) ^ gmul(col[3], 14)
    return new_state


def add_round_key(state: list, round_key: list) -> list:
    """AddRoundKey: XOR state dengan round key."""
    return [[state[r][c] ^ round_key[r][c] for c in range(4)] for r in range(4)]


# Key Schedule (Key Expansion)

def key_expansion(key: bytes) -> list:
    """
    Key Expansion untuk AES-128: menghasilkan 11 round keys (masing-masing 16 byte).
    Input : 16-byte key
    Output: list of 11 state (4×4), satu per round
    """
    assert len(key) == 16, "Key AES-128 harus 16 byte"

    # W: word array, setiap word = 4 byte
    W = [list(key[i:i + 4]) for i in range(0, 16, 4)]  # W[0..3]

    for i in range(4, 44):
        temp = W[i - 1][:]
        if i % 4 == 0:
            # RotWord: rotasi kiri 1 byte
            temp = temp[1:] + temp[:1]
            # SubWord: substitusi dengan S-Box
            temp = [S_BOX[b] for b in temp]
            # XOR dengan RCON
            temp[0] ^= RCON[i // 4 - 1]
        W.append([W[i - 4][j] ^ temp[j] for j in range(4)])

    # Susun menjadi 11 round keys, masing-masing 4 word (16 byte)
    round_keys = []
    for rnd in range(11):
        # Konversi 4 word menjadi state 4×4 (column-major)
        words = W[rnd * 4:(rnd + 1) * 4]
        rk_bytes = bytes(w[b] for w in words for b in range(4))
        round_keys.append(bytes_to_state(rk_bytes))
    return round_keys


# Block Encrypt / Decrypt

def aes_encrypt_block(plaintext_block: bytes, key: bytes) -> bytes:
    """
    Enkripsi satu blok 16-byte dengan AES-128.
    """
    assert len(plaintext_block) == 16, "Blok plaintext harus 16 byte"
    assert len(key) == 16, "Kunci harus 16 byte"

    round_keys = key_expansion(key)
    state = bytes_to_state(plaintext_block)

    # Round 0: AddRoundKey awal
    state = add_round_key(state, round_keys[0])

    # Round 1–9: SubBytes, ShiftRows, MixColumns, AddRoundKey
    for rnd in range(1, 10):
        state = sub_bytes(state)
        state = shift_rows(state)
        state = mix_columns(state)
        state = add_round_key(state, round_keys[rnd])

    # Round 10 (final): tanpa MixColumns
    state = sub_bytes(state)
    state = shift_rows(state)
    state = add_round_key(state, round_keys[10])

    return state_to_bytes(state)


def aes_decrypt_block(ciphertext_block: bytes, key: bytes) -> bytes:
    """
    Dekripsi satu blok 16-byte dengan AES-128.
    """
    assert len(ciphertext_block) == 16, "Blok ciphertext harus 16 byte"
    assert len(key) == 16, "Kunci harus 16 byte"

    round_keys = key_expansion(key)
    state = bytes_to_state(ciphertext_block)

    # Round 10 awal
    state = add_round_key(state, round_keys[10])

    # Round 9–1: InvShiftRows, InvSubBytes, AddRoundKey, InvMixColumns
    for rnd in range(9, 0, -1):
        state = inv_shift_rows(state)
        state = inv_sub_bytes(state)
        state = add_round_key(state, round_keys[rnd])
        state = inv_mix_columns(state)

    # Round 0 final: tanpa InvMixColumns
    state = inv_shift_rows(state)
    state = inv_sub_bytes(state)
    state = add_round_key(state, round_keys[0])

    return state_to_bytes(state)


# Padding PKCS#7

def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    """Tambah padding PKCS#7 agar panjang data kelipatan block_size."""
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)


def pkcs7_unpad(data: bytes) -> bytes:
    """Hapus padding PKCS#7."""
    if not data:
        raise ValueError("Data kosong")
    pad_len = data[-1]
    if pad_len == 0 or pad_len > 16:
        raise ValueError(f"Padding tidak valid: {pad_len}")
    if data[-pad_len:] != bytes([pad_len] * pad_len):
        raise ValueError("Padding PKCS#7 tidak valid")
    return data[:-pad_len]


# Mode CBC (Cipher Block Chaining)

def aes_encrypt_cbc(plaintext: bytes, key: bytes, iv: bytes = None) -> bytes:
    """
    Enkripsi dengan AES-128-CBC.
    IV default = 16 byte nol (0x00).
    Output: IV (16 byte) + ciphertext
    """
    assert len(key) == 16
    if iv is None:
        iv = b'\x00' * 16
    assert len(iv) == 16

    plaintext = pkcs7_pad(plaintext)
    prev_block = iv
    ciphertext = iv  # Sisipkan IV di depan

    for i in range(0, len(plaintext), 16):
        block = plaintext[i:i + 16]
        # XOR dengan blok sebelumnya (atau IV untuk blok pertama)
        xored = bytes(a ^ b for a, b in zip(block, prev_block))
        enc_block = aes_encrypt_block(xored, key)
        ciphertext += enc_block
        prev_block = enc_block

    return ciphertext


def aes_decrypt_cbc(ciphertext: bytes, key: bytes) -> bytes:
    """
    Dekripsi dengan AES-128-CBC.
    Input: IV (16 byte pertama) + ciphertext
    """
    assert len(key) == 16
    assert len(ciphertext) >= 32, "Ciphertext terlalu pendek (min 32 byte: IV + 1 blok)"

    iv = ciphertext[:16]
    ciphertext = ciphertext[16:]

    prev_block = iv
    plaintext = b''

    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i:i + 16]
        dec_block = aes_decrypt_block(block, key)
        plain_block = bytes(a ^ b for a, b in zip(dec_block, prev_block))
        plaintext += plain_block
        prev_block = block

    return pkcs7_unpad(plaintext)


# Antarmuka publik: encrypt / decrypt (bytes dan hex)

def encrypt(plaintext: bytes, key: bytes, iv: bytes = None) -> bytes:
    """
    Enkripsi plaintext dengan AES-128-CBC.
    key  : 16 byte (ASCII atau bytes)
    iv   : 16 byte opsional (default nol)
    Return: ciphertext bytes (termasuk IV di depan)
    """
    if isinstance(key, str):
        key = key.encode('ascii')
    key = _pad_key(key)
    return aes_encrypt_cbc(plaintext, key, iv)


def decrypt(ciphertext: bytes, key: bytes) -> bytes:
    """
    Dekripsi ciphertext dengan AES-128-CBC.
    key      : 16 byte (ASCII atau bytes)
    ciphertext: bytes dengan IV di 16 byte pertama
    Return: plaintext bytes
    """
    if isinstance(key, str):
        key = key.encode('ascii')
    key = _pad_key(key)
    return aes_decrypt_cbc(ciphertext, key)


def encrypt_to_hex(plaintext: bytes, key: bytes, iv: bytes = None) -> str:
    """Enkripsi dan kembalikan hasil dalam format hexadecimal."""
    return encrypt(plaintext, key, iv).hex().upper()


def decrypt_from_hex(hex_ciphertext: str, key: bytes) -> bytes:
    """Dekripsi dari hexadecimal string."""
    return decrypt(bytes.fromhex(hex_ciphertext), key)


def _pad_key(key: bytes) -> bytes:
    """Pastikan kunci tepat 16 byte: potong jika lebih, pad dengan nol jika kurang."""
    if len(key) > 16:
        return key[:16]
    return key.ljust(16, b'\x00')


# Self-test sederhana
if __name__ == '__main__':
    print("=== AES-128 Self-Test ===")

    # Test vector dari FIPS 197 (Appendix B) — ECB block
    key_tv  = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    plain_tv = bytes.fromhex("3243f6a8885a308d313198a2e0370734")
    cipher_tv = bytes.fromhex("3925841d02dc09fbdc118597196a0b32")

    result = aes_encrypt_block(plain_tv, key_tv)
    print(f"Plaintext : {plain_tv.hex().upper()}")
    print(f"Key       : {key_tv.hex().upper()}")
    print(f"Ciphertext (computed): {result.hex().upper()}")
    print(f"Ciphertext (expected): {cipher_tv.hex().upper()}")
    print(f"Enkripsi blok: {'PASS ✓' if result == cipher_tv else 'FAIL ✗'}")

    # Test dekripsi blok
    decrypted = aes_decrypt_block(cipher_tv, key_tv)
    print(f"Dekripsi blok: {'PASS ✓' if decrypted == plain_tv else 'FAIL ✗'}")

    # Test CBC dengan ASCII key
    key_ascii = b'ThisIsASecretKey'   # 16 bytes
    plaintext = b'Hello, World! AES-128-CBC Test.'
    print(f"\nPlaintext  : {plaintext}")
    ciphertext = encrypt(plaintext, key_ascii)
    print(f"Ciphertext : {ciphertext.hex().upper()}")
    recovered  = decrypt(ciphertext, key_ascii)
    print(f"Recovered  : {recovered}")
    print(f"CBC round-trip: {'PASS ✓' if recovered == plaintext else 'FAIL ✗'}")
