"""Implementación educativa del algoritmo AES-128.

Este módulo contiene únicamente la lógica criptográfica de AES,
separada por etapas (SubBytes, ShiftRows, MixColumns, AddRoundKey y
expansión de clave), además de los modos de operación ECB y CBC con
relleno PKCS#7.

No depende de ninguna librería de interfaz gráfica: toda la lógica de
presentación vive en ``main.py``.
"""

from __future__ import annotations

import os

# ---------------------------------------------------------------------------
# Tablas constantes de AES
# ---------------------------------------------------------------------------

S_BOX = (
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B,
    0xFE, 0xD7, 0xAB, 0x76, 0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0,
    0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0, 0xB7, 0xFD, 0x93, 0x26,
    0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2,
    0xEB, 0x27, 0xB2, 0x75, 0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0,
    0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84, 0x53, 0xD1, 0x00, 0xED,
    0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F,
    0x50, 0x3C, 0x9F, 0xA8, 0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5,
    0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2, 0xCD, 0x0C, 0x13, 0xEC,
    0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14,
    0xDE, 0x5E, 0x0B, 0xDB, 0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C,
    0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79, 0xE7, 0xC8, 0x37, 0x6D,
    0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F,
    0x4B, 0xBD, 0x8B, 0x8A, 0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E,
    0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E, 0xE1, 0xF8, 0x98, 0x11,
    0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F,
    0xB0, 0x54, 0xBB, 0x16,
)

INV_S_BOX = tuple(S_BOX.index(i) for i in range(256))

RCON = (
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36,
)

BLOCK_SIZE = 16  # bytes (128 bits)
NB = 4  # columnas del estado (siempre 4 en AES)
NK = 4  # palabras de la clave (4 -> AES-128)
NR = 10  # número de rondas (10 -> AES-128)


# ---------------------------------------------------------------------------
# Aritmética en GF(2^8)
# ---------------------------------------------------------------------------

def _xtime(a: int) -> int:
    """Multiplica ``a`` por 2 dentro del campo GF(2^8)."""
    a <<= 1
    if a & 0x100:
        a ^= 0x11B
    return a & 0xFF


def _gmul(a: int, b: int) -> int:
    """Multiplicación de dos bytes en el campo GF(2^8) usado por AES."""
    result = 0
    for _ in range(8):
        if b & 1:
            result ^= a
        a = _xtime(a)
        b >>= 1
    return result & 0xFF


# ---------------------------------------------------------------------------
# Etapa: expansión de clave (Key Schedule)
# ---------------------------------------------------------------------------

def key_expansion(key: bytes) -> list[list[int]]:
    """Expande una clave de 16 bytes en ``NR + 1`` claves de ronda.

    Devuelve una lista de palabras de 4 bytes (``(NR + 1) * 4`` palabras).
    """
    if len(key) != BLOCK_SIZE:
        raise ValueError("La clave AES-128 debe tener 16 bytes (128 bits).")

    words = [list(key[i * 4:i * 4 + 4]) for i in range(NK)]

    for i in range(NK, NB * (NR + 1)):
        temp = list(words[i - 1])
        if i % NK == 0:
            # RotWord
            temp = temp[1:] + temp[:1]
            # SubWord
            temp = [S_BOX[b] for b in temp]
            # Rcon
            temp[0] ^= RCON[i // NK - 1]
        words.append([words[i - NK][j] ^ temp[j] for j in range(4)])

    return words


def _round_key_matrix(words: list[list[int]], round_number: int) -> list[list[int]]:
    """Construye la matriz de estado (4x4) de la clave de una ronda dada."""
    start = round_number * NB
    columns = words[start:start + NB]
    return [[columns[c][r] for c in range(NB)] for r in range(4)]


# ---------------------------------------------------------------------------
# Etapas sobre el "estado" (matriz 4x4 de bytes)
# ---------------------------------------------------------------------------

def bytes_to_state(block: bytes) -> list[list[int]]:
    """Convierte 16 bytes en la matriz de estado 4x4 (orden por columnas)."""
    return [[block[row + 4 * col] for col in range(4)] for row in range(4)]


def state_to_bytes(state: list[list[int]]) -> bytes:
    """Convierte la matriz de estado 4x4 de vuelta a 16 bytes."""
    return bytes(state[row][col] for col in range(4) for row in range(4))


def add_round_key(state: list[list[int]], round_key: list[list[int]]) -> list[list[int]]:
    """Etapa AddRoundKey: XOR entre el estado y la clave de ronda."""
    return [
        [state[r][c] ^ round_key[r][c] for c in range(4)]
        for r in range(4)
    ]


def sub_bytes(state: list[list[int]]) -> list[list[int]]:
    """Etapa SubBytes: sustitución no lineal byte a byte usando el S-Box."""
    return [[S_BOX[state[r][c]] for c in range(4)] for r in range(4)]


def inv_sub_bytes(state: list[list[int]]) -> list[list[int]]:
    """Inversa de SubBytes, usada en el descifrado."""
    return [[INV_S_BOX[state[r][c]] for c in range(4)] for r in range(4)]


def shift_rows(state: list[list[int]]) -> list[list[int]]:
    """Etapa ShiftRows: desplaza cíclicamente cada fila a la izquierda."""
    return [
        state[r][r:] + state[r][:r]
        for r in range(4)
    ]


def inv_shift_rows(state: list[list[int]]) -> list[list[int]]:
    """Inversa de ShiftRows: desplaza cada fila a la derecha."""
    return [
        state[r][-r:] + state[r][:-r] if r else state[r][:]
        for r in range(4)
    ]


def mix_columns(state: list[list[int]]) -> list[list[int]]:
    """Etapa MixColumns: mezcla cada columna mediante multiplicación en GF(2^8)."""
    new_state = [[0] * 4 for _ in range(4)]
    for c in range(4):
        col = [state[r][c] for r in range(4)]
        new_state[0][c] = _gmul(col[0], 2) ^ _gmul(col[1], 3) ^ col[2] ^ col[3]
        new_state[1][c] = col[0] ^ _gmul(col[1], 2) ^ _gmul(col[2], 3) ^ col[3]
        new_state[2][c] = col[0] ^ col[1] ^ _gmul(col[2], 2) ^ _gmul(col[3], 3)
        new_state[3][c] = _gmul(col[0], 3) ^ col[1] ^ col[2] ^ _gmul(col[3], 2)
    return new_state


def inv_mix_columns(state: list[list[int]]) -> list[list[int]]:
    """Inversa de MixColumns, usada en el descifrado."""
    new_state = [[0] * 4 for _ in range(4)]
    for c in range(4):
        col = [state[r][c] for r in range(4)]
        new_state[0][c] = (
            _gmul(col[0], 0x0E) ^ _gmul(col[1], 0x0B)
            ^ _gmul(col[2], 0x0D) ^ _gmul(col[3], 0x09)
        )
        new_state[1][c] = (
            _gmul(col[0], 0x09) ^ _gmul(col[1], 0x0E)
            ^ _gmul(col[2], 0x0B) ^ _gmul(col[3], 0x0D)
        )
        new_state[2][c] = (
            _gmul(col[0], 0x0D) ^ _gmul(col[1], 0x09)
            ^ _gmul(col[2], 0x0E) ^ _gmul(col[3], 0x0B)
        )
        new_state[3][c] = (
            _gmul(col[0], 0x0B) ^ _gmul(col[1], 0x0D)
            ^ _gmul(col[2], 0x09) ^ _gmul(col[3], 0x0E)
        )
    return new_state


# ---------------------------------------------------------------------------
# Cifrado / descifrado de un bloque de 16 bytes
# ---------------------------------------------------------------------------

def encrypt_block(block: bytes, round_keys: list[list[list[int]]]) -> bytes:
    """Cifra un único bloque de 16 bytes aplicando las 10 rondas de AES-128."""
    state = bytes_to_state(block)
    state = add_round_key(state, round_keys[0])

    for round_number in range(1, NR):
        state = sub_bytes(state)
        state = shift_rows(state)
        state = mix_columns(state)
        state = add_round_key(state, round_keys[round_number])

    # Ronda final: sin MixColumns
    state = sub_bytes(state)
    state = shift_rows(state)
    state = add_round_key(state, round_keys[NR])

    return state_to_bytes(state)


def decrypt_block(block: bytes, round_keys: list[list[list[int]]]) -> bytes:
    """Descifra un único bloque de 16 bytes revirtiendo las 10 rondas."""
    state = bytes_to_state(block)
    state = add_round_key(state, round_keys[NR])

    for round_number in range(NR - 1, 0, -1):
        state = inv_shift_rows(state)
        state = inv_sub_bytes(state)
        state = add_round_key(state, round_keys[round_number])
        state = inv_mix_columns(state)

    # Ronda final: sin InvMixColumns
    state = inv_shift_rows(state)
    state = inv_sub_bytes(state)
    state = add_round_key(state, round_keys[0])

    return state_to_bytes(state)


def _build_round_keys(key: bytes) -> list[list[list[int]]]:
    """Genera las matrices de clave de ronda (0..NR) a partir de la clave maestra."""
    words = key_expansion(key)
    return [_round_key_matrix(words, i) for i in range(NR + 1)]


# ---------------------------------------------------------------------------
# Relleno PKCS#7
# ---------------------------------------------------------------------------

def pkcs7_pad(data: bytes) -> bytes:
    """Añade relleno PKCS#7 hasta completar un múltiplo de 16 bytes."""
    pad_len = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    return data + bytes([pad_len]) * pad_len


def pkcs7_unpad(data: bytes) -> bytes:
    """Elimina el relleno PKCS#7 previamente añadido."""
    if not data:
        raise ValueError("No hay datos para quitar el relleno.")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > BLOCK_SIZE or data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Relleno PKCS#7 inválido: revise la clave o el texto cifrado.")
    return data[:-pad_len]


# ---------------------------------------------------------------------------
# Modos de operación: ECB y CBC
# ---------------------------------------------------------------------------

def encrypt_ecb(data: bytes, key: bytes) -> bytes:
    """Cifra ``data`` en modo ECB con relleno PKCS#7."""
    round_keys = _build_round_keys(key)
    padded = pkcs7_pad(data)
    blocks = [padded[i:i + BLOCK_SIZE] for i in range(0, len(padded), BLOCK_SIZE)]
    return b"".join(encrypt_block(b, round_keys) for b in blocks)


def decrypt_ecb(data: bytes, key: bytes) -> bytes:
    """Descifra ``data`` en modo ECB y quita el relleno PKCS#7."""
    if len(data) % BLOCK_SIZE != 0:
        raise ValueError("El texto cifrado debe ser múltiplo de 16 bytes.")
    round_keys = _build_round_keys(key)
    blocks = [data[i:i + BLOCK_SIZE] for i in range(0, len(data), BLOCK_SIZE)]
    plain = b"".join(decrypt_block(b, round_keys) for b in blocks)
    return pkcs7_unpad(plain)


def _xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def encrypt_cbc(data: bytes, key: bytes, iv: bytes) -> bytes:
    """Cifra ``data`` en modo CBC con relleno PKCS#7 y vector de inicio ``iv``."""
    if len(iv) != BLOCK_SIZE:
        raise ValueError("El IV debe tener 16 bytes (128 bits).")
    round_keys = _build_round_keys(key)
    padded = pkcs7_pad(data)
    blocks = [padded[i:i + BLOCK_SIZE] for i in range(0, len(padded), BLOCK_SIZE)]

    previous = iv
    cipher_blocks = []
    for block in blocks:
        mixed = _xor_bytes(block, previous)
        encrypted = encrypt_block(mixed, round_keys)
        cipher_blocks.append(encrypted)
        previous = encrypted

    return b"".join(cipher_blocks)


def decrypt_cbc(data: bytes, key: bytes, iv: bytes) -> bytes:
    """Descifra ``data`` en modo CBC y quita el relleno PKCS#7."""
    if len(iv) != BLOCK_SIZE:
        raise ValueError("El IV debe tener 16 bytes (128 bits).")
    if len(data) % BLOCK_SIZE != 0:
        raise ValueError("El texto cifrado debe ser múltiplo de 16 bytes.")

    round_keys = _build_round_keys(key)
    blocks = [data[i:i + BLOCK_SIZE] for i in range(0, len(data), BLOCK_SIZE)]

    previous = iv
    plain_blocks = []
    for block in blocks:
        decrypted = decrypt_block(block, round_keys)
        plain_blocks.append(_xor_bytes(decrypted, previous))
        previous = block

    return pkcs7_unpad(b"".join(plain_blocks))


def generate_random_bytes(length: int = BLOCK_SIZE) -> bytes:
    """Genera bytes aleatorios criptográficamente seguros (clave o IV)."""
    return os.urandom(length)