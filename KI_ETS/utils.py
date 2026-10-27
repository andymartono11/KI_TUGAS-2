import os
import struct
import json

from aes import encrypt, decrypt, encrypt_to_hex, decrypt_from_hex, _pad_key
from config import NONCE_LEN, SESSION_KEY_LEN, ID_ALICE, ID_BOB



# Nonce


def generate_nonce(length: int = NONCE_LEN) -> bytes:
    """Buat nonce acak sejumlah `length` byte."""
    return os.urandom(length)



# Padding identitas menjadi 8 byte


def pad_id(entity_id: str, length: int = 8) -> bytes:
    """Padkan ID ke `length` byte (ASCII, spasi di kanan)."""
    return entity_id.encode('ascii').ljust(length)[:length]


def unpad_id(raw: bytes) -> str:
    """Hapus padding spasi dari ID."""
    return raw.decode('ascii').rstrip()



# Serialisasi / Deserialisasi pesan protokol (JSON over socket)


def send_msg(sock, data: dict) -> None:
    """Kirim dictionary sebagai JSON dengan panjang 4-byte di depan."""
    payload = json.dumps(data).encode('utf-8')
    header = struct.pack('>I', len(payload))
    sock.sendall(header + payload)


def recv_msg(sock) -> dict:
    """Terima pesan JSON (4-byte length prefix)."""
    raw_len = _recv_exact(sock, 4)
    msg_len = struct.unpack('>I', raw_len)[0]
    payload = _recv_exact(sock, msg_len)
    return json.loads(payload.decode('utf-8'))


def _recv_exact(sock, n: int) -> bytes:
    """Terima tepat n byte dari socket."""
    buf = b''
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Koneksi terputus saat menerima data")
        buf += chunk
    return buf



# Fungsi f(N2) untuk autentikasi (langkah 5)


def compute_f_n2(n2: bytes) -> bytes:
    """
    f(N2) = N2 + 1  (integer addition, big-endian, mod 2^(8*len)).
    Digunakan Alice untuk membuktikan ia mengetahui N2.
    """
    n2_int = int.from_bytes(n2, 'big')
    f_n2_int = (n2_int + 1) % (2 ** (8 * len(n2)))
    return f_n2_int.to_bytes(len(n2), 'big')



# Enkripsi / Dekripsi pesan protokol


def aes_encrypt(plaintext: bytes, key_ascii: str) -> str:
    """
    Enkripsi plaintext (bytes) dengan kunci ASCII.
    Return: HEX string (IV + ciphertext).
    """
    key_bytes = _pad_key(key_ascii.encode('ascii'))
    return encrypt(plaintext, key_bytes).hex().upper()


def aes_decrypt(hex_cipher: str, key_ascii: str) -> bytes:
    """
    Dekripsi HEX string (IV + ciphertext) dengan kunci ASCII.
    Return: plaintext bytes.
    """
    key_bytes = _pad_key(key_ascii.encode('ascii'))
    raw = bytes.fromhex(hex_cipher)
    return decrypt(raw, key_bytes)



# Tampilan / Logging protokol


DIVIDER = '─' * 60

def print_step(step_no: int, description: str) -> None:
    print(f"\n{DIVIDER}")
    print(f"  LANGKAH {step_no}: {description}")
    print(DIVIDER)


def print_field(label: str, value, as_hex: bool = False) -> None:
    if isinstance(value, bytes):
        display = value.hex().upper() if as_hex else value
        print(f"  {label:<22}: {display}")
    else:
        print(f"  {label:<22}: {value}")


def bytes_to_hex(data: bytes) -> str:
    return data.hex().upper()


def hex_to_bytes(hex_str: str) -> bytes:
    return bytes.fromhex(hex_str)
