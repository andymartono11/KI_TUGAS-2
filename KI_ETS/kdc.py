import socket
import os
import sys

from config import (
    KDC_HOST, KDC_PORT, BUFFER_SIZE, TIMEOUT,
    ID_ALICE, ID_BOB, ID_KDC, SESSION_KEY_LEN
)
from aes import encrypt, _pad_key
from utils import (
    send_msg, recv_msg, aes_encrypt,
    print_step, print_field, bytes_to_hex, pad_id,
    DIVIDER
)



# Konfigurasi Master Key KDC


def get_master_keys() -> tuple[str, str]:
    """
    Minta operator KDC memasukkan master key Ka dan Kb.
    Kunci harus ASCII, tepat 16 karakter (dipadding/dipotong otomatis).
    """
    print("╔══════════════════════════════════════════════════════════╗")
    print("║         KEY DISTRIBUTION CENTER (KDC)                   ║")
    print("╚══════════════════════════════════════════════════════════╝")
    print(f"  Listening pada {KDC_HOST}:{KDC_PORT}")
    print()
    print("  Masukkan master key yang sudah disepakati sebelumnya.")
    print("  Key ASCII (akan dipadding/dipotong ke 16 karakter).")
    print()

    ka = input("  Master Key Ka (untuk Alice) : ").strip()
    kb = input("  Master Key Kb (untuk Bob)   : ").strip()

    # Normalisasi ke tepat 16 karakter
    ka = (ka + '\x00' * 16)[:16]
    kb = (kb + '\x00' * 16)[:16]

    print()
    print(f"  Ka (hex) : {ka.encode('ascii', errors='replace').hex().upper()}")
    print(f"  Kb (hex) : {kb.encode('ascii', errors='replace').hex().upper()}")
    return ka, kb



# Pemrosesan permintaan Alice (Langkah 1 → 2)


def handle_alice_request(conn, addr, ka: str, kb: str) -> None:
    """
    Terima permintaan distribusi kunci dari Alice dan kirim respons.
    """
    print(f"\n  [+] Koneksi baru dari {addr}")

    #  Langkah 1: Terima dari Alice 
    print_step(1, "KDC menerima permintaan dari Alice")
    try:
        msg = recv_msg(conn)
    except Exception as e:
        print(f"  [!] Gagal menerima pesan: {e}")
        return

    id_a_raw  = bytes.fromhex(msg['id_a'])
    id_b_raw  = bytes.fromhex(msg['id_b'])
    n1_bytes  = bytes.fromhex(msg['n1'])

    print_field("ID_A (hex)", msg['id_a'].upper())
    print_field("ID_A (ascii)", id_a_raw.decode('ascii', errors='replace').rstrip())
    print_field("ID_B (hex)", msg['id_b'].upper())
    print_field("ID_B (ascii)", id_b_raw.decode('ascii', errors='replace').rstrip())
    print_field("N1 (nonce, hex)", msg['n1'].upper())

    # Validasi ID
    if id_a_raw != pad_id(ID_ALICE.strip()) or id_b_raw != pad_id(ID_BOB.strip()):
        print("  [!] ID tidak dikenali. Koneksi ditutup.")
        conn.close()
        return

    #  Generate Session Key Ks 
    ks = os.urandom(SESSION_KEY_LEN)
    print()
    print_field("Ks (session key, hex)", ks.hex().upper())

    #  Langkah 2: Enkripsi dan kirim respons 
    print_step(2, "KDC mengirim tiket terenkripsi ke Alice")

    #  Bangun pesan yang dienkripsi dengan Ka:
    #    Ks (16 byte) || ID_A (8 byte) || ID_B (8 byte) || N1 (8 byte) = 40 byte
    msg_for_alice = ks + id_a_raw + id_b_raw + n1_bytes

    #  Bangun tiket yang dienkripsi dengan Kb:
    #    Ks (16 byte) || ID_A (8 byte) = 24 byte
    ticket_for_bob = ks + id_a_raw

    ka_key = _pad_key(ka.encode('ascii'))
    kb_key = _pad_key(kb.encode('ascii'))

    enc_ka = encrypt(msg_for_alice, ka_key)    # E(Ka, Ks||ID_A||ID_B||N1)
    enc_kb = encrypt(ticket_for_bob, kb_key)  # E(Kb, Ks||ID_A)

    print()
    print(f"  Plainteks untuk Alice  : Ks || ID_A || ID_B || N1")
    print(f"    = {msg_for_alice.hex().upper()}")
    print()
    print(f"  E(Ka, Ks||ID_A||ID_B||N1) [hex]:")
    print(f"    {enc_ka.hex().upper()}")
    print()
    print(f"  Plainteks tiket Bob    : Ks || ID_A")
    print(f"    = {ticket_for_bob.hex().upper()}")
    print()
    print(f"  E(Kb, Ks||ID_A) [hex]:")
    print(f"    {enc_kb.hex().upper()}")

    response = {
        'enc_ka': enc_ka.hex(),    # E(Ka, Ks||ID_A||ID_B||N1)
        'enc_kb': enc_kb.hex(),    # E(Kb, Ks||ID_A) — tiket untuk Bob
    }
    send_msg(conn, response)
    print()
    print("  [✓] Respons terkirim ke Alice.")
    conn.close()



# Main — server KDC


def main():
    ka, kb = get_master_keys()

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((KDC_HOST, KDC_PORT))
    server.listen(5)

    print(DIVIDER)
    print(f"  KDC siap. Menunggu permintaan pada {KDC_HOST}:{KDC_PORT} ...")
    print(DIVIDER)

    try:
        while True:
            conn, addr = server.accept()
            conn.settimeout(TIMEOUT)
            try:
                handle_alice_request(conn, addr, ka, kb)
            except Exception as e:
                print(f"  [!] Error saat memproses permintaan: {e}")
            finally:
                conn.close()
    except KeyboardInterrupt:
        print("\n  [!] KDC dihentikan.")
    finally:
        server.close()


if __name__ == '__main__':
    main()
