import socket
import threading
import sys

from config import (
    KDC_HOST, KDC_PORT,
    BOB_HOST, BOB_PORT,
    ALICE_HOST, ALICE_PORT,
    BUFFER_SIZE, TIMEOUT,
    ID_ALICE, ID_BOB, SESSION_KEY_LEN, NONCE_LEN
)
from aes import encrypt, decrypt, _pad_key
from utils import (
    send_msg, recv_msg,
    generate_nonce, pad_id, unpad_id, compute_f_n2,
    print_step, print_field, bytes_to_hex,
    DIVIDER
)


# Distribusi Kunci (Langkah 1–5)

def phase_key_distribution(ka: str) -> tuple[bytes, bytes]:
    """
    Jalankan langkah 1–5 protokol distribusi kunci.
    Return: (session_key_Ks, ticket_for_bob)
    """

    #  Langkah 1: Kirim ke KDC 
    print_step(1, "Alice → KDC  |  ID_A || ID_B || N1")

    n1 = generate_nonce(NONCE_LEN)
    id_a = pad_id(ID_ALICE.strip())
    id_b = pad_id(ID_BOB.strip())

    print_field("ID_A", ID_ALICE)
    print_field("ID_B", ID_BOB)
    print_field("N1 (nonce, hex)", bytes_to_hex(n1))

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(TIMEOUT)
        print(f"\n  Menghubungi KDC di {KDC_HOST}:{KDC_PORT} ...")
        s.connect((KDC_HOST, KDC_PORT))

        send_msg(s, {
            'id_a': id_a.hex(),
            'id_b': id_b.hex(),
            'n1'  : n1.hex(),
        })
        print("  [✓] Pesan terkirim ke KDC.")

        #  Langkah 2: Terima dari KDC 
        print_step(2, "KDC → Alice  |  E(Ka, Ks||ID_A||ID_B||N1) || E(Kb, Ks||ID_A)")
        response = recv_msg(s)

    enc_ka_hex = response['enc_ka']
    enc_kb_hex = response['enc_kb']   # Tiket untuk Bob

    print_field("E(Ka, Ks||ID_A||ID_B||N1) [hex]", enc_ka_hex.upper())
    print_field("E(Kb, Ks||ID_A) [hex]", enc_kb_hex.upper())

    # Dekripsi E(Ka, ...) dengan kunci Ka milik Alice
    ka_key = _pad_key(ka.encode('ascii'))
    try:
        decrypted = decrypt(bytes.fromhex(enc_ka_hex), ka_key)
    except Exception as e:
        print(f"\n  [!] GAGAL mendekripsi E(Ka,...): {e}")
        sys.exit(1)

    # Parsing plaintext: Ks(16) || ID_A(8) || ID_B(8) || N1(8)
    ks      = decrypted[0:16]
    ida_got = decrypted[16:24]
    idb_got = decrypted[24:32]
    n1_got  = decrypted[32:40]

    print()
    print("  [✓] Berhasil mendekripsi dengan Ka:")
    print_field("  Ks (session key, hex)", bytes_to_hex(ks))
    print_field("  ID_A (verifikasi)", unpad_id(ida_got))
    print_field("  ID_B (verifikasi)", unpad_id(idb_got))
    print_field("  N1 (verifikasi)", bytes_to_hex(n1_got))

    # Verifikasi integritas (N1 harus cocok)
    if n1_got != n1:
        print("  [!] N1 tidak cocok! Kemungkinan serangan replay. Dibatalkan.")
        sys.exit(1)
    print("  [✓] Verifikasi N1: OK")

    ticket_for_bob = bytes.fromhex(enc_kb_hex)
    return ks, ticket_for_bob


def phase_authentication(ks: bytes, ticket_for_bob: bytes) -> None:
    """
    Jalankan langkah 3–5: kirim tiket ke Bob dan autentikasi nonce.
    """

    #  Langkah 3: Alice → Bob: kirim tiket ──────────────────
    print_step(3, "Alice → Bob  |  E(Kb, Ks||ID_A)  [tiket]")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(TIMEOUT)
        print(f"  Menghubungi Bob di {BOB_HOST}:{BOB_PORT} ...")
        s.connect((BOB_HOST, BOB_PORT))

        # Kirim tiket
        send_msg(s, {
            'type'  : 'ticket',
            'ticket': ticket_for_bob.hex(),
        })
        print_field("  E(Kb, Ks||ID_A) [hex]", bytes_to_hex(ticket_for_bob))
        print("  [✓] Tiket terkirim ke Bob.")

        #  Langkah 4: Terima E(Ks, N2) dari Bob 
        print_step(4, "Bob → Alice  |  E(Ks, N2)")
        msg4 = recv_msg(s)
        enc_n2_hex = msg4['enc_n2']
        print_field("  E(Ks, N2) [hex]", enc_n2_hex.upper())

        # Dekripsi N2 menggunakan Ks
        ks_key = _pad_key(ks)
        try:
            n2 = decrypt(bytes.fromhex(enc_n2_hex), ks_key)
        except Exception as e:
            print(f"  [!] GAGAL mendekripsi N2: {e}")
            sys.exit(1)

        print_field("  N2 (hex)", bytes_to_hex(n2))

        #  Langkah 5: Kirim E(Ks, f(N2)) ke Bob 
        print_step(5, "Alice → Bob  |  E(Ks, f(N2))")
        f_n2 = compute_f_n2(n2)
        enc_f_n2 = encrypt(f_n2, ks_key)
        print_field("  f(N2) = N2+1 (hex)", bytes_to_hex(f_n2))
        print_field("  E(Ks, f(N2)) [hex]", bytes_to_hex(enc_f_n2))

        send_msg(s, {
            'type'    : 'auth',
            'enc_fn2' : enc_f_n2.hex(),
        })
        print("  [✓] Bukti autentikasi terkirim ke Bob.")

        # Tunggu konfirmasi dari Bob
        confirm = recv_msg(s)
        if confirm.get('status') == 'ok':
            print("\n  [✓] Bob mengkonfirmasi autentikasi berhasil!")
        else:
            print(f"\n  [!] Bob menolak autentikasi: {confirm}")
            sys.exit(1)

    print()
    print(DIVIDER)
    print("  ✅ KEY DISTRIBUTION SELESAI — Session Key Ks telah disepakati.")
    print(DIVIDER)


# Fase Chat Dua Arah (Langkah 6+)

def phase_chat(ks: bytes) -> None:
    """Komunikasi dua arah dengan Bob menggunakan AES(Ks)."""
    ks_key = _pad_key(ks)
    print("\n  Mode CHAT aktif. Ketik pesan dan tekan Enter untuk mengirim.")
    print("  Ketik 'exit' untuk keluar.\n")

    # Alice bertindak sebagai CLIENT terhadap Bob yang menjadi chat server
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((BOB_HOST, BOB_PORT))
        send_msg(s, {'type': 'chat_start'})

        # Thread untuk menerima pesan dari Bob
        def receive_thread():
            while True:
                try:
                    msg = recv_msg(s)
                    if msg.get('type') == 'chat_end':
                        print("\n  [Bob telah keluar dari sesi chat]")
                        break
                    enc_hex = msg.get('ciphertext', '')
                    print(f"\n  [Diterima dari Bob]")
                    print(f"    Ciphertext (hex) : {enc_hex.upper()}")
                    try:
                        plaintext = decrypt(bytes.fromhex(enc_hex), ks_key).decode('utf-8')
                        print(f"    Plaintext        : {plaintext}")
                    except Exception as e:
                        print(f"    [!] Gagal dekripsi: {e}")
                    print("  Alice> ", end='', flush=True)
                except Exception:
                    break

        t = threading.Thread(target=receive_thread, daemon=True)
        t.start()

        # Loop pengiriman pesan Alice
        while True:
            try:
                user_input = input("  Alice> ").strip()
            except (EOFError, KeyboardInterrupt):
                user_input = 'exit'

            if user_input.lower() == 'exit':
                send_msg(s, {'type': 'chat_end'})
                print("  [Sesi chat diakhiri oleh Alice]")
                break
            if not user_input:
                continue

            enc_bytes = encrypt(user_input.encode('utf-8'), ks_key)
            enc_hex   = enc_bytes.hex()
            print(f"    Plaintext        : {user_input}")
            print(f"    Ciphertext (hex) : {enc_hex.upper()}")
            send_msg(s, {'type': 'chat', 'ciphertext': enc_hex})


# Main

def main():
    print("╔══════════════════════════════════════════════════════════╗")
    print("║         ALICE — INITIATOR A                              ║")
    print("╚══════════════════════════════════════════════════════════╝")
    print(f"  KDC : {KDC_HOST}:{KDC_PORT}")
    print(f"  Bob : {BOB_HOST}:{BOB_PORT}")
    print()

    # Minta master key Ka dari pengguna
    print("  Masukkan master key Ka yang sudah disepakati dengan KDC.")
    print("  Key ASCII (akan dipadding/dipotong ke 16 karakter).\n")
    ka = input("  Master Key Ka : ").strip()
    ka = (ka + '\x00' * 16)[:16]
    print(f"  Ka (hex) : {ka.encode('ascii', errors='replace').hex().upper()}")

    #  Fase Distribusi Kunci 
    ks, ticket_for_bob = phase_key_distribution(ka)

    #  Fase Autentikasi 
    phase_authentication(ks, ticket_for_bob)

    #  Fase Chat 
    print("\n  Memulai sesi chat dengan Bob ...")
    phase_chat(ks)
    print("\n  Sampai jumpa!")


if __name__ == '__main__':
    main()
