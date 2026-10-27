import socket
import threading
import sys

from config import (
    BOB_HOST, BOB_PORT,
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


# Tangani koneksi dari Alice

def handle_alice_connection(conn, addr, kb: str, kb_key: bytes) -> bytes | None:
    """
    Proses langkah 3, 4, dan 5 dari koneksi Alice.
    Return: session key Ks jika autentikasi berhasil, None jika gagal.
    """
    print(f"\n  [+] Koneksi dari {addr}")

    try:
        msg = recv_msg(conn)
    except Exception as e:
        print(f"  [!] Gagal menerima pesan: {e}")
        return None

    msg_type = msg.get('type')

    if msg_type != 'ticket':
        print(f"  [!] Pesan tidak dikenali (type={msg_type})")
        return None

    #  Langkah 3: Terima tiket dari Alice 
    print_step(3, "Alice → Bob  |  E(Kb, Ks||ID_A)  [tiket]")
    ticket_hex = msg['ticket']
    print_field("  E(Kb, Ks||ID_A) [hex]", ticket_hex.upper())

    # Dekripsi tiket dengan Kb
    try:
        decrypted = decrypt(bytes.fromhex(ticket_hex), kb_key)
    except Exception as e:
        print(f"  [!] GAGAL mendekripsi tiket: {e}")
        send_msg(conn, {'status': 'error', 'reason': 'ticket decryption failed'})
        return None

    # Parsing: Ks(16) || ID_A(8)
    ks      = decrypted[0:16]
    ida_raw = decrypted[16:24]
    ks_key  = _pad_key(ks)

    print()
    print("  [✓] Berhasil mendekripsi tiket dengan Kb:")
    print_field("  Ks (session key, hex)", bytes_to_hex(ks))
    print_field("  ID_A (dari tiket)", unpad_id(ida_raw))

    # Verifikasi ID_A
    expected_id_a = pad_id(ID_ALICE.strip())
    if ida_raw != expected_id_a:
        print("  [!] ID_A tidak valid. Koneksi ditolak.")
        send_msg(conn, {'status': 'error', 'reason': 'invalid ID_A'})
        return None
    print("  [✓] Verifikasi ID_A: OK")

    #  Langkah 4: Kirim E(Ks, N2) ke Alice 
    print_step(4, "Bob → Alice  |  E(Ks, N2)")
    n2 = generate_nonce(NONCE_LEN)
    enc_n2 = encrypt(n2, ks_key)

    print_field("  N2 (nonce, hex)", bytes_to_hex(n2))
    print_field("  E(Ks, N2) [hex]", bytes_to_hex(enc_n2))

    send_msg(conn, {'type': 'challenge', 'enc_n2': enc_n2.hex()})
    print("  [✓] Challenge N2 terkirim ke Alice.")

    #  Langkah 5: Terima E(Ks, f(N2)) dari Alice 
    print_step(5, "Alice → Bob  |  E(Ks, f(N2))")
    try:
        msg5 = recv_msg(conn)
    except Exception as e:
        print(f"  [!] Gagal menerima langkah 5: {e}")
        return None

    if msg5.get('type') != 'auth':
        print("  [!] Tipe pesan tidak sesuai di langkah 5")
        return None

    enc_fn2_hex = msg5['enc_fn2']
    print_field("  E(Ks, f(N2)) [hex]", enc_fn2_hex.upper())

    # Dekripsi dan verifikasi f(N2)
    try:
        fn2_received = decrypt(bytes.fromhex(enc_fn2_hex), ks_key)
    except Exception as e:
        print(f"  [!] GAGAL mendekripsi f(N2): {e}")
        send_msg(conn, {'status': 'error', 'reason': 'decryption failed'})
        return None

    fn2_expected = compute_f_n2(n2)
    print_field("  f(N2) diterima (hex)", bytes_to_hex(fn2_received))
    print_field("  f(N2) expected (hex)", bytes_to_hex(fn2_expected))

    if fn2_received != fn2_expected:
        print("  [!] f(N2) tidak cocok! Autentikasi GAGAL.")
        send_msg(conn, {'status': 'error', 'reason': 'authentication failed'})
        return None

    print("  [✓] Verifikasi f(N2): OK — Alice terautentikasi!")
    send_msg(conn, {'status': 'ok'})

    print()
    print(DIVIDER)
    print("  ✅ KEY DISTRIBUTION SELESAI — Session Key Ks telah disepakati.")
    print(DIVIDER)

    return ks



# Chat dua arah


def phase_chat(conn, addr, ks: bytes) -> None:
    """Sesi chat dua arah menggunakan AES(Ks)."""
    ks_key = _pad_key(ks)
    print("\n  Mode CHAT aktif. Ketik pesan dan tekan Enter untuk mengirim.")
    print("  Ketik 'exit' untuk keluar.\n")

    # Thread untuk menerima pesan dari Alice
    def receive_thread():
        while True:
            try:
                msg = recv_msg(conn)
                if msg.get('type') == 'chat_end':
                    print("\n  [Alice telah keluar dari sesi chat]")
                    break
                enc_hex = msg.get('ciphertext', '')
                print(f"\n  [Diterima dari Alice]")
                print(f"    Ciphertext (hex) : {enc_hex.upper()}")
                try:
                    plaintext = decrypt(bytes.fromhex(enc_hex), ks_key).decode('utf-8')
                    print(f"    Plaintext        : {plaintext}")
                except Exception as e:
                    print(f"    [!] Gagal dekripsi: {e}")
                print("  Bob> ", end='', flush=True)
            except Exception:
                break

    t = threading.Thread(target=receive_thread, daemon=True)
    t.start()

    # Loop pengiriman pesan Bob
    while True:
        try:
            user_input = input("  Bob> ").strip()
        except (EOFError, KeyboardInterrupt):
            user_input = 'exit'

        if user_input.lower() == 'exit':
            send_msg(conn, {'type': 'chat_end'})
            print("  [Sesi chat diakhiri oleh Bob]")
            break
        if not user_input:
            continue

        enc_bytes = encrypt(user_input.encode('utf-8'), ks_key)
        enc_hex   = enc_bytes.hex()
        print(f"    Plaintext        : {user_input}")
        print(f"    Ciphertext (hex) : {enc_hex.upper()}")
        send_msg(conn, {'type': 'chat', 'ciphertext': enc_hex})



# Main — server Bob


def main():
    print("╔══════════════════════════════════════════════════════════╗")
    print("║         BOB — RESPONDER B                                ║")
    print("╚══════════════════════════════════════════════════════════╝")
    print(f"  Listening pada {BOB_HOST}:{BOB_PORT}")
    print()

    # Minta master key Kb dari pengguna
    print("  Masukkan master key Kb yang sudah disepakati dengan KDC.")
    print("  Key ASCII (akan dipadding/dipotong ke 16 karakter).\n")
    kb = input("  Master Key Kb : ").strip()
    kb = (kb + '\x00' * 16)[:16]
    kb_key = _pad_key(kb.encode('ascii'))
    print(f"  Kb (hex) : {kb.encode('ascii', errors='replace').hex().upper()}")

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((BOB_HOST, BOB_PORT))
    server.listen(5)

    print(DIVIDER)
    print(f"  Bob siap. Menunggu Alice pada {BOB_HOST}:{BOB_PORT} ...")
    print(DIVIDER)

    session_ks = None

    try:
        while True:
            conn, addr = server.accept()
            conn.settimeout(TIMEOUT)

            if session_ks is None:
                # Fase distribusi kunci
                ks = handle_alice_connection(conn, addr, kb, kb_key)
                if ks is not None:
                    session_ks = ks
                    conn.close()
            else:
                # Cek apakah ini sesi chat
                try:
                    msg = recv_msg(conn)
                    if msg.get('type') == 'chat_start':
                        print("\n  [+] Alice memulai sesi chat.")
                        phase_chat(conn, addr, session_ks)
                        session_ks = None  # Reset untuk sesi baru
                    else:
                        print(f"  [!] Pesan tak terduga: {msg}")
                except Exception as e:
                    print(f"  [!] Error: {e}")
                finally:
                    conn.close()
    except KeyboardInterrupt:
        print("\n  [!] Bob dihentikan.")
    finally:
        server.close()


if __name__ == '__main__':
    main()
