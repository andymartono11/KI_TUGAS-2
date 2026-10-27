# IP Address dan Port — DISESUAIKAN dengan setup jaringan 


# Key Distribution Center (KDC)
KDC_HOST = '127.0.0.1'      # Ganti dengan IP mesin KDC
KDC_PORT = 9000

# Alice (Initiator A)
ALICE_HOST = '127.0.0.2'    # Ganti dengan IP mesin Alice
ALICE_PORT = 9001

# Bob (Responder B)
BOB_HOST = '127.0.0.3'      # Ganti dengan IP mesin Bob
BOB_PORT = 9002


# Identitas entitas — panjang tepat 8 karakter (padding spasi)

ID_ALICE = 'ALICE   '   # 8 chars
ID_BOB   = 'BOB     '   # 8 chars
ID_KDC   = 'KDC     '   # 8 chars


# Parameter jaringan

BUFFER_SIZE   = 65536   # bytes — buffer socket
TIMEOUT       = 30      # detik — timeout koneksi

# Panjang nonce (N1, N2) dalam byte
NONCE_LEN = 8

# Panjang session key dalam byte (AES-128 → 16 byte)
SESSION_KEY_LEN = 16
