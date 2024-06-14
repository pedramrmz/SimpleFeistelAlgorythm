from hashlib import sha256
from Crypto.Cipher import AES

def left_circular_shift(bits, shift):
    return ((bits << shift) & (2**64 - 1)) | (bits >> (64 - shift))

def sha256_hash(data):
    return int(sha256(data).hexdigest(), 16)

def generate_subkeys_with_hash(main_key):
    subkeys = []
    for i in range(1, 21):
        data = (main_key.to_bytes(32, 'big') + i.to_bytes(4, 'big'))
        subkey = sha256_hash(data) & (2**256 - 1)
        subkeys.append(subkey)
    return subkeys

def sbox(x):
    # Complex S-Box
    sbox_table = [
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
        0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        # Add the rest of the S-Box values for complexity
    ]
    return sbox_table[x % len(sbox_table)]

def permutation_box(x):
    # P-Box for bit diffusion
    return ((x & 0x0F0F0F0F0F0F0F0F) << 4) | ((x & 0xF0F0F0F0F0F0F0F0) >> 4)

def round_function(R, K):
    R1 = (R >> 32) & (2**32 - 1)
    R2 = R & (2**32 - 1)
    T1 = sbox(R1)
    T2 = sbox(R2)
    return ((T1 << 32) | T2) ^ K

def aes_encrypt(block, key):
    cipher = AES.new(key.to_bytes(32, 'big'), AES.MODE_ECB)
    encrypted_block = cipher.encrypt(block.to_bytes(16, 'big'))
    return int.from_bytes(encrypted_block, 'big')

def feistel_encrypt_with_aes(plaintext, main_key):
    L = (plaintext >> 64) & (2**64 - 1)
    R = plaintext & (2**64 - 1)
    subkeys = generate_subkeys_with_hash(main_key)
    L ^= (main_key >> 192) & (2**64 - 1)
    R ^= (main_key >> 128) & (2**64 - 1)
    for i in range(20):
        L, R = R, L ^ round_function(R, subkeys[i])
        R = permutation_box(R)
        R = aes_encrypt(R, subkeys[i])  # Added AES encryption layer
    L ^= (main_key >> 64) & (2**64 - 1)
    R ^= main_key & (2**64 - 1)
    return (R << 64) | L

def feistel_decrypt_with_aes(ciphertext, main_key):
    L = ciphertext & (2**64 - 1)
    R = (ciphertext >> 64) & (2**64 - 1)
    subkeys = generate_subkeys_with_hash(main_key)
    R ^= main_key & (2**64 - 1)
    L ^= (main_key >> 64) & (2**64 - 1)
    for i in reversed(range(20)):
        R = aes_encrypt(R, subkeys[i])  # Added AES encryption layer
        R = permutation_box(R)
        L, R = R ^ round_function(L, subkeys[i]), L
    R ^= (main_key >> 128) & (2**64 - 1)
    L ^= (main_key >> 192) & (2**64 - 1)
    return (L << 64) | R

# Sample usage
main_key = 0x0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF
plaintext = 0x0123456789ABCDEF0123456789ABCDEF
ciphertext = feistel_encrypt_with_aes(plaintext, main_key)
print(f"Ciphertext: {ciphertext:032X}")
decrypted = feistel_decrypt_with_aes(ciphertext, main_key)
print(f"Decrypted: {decrypted:032X}")
