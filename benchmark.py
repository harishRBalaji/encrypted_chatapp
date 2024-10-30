import time
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import serialization
# from phe import paillier
import random
import base64

import sys

# Generate a 1 MB random message
message = os.urandom(1024 * 1024)
print("Message size: ", sys.getsizeof(message)/2**20, "MB")

def time_execution(func):
    def wrapper(*args, **kwargs):
        start = time.time()
        result = func(*args, **kwargs)
        end = time.time()
        print(f"{func.__name__} took {end - start:.4f} seconds")
        return result
    return wrapper

from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad

@time_execution
def des_encrypt_decrypt(message):
    key = os.urandom(8)  # DES uses a 56-bit key (8 bytes)
    iv = os.urandom(8)
    cipher = DES.new(key, DES.MODE_CBC, iv)
    
    # Pad the message to make it compatible with DES block size
    padded_message = pad(message, DES.block_size)
    
    # Encrypt
    t = time.time()
    ciphertext = cipher.encrypt(padded_message)
    print("Encryption time:", time.time()-t)
    print("Ciphertext size: ", sys.getsizeof(ciphertext)/2**20, "MB")
    # Decrypt
    decipher = DES.new(key, DES.MODE_CBC, iv)
    t = time.time()
    decrypted_padded_message = decipher.decrypt(ciphertext)
    decrypted_message = unpad(decrypted_padded_message, DES.block_size)
    print("Decryption time:", time.time()-t)
    assert message == decrypted_message, "DES decryption failed!"


@time_execution
def aes_encrypt_decrypt(message):
    key = os.urandom(32)  # 256-bit key
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    decryptor = cipher.decryptor()

    # Pad the message
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_message = padder.update(message) + padder.finalize()

    # Encrypt
    t = time.time()
    ciphertext = encryptor.update(padded_message) + encryptor.finalize()
    print("Encryption time:", time.time()-t)
    print("Ciphertext size: ", sys.getsizeof(ciphertext)/2**20, "MB")
    # Decrypt
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    t = time.time()
    decrypted_padded_message = decryptor.update(ciphertext) + decryptor.finalize()
    decrypted_message = unpadder.update(decrypted_padded_message) + unpadder.finalize()
    print("Decryption time:", time.time()-t)
    assert message == decrypted_message, "AES decryption failed!"

@time_execution
def rsa_encrypt_decrypt(message):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    # Encrypt (chunked because RSA can't handle large messages)
    chunk_size = 190  # Size limit for RSA-2048 with padding
    t = time.time()
    ciphertext = b"".join([
        public_key.encrypt(
            message[i:i + chunk_size],
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        for i in range(0, len(message), chunk_size)
    ])
    print("Ciphertext size: ", sys.getsizeof(ciphertext)/2**20, "MB")
    print("Encryption time:", time.time()-t)
    # Decrypt
    t = time.time()
    decrypted_message = b"".join([
        private_key.decrypt(
            ciphertext[i:i + 256],
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        for i in range(0, len(ciphertext), 256)
    ])
    print("Decryption time:", time.time()-t)
    assert message == decrypted_message, "RSA decryption failed!"

@time_execution
def prg_based_otp_encrypt_decrypt(message):
    t = time.time()
    key = os.urandom(32)  # Random 256-bit key as seed for PRG
    random.seed(key)
    prg_stream = bytes([random.getrandbits(8) for _ in range(len(message))])

    # Encrypt (XOR with PRG stream)
    
    ciphertext = bytes([m ^ s for m, s in zip(message, prg_stream)])
    print("Encryption time:", time.time()-t)
    print("Ciphertext size: ", sys.getsizeof(ciphertext)/2**20, "MB")
    # Reset PRG for decryption
    t = time.time()
    random.seed(key)
    prg_stream = bytes([random.getrandbits(8) for _ in range(len(message))])

    # Decrypt (XOR with PRG stream again)
    decrypted_message = bytes([c ^ s for c, s in zip(ciphertext, prg_stream)])
    print("Decryption time:", time.time()-t)

    assert message == decrypted_message, "OTP decryption failed!"

# Run tests
print("Testing AES:")
aes_encrypt_decrypt(message)

# Run test for DES
print("\nTesting DES:")
des_encrypt_decrypt(message)


print("\nTesting RSA:")
rsa_encrypt_decrypt(message)

print("\nTesting PRG-based OTP:")
prg_based_otp_encrypt_decrypt(message)
