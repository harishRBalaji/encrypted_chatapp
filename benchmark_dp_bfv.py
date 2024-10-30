import tenseal as ts
import time
import os
import numpy as np
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

# Generate a 1 MB random message
message = os.urandom(1024 * 1024)

def time_execution(func):
    def wrapper(*args, **kwargs):
        start = time.time()
        result = func(*args, **kwargs)
        end = time.time()
        print(f"{func.__name__} took {end - start:.4f} seconds")
        return result
    return wrapper

@time_execution
def bfv_encrypt_decrypt(message):
    # Initialize BFV context with a polynomial modulus degree and a plain modulus
    context = ts.context(ts.SCHEME_TYPE.BFV, poly_modulus_degree=8192, plain_modulus=1032193)
    context.global_scale = 2**40

    # Encode and encrypt a small integer array for testing
    t = time.time()
    message_int = int.from_bytes(message[:8], 'big')  # Encrypt 8 bytes for a simple BFV test
    encrypted_message = ts.bfv_vector(context, [message_int])
    print("BFV Encryption time:",(time.time()-t)*1024*1024/8)
    # Measure ciphertext size
    ciphertext_size = len(encrypted_message.serialize())
    print(f"BFV Ciphertext size: {ciphertext_size} bytes")

    # Decrypt
    t = time.time()
    decrypted_message = encrypted_message.decrypt()
    decrypted_bytes = int(decrypted_message[0]).to_bytes(8, 'big')
    print("BFV Decryption time:",(time.time()-t)*1024*1024/8)
    assert message[:8] == decrypted_bytes, "BFV decryption failed!"

@time_execution
def dp_with_laplace_noise(message):
    # Differential privacy simulation with Laplace noise
    sensitivity = 1.0
    epsilon = 0.5
    noise_scale = sensitivity / epsilon

    # Apply Laplace noise to the first 8 bytes of the message for demonstration
    noisy_message = np.frombuffer(message[:8], dtype=np.uint8) + np.random.laplace(0, noise_scale, 8)

    # Clip noisy values to fit byte range
    noisy_message = np.clip(noisy_message, 0, 255).astype(np.uint8)
    noisy_bytes = noisy_message.tobytes()

    # Measure "ciphertext" size for storage purposes (message + noise as DP)
    ciphertext_size = len(noisy_bytes)
    print(f"DP-noised data size: {ciphertext_size} bytes")

    # For the purpose of benchmarking, we don’t decrypt since DP-noised data is inherently approximate

# Run tests
print("\nTesting BFV (FHE) with TenSEAL:")
bfv_encrypt_decrypt(message)

print("\nTesting Differential Privacy with Laplace Noise:")
dp_with_laplace_noise(message)
