from Crypto.Cipher import AES

key = b'Sixteen byte key'

cipher = AES.new(key, AES.MODE_EAX)


nonce = cipher.nonce
print(type(nonce))
data = b'Hello World'

ciphertext, tag = cipher.encrypt_and_digest(data)

print(ciphertext)


cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
plaintext = cipher.decrypt(ciphertext)
# cipher.verify(tag)
print(plaintext.decode('utf-8'))