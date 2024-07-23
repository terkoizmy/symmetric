from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from base64 import urlsafe_b64encode, urlsafe_b64decode
import os

def generate_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def encrypt_asymmetric(public_key, plaintext):
    ciphertext = public_key.encrypt(
        plaintext.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return urlsafe_b64encode(ciphertext).decode()

def decrypt_asymmetric(private_key, ciphertext):
    ciphertext = urlsafe_b64decode(ciphertext)
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext.decode()

# Contoh penggunaan
private_key, public_key = generate_keys()
plaintext = 'This is a secret message.'

encrypted = encrypt_asymmetric(public_key, plaintext)
print(f'Encrypted: {encrypted}')

decrypted = decrypt_asymmetric(private_key, encrypted)
print(f'Decrypted: {decrypted}')
