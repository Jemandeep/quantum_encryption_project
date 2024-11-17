from fastapi import FastAPI
from typing import Dict
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os
import base64

app = FastAPI()

# Key and IV generation
AES_KEY = os.urandom(32)  # 256-bit AES key
AES_IV = os.urandom(16)   # 128-bit IV (Initialization Vector)

# AES Encryption
def aes_encrypt(plaintext: str, key: bytes, iv: bytes) -> str:
    # Pad the plaintext to make it a multiple of the block size
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(plaintext.encode()) + padder.finalize()

    # Encrypt the padded plaintext
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted = encryptor.update(padded_data) + encryptor.finalize()

    # Return encrypted data in Base64 format for easy transmission
    return base64.b64encode(encrypted).decode()

# AES Decryption
def aes_decrypt(encrypted: str, key: bytes, iv: bytes) -> str:
    # Decode the Base64-encoded encrypted data
    encrypted_data = base64.b64decode(encrypted)

    # Decrypt the encrypted data
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

    # Remove padding from decrypted plaintext
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(padded_data) + unpadder.finalize()

    return plaintext.decode()

@app.get("/")
def read_root():
    return {"message": "Hello, AES Encryption with Cryptography!"}

@app.post("/encrypt")
def encrypt(data: Dict[str, str]):
    plaintext = data.get("plaintext")
    if not plaintext:
        return {"error": "No plaintext provided"}
    encrypted = aes_encrypt(plaintext, AES_KEY, AES_IV)
    return {"encrypted": encrypted}

@app.post("/decrypt")
def decrypt(data: Dict[str, str]):
    encrypted = data.get("encrypted")
    if not encrypted:
        return {"error": "No encrypted text provided"}
    decrypted = aes_decrypt(encrypted, AES_KEY, AES_IV)
    return {"decrypted": decrypted}
