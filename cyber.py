import hashlib
import os
from cryptography.fernet import Fernet

# Password Hashing
def hash_password(password):
    """Hash a password using SHA-256"""
    return hashlib.sha256(password.encode()).hexdigest()

# Encryption
def generate_key():
    """Generate a secret key for encryption"""
    return Fernet.generate_key()

def encrypt_data(data, key):
    """Encrypt data using the provided key"""
    cipher_suite = Fernet(key)
    cipher_text = cipher_suite.encrypt(data.encode())
    return cipher_text

def decrypt_data(cipher_text, key):
    """Decrypt data using the provided key"""
    cipher_suite = Fernet(key)
    plain_text = cipher_suite.decrypt(cipher_text)
    return plain_text.decode()

# Secure Data Transfer
def send_data(data, key):
    """Simulate sending encrypted data"""
    encrypted_data = encrypt_data(data, key)
    print("Sending encrypted data:", encrypted_data)
    return encrypted_data

def receive_data(encrypted_data, key):
    """Simulate receiving encrypted data"""
    decrypted_data = decrypt_data(encrypted_data, key)
    print("Received decrypted data:", decrypted_data)

# Main function
def main():
    # Password Hashing
    password = "mysecretpassword"
    hashed_password = hash_password(password)
    print("Hashed Password:", hashed_password)

    # Encryption
    key = generate_key()
    print("Generated Key:", key)

    data = "This is some sensitive data"
    encrypted_data = send_data(data, key)
    receive_data(encrypted_data, key)

if __name__ == "__main__":
    main()