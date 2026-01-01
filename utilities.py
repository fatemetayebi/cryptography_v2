import os
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import base64
from cryptography.hazmat.primitives import serialization

USER_FOLDER_PATH = folder_path = "users"
file_path = os.path.join(folder_path, "user.json")
USER_FILE_PATH = file_path


def hash(password, salt = None):
    iterations = 1_000_000
    if salt is None:
        salt = base64.b64encode(os.urandom(16)).decode().strip("=")
    dk = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        int(iterations),
    )

    hash_b64 = base64.b64encode(dk).decode("utf-8")

    return f"pbkdf2_sha256${iterations}${salt}${hash_b64}"


def extract_salt(stored_hash):
    algorithm, iterations, salt, digest = stored_hash.split("$")
    return salt


def check_password(plain_password, hashed_password):
    salt = extract_salt(hashed_password)
    if hashed_password == hash(plain_password, salt=salt):
        return True
    else:
        return False


def generate_key_from_password(password, length):
    hashed_password = hashlib.sha1(password.encode()).hexdigest()
    key = hashed_password[:length]
    return key


def generate_rsa_private_public_keys(key_size=2048):
    print('generating rsa private key')

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size
    )
    public_key = private_key.public_key()

    # serialize private key to PEM string
    pem_private = private_key.private_bytes(
        encoding = serialization.Encoding.PEM,
        format = serialization.PrivateFormat.PKCS8,
        encryption_algorithm = serialization.NoEncryption()
    ).decode('utf-8')

    # serialize public key too (optional)
    pem_public = public_key.public_bytes(
        encoding = serialization.Encoding.PEM,
        format = serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')

    return pem_private, pem_public



def AES_encrypt(plaintext, password):
    key = generate_key_from_password(password, 16).encode("utf-8")
    if not isinstance(plaintext, str):
        raise TypeError("plaintext must be a string")
    plaintext_bytes = plaintext.encode('utf-8')
    cipher = AES.new(key, AES.MODE_ECB)
    padded_plaintext = pad(plaintext_bytes, AES.block_size)
    ciphertext_bytes = cipher.encrypt(padded_plaintext)
    ciphertext = base64.b64encode(ciphertext_bytes).decode('utf-8')
    return ciphertext


def AES_decrypt(ciphertext, password):
    key = generate_key_from_password(password, 16).encode("utf-8")
    ciphertext_bytes = ciphertext.encode('utf-8')
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted_bytes = cipher.decrypt(ciphertext_bytes)
    from Crypto.Util.Padding import unpad
    plaintext_bytes = unpad(decrypted_bytes, AES.block_size)
    return plaintext_bytes.decode('utf-8')


def generate_user_data(username, password):
    private_key, public_key = generate_rsa_private_public_keys()
    encrypted_private_key = AES_encrypt(private_key, password)
    return {
      "username": username,
      "password_hash": hash(password),
      "public_key": public_key,
      "encrypted_private_key": encrypted_private_key,
    }


# core/crypto.py

def encrypt_file(file_path, key):
    """
    Encrypt a file using the provided key
    Returns path to the encrypted file
    """
    # TODO: Implement file encryption logic
    # Example implementation:
    # - Read file content
    # - Encrypt the content
    # - Save as new file with .enc extension
    # - Return output file path

    output_path = file_path + ".enc"
    # Your encryption logic here
    return output_path


def decrypt_file(file_path, key):
    """
    Decrypt a file using the provided key
    Returns path to the decrypted file
    """
    # TODO: Implement file decryption logic
    # Example implementation:
    # - Read encrypted file
    # - Decrypt the content
    # - Save as new file without .enc extension
    # - Return output file path

    if file_path.endswith('.enc'):
        output_path = file_path[:-4]  # Remove .enc extension
    else:
        output_path = file_path + ".decrypted"

    # Your decryption logic here
    return output_path


def encrypt_text(text, key):
    """
    Encrypt text using the provided key
    Returns encrypted text as string
    """
    # TODO: Implement text encryption logic
    # Example: Simple XOR encryption (for demonstration only)
    encrypted = ""
    for i, char in enumerate(text):
        key_char = key[i % len(key)]
        encrypted += chr(ord(char) ^ ord(key_char))
    return encrypted


def decrypt_text(encrypted_text, key):
    """
    Decrypt text using the provided key
    Returns decrypted text as string
    """
    # TODO: Implement text decryption logic
    # Example: Simple XOR decryption (same as encryption)
    decrypted = ""
    for i, char in enumerate(encrypted_text):
        key_char = key[i % len(key)]
        decrypted += chr(ord(char) ^ ord(key_char))
    return decrypted
