from cryptography.hazmat.primitives.asymmetric import rsa
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import base64
from cryptography.hazmat.primitives import serialization
import os
import json
from utilities import USER_FILE_PATH, USER_FOLDER_PATH, hash, generate_key_from_password, check_password



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


def authenticate_user(username, password):
    file_path = USER_FILE_PATH
    folder_path = USER_FOLDER_PATH
    if not os.path.exists(folder_path):
        os.makedirs(folder_path)
        print(f"Folder '{folder_path}' created.")

    if not os.path.exists(file_path):
        initial_data = []
        with open(file_path, "w", encoding="utf-8") as file:
            json.dump(initial_data, file, indent=4)
        print(f"File '{file_path}' created with initial empty list.")

    with open(file_path, "r", encoding="utf-8") as file:
        users = json.load(file)

    user_found = None
    for user in users:
        if user["username"] == username:
            user_found = user
            break

    if user_found:
        if check_password(password, user_found["password_hash"]):
            result = {"success":True, "message":"Login successful!"}
        else:
            print(f'password hash mismatch: {user_found["password_hash"]} != {password}')
            result = {"success": False, "message": "Something went wrong!"}

    else:
        users.append(generate_user_data(username, password))
        with open(file_path, "w", encoding="utf-8") as file:
            json.dump(users, file, indent=4)

        result = {"success":True, "message":"User created - Login successful!"}

    return result


