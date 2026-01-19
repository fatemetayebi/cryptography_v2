from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import json
from utilities import USER_FILE_PATH, hash, check_password, get_user_from_file
from cryptography.hazmat.primitives.serialization import PrivateFormat, Encoding, BestAvailableEncryption


def generate_rsa_private_public_keys(password, key_size=2048):

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size
    )
    public_key = private_key.public_key()

    # serialize private key to PEM string
    encryption_algorithm = BestAvailableEncryption(password.encode("utf-8"))

    pem_private = private_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=encryption_algorithm
    ).decode('utf-8')

    # serialize public key too (optional)
    pem_public = public_key.public_bytes(
        encoding = serialization.Encoding.PEM,
        format = serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')

    return pem_private, pem_public



def generate_user_data(username, password):
    private_key, public_key = generate_rsa_private_public_keys(password=password)
    return {
      "username": username,
      "password_hash": hash(password),
      "public_key": public_key,
      "encrypted_private_key": private_key,
    }


def authenticate_user(username, password):
    user_found = get_user_from_file(username)
    file_path = USER_FILE_PATH

    if user_found:
        if check_password(password, user_found["password_hash"]):
            result = {"success":True, "message":"Login successful!"}
        else:
            # print(f'password hash mismatch: {user_found["password_hash"]} != {password}')
            result = {"success": False, "message": "Something went wrong!"}

    else:
        with open(file_path, "r", encoding="utf-8") as file:
            users = json.load(file)
        users.append(generate_user_data(username, password))
        with open(file_path, "w", encoding="utf-8") as file:
            json.dump(users, file, indent=4)

        result = {"success":True, "message":"User created - Login successful!"}

    return result


