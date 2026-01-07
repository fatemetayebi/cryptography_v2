import hashlib
import base64
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import json
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key


USER_FOLDER_PATH = folder_path = "users"
file_path = os.path.join(folder_path, "user.json")
USER_FILE_PATH = file_path


def get_user_from_file(username):
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
        return user_found

    else:
        return None


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
    print(f'password: {password}, length: {length}')
    """
    Generate a key from password using SHA1 hash

    Args:
        password: String password
        length: Desired key length (1-40 for SHA1 hex)

    Returns:
        Hexadecimal key string of specified length
    """
    # Validation
    if password is None:
        raise ValueError("Password cannot be None")

    if not isinstance(password, str):
        raise TypeError("Password must be a string")

    if length <= 0 or length > 40:
        raise ValueError("Length must be between 1 and 40")

    try:
        # Hash the password
        hashed_password = hashlib.sha1(password.encode()).hexdigest()

        # Extract the key
        key = hashed_password[:length]

        return key

    except Exception as e:
        raise RuntimeError(f"Key generation failed: {str(e)}")



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


def get_private_key(username, password):
    user = get_user_from_file(username)
    encrypted_private_key_pem = user.get("encrypted_private_key")

    # PEM is plain text → encode to bytes
    pem_bytes = encrypted_private_key_pem.encode("utf-8")

    private_key = load_pem_private_key(
        pem_bytes,
        password=password.encode("utf-8") if password else None,
    )
    print(f"Private key loaded OK: {private_key}")
    return private_key



def get_public_key(user):
    pass

