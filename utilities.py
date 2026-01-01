import hashlib
import base64
import os


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


import hashlib


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



