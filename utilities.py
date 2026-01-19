import hashlib
import base64
import os
import tempfile
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import json
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from cryptography.hazmat.primitives.ciphers import Cipher, modes, algorithms as AES_algorithm
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

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



def AES_encrypt(plaintext, key):
    if not isinstance(plaintext, str):
        raise TypeError("plaintext must be a string")
    plaintext_bytes = plaintext.encode('utf-8')
    cipher = AES.new(key, AES.MODE_ECB)
    padded_plaintext = pad(plaintext_bytes, AES.block_size)
    ciphertext_bytes = cipher.encrypt(padded_plaintext)
    ciphertext = base64.b64encode(ciphertext_bytes).decode('utf-8')
    return ciphertext


def AES_decrypt(ciphertext, key, iv):
    cipher_algorithm = {
        'AES': AES_algorithm.AES(key),
    }.get('AES'.upper())

    algorithm_upper = 'AES'

    cipher_mode = {
        'CBC': modes.CBC(iv),
        'CFB': modes.CFB(iv),
        'CTR': modes.CTR(iv)
    }.get('CBC'.upper())

    cipher = Cipher(cipher_algorithm, cipher_mode, backend=default_backend())
    decryptor = cipher.decryptor()

    # Process file
    unpadder = padding.PKCS7(cipher_algorithm.block_size).unpadder()
    final_decrypted = decryptor.finalize()
    final_unpadded = unpadder.update(final_decrypted) + unpadder.finalize()
    return final_unpadded


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



def get_public_key(username):
    user = get_user_from_file(username)
    public_key_pem = user.get("public_key")

    # PEM is plain text → encode to bytes
    pem_bytes = public_key_pem.encode("utf-8")

    public_key = load_pem_public_key(pem_bytes)
    print(f"Private key loaded OK: {public_key}")
    return public_key



import json

def get_file_header(filename):
    header = ""
    with open(filename, 'rb') as f:
        content = f.read()
        start = content.find(b'{')
        end = content.find(b'}')
        json_data = content[start:end + 1]
        header = json.loads(json_data.decode('utf-8'))
        return header




def clean_main_content_in_place(filename):

    content_separator = b'---CONTENT_SEPARATOR---'
    mac_separator = b'---MAC_SEPARATOR---'

    with open(filename, 'rb') as f:
        full_data = f.read()

    mac_separator_pos = full_data.find(mac_separator)
    if mac_separator_pos == -1:
        raise ValueError("جداکننده MAC یافت نشد.")

    content_separator_pos = full_data.find(content_separator, mac_separator_pos)
    if content_separator_pos == -1:
        raise ValueError("جداکننده محتوا یافت نشد.")

    start_of_content = content_separator_pos + len(content_separator)
    main_content = full_data[start_of_content:len(full_data)]

    # ۳. بازنویسی فایل اصلی با محتوای تمیز شده (استفاده از فایل موقت برای ایمنی)
    temp_file_descriptor, temp_filename = tempfile.mkstemp()

    try:
        with os.fdopen(temp_file_descriptor, 'wb') as tmp_f:
            tmp_f.write(main_content)

        # جایگزینی فایل اصلی با فایل موقت
        os.replace(temp_filename, filename)

    except Exception as e:
        # اگر مشکلی در نوشتن پیش آمد، فایل موقت را پاک کن
        os.remove(temp_filename)
        raise Exception(f"خطا در بازنویسی فایل: {str(e)}")

