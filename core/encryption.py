
from cryptography.hazmat.primitives.ciphers import Cipher, modes, algorithms as AES_algorithm
from cryptography.hazmat.decrepit.ciphers import algorithms

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os
import json
from datetime import datetime
from utilities import generate_key_from_password
from set_user import app_config
from .mac import embed_mac_in_file
from .signature import sign_file


def encrypt_file_with_symmetric(input_file, key, algorithm, mode, sender, receiver):
    # Parameter validation
    if not os.path.exists(input_file):
        raise FileNotFoundError(f"Input file not found: {input_file}")

    if len(key) not in [16, 24, 32] and algorithm == 'AES':
        raise ValueError("Key must be 16, 24, or 32 bytes for AES")

    # Create custom header
    header = {
        'algorithm': algorithm,
        'mode': mode,
        'sender': sender,
        'receiver': receiver,
        'timestamp': datetime.utcnow().isoformat(),
        'original_size': os.path.getsize(input_file)
    }

    # Convert header to bytes
    header_json = json.dumps(header).encode('utf-8')
    header_length = len(header_json).to_bytes(4, byteorder='big')

    # Select algorithm and mode
    cipher_algorithm = {
        'AES': AES_algorithm.AES(key),
        'DES': algorithms.TripleDES(key),  # Using TripleDES as an example
        '3DES': algorithms.TripleDES(key)
    }.get(algorithm.upper())

    if cipher_algorithm is None:
        raise ValueError(f"Unsupported algorithm: {algorithm}")

    # Select encryption mode
    iv = key[:16]
    cipher_mode = {
        'CBC': modes.CBC(iv),
        'CFB': modes.CFB(iv),
        'OFB': modes.OFB(iv),
        'CTR': modes.CTR(iv)
    }.get(mode.upper())

    if cipher_mode is None:
        raise ValueError(f"Unsupported encryption mode: {mode}")

    # Create cipher
    cipher = Cipher(cipher_algorithm, cipher_mode, backend=default_backend())
    encryptor = cipher.encryptor()

    # Process the file
    padder = padding.PKCS7(cipher_algorithm.block_size).padder()

    with open(input_file, 'rb') as f_in, open(input_file + '.enc', 'wb') as f_out:
        # Write header (header length + header itself)
        f_out.write(header_length)
        f_out.write(header_json)
        f_out.write(iv)  # Write IV

        # Encrypt and write data
        while chunk := f_in.read(4096):
            padded_chunk = padder.update(chunk)
            encrypted_chunk = encryptor.update(padded_chunk)
            f_out.write(encrypted_chunk)

        # Write final block
        final_padded = padder.finalize()
        final_encrypted = encryptor.update(final_padded) + encryptor.finalize()
        f_out.write(final_encrypted)


def encrypt_file(file_path, encryption_mode, cipher_mode, target_user, mac_mode = None):
    """
    Encrypt a file using the provided key
    Returns path to the encrypted file
    """
    username = app_config.username
    password = app_config.password
    key = generate_key_from_password(password, 16).encode("utf-8")
    embed_mac_in_file(file_path, mac_mode, key, file_path)
    sign_file(file_path)
    if encryption_mode == 'AES' or encryption_mode == 'DES' or encryption_mode == '3DES':
        encrypt_file_with_symmetric(file_path, key, encryption_mode, cipher_mode, username, target_user)


    output_path = file_path + ".enc"
    # Your encryption logic here
    return output_path
