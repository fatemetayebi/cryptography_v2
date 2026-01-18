
from cryptography.hazmat.primitives.ciphers import Cipher, modes, algorithms as AES_algorithm
from cryptography.hazmat.decrepit.ciphers import algorithms
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os
import json
from utilities import get_file_header, generate_key_from_password
from set_user import app_config
from .mac import extract_and_verify_mac


def decrypt_file_with_symmetric(encrypted_file: str, key: bytes):

    if not encrypted_file.endswith('.enc'):
        raise ValueError("File must have .enc extension")

    if not os.path.exists(encrypted_file):
        raise FileNotFoundError(f"Encrypted file not found: {encrypted_file}")

    output_file = encrypted_file[:-4]  # Remove .enc extension

    with open(encrypted_file, 'rb') as f_in:
        # Read header
        header_length = int.from_bytes(f_in.read(4), byteorder='big')
        header_json = f_in.read(header_length)
        iv = f_in.read(16)  # Read IV

        try:
            header = json.loads(header_json.decode('utf-8'))
        except json.JSONDecodeError:
            raise ValueError("Invalid header format")

        # Validate header
        required_keys = {'algorithm', 'mode', 'original_size'}
        if not required_keys.issubset(header.keys()):
            raise ValueError("Missing required header fields")

        # Select algorithm and mode
        cipher_algorithm = {
            'AES': AES_algorithm.AES(key),
            'DES': algorithms.TripleDES(key),
            '3DES': algorithms.TripleDES(key)
        }.get(header['algorithm'].upper())

        cipher_mode = {
            'CBC': modes.CBC(iv),
            'CFB': modes.CFB(iv),
            'OFB': modes.OFB(iv),
            'CTR': modes.CTR(iv)
        }.get(header['mode'].upper())

        if cipher_algorithm is None or cipher_mode is None:
            raise ValueError("Unsupported algorithm or mode in header")

        # Create cipher
        cipher = Cipher(cipher_algorithm, cipher_mode, backend=default_backend())
        decryptor = cipher.decryptor()

        # Process file
        unpadder = padding.PKCS7(cipher_algorithm.block_size).unpadder()

        with open(output_file, 'wb') as f_out:
            while chunk := f_in.read(4096):
                decrypted_chunk = decryptor.update(chunk)
                unpadded_chunk = unpadder.update(decrypted_chunk)
                f_out.write(unpadded_chunk)

            # Finalize
            final_decrypted = decryptor.finalize()
            final_unpadded = unpadder.update(final_decrypted) + unpadder.finalize()
            f_out.write(final_unpadded)

    return output_file


def decrypt_file(file_path):
    """
    Decrypt a file using the provided key
    Returns path to the decrypted file
    """
    password = app_config.password
    key = generate_key_from_password(password, 16).encode("utf-8")
    try:
        header = get_file_header(file_path)
        print(header)
    except (FileNotFoundError, ValueError) as e:
        print(f"Error: {e}")
    encryption_mode = header['algorithm']
    cipher_mode = header['mode']
    sender = header['sender']
    receiver = header['receiver']
    if encryption_mode == 'AES' or encryption_mode == 'DES' or encryption_mode == '3DES':
        decrypt_file_with_symmetric(file_path, key)

    if file_path.endswith('.enc'):
        output_path = file_path[:-4]  # Remove .enc extension
    else:
        output_path = file_path + ".decrypted"

    result = extract_and_verify_mac(output_path, key)
    print(f'result: {result}')

    return output_path