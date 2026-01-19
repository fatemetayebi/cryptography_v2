from utilities import generate_key_from_password, AES_encrypt, get_public_key
from set_user import app_config
from core.mac import embed_mac_in_file
from core.signature import sign_file
from core.crypto import RSA_encryption, symmetric_encrypt
import os
import json
from datetime import datetime


def encrypt_file_with_secure_envelope(input_file, sender, receiver, key):

    if not os.path.exists(input_file):
        raise FileNotFoundError(f"Input file not found: {input_file}")

    dek = key
    receiver_public_key = get_public_key(receiver)
    wrapped_dek = RSA_encryption(dek, receiver_public_key)

    with open(input_file, 'rb') as f_in:
        data = f_in.read()
        encrypted_data = AES_encrypt(data, key)

    header = {
        'encryption_scheme': 'SECURE_ENVELOPE_AES256_RSA2048',
        'algorithm': 'AES',
        'sender': sender,
        'receiver': receiver,
        'timestamp': datetime.utcnow().isoformat(),
        'encrypted_data_size': len(encrypted_data),
        'dek_size': len(wrapped_dek),
    }

    header_json = json.dumps(header).encode('utf-8')

    output_file = input_file + '.enc_secure'
    with open(output_file, 'wb') as f_out:
        f_out.write(header_json)
        f_out.write(wrapped_dek)
        f_out.write(encrypted_data)
    print(f"File encrypted successfully to: {output_file}")
    print(f"Encrypted DEK Size: {len(wrapped_dek)} bytes")


def encrypt_file_with_symmetric(input_file, key, algorithm, mode, sender, receiver):

    if not os.path.exists(input_file):
        raise FileNotFoundError(f"Input file not found: {input_file}")

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

    with open(input_file, 'rb') as f_in:
        file_contents = f_in.read()

    encrypted_payload = symmetric_encrypt(file_contents, key, algorithm, mode)
    with open(input_file, 'rb') as f_in, open(input_file + '.enc', 'wb') as f_out:
        f_out.write(header_json)
        f_out.write(encrypted_payload)



def encrypt_file(file_path, encryption_mode, cipher_mode, receiver, mac_mode = None):
    """
    Encrypt a file using the provided key
    Returns path to the encrypted file
    """
    sender = username = app_config.username
    password = app_config.password
    key = generate_key_from_password(password, 16).encode("utf-8")
    embed_mac_in_file(file_path, mac_mode, key, file_path)
    sign_file(file_path)

    if encryption_mode == 'AES' or encryption_mode == 'DES' or encryption_mode == '3DES':
        encrypt_file_with_symmetric(file_path, key, encryption_mode, cipher_mode, username, receiver)

    if encryption_mode == 'SecureEnvelop':
        encrypt_file_with_secure_envelope(file_path, sender, receiver, key)


    output_path = file_path + ".enc"
    # Your encryption logic here
    return output_path
