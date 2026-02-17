from utilities import generate_key_from_password, get_public_key
from set_user import app_config
from core.mac import embed_mac_in_file
from core.signature import sign_file
from core.crypto import RSA_encryption, symmetric_encrypt
import os
import json
from datetime import datetime


def encrypt_file_with_RSA(input_file, sender, receiver):
    """
    Encrypt file using RSA (for small files only)
    Returns: path to encrypted file
    """
    receiver_public_key = get_public_key(receiver)

    # Read file content
    with open(input_file, 'rb') as f_in:
        data = f_in.read()

    # Check RSA size limitation
    max_size = (receiver_public_key.key_size // 8) - 66  # For OAEP padding
    if len(data) > max_size:
        raise ValueError(f"File too large for RSA encryption. Max size: {max_size} bytes, Actual: {len(data)} bytes")

    # Encrypt data
    encrypted_data = RSA_encryption(data, receiver_public_key)

    # Create header
    header = {
        'algorithm': 'RSA',
        'sender': sender,
        'receiver': receiver,
        'timestamp': datetime.utcnow().isoformat(),
        'encrypted_data_size': len(encrypted_data),
        'original_size': len(data),
        'key_size': receiver_public_key.key_size
    }

    header_json = json.dumps(header).encode('utf-8')

    # Create output file
    output_file = input_file + '.enc'
    with open(output_file, 'wb') as f_out:
        f_out.write(header_json)
        f_out.write(encrypted_data)

    print(f"✅ RSA encryption successful. Output: {output_file}")
    return output_file



