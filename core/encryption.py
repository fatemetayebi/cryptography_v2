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


def encrypt_file_with_secure_envelope(input_file, sender, receiver, key):
    """
    Encrypt file using Secure Envelope (RSA + AES)
    """
    if not os.path.exists(input_file):
        raise FileNotFoundError(f"Input file not found: {input_file}")

    # Generate random DEK (Data Encryption Key)
    import secrets
    dek = secrets.token_bytes(32)  # 256-bit key for AES

    # Encrypt DEK with RSA
    receiver_public_key = get_public_key(receiver)
    wrapped_dek = RSA_encryption(dek, receiver_public_key)

    # Encrypt data with AES
    algorithm = 'AES'
    mode = 'CBC'

    with open(input_file, 'rb') as f_in:
        data = f_in.read()
        encrypted_data = symmetric_encrypt(data, dek, algorithm, mode)

    # Create header
    header = {
        'encryption_scheme': 'SECURE_ENVELOPE_AES256_RSA2048',
        'algorithm': 'SecureEnvelop',
        'sender': sender,
        'receiver': receiver,
        'timestamp': datetime.utcnow().isoformat(),
        'encrypted_data_size': len(encrypted_data),
        'dek_size': len(wrapped_dek),
        'original_size': len(data),
        'symmetric_algorithm': algorithm,
        'symmetric_mode': mode
    }

    header_json = json.dumps(header).encode('utf-8')

    # Create output file
    output_file = input_file + '.enc'
    with open(output_file, 'wb') as f_out:
        f_out.write(header_json)
        f_out.write(wrapped_dek)
        f_out.write(encrypted_data)

    print(f"✅ Secure Envelope encryption successful. Output: {output_file}")
    print(f"📦 Encrypted DEK Size: {len(wrapped_dek)} bytes")
    return output_file


def encrypt_file_with_symmetric(input_file, key, algorithm, mode, sender, receiver):
    """
    Encrypt file using symmetric encryption
    """
    if not os.path.exists(input_file):
        raise FileNotFoundError(f"Input file not found: {input_file}")

    # Create header
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

    # Read and encrypt file
    with open(input_file, 'rb') as f_in:
        file_contents = f_in.read()

    encrypted_payload = symmetric_encrypt(file_contents, key, algorithm, mode)

    # Write encrypted file
    output_file = input_file + '.enc'
    with open(output_file, 'wb') as f_out:
        f_out.write(header_json)
        f_out.write(encrypted_payload)

    print(f"✅ {algorithm} encryption successful. Output: {output_file}")
    return output_file


def encrypt_file(file_path, encryption_mode, cipher_mode, receiver, mac_mode=None):
    """
    Main encryption function with correct order: Encrypt → Sign → MAC
    """
    sender = app_config.username
    password = app_config.password
    key = generate_key_from_password(password, 16).encode("utf-8")

    print(f"🔐 Starting encryption process...")
    print(f"📁 File: {file_path}")
    print(f"🔑 Algorithm: {encryption_mode}")
    print(f"👤 Sender: {sender}, Receiver: {receiver}")

    # Step 1: Encrypt the file
    if encryption_mode == 'RSA':
        encrypted_file = encrypt_file_with_RSA(file_path, sender, receiver)
    elif encryption_mode == 'SecureEnvelop':
        encrypted_file = encrypt_file_with_secure_envelope(file_path, sender, receiver, key)
    elif encryption_mode in ['AES', 'DES', '3DES']:
        encrypted_file = encrypt_file_with_symmetric(file_path, key, encryption_mode, cipher_mode, sender, receiver)
    else:
        raise ValueError(f"Unsupported encryption mode: {encryption_mode}")

    print(f"✅ Step 1: Encryption completed -> {encrypted_file}")

    # Step 2: Sign the encrypted file
    signed_file = sign_file(encrypted_file)
    print(f"✅ Step 2: Signature added -> {signed_file}")

    # Step 3: Add MAC to the signed file
    if mac_mode:
        final_file = embed_mac_in_file(signed_file, mac_mode, key, signed_file)
        print(f"✅ Step 3: MAC added -> {final_file}")
    else:
        final_file = signed_file
        print(f"⚠️ Step 3: No MAC mode specified, skipping MAC")

    print(f"🎉 Encryption process completed successfully!")
    print(f"📊 Final file: {final_file}")

    return final_file
