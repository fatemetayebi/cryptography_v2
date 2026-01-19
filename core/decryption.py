import os
import json
from utilities import get_file_header, generate_key_from_password, clean_main_content_in_place, get_private_key
from set_user import app_config
from core.mac import extract_and_verify_mac
from core.signature import verify_file_signature
from core.crypto import RSA_decryption, symmetric_decrypt


def decrypt_secure_envelope(input_file):
    user = app_config.username
    password = app_config.password

    if not os.path.exists(input_file):
        raise FileNotFoundError(f"Encrypted file not found: {input_file}")

    # Read header
    header = get_file_header(input_file)
    print(f'receiver: {header["receiver"]}, user: {user}')

    if header['receiver'] != user:
        raise PermissionError(f"You ({user}) don't have permission to decrypt {input_file}")

    # Read entire file
    with open(input_file, 'rb') as f:
        content = f.read()

    # Find end of JSON header
    try:
        # Find the first closing brace
        header_end = content.find(b'}') + 1

        # Read header accurately
        header_json = content[:header_end]
        header = json.loads(header_json.decode('utf-8'))

        # Read wrapped DEK
        wrapped_dek_start = header_end
        wrapped_dek_end = wrapped_dek_start + header['dek_size']
        wrapped_dek = content[wrapped_dek_start:wrapped_dek_end]

        # Read encrypted data
        encrypted_data_start = wrapped_dek_end
        encrypted_data = content[encrypted_data_start:]

    except Exception as e:
        raise ValueError(f"Error parsing encrypted file: {str(e)}")

    # Decrypt DEK
    user_private_key = get_private_key(user, password)
    main_key = RSA_decryption(wrapped_dek, user_private_key)

    # Decrypt main data
    algorithm = 'AES'
    mode = 'CBC'

    try:
        main_data = symmetric_decrypt(encrypted_data, main_key, algorithm, mode)
    except Exception as e:
        raise ValueError(f"Decryption failed: {str(e)}")

    # Create output file (different name)
    output_file = input_file
    with open(output_file, 'wb') as f_out:
        f_out.write(main_data)

    print(f"File decrypted successfully to: {output_file}")
    print(f"Original file preserved: {input_file}")
    return output_file


def decrypt_file_with_symmetric(encrypted_file, key):
    if not encrypted_file.endswith('.enc'):
        raise ValueError("File must have .enc extension")

    if not os.path.exists(encrypted_file):
        raise FileNotFoundError(f"Encrypted file not found: {encrypted_file}")

    output_file = encrypted_file[:-4]  # Remove .enc extension
    header = get_file_header(encrypted_file)
    mode_name = header['mode']

    with open(encrypted_file, 'rb') as f_in:
        data = f_in.read()
        end_of_header = data.find(b'}')
        encrypted_data = data[end_of_header + 1:len(data)]
        decrypted_data = symmetric_decrypt(
            encrypted_data=encrypted_data,
            key=key,
            algorithm=header['algorithm'].upper(),
            mode=mode_name
        )

        if header['original_size'] != len(decrypted_data):
            print(
                f"Warning: Decrypted size ({len(decrypted_data)}) does not match original size ({header['original_size']}).")

    with open(output_file, 'wb') as f_out:
        f_out.write(decrypted_data)

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
    except (FileNotFoundError, ValueError) as e:
        print(f"Error: {e}")

    encryption_mode = header['algorithm']
    print(f'encryption_mode: {encryption_mode}')

    if encryption_mode == 'AES' or encryption_mode == 'DES' or encryption_mode == '3DES':
        decrypt_file_with_symmetric(file_path, key)
    elif encryption_mode == 'SecureEnvelope':
        decrypt_secure_envelope(file_path)

    if file_path.endswith('.enc'):
        file_path = file_path[:-4]  # Remove .enc extension

    mac_result = extract_and_verify_mac(file_path, key)
    sign_result = verify_file_signature(file_path)
    print(f'mac_result: {mac_result}, sign_result: {sign_result}')

    if not mac_result['is_valid'] or not sign_result['is_valid']:
        raise Exception("MAC or signature verification failed")
    else:
        clean_main_content_in_place(file_path, mac_result)


    return file_path