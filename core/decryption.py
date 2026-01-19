import os
from utilities import get_file_header, generate_key_from_password, clean_main_content_in_place, get_private_key
from set_user import app_config
from core.mac import extract_and_verify_mac
from core.signature import verify_file_signature
from core.crypto import RSA_decryption, symmetric_decrypt


# def decrypt_secure_envelope(input_file):
#     user = app_config.username
#     password = app_config.password
#     if not os.path.exists(input_file):
#         raise FileNotFoundError(f"Encrypted file not found: {input_file}")
#
#     header = get_file_header(input_file)
#     if header['receiver'] != user:
#         raise PermissionError(f"You {user} dont have access to decrypt {input_file}")
#
#     user_private_key = get_private_key(user, password)
#     main_key = RSA_decryption(header['key'], user_private_key)
#
#     with open(input_file, 'rb') as f:
#         content = f.read()
#         end = content.find(b'}')
#
#     encrypted_key = content[end:header['dek_size']]
#     encrypted_data = content[end + header['dek_size']:len(content)]
#     main_key = RSA_decryption(encrypted_key, user_private_key)
#     cipher = Cipher(cipher_algorithm, cipher_mode, backend=default_backend())
#     decryptor = cipher.decryptor()
#
#     # Process file
#     unpadder = padding.PKCS7(cipher_algorithm.block_size).unpadder()
#
#     with open(output_file, 'wb') as f_out:
#         while chunk := f_in.read(4096):
#             decrypted_chunk = decryptor.update(chunk)
#             unpadded_chunk = unpadder.update(decrypted_chunk)
#             f_out.write(unpadded_chunk)
#
#         # Finalize
#         final_decrypted = decryptor.finalize()
#         final_unpadded = unpadder.update(final_decrypted) + unpadder.finalize()
#         f_out.write(final_unpadded)
#
#
#     return output_file
#
#     print("رمزگشایی با موفقیت انجام شد.")


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
        encrypted_data = data[end_of_header+1:len(data)]
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
        print(header)
    except (FileNotFoundError, ValueError) as e:
        print(f"Error: {e}")
    encryption_mode = header['algorithm']
    cipher_mode = header['mode']
    sender = header['sender']
    receiver = header['receiver']
    if encryption_mode == 'AES' or encryption_mode == 'DES' or encryption_mode == '3DES':
        decrypt_file_with_symmetric(file_path, key)

    # if encryption_mode == 'SecureEnvelop':

    if file_path.endswith('.enc'):
        file_path = file_path[:-4]  # Remove .enc extension

    mac_result = extract_and_verify_mac(file_path, key)
    sign_result = verify_file_signature(file_path)
    clean_main_content_in_place(file_path)

    if not mac_result['is_valid'] or not sign_result['is_valid']:
        raise Exception("mac or signature verification failed")

    print(f'mac_result: {mac_result}, sign_result: {sign_result}')

    return file_path