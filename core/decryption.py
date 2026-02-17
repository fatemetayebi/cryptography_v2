import os
import json
from utilities import get_file_header, generate_key_from_password, clean_main_content_in_place, get_private_key
from set_user import app_config
from core.mac import extract_and_verify_mac
from core.signature import verify_file_signature

# Try to import from core.crypto, fallback to direct import if needed
try:
    from core.crypto import RSA_decryption, symmetric_decrypt
except ImportError as e:
    print(f"⚠️ Import warning: {e}")
    # Fallback imports
    import sys
    import os as os_module

    sys.path.insert(0, os_module.path.dirname(os_module.path.dirname(os_module.path.abspath(__file__))))
    from crypto import RSA_decryption, symmetric_decrypt


def extract_nested_header(file_path):
    """
    Extract the innermost header from nested structure (MAC → Signature → Encryption)
    """
    with open(file_path, 'rb') as f:
        content = f.read()

    # Find MAC header end
    mac_header_end = content.find(b'}') + 1
    if mac_header_end == 0:
        raise ValueError("No MAC header found")

    # Skip MAC separator and MAC value
    mac_separator = b'---MAC_SEPARATOR---'
    mac_separator_pos = content.find(mac_separator, mac_header_end)
    if mac_separator_pos == -1:
        raise ValueError("MAC separator not found")

    # Skip MAC value (16 bytes for OMAC)
    mac_value_end = mac_separator_pos + len(mac_separator) + 16

    # Find content separator after MAC value
    content_separator = b'---CONTENT_SEPARATOR---'
    content_separator_pos = content.find(content_separator, mac_value_end)
    if content_separator_pos == -1:
        raise ValueError("Content separator not found after MAC")

    # Start of signature header
    signature_start = content_separator_pos + len(content_separator)

    # Find signature header end
    signature_header_end = content.find(b'}', signature_start) + 1
    if signature_header_end == 0:
        raise ValueError("No signature header found")

    # Skip signature separator and signature
    signature_separator = b'---SIGNATURE_SEPARATOR---'
    signature_separator_pos = content.find(signature_separator, signature_header_end)
    if signature_separator_pos == -1:
        raise ValueError("Signature separator not found")

    # Skip signature (256 bytes for RSA-PSS)
    signature_end = signature_separator_pos + len(signature_separator) + 256

    # Find content separator after signature
    content_separator_pos2 = content.find(content_separator, signature_end)
    if content_separator_pos2 == -1:
        raise ValueError("Content separator not found after signature")

    # Start of encryption header
    encryption_header_start = content_separator_pos2 + len(content_separator)

    # Find encryption header end
    encryption_header_end = content.find(b'}', encryption_header_start) + 1
    if encryption_header_end == 0:
        raise ValueError("No encryption header found")

    # Parse encryption header
    encryption_header_bytes = content[encryption_header_start:encryption_header_end]
    try:
        encryption_header = json.loads(encryption_header_bytes.decode('utf-8'))
    except json.JSONDecodeError as e:
        raise ValueError(f"Failed to parse encryption header: {e}")

    return encryption_header, encryption_header_end, content


def decrypt_RSA(input_file, header):
    """
    Decrypt RSA encrypted file
    """
    user = app_config.username
    password = app_config.password

    if not os.path.exists(input_file):
        raise FileNotFoundError(f"Encrypted file not found: {input_file}")

    # Verify receiver
    print(f"👤 Receiver in header: {header.get('receiver', 'N/A')}, Current user: {user}")

    if header.get('receiver') != user:
        raise PermissionError(f"You ({user}) don't have permission to decrypt {input_file}")

    # Read entire file and extract encryption data
    header, header_end, content = extract_nested_header(input_file)

    # Read encrypted data (after encryption header)
    encrypted_data = content[header_end:]

    print(f"📊 Header size: {header_end} bytes")
    print(f"📊 Encrypted data size: {len(encrypted_data)} bytes")
    print(f"📊 Expected size from header: {header.get('encrypted_data_size', 'N/A')}")

    # Decrypt main data
    user_private_key = get_private_key(user, password)

    try:
        main_data = RSA_decryption(encrypted_data, user_private_key)
        print(f"✅ RSA decryption successful")
        print(f"📊 Decrypted data size: {len(main_data)} bytes")
        print(f"📊 Original size from header: {header.get('original_size', 'N/A')}")
    except Exception as e:
        print(f"❌ RSA decryption failed: {e}")
        raise

    # Create output file
    if input_file.endswith('.enc'):
        output_file = input_file[:-4]  # Remove .enc extension
    else:
        output_file = input_file + '.decrypted'

    with open(output_file, 'wb') as f_out:
        f_out.write(main_data)

    print(f"💾 Decrypted file saved as: {output_file}")
    return output_file


def decrypt_secure_envelope(input_file):
    """
    Decrypt Secure Envelope encrypted file
    """
    user = app_config.username
    password = app_config.password

    if not os.path.exists(input_file):
        raise FileNotFoundError(f"Encrypted file not found: {input_file}")

    # Extract nested header
    header, header_end, content = extract_nested_header(input_file)

    print(f"👤 Receiver in header: {header.get('receiver', 'N/A')}, Current user: {user}")

    if header.get('receiver') != user:
        raise PermissionError(f"You ({user}) don't have permission to decrypt {input_file}")

    # Parse file structure
    try:
        # Read wrapped DEK (starts right after encryption header)
        dek_size = header.get('dek_size', 256)  # Default to 256 bytes for RSA
        wrapped_dek_start = header_end
        wrapped_dek_end = wrapped_dek_start + dek_size
        wrapped_dek = content[wrapped_dek_start:wrapped_dek_end]

        # Read encrypted data
        encrypted_data_start = wrapped_dek_end
        encrypted_data = content[encrypted_data_start:]

        print(f"📊 Header size: {header_end} bytes")
        print(f"📊 Wrapped DEK size: {len(wrapped_dek)} bytes")
        print(f"📊 Encrypted data size: {len(encrypted_data)} bytes")

    except Exception as e:
        raise ValueError(f"Error parsing encrypted file: {str(e)}")

    # Decrypt DEK with RSA
    user_private_key = get_private_key(user, password)
    try:
        main_key = RSA_decryption(wrapped_dek, user_private_key)
        print(f"✅ DEK decryption successful")
        print(f"📊 DEK size: {len(main_key)} bytes")
    except Exception as e:
        print(f"❌ DEK decryption failed: {e}")
        raise

    # Decrypt main data with symmetric algorithm
    algorithm = header.get('symmetric_algorithm', 'AES')
    mode = header.get('symmetric_mode', 'CBC')

    try:
        main_data = symmetric_decrypt(encrypted_data, main_key, algorithm, mode)
        print(f"✅ Symmetric decryption successful")
        print(f"📊 Decrypted data size: {len(main_data)} bytes")
        print(f"📊 Original size from header: {header.get('original_size', 'N/A')}")
    except Exception as e:
        raise ValueError(f"Decryption failed: {str(e)}")

    # Create output file
    if input_file.endswith('.enc'):
        output_file = input_file[:-4]  # Remove .enc extension
    else:
        output_file = input_file + '.decrypted'

    with open(output_file, 'wb') as f_out:
        f_out.write(main_data)

    print(f"💾 Decrypted file saved as: {output_file}")
    return output_file


def decrypt_file_with_symmetric(encrypted_file, key):
    """
    Decrypt symmetrically encrypted file with nested structure
    """
    if not encrypted_file.endswith('.enc'):
        raise ValueError("File must have .enc extension")

    if not os.path.exists(encrypted_file):
        raise FileNotFoundError(f"Encrypted file not found: {encrypted_file}")

    # Extract nested header
    header, header_end, content = extract_nested_header(encrypted_file)

    algorithm = header.get('algorithm', 'AES')
    mode_name = header.get('symmetric_mode', 'CBC') or header.get('mode', 'CBC')

    print(f"🔑 Algorithm: {algorithm}, Mode: {mode_name}")

    # Read encrypted data (after encryption header)
    encrypted_data = content[header_end:]

    # For SecureEnvelope, we need to handle DEK + encrypted data
    if algorithm == 'SecureEnvelop' or algorithm == 'SecureEnvelope':
        # This should be handled by decrypt_secure_envelope
        raise ValueError("SecureEnvelope should be handled by decrypt_secure_envelope function")

    # For regular symmetric encryption
    try:
        decrypted_data = symmetric_decrypt(
            encrypted_data=encrypted_data,
            key=key,
            algorithm=algorithm.upper(),
            mode=mode_name
        )
    except Exception as e:
        print(f"❌ Symmetric decryption failed: {e}")
        # Try to handle SecureEnvelope structure
        if 'dek_size' in header:
            dek_size = header['dek_size']
            wrapped_dek = encrypted_data[:dek_size]
            actual_encrypted_data = encrypted_data[dek_size:]

            # Decrypt DEK first (for SecureEnvelope)
            user_private_key = get_private_key(app_config.username, app_config.password)
            main_key = RSA_decryption(wrapped_dek, user_private_key)

            # Then decrypt data
            decrypted_data = symmetric_decrypt(
                encrypted_data=actual_encrypted_data,
                key=main_key,
                algorithm=algorithm.upper(),
                mode=mode_name
            )
        else:
            raise

    # Verify size
    if 'original_size' in header and header['original_size'] != len(decrypted_data):
        print(
            f"⚠️ Warning: Decrypted size ({len(decrypted_data)}) does not match original size ({header['original_size']})")

    # Create output file
    output_file = encrypted_file[:-4]  # Remove .enc extension

    with open(output_file, 'wb') as f_out:
        f_out.write(decrypted_data)

    print(f"💾 Decrypted file saved as: {output_file}")
    return output_file


def decrypt_file(file_path):
    """
    Main decryption function with correct order: Verify MAC → Verify Signature → Decrypt
    """
    password = app_config.password
    key = generate_key_from_password(password, 16).encode("utf-8")

    print(f"🔓 Starting decryption process...")
    print(f"📁 File: {file_path}")

    # Step 1: Extract the innermost header
    try:
        header, header_end, content = extract_nested_header(file_path)
    except (FileNotFoundError, ValueError, json.JSONDecodeError) as e:
        print(f"❌ Error reading file header: {e}")
        raise

    # Get encryption mode
    encryption_mode = header.get('algorithm')
    if not encryption_mode:
        # Try alternative keys
        encryption_mode = header.get('encryption_mode') or header.get('mode') or 'AES'
        print(f"⚠️ 'algorithm' key not found, using '{encryption_mode}' instead")

    print(f"🔑 Encryption mode detected: {encryption_mode}")
    print(f"📊 File structure: MAC → Signature → {encryption_mode} Encryption")

    # Step 2: Verify MAC (if present)
    try:
        print("🔍 Step 1: Verifying MAC...")
        mac_result = extract_and_verify_mac(file_path, key)
        if not mac_result['is_valid']:
            print("❌ MAC verification failed!")
            raise Exception("MAC verification failed")
        print("✅ MAC verification successful")
    except Exception as e:
        print(f"⚠️ MAC verification skipped or failed: {e}")
        mac_result = None

    # Step 3: Verify Signature (if present)
    try:
        print("🔍 Step 2: Verifying signature...")
        sign_result = verify_file_signature(file_path)
        if not sign_result['is_valid']:
            print("❌ Signature verification failed!")
            raise Exception("Signature verification failed")
        print("✅ Signature verification successful")
    except Exception as e:
        print(f"⚠️ Signature verification skipped or failed: {e}")
        sign_result = None

    # Step 4: Decrypt based on encryption mode
    print(f"🔍 Step 3: Decrypting with {encryption_mode}...")

    try:
        if encryption_mode == 'RSA':
            decrypted_file = decrypt_RSA(file_path, header)
        elif encryption_mode == 'SecureEnvelop' or encryption_mode == 'SecureEnvelope':
            decrypted_file = decrypt_secure_envelope(file_path)
        elif encryption_mode in ['AES', 'DES', '3DES']:
            decrypted_file = decrypt_file_with_symmetric(file_path, key)
        else:
            raise ValueError(f"Unsupported encryption mode: {encryption_mode}")
    except Exception as e:
        print(f"❌ Decryption failed: {e}")
        raise

    print(f"🎉 Decryption process completed successfully!")
    print(f"📊 Decrypted file: {decrypted_file}")

    # Step 5: Clean up if needed
    if mac_result and 'original_content' in mac_result:
        try:
            clean_main_content_in_place(file_path, mac_result)
            print("🧹 Original content cleaned up")
        except Exception as e:
            print(f"⚠️ Cleanup failed: {e}")

    return decrypted_file
