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


