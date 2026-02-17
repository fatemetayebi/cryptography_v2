import os
import json
from utilities import get_file_header, generate_key_from_password, clean_main_content_in_place, get_private_key
from set_user import app_config
from core.mac import extract_and_verify_mac
from core.signature import verify_file_signature


def decrypt_file(file_path):
    """
    Decrypt a file using the provided key
    Returns path to the decrypted file
    """
    password = app_config.password
    key = generate_key_from_password(password, 16).encode("utf-8")

    print(f"🔓 Starting decryption process...")
    print(f"📁 File: {file_path}")

    try:
        header, header_end, content = extract_nested_header(file_path)
    except (FileNotFoundError, ValueError, json.JSONDecodeError) as e:
        print(f"❌ Error reading file header: {e}")
        raise

    encryption_mode = header.get('algorithm')
    if not encryption_mode:
        # Try alternative keys
        encryption_mode = header.get('encryption_mode') or header.get('mode') or 'AES'
        print(f"⚠️ 'algorithm' key not found, using '{encryption_mode}' instead")

    print(f"🔑 Encryption mode detected: {encryption_mode}")
    print(f"📊 File structure: MAC → Signature → {encryption_mode} Encryption")

    if encryption_mode == 'AES' or encryption_mode == 'DES' or encryption_mode == '3DES':
        decrypt_file_with_symmetric(file_path, key)
    elif encryption_mode == 'SecureEnvelope':
        decrypt_secure_envelope(file_path)

    elif encryption_mode == 'RSA':
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
        decrypted_file = decrypt_RSA(file_path, header)
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