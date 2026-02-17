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