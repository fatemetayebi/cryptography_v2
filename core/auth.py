import os
import json
import hashlib
from django.db.models.expressions import result
from utilities import USER_FILE_PATH, USER_FOLDER_PATH, hash, generate_user_data


def authenticate_user(username, password):
    result = []
    file_path = USER_FILE_PATH
    folder_path = USER_FOLDER_PATH
    if not os.path.exists(folder_path):
        os.makedirs(folder_path)
        print(f"Folder '{folder_path}' created.")

    if not os.path.exists(file_path):
        initial_data = []
        with open(file_path, "w", encoding="utf-8") as file:
            json.dump(initial_data, file, indent=4)
        print(f"File '{file_path}' created with initial empty list.")

    with open(file_path, "r", encoding="utf-8") as file:
        users = json.load(file)

    user_found = None
    for user in users:
        if user["username"] == username:
            user_found = user
            break

    password = hash(password)
    if user_found:
        if user_found["password"] == password:
            result.append({"success":True, "message":"Login successful!"})
        else:
            result.append({"success": False, "message": "Something went wrong!"})

    else:
        users.append(generate_user_data(username, password))
        with open(file_path, "w", encoding="utf-8") as file:
            json.dump(users, file, indent=4)

        result.append({"success":True, "message":"User created - Login successful!"})

    return result


