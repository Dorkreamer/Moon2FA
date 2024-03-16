import pyotp
import time
import json
import sys
import getpass
import os
import shutil
from objdict import ObjDict

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

import base64
import datetime

if getattr(sys, 'frozen', False):
    # When the script is run as a bundled executable
    root = os.path.dirname(sys.executable)
else:
    # When the script is run as a Python script
    root = os.path.dirname(os.path.abspath(sys.argv[0]))

def derive_key_from_password(password):
    """
    Derives a cryptographic key from the provided password.
    """
    salt = b'salt_'  # Salt should be randomly generated and stored securely in practice
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # Length of the key
        salt=salt,
        iterations=100000,  # Number of iterations, can be adjusted for desired security
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    return key

class storage:
    @staticmethod
    def decrypt(secret):
        with open(os.path.join(root, "keys.moon"), "rb") as keyfile:
            key = base64.urlsafe_b64encode(secret)
            return Fernet(key).decrypt(keyfile.read()).decode()
    
    @staticmethod
    def encrypt(content, secret):
        key = base64.urlsafe_b64encode(secret)
        return Fernet(key).encrypt(content)

    @staticmethod
    def set(secret, key, value):
        if not os.path.exists(os.path.join(root, "keys.moon")):
            data = ObjDict()
        else:
            try:
                data = ObjDict.loads(storage.decrypt(secret))
            except Exception as e:
                print("Your keys.moon file is corrupted!!")
                shutil.move(os.path.join(root, "keys.moon"), f".keys_backup.moon")   # Don't wanna lose user data UwU
                data = ObjDict()
            
        with open(os.path.join(root, "keys.moon"), "wb") as file:
            data[key] = value 
            data = storage.encrypt(json.dumps(data).encode(), secret)
            file.write(data)

    @staticmethod
    def read(secret, key):
        if not os.path.exists(os.path.join(root, "keys.moon")):
            return None
        else:
            try:
                data = json.loads(storage.decrypt(secret))
                return data.get(key)
            except:
                return None

    @staticmethod
    def read_all(secret):
        if not os.path.exists(os.path.join(root, "keys.moon")):
            return None
        else:
            try:
                data = json.loads(storage.decrypt(secret))
                return data
            except:
                return None

    @staticmethod
    def remove(secret, index):
        if not os.path.exists(os.path.join(root, "keys.moon")):
            return None
        else:
            with open(os.path.join(root, "keys.moon"), "rb+") as file:
                data = json.loads(storage.decrypt(secret))
                del data[index]
                file.seek(0)
                file.truncate()
                file.write(storage.encrypt(json.dumps(data).encode(), secret))

def remove_key(secret, index=None):
    keys = storage.read_all(secret)
    
    key_list = []
    if not index:
        for idx, key in enumerate(keys, 1):
            print(f"[{idx}] | {key}")
            key_list.append(key)
        
        index = int(input("Which key would you like to remove?\n> ")) - 1
    
    if 0 <= index < len(keys):  # Check if the index is valid
        storage.remove(secret, key_list[index])
        print(f"Key removed successfully!")
    else:
        print("Invalid index! Please choose a valid index.")
        remove_key(secret)  # Call the function again to retry
    
    prompt = input("Would you like to remove another key? (Y/n)\n> ").lower()
    
    if prompt in ["y", "yes"]:
        remove_key(secret)

def add_key(secret, name=None, key=None):
    name = input("What's the name of your key?\n> ")
    key = getpass.getpass("What is your key?\n> ").upper().replace(" ","")
    print(key) #remove
    storage.set(secret, name, key)
    print(f"Key: {name} was saved successfully!")

    prompt = input("Would you like to add another key? (Y/n)\n> ").lower()
    
    if prompt in ["y", "yes"]:
        add_key(secret)

def setup():
    # Greet the user and guide them through setting up their keys
    print(f"Welcome, {getpass.getuser()}! This seems to be your first time using Moon2FA!")
    print("Let's get you started by firstly creating your master password! This will be your key to access your... keys")
    
    secret = getpass.getpass("Password:\n> ")
    secret = derive_key_from_password(secret)
    add_key(secret)
    
    input("Press Enter to continue...")

def main_loop():
    os.system("clear")
    if not os.path.isfile(os.path.join(root, "keys.moon")):
        return setup()

    print(f"Hello, {getpass.getuser()}! Welcome back to Moon2FA!! :3")
    secret = derive_key_from_password(getpass.getpass("Password:\n> "))
    keys = storage.read_all(secret)
    
    if not keys:
        prompt = input("Wrong password or you have no keys! Are you sure you want to proceed? | Y/n |\n> ")
        if prompt in ["y", "yes"]:
            pass
        else:
            return None

    try:
        if sys.argv[1] in ["add", "+", "new"]:
            add_key(secret)

        elif sys.argv[1] in ["remove", "delete", "-", "rm"]:
            try:
                if sys.argv[2]:
                    index = int(sys.argv[2])
                    remove_key(secret, index)
            except IndexError:
                remove_key(secret)
    except IndexError:
        pass

    while True:
        if not keys:
            return print("Wrong password or corrupted keys file, please try again!")

        for key, value in keys.items():
            try:
                print(f"{key} | {pyotp.TOTP(value).now()} | {round(datetime.datetime.now().timestamp() % pyotp.TOTP(value).interval - pyotp.TOTP(value).interval) * -1}s")
            except:
                print(f"{key} | Invalid ({value})")
        
        time.sleep(1)
        os.system("clear")

if __name__ == "__main__":
    main_loop()
