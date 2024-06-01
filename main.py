import pyotp
import time
import json
import sys
import getpass
import os
import shutil
from objdict import ObjDict
from pathlib import Path

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

import base64
import datetime
from consoledraw import Console

class constants:
    key_path = os.path.join(Path.home(), ".config/Moon2FA/")

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
        """
        Decrypts the content of the keys.moon file using the provided secret key.

        Parameters:
        `secret (bytes)`: The secret key used for encryption and decryption.

        Returns:
        `str`: The decrypted content of the keys.moon file.

        This method reads the content of the keys.moon file, encrypts it using the provided secret key,
        and then decodes the encrypted content to a string.
        """
        with open(os.path.join(constants.key_path,"keys.moon"), "rb") as keyfile:
            key = base64.urlsafe_b64encode(secret)
            return Fernet(key).decrypt(keyfile.read()).decode()
    
    @staticmethod
    def encrypt(content, secret):
        """
        Encrypts the provided content using the provided secret key.

        Parameters:
        `content (bytes)`: The content to be encrypted.
        `secret (bytes)`: The secret key used for encryption.

        Returns:
        `bytes`: The encrypted content.

        This method uses the Fernet symmetric encryption algorithm from the cryptography library.
        It first encodes the secret key using base64.urlsafe_b64encode, then creates a Fernet instance with the encoded key.
        Finally, it encrypts the provided content using the Fernet instance and returns the encrypted content.
        """
        key = base64.urlsafe_b64encode(secret)
        return Fernet(key).encrypt(content)

    @staticmethod
    def set(secret, key, value):
        """
        Sets a key-value pair in the encrypted storage.

        Parameters:
        `secret (bytes)`: The secret key used for encryption and decryption.
        `key (str)`: The key to be stored.
        `value (str)`: The value associated with the key.

        Returns:
        `None`

        This method first checks if the `keys.moon` file exists. If it doesn't, it creates a new directory if it doesn't exist,
        and then creates a new ObjDict. If the file exists, it tries to decrypt the content and load it into an ObjDict.
        If decryption fails, it prints an error message, moves the corrupted file to a backup, and creates a new ObjDict.

        After loading the data, it sets the provided key-value pair in the ObjDict.
        Then, it encrypts the updated ObjDict, encodes it to bytes, and writes it to the `keys.moon` file.
        """
        if not os.path.exists(os.path.join(constants.key_path, "keys.moon")):
            if not os.path.isdir(constants.key_path):
                os.makedirs(constants.key_path)
            data = ObjDict()
        else:
            try:
                data = ObjDict.loads(storage.decrypt(secret))
            except Exception as e:
                print("Your keys.moon file is corrupted!!")
                shutil.move(os.path.join(constants.key_path, "keys.moon"), os.path.join(constants.key_path, "keys_backup.moon"))   # Don't wanna lose user data UwU
                data = ObjDict()
            
        with open(os.path.join(constants.key_path, "keys.moon"), "wb") as file:
            data[key] = value 
            data = storage.encrypt(json.dumps(data).encode(), secret)
            file.write(data)

    @staticmethod
    def read(secret, key):
        """
        Reads a specific key from the encrypted storage.

        Parameters:
        `secret (bytes)`: The secret key used for encryption and decryption.
        `key (str)`: The key to be retrieved.

        Returns:
        `str`: The value associated with the provided key, or None if the key does not exist or an error occurs.

        This method first checks if the `keys.moon` file exists. If it doesn't, it returns None.
        If the file exists, it tries to decrypt the content and load it into a dictionary.
        If decryption fails, it returns None.
        After loading the data, it retrieves the value associated with the provided key using the `get()` method.
        If the key does not exist, it returns None.
        """
        if not os.path.exists(os.path.join(constants.key_path, "keys.moon")):
            return None
        else:
            try:
                data = json.loads(storage.decrypt(secret))
                return data.get(key)
            except:
                return None

    @staticmethod
    def read_all(secret):
        """
        Reads all key-value pairs from the encrypted storage.

        Parameters:
        `secret (bytes)`: The secret key used for encryption and decryption.

        Returns:
        `dict`: A dictionary containing all key-value pairs from the storage, or None if the file does not exist or an error occurs.

        This method first checks if the `keys.moon` file exists. If it doesn't, it returns None.
        If the file exists, it tries to decrypt the content and load it into a dictionary.
        If decryption fails, it returns None.
        After loading the data, it returns the dictionary containing all key-value pairs.
        """
        if not os.path.exists(os.path.join(constants.key_path, "keys.moon")):
            return None
        else:
            try:
                data = json.loads(storage.decrypt(secret))
                return data
            except:
                return None

    @staticmethod
    def remove(secret, index):
        """
        Removes a key-value pair from the encrypted storage.

        Parameters:
        `secret (bytes)`: The secret key used for encryption and decryption.
        `index (str)`: The index of the key to be removed.

        Returns:
        `None`

        This method first checks if the `keys.moon` file exists. If it doesn't, it returns None.
        If the file exists, it tries to decrypt the content and load it into a dictionary.
        After loading the data, it removes the key-value pair associated with the provided index.
        Then, it writes the updated dictionary back to the `keys.moon` file after encrypting it.
        """
        if not os.path.exists(os.path.join(constants.key_path, "keys.moon")):
            return None
        else:
            with open(os.path.join(constants.key_path, "keys.moon"), "rb+") as file:
                data = json.loads(storage.decrypt(secret))
                del data[index]
                file.seek(0)
                file.truncate()
                file.write(storage.encrypt(json.dumps(data).encode(), secret))

def remove_key(secret, index=None):
    """
    Function to remove a key from the storage.

    Parameters:
    `secret (bytes)`: The secret key used for encryption and decryption.
    `index (int, optional)`: The index of the key to be removed. If not provided, the user will be prompted to choose one.

    Returns:
    `None`

    This function first retrieves all keys from the storage using the `storage.read_all()` function.
    It then prompts the user to choose a key to remove if no index is provided.
    After the user has chosen a key, it calls the `storage.remove()` function to remove the key from the storage.
    Finally, it asks the user if they want to remove another key. If the user chooses to remove another key, it calls itself recursively.
    """
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
    """
    Function to add a new key to the storage.

    Parameters:
    `secret (bytes)`: The secret key used for encryption and decryption.
    `name (str, optional)`: The name of the key. If not provided, it will be requested from the user.
    `key (str, optional)`: The key itself. If not provided, it will be requested from the user.

    Returns:
    `None`

    This function prompts the user to input the name and key for a new key.
    It then calls the `storage.set()` function to save the key in the storage.
    After saving, it asks the user if they want to add another key.
    If the user chooses to add another key, it calls itself recursively.
    """
    name = input("What's the name of your key?\n> ")
    key = getpass.getpass("What is your key?\n> ").upper().replace(" ","")
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
    """
    The main loop of the application. Handles user interactions, key management, and TOTP generation.

    Returns:
        None
    """
    # Check if the keys file exists, if not, run the setup
    if not os.path.isfile(os.path.join(constants.key_path, "keys.moon")):
        return setup()

    # Greet the user and prompt for their password
    print(f"Hello, {getpass.getuser()}! Welcome back to Moon2FA!! :3")
    secret = derive_key_from_password(getpass.getpass("Password:\n> "))

    # Retrieve all keys from the storage
    keys = storage.read_all(secret)
    
    # If no keys are found, prompt the user to proceed or exit
    if not keys:
        prompt = input("Wrong password or you have no keys! Are you sure you want to proceed? | Y/n |\n> ")
        if prompt in ["y", "yes"]:
            pass
        else:
            return None

    # Handle command line arguments for adding or removing keys
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

    # If no keys are found after handling command line arguments, exit with an error message
    if not keys:
        return print("Wrong password or corrupted keys file, please try again!")
    
    # Initialize the console for TOTP display
    console = Console(hideCursor=False)

    # Infinite loop for TOTP display and user interaction
    while True:
        try:
            with console:
                # Display each key and its corresponding TOTP code and remaining time
                for key, value in keys.items():
                    try:
                        console.print(f"{key} | {pyotp.TOTP(value).now()} | {round(datetime.datetime.now().timestamp() % pyotp.TOTP(value).interval - pyotp.TOTP(value).interval) * -1}s")
                    except Exception as e:
                        console.print(f"{key} | Invalid ({value})")
                time.sleep(0.1)
        except KeyboardInterrupt:
            # Exit the loop on keyboard interrupt
            sys.exit(0)

if __name__ == "__main__":
    main_loop()
