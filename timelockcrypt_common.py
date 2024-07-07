import os
import base64
import binascii
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import time
from argon2.low_level import hash_secret_raw, Type

AES_KEY_SIZE = 32
AES_BLOCK_SIZE = 16
AES_IV_SIZE = 16
AES_TAG_SIZE = 16
ARGON2_SALT_SIZE = 16

# Constants for Argon2 key derivation
ARGON2_TIME_COST = 4
ARGON2_MEMORY_COST = 102400
ARGON2_PARALLELISM = 8
ARGON2_HASH_LEN = AES_KEY_SIZE

def argon2id_key_derivation(password_bytes, salt):
    return hash_secret_raw(
        secret=password_bytes,
        salt=salt,
        time_cost=ARGON2_TIME_COST,
        memory_cost=ARGON2_MEMORY_COST,
        parallelism=ARGON2_PARALLELISM,
        hash_len=ARGON2_HASH_LEN,
        type=Type.ID
    )

def generate_proof_of_work_key(initial_key, time_seconds, salt_for_pow):
    proof_key = initial_key
    end_time = time.time() + time_seconds
    iterations = 0
    while time.time() < end_time:
        proof_key = argon2id_key_derivation(proof_key, salt_for_pow)
        iterations += 1
    return proof_key, iterations

def generate_proof_of_work_key_decrypt(initial_key, iterations, salt_for_pow):
    proof_key = initial_key
    for _ in range(iterations):
        proof_key = argon2id_key_derivation(proof_key, salt_for_pow)
    return proof_key

def encrypt_text(plaintext, password, time_seconds):
    time_lock_salt = os.urandom(AES_BLOCK_SIZE)
    key = generate_key(password, time_lock_salt)
    cipher = AES.new(key, AES.MODE_GCM, nonce=get_random_bytes(AES_IV_SIZE))
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode())
    encrypted_data = time_lock_salt + cipher.nonce + ciphertext + tag

    salt_for_pow = os.urandom(ARGON2_SALT_SIZE)
    initial_key = generate_key(password, salt_for_pow)
    time_lock_key, proof_iterations = generate_proof_of_work_key(initial_key, time_seconds, salt_for_pow)
    time_lock_cipher = AES.new(time_lock_key, AES.MODE_GCM, nonce=get_random_bytes(AES_IV_SIZE))
    time_lock_ciphertext, time_lock_tag = time_lock_cipher.encrypt_and_digest(encrypted_data)
    time_lock_encrypted_data = salt_for_pow + time_lock_cipher.nonce + time_lock_ciphertext + time_lock_tag

    return base64.b64encode(time_lock_encrypted_data).decode(), proof_iterations

def decrypt_text(encrypted_data_base64, password, pow_iterations):
    try:
        encrypted_data = base64.b64decode(encrypted_data_base64)
    except binascii.Error:
        print("Error: Invalid base64 encoding.")
        return None
    
    if len(encrypted_data) < AES_BLOCK_SIZE + AES_IV_SIZE + AES_TAG_SIZE:
        print("Error: Invalid encrypted data length.")
        return None
    
    salt_for_pow = encrypted_data[:ARGON2_SALT_SIZE]
    time_lock_nonce = encrypted_data[ARGON2_SALT_SIZE:ARGON2_SALT_SIZE + AES_IV_SIZE]
    time_lock_ciphertext = encrypted_data[ARGON2_SALT_SIZE + AES_IV_SIZE:-AES_TAG_SIZE]
    time_lock_tag = encrypted_data[-AES_TAG_SIZE:]

    initial_key = generate_key(password, salt_for_pow)
    time_lock_key = generate_proof_of_work_key_decrypt(initial_key, pow_iterations, salt_for_pow)
    time_lock_cipher = AES.new(time_lock_key, AES.MODE_GCM, nonce=time_lock_nonce)
    
    try:
        intermediate_encrypted_data = time_lock_cipher.decrypt_and_verify(time_lock_ciphertext, time_lock_tag)
    except ValueError as e:
        print(f"Error: Time-lock decryption failed. Reason: {str(e)}")
        return None

    salt = intermediate_encrypted_data[:AES_BLOCK_SIZE]
    nonce = intermediate_encrypted_data[AES_BLOCK_SIZE:AES_BLOCK_SIZE + AES_IV_SIZE]
    ciphertext = intermediate_encrypted_data[AES_BLOCK_SIZE + AES_IV_SIZE:-AES_TAG_SIZE]
    tag = intermediate_encrypted_data[-AES_TAG_SIZE:]

    key = generate_key(password, salt)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

    try:
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext.decode()
    except ValueError as e:
        print(f"Error: Original decryption failed. Reason: {str(e)}")
        return None

def generate_key(password, salt=None):
    if salt is None:
        salt = os.urandom(ARGON2_SALT_SIZE)
    return argon2id_key_derivation(password.encode(), salt)

def encrypt_file(file_path, password, time_seconds):
    with open(file_path, 'rb') as f:
        plaintext = f.read()

    time_lock_salt = os.urandom(AES_BLOCK_SIZE)
    key = generate_key(password, time_lock_salt)
    nonce = get_random_bytes(AES_IV_SIZE)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    encrypted_data = time_lock_salt + nonce + ciphertext + tag

    salt_for_pow = os.urandom(ARGON2_SALT_SIZE)
    initial_key = generate_key(password, salt_for_pow)
    time_lock_key, proof_iterations = generate_proof_of_work_key(initial_key, time_seconds, salt_for_pow)
    time_lock_cipher = AES.new(time_lock_key, AES.MODE_GCM, nonce=get_random_bytes(AES_IV_SIZE))
    time_lock_ciphertext, time_lock_tag = time_lock_cipher.encrypt_and_digest(encrypted_data)
    time_lock_encrypted_data = salt_for_pow + time_lock_cipher.nonce + time_lock_ciphertext + time_lock_tag

    output_file_path = file_path + ".enc"

    with open(output_file_path, 'xb') as f:
        f.write(time_lock_encrypted_data)

    return output_file_path, proof_iterations


def decrypt_file(file_path, password, pow_iterations, output_dir=None):
    with open(file_path, 'rb') as f:
        encrypted_data = f.read()

    salt_for_pow = encrypted_data[:ARGON2_SALT_SIZE]
    time_lock_nonce = encrypted_data[ARGON2_SALT_SIZE:ARGON2_SALT_SIZE + AES_IV_SIZE]
    time_lock_ciphertext = encrypted_data[ARGON2_SALT_SIZE + AES_IV_SIZE:-AES_TAG_SIZE]
    time_lock_tag = encrypted_data[-AES_TAG_SIZE:]

    initial_key = generate_key(password, salt_for_pow)
    try:
        time_lock_key = generate_proof_of_work_key_decrypt(initial_key, pow_iterations, salt_for_pow)
    except ValueError as e:
        print(f"Error: Invalid proof-of-work iterations. {str(e)}")
        return False

    time_lock_cipher = AES.new(time_lock_key, AES.MODE_GCM, nonce=time_lock_nonce)

    try:
        intermediate_encrypted_data = time_lock_cipher.decrypt_and_verify(time_lock_ciphertext, time_lock_tag)
    except ValueError as e:
        print("Error: Time-lock decryption failed. Incorrect password or corrupted data.")
        return False

    salt = intermediate_encrypted_data[:AES_BLOCK_SIZE]
    nonce = intermediate_encrypted_data[AES_BLOCK_SIZE:AES_BLOCK_SIZE + AES_IV_SIZE]
    ciphertext = intermediate_encrypted_data[AES_BLOCK_SIZE + AES_IV_SIZE:-AES_TAG_SIZE]
    tag = intermediate_encrypted_data[-AES_TAG_SIZE:]

    key = generate_key(password, salt)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

    try:
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    except ValueError as e:
        print("Error: Original decryption failed. Incorrect password or corrupted file.")
        return False

    output_file_name = os.path.basename(file_path)
    if output_dir:
        output_path = os.path.join(output_dir, output_file_name[:-4])
    else:
        output_path = output_file_name[:-4]
    try:
        with open(output_path, 'xb') as f:
            f.write(plaintext)
        print("File decrypted successfully.")
        return True
    except IOError as e:
        print(f"Error: Unable to write decrypted file. {str(e)}")
        return False



def convert_to_seconds(time_string):
    unit = time_string[-1].lower()
    value = int(time_string[:-1])
    if unit == 's':
        return value
    elif unit == 'm':
        return value * 60
    elif unit == 'h':
        return value * 3600
    elif unit == 'd':
        return value * 86400
    elif unit == 'w':
        return value * 604800
    else:
        raise ValueError("Invalid time format. Use 's' for seconds, 'm' for minutes, 'h' for hours, 'd' for days, or 'w' for weeks.")
