import numpy as np
import time
import secrets
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend

# ------------------- HILL CIPHER FUNCTIONS (MODIFIED) -------------------

ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 "
MODULUS = len(ALPHABET)

def mod_inv(a, m):
    for i in range(1, m):
        if (a * i) % m == 1:
            return i
    return None

def generate_valid_key_matrix():
    while True:
        matrix = np.random.randint(0, MODULUS, (2, 2))
        det = int(round(np.linalg.det(matrix))) % MODULUS
        if det != 0 and mod_inv(det, MODULUS) is not None:
            return matrix

def matrix_mod_inv(matrix, modulus):
    det = int(np.round(np.linalg.det(matrix))) % modulus
    det_inv = mod_inv(det, modulus)
    if det_inv is None:
        raise ValueError("Matrix is not invertible")

    a, b = matrix[0]
    c, d = matrix[1]
    adjugate = np.array([[d, -b], [-c, a]]) % modulus
    return (det_inv * adjugate) % modulus

def char_to_index(c):
    return ALPHABET.index(c)

def index_to_char(i):
    return ALPHABET[i % MODULUS]

def preprocess_message(message):
    message = message.upper()
    message = ''.join(c for c in message if c in ALPHABET)
    if len(message) % 2 != 0:
        message += 'X'
    return message

def hill_encrypt(message, key_matrix):
    message = preprocess_message(message)
    message_vector = [char_to_index(c) for c in message]
    cipher = ''
    for i in range(0, len(message_vector), 2):
        block = np.array(message_vector[i:i+2])
        result = np.dot(key_matrix, block) % MODULUS
        cipher += ''.join(index_to_char(int(num)) for num in result)
    return cipher

def hill_decrypt(cipher, key_matrix):
    cipher = cipher.upper()
    cipher_vector = [char_to_index(c) for c in cipher if c in ALPHABET]
    plain = ''
    inv_key = matrix_mod_inv(key_matrix, MODULUS)
    for i in range(0, len(cipher_vector), 2):
        block = np.array(cipher_vector[i:i+2])
        result = np.dot(inv_key, block) % MODULUS
        plain += ''.join(index_to_char(int(num)) for num in result)
    return plain

# ------------------- ECC BIOMETRIC SECURITY FUNCTIONS -------------------

def get_ecc_curve(key_size):
    if key_size == 256:
        return ec.SECP256R1()
    elif key_size == 384:
        return ec.SECP384R1()
    elif key_size == 521:
        return ec.SECP521R1()
    else:
        raise ValueError("Unsupported ECC key size. Choose 256, 384, or 521.")

def measure_ecc_keygen_time(ecc_curve):
    start = time.time()
    private_key = ec.generate_private_key(ecc_curve, default_backend())
    public_key = private_key.public_key()
    end = time.time()
    return end - start

def simulate_biometric_match(template_size):
    start = time.time()
    template1 = secrets.token_bytes(template_size // 8)
    template2 = template1  # Perfect match simulation
    match = template1 == template2
    end = time.time()
    return end - start, match

def evaluate_security(ecc_key_size, biometric_entropy):
    ecc_security = ecc_key_size // 2
    total_security = min(ecc_security, biometric_entropy)
    return ecc_security, total_security

# ------------------- MAIN INTERFACE -------------------

def main():
    key_matrix = generate_valid_key_matrix()
    print("Session Key Matrix (used for all Hill Cipher operations):\n", key_matrix)

    while True:
        print("\nChoose method:")
        print("1. Hill Cipher")
        print("2. ECC Biometric Security Analysis")
        print("3. Exit")

        choice = input("Enter 1, 2 or 3: ")

        if choice == '1':
            action = input("Encrypt or Decrypt? (e/d): ")
            text = input("Enter the sentence: ")

            if action.lower() == 'e':
                encrypted = hill_encrypt(text, key_matrix)
                print("Encrypted Text:", encrypted)
            elif action.lower() == 'd':
                decrypted = hill_decrypt(text, key_matrix)
                print("Decrypted Text:", decrypted)
            else:
                print("Invalid action.")

        elif choice == '2':
            print("=== ECC-Based Biometric Security Analysis ===")
            try:
                ecc_key_size = int(input("Enter ECC Key Size (256, 384, 521): "))
                template_size = int(input("Enter Biometric Template Size (bits): "))
                biometric_entropy = int(input("Enter Biometric Entropy (bits): "))
            except ValueError:
                print("Invalid input. Please enter numeric values.")
                continue

            try:
                curve = get_ecc_curve(ecc_key_size)
            except ValueError as e:
                print(e)
                continue

            ecc_time = measure_ecc_keygen_time(curve)
            bio_time, match = simulate_biometric_match(template_size)
            ecc_sec, total_sec = evaluate_security(ecc_key_size, biometric_entropy)

            print("\n=== Results ===")
            print(f"ECC Key Generation Time: {ecc_time:.6f} sec")
            print(f"Biometric Matching Time: {bio_time:.6f} sec")
            print(f"Total Authentication Time: {ecc_time + bio_time:.6f} sec")
            print(f"ECC Security Level: {ecc_sec} bits")
            print(f"System Security Level: {total_sec} bits")
            print(f"Biometric Match: {match}")

        elif choice == '3':
            print("Exiting the program. Goodbye!")
            break

        else:
            print("Invalid choice. Please select 1, 2, or 3.")

# ------------------- RUN -------------------
if __name__ == '__main__':
    main()
