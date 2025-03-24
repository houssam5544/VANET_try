import socket
import json
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import base64

# AES Encryption Key (must match the server's key)
# 32-byte AES key (must be the same for client and server)
AES_KEY = b'SUPER_SECURE_AES_KEY_32_BYTE!!!!'

# Simulated pre-installed LTC (provided by manufacturer)
LTC = "Vehicle_LTC_Signed_By_Manufacturer"

# AES Encryption and Decryption


def aes_encrypt(key, plaintext):
    iv = os.urandom(16)  # Generate a new IV
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(algorithms.AES.block_size).padder()

    padded_data = padder.update(plaintext.encode()) + padder.finalize()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    return base64.b64encode(iv + ciphertext).decode()  # Encode IV + ciphertext


def aes_decrypt(key, ciphertext):
    data = base64.b64decode(ciphertext)  # Decode base64
    iv, actual_ciphertext = data[:16], data[16:]  # Extract IV

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()

    padded_plaintext = decryptor.update(
        actual_ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    return (unpadder.update(padded_plaintext) + unpadder.finalize()).decode()

# Client function to communicate with RA


def send_request(server, port, request):
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((server, port))
    encrypted_request = aes_encrypt(AES_KEY, json.dumps(request))
    # Debugging
    print(
        f"Sending Encrypted Request to {server}:{port} -> {encrypted_request}")

    client.send(encrypted_request.encode())
    encrypted_response = client.recv(4096).decode()

    print(f"Received Encrypted Response: {encrypted_response}")  # Debugging
    response = json.loads(aes_decrypt(AES_KEY, encrypted_response))

    client.close()
    return response

# Simulating the vehicle's certificate request process


def vehicle_request_process():
    print("Starting vehicle request process...")

    # Step 1: Send LTC to RA for validation and certificate request
    ra_response = send_request("localhost", 5000, {"LTC": LTC})
    print("RA Response:", ra_response)

    if "Pseudonym_Certificate" in ra_response:
        print("Received Pseudonym Certificate:",
              ra_response["Pseudonym_Certificate"])
    else:
        print("Failed to obtain Pseudonym Certificate")


if __name__ == "__main__":
    vehicle_request_process()
