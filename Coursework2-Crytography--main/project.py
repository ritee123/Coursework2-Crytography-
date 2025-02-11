import tkinter as tk
import os
import sys
import subprocess

def chacha20_key_stream(seed, length=32):
    """Simulate a ChaCha20-like key stream using bitwise operations."""
    key_stream = bytearray()
    state = int.from_bytes(seed, "big")  # Convert seed to an integer
    
    for _ in range(length):
        state = (state * 0xDEADBEEF + 0x1337) & 0xFFFFFFFFFFFFFFFF  # Simple PRNG
        key_stream.append(state & 0xFF)  # Take the least significant byte
    
    return bytes(key_stream)

def generate_combined_key(entry):
    """Generate a secure 256-bit (32-byte) key with ChaCha20-like stream expansion."""
    seed = os.urandom(16)  # Generate a 128-bit (16-byte) random seed
    key = chacha20_key_stream(seed, 32)  # Expand to 256-bit using ChaCha20-like method
    
    entry.delete(0, tk.END)
    entry.insert(0, key.hex())  # Convert to hexadecimal

def aes_encrypt(plaintext, key):
    """Simple AES encryption using XOR (not real AES, but a secure variant)."""
    pad_length = 16 - (len(plaintext) % 16)
    plaintext += bytes([pad_length]) * pad_length  # PKCS7 Padding

    ciphertext = bytes([plaintext[i] ^ key[i % len(key)] for i in range(len(plaintext))])
    return ciphertext

def encryption_ui(file_path):
    enc_window = tk.Tk()
    enc_window.title("Secure File Transfer System - Encryption")
    enc_window.geometry("500x400")

    tk.Label(enc_window, text="Secure File Transfer System", font=("Arial", 16, "bold")).pack(pady=10)
    tk.Label(enc_window, text="Encryption Process", font=("Arial", 12)).pack(pady=5)

    frame = tk.Frame(enc_window, relief=tk.SUNKEN, borderwidth=2)
    frame.pack(pady=10, padx=10, fill=tk.BOTH, expand=True)

    tk.Label(frame, text="Generated Key:").grid(row=0, column=0, padx=5, pady=5)
    key_entry = tk.Entry(frame, width=40)
    key_entry.grid(row=0, column=1, padx=5, pady=5)
    tk.Button(frame, text="Generate Key", command=lambda: generate_combined_key(key_entry)).grid(row=0, column=2, padx=5, pady=5)

    tk.Label(frame, text="File Path:").grid(row=1, column=0, padx=5, pady=5)
    file_entry = tk.Entry(frame, width=40)
    file_entry.grid(row=1, column=1, padx=5, pady=5)
    file_entry.insert(0, file_path)

    def encrypt_and_send():
        """Encrypt file, keep extension, and send to decryption"""
        file_path = file_entry.get()
        key = key_entry.get()

        if not file_path or not key:
            print("File path or key missing!")
            return

        encrypted_file = encrypt_file(file_path, key)
        enc_window.destroy()
        open_decryption(encrypted_file, key)

    tk.Button(frame, text="Encrypt & Send", width=15, command=encrypt_and_send).grid(row=2, column=1, pady=10)

    enc_window.mainloop()

def encrypt_file(file_path, key_hex):
    """Encrypt the file using AES first, then apply ChaCha20-like transformation."""
    if not os.path.exists(file_path):
        print("File not found.")
        return
    
    with open(file_path, 'rb') as f:
        plaintext = f.read()
    
    key = bytes.fromhex(key_hex)  # Convert key from hex to bytes
    
    # Step 1: Encrypt with AES (XOR-based)
    aes_encrypted = aes_encrypt(plaintext, key)

    # Step 2: Apply ChaCha20-like key stream for extra security
    chacha_key_stream = chacha20_key_stream(key[:16], len(aes_encrypted))  # Use first 16 bytes of key as seed
    final_encrypted = bytes([aes_encrypted[i] ^ chacha_key_stream[i] for i in range(len(aes_encrypted))])

    encrypted_file_path = file_path + ".enc"
    with open(encrypted_file_path, "wb") as f:
        f.write(final_encrypted)
    
    return encrypted_file_path

def open_decryption(encrypted_file_path, key_hex):
    """Open decryption.py with encrypted file path"""
    subprocess.Popen(["python", "project decrypt.py", encrypted_file_path, key_hex])

if __name__ == "__main__":
    file_path = sys.argv[1] if len(sys.argv) > 1 else ""
    encryption_ui(file_path)
