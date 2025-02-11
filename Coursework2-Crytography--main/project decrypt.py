import tkinter as tk
import os
import sys

def chacha20_key_stream(seed, length=32):
    """Simulate a ChaCha20-like key stream using bitwise operations."""
    key_stream = bytearray()
    state = int.from_bytes(seed, "big")  # Convert seed to an integer
    
    for _ in range(length):
        state = (state * 0xDEADBEEF + 0x1337) & 0xFFFFFFFFFFFFFFFF  # Simple PRNG
        key_stream.append(state & 0xFF)  # Take the least significant byte
    
    return bytes(key_stream)

def aes_decrypt(ciphertext, key):
    """Simple AES-like decryption (XOR-based)."""
    plaintext = bytes([ciphertext[i] ^ key[i % len(key)] for i in range(len(ciphertext))])
    pad_length = plaintext[-1]
    return plaintext[:-pad_length]

def decrypt_file(file_path, key_hex, result_label):
    if not os.path.exists(file_path):
        result_label.config(text="File not found.", fg="red")
        return

    try:
        with open(file_path, 'rb') as f:
            ciphertext = f.read()

        entered_key = key_hex.strip()
        if not entered_key:
            result_label.config(text="Please enter the encryption key.", fg="red")
            return

        key = bytes.fromhex(entered_key)
        
        # Step 1: Reverse ChaCha20-like transformation
        chacha_key_stream = chacha20_key_stream(key[:16], len(ciphertext))
        aes_encrypted = bytes([ciphertext[i] ^ chacha_key_stream[i] for i in range(len(ciphertext))])
        
        # Step 2: Decrypt AES-like encryption
        plaintext = aes_decrypt(aes_encrypted, key)

        # Save decrypted file
        parent_directory = os.path.dirname(file_path)
        decrypted_folder = os.path.join(parent_directory, "decrypted_files")
        if not os.path.exists(decrypted_folder):
            os.makedirs(decrypted_folder)

        original_filename = os.path.basename(file_path).replace(".enc", "")
        decrypted_file_path = os.path.join(decrypted_folder, original_filename)

        with open(decrypted_file_path, "wb") as f:
            f.write(plaintext)

        result_label.config(text=f"Decryption successful! File saved to: {decrypted_file_path}", fg="green")
    except Exception as e:
        result_label.config(text="Decryption failed! Invalid key or corrupted file.", fg="red")

def decryption_ui():
    dec_window = tk.Tk()
    dec_window.title("Secure File Transfer System - Decryption")
    dec_window.geometry("500x400")

    tk.Label(dec_window, text="Secure File Transfer System", font=("Arial", 16, "bold")).pack(pady=10)
    tk.Label(dec_window, text="Decryption Process", font=("Arial", 12)).pack(pady=5)

    frame = tk.Frame(dec_window)
    frame.pack(pady=10, padx=10)

    tk.Button(frame, text="Receive File", width=20, command=lambda: receive_file(file_entry)).grid(row=0, column=1, pady=5)

    tk.Label(frame, text="Received File:").grid(row=1, column=0, padx=5, pady=5)
    file_entry = tk.Entry(frame, width=40)
    file_entry.grid(row=1, column=1, padx=5, pady=5)

    tk.Label(frame, text="Enter Key:").grid(row=2, column=0, padx=5, pady=5)
    key_entry = tk.Entry(frame, width=40)
    key_entry.grid(row=2, column=1, padx=5, pady=5)

    result_label = tk.Label(frame, text="", fg="red")
    result_label.grid(row=4, column=1, pady=5)

    def decrypt_and_restore():
        decrypt_file(file_entry.get(), key_entry.get(), result_label)

    tk.Button(frame, text="Decrypt", width=15, command=decrypt_and_restore).grid(row=3, column=1, pady=10)

    dec_window.mainloop()

def receive_file(entry):
    """Receive encrypted file and display its path."""
    encrypted_file_path = sys.argv[1] if len(sys.argv) > 1 else "No file received"
    entry.delete(0, tk.END)
    entry.insert(0, encrypted_file_path)

if __name__ == "__main__":
    decryption_ui()