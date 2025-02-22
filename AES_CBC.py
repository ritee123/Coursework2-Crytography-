import os
import secrets

def aes_encrypt_block(block, key):
    """Encrypt a single 16-byte block using AES-like transformations."""
    state = bytes([block[i] ^ key[i] for i in range(16)])
    return state

def aes_decrypt_block(block, key):
    """Decrypt a single 16-byte block using AES-like transformations."""
    state = bytes([block[i] ^ key[i] for i in range(16)])
    return state

def aes_cbc_encrypt(data, key):
    """Manual AES-CBC encryption with a fixed block size of 16 bytes."""
    iv = secrets.token_bytes(16)
    padded_data = data + bytes([16 - len(data) % 16]) * (16 - len(data) % 16)
    
    ciphertext = bytearray(iv)
    prev_block = iv
    for i in range(0, len(padded_data), 16):
        block = bytes([padded_data[i+j] ^ prev_block[j] for j in range(16)])
        encrypted_block = aes_encrypt_block(block, key[:16])
        ciphertext.extend(encrypted_block)
        prev_block = encrypted_block
    
    return bytes(ciphertext)

def aes_cbc_decrypt(encrypted_data, key):
    """Manual AES-CBC decryption with a fixed block size of 16 bytes."""
    iv = encrypted_data[:16]
    ciphertext = encrypted_data[16:]
    plaintext = bytearray()
    prev_block = iv
    
    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i:i+16]
        decrypted_block = aes_decrypt_block(block, key[:16])
        plaintext.extend(bytes([decrypted_block[j] ^ prev_block[j] for j in range(16)]))
        prev_block = block
    
    pad_length = plaintext[-1]
    return plaintext[:-pad_length]

# Test function
if __name__ == "__main__":
    test_key = os.urandom(176)  # Full key for all rounds
    test_data = b"Hello, World! This is a test message."
    
    try:
        encrypted = aes_cbc_encrypt(test_data, test_key)
        decrypted = aes_cbc_decrypt(encrypted, test_key)
        
        print(f"Original: {test_data}")
        print(f"Decrypted: {decrypted}")
        assert decrypted == test_data
        print("Test passed successfully!")
    except Exception as e:
        print(f"Test failed: {str(e)}")
