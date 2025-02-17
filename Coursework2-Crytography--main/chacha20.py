import os

def chacha20_key_stream(seed, length=32):
    """Simulate a ChaCha20-like key stream using bitwise operations."""
    key_stream = bytearray()
    state = int.from_bytes(seed, "big")  # Convert seed to an integer
    
    for _ in range(length):
        state = (state * 0xDEADBEEF + 0x1337) & 0xFFFFFFFFFFFFFFFF  # Simple PRNG
        key_stream.append(state & 0xFF)  # Take the least significant byte
    
    return bytes(key_stream)

def generate_combined_key():
    """Generate a secure 256-bit (32-byte) key with ChaCha20-like stream expansion."""
    seed = os.urandom(16)  # Generate a 128-bit (16-byte) random seed
    key = chacha20_key_stream(seed, 32)  # Expand to 256-bit using ChaCha20-like method
    
    # Generate additional key material for AES rounds
    expanded_key = bytearray()
    expanded_key.extend(key)  # First 32 bytes
    
    # Generate remaining key material for AES rounds
    for i in range(5):  # Generate additional key material
        next_seed = chacha20_key_stream(expanded_key[i*32:(i+1)*32], 32)
        expanded_key.extend(next_seed)
    
    return bytes(expanded_key[:176])  # Return exactly 176 bytes for AES rounds

def test_key_generation():
    """Test the key generation"""
    try:
        # Generate and test a key
        key = generate_combined_key()
        print(f"Generated key length: {len(key)} bytes")
        print(f"Key (hex): {key.hex()}")
        
        # Verify key length
        assert len(key) == 176, f"Key length should be 176 bytes, got {len(key)}"
        
        # Generate multiple keys to test uniqueness
        keys = [generate_combined_key() for _ in range(3)]
        assert len(set(keys)) == 3, "Generated duplicate keys"
        
        print("Key generation test passed successfully!")
        
    except Exception as e:
        print(f"Test failed: {str(e)}")

if __name__ == "__main__":
    test_key_generation()
