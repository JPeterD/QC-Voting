"""
Examples demonstrating the usage of the TFHE library

This file contains examples showing how to:
1. Create an encryption context
2. Encrypt and decrypt data
3. Perform homomorphic operations
4. Work with different data types
"""

from tfhe_lib import TFHEContext, homomorphic_and, homomorphic_or, homomorphic_xor, homomorphic_not
import time


def example_basic_encryption():
    """Example demonstrating basic encryption and decryption"""
    print("\n=== Basic Encryption/Decryption Example ===")
    
    # Create an encryption context with default parameters
    context = TFHEContext().generate_keys()
    
    # Encrypt a single bit
    bit = 1
    encrypted_bit = context.encrypt_bit(bit)
    decrypted_bit = context.decrypt_to_bit(encrypted_bit)
    
    print(f"Original bit: {bit}")
    print(f"Decrypted bit: {decrypted_bit}")
    print(f"Correctly decrypted: {bit == decrypted_bit}")
    
    # Encrypt a list of bits
    bits = [1, 0, 1, 1, 0, 0, 1]
    encrypted_bits = context.encrypt_bits(bits)
    decrypted_bits = context.decrypt_to_bits(encrypted_bits)
    
    print(f"\nOriginal bits: {bits}")
    print(f"Decrypted bits: {decrypted_bits}")
    print(f"Correctly decrypted: {bits == decrypted_bits[:len(bits)]}")


def example_binary_operations():
    """Example demonstrating binary homomorphic operations"""
    print("\n=== Binary Operations Example ===")
    
    # Create an encryption context
    context = TFHEContext().generate_keys()
    
    # Encrypt two bits
    bit1, bit2 = 1, 0
    cipher1 = context.encrypt_bit(bit1)
    cipher2 = context.encrypt_bit(bit2)
    
    print(f"Bit 1: {bit1}, Bit 2: {bit2}")
    
    # Perform binary operations
    and_cipher = homomorphic_and(cipher1, cipher2)
    or_cipher = homomorphic_or(cipher1, cipher2)
    xor_cipher = homomorphic_xor(cipher1, cipher2)
    not_cipher1 = homomorphic_not(cipher1)
    not_cipher2 = homomorphic_not(cipher2)
    
    # Decrypt results
    and_result = context.decrypt_to_bit(and_cipher)
    or_result = context.decrypt_to_bit(or_cipher)
    xor_result = context.decrypt_to_bit(xor_cipher)
    not_result1 = context.decrypt_to_bit(not_cipher1)
    not_result2 = context.decrypt_to_bit(not_cipher2)
    
    # Check results
    print(f"AND: {bit1} & {bit2} = {and_result} (expected {bit1 & bit2})")
    print(f"OR: {bit1} | {bit2} = {or_result} (expected {bit1 | bit2})")
    print(f"XOR: {bit1} ^ {bit2} = {xor_result} (expected {bit1 ^ bit2})")
    print(f"NOT: !{bit1} = {not_result1} (expected {1 - bit1})")
    print(f"NOT: !{bit2} = {not_result2} (expected {1 - bit2})")


def example_arithmetic_operations():
    """Example demonstrating homomorphic arithmetic operations"""
    print("\n=== Arithmetic Operations Example ===")
    
    # Create an encryption context
    context = TFHEContext().generate_keys()
    
    # Encrypt two values
    value1, value2 = [1, 0, 1], [0, 1, 1]
    cipher1 = context.encrypt(value1)
    cipher2 = context.encrypt(value2)
    
    print(f"Value 1: {value1}")
    print(f"Value 2: {value2}")
    
    # Perform arithmetic operations
    sum_cipher = cipher1 + cipher2
    product_cipher = cipher1 * cipher2
    
    # Decrypt results
    sum_result = context.decrypt(sum_cipher)
    product_result = context.decrypt(product_cipher)
    
    print(f"Sum: {sum_result}")
    print(f"Product: {product_result}")


def example_integer_encoding():
    """Example demonstrating integer encoding and operations"""
    print("\n=== Integer Encoding Example ===")
    
    # Create an encryption context with larger polynomial size for integers
    context = TFHEContext(polynomial_size=32).generate_keys()
    
    # Encrypt two integers
    int1, int2 = 15, 7
    
    # Encrypt integers as binary representation
    cipher1 = context.encrypt_integer(int1, bit_width=8)
    cipher2 = context.encrypt_integer(int2, bit_width=8)
    
    print(f"Integer 1: {int1}")
    print(f"Integer 2: {int2}")
    
    # Decrypt integers
    dec_int1 = context.decrypt_to_integer(cipher1)
    dec_int2 = context.decrypt_to_integer(cipher2)
    
    print(f"Decrypted integer 1: {dec_int1}")
    print(f"Decrypted integer 2: {dec_int2}")
    
    # Note: For proper integer addition and multiplication, we would need a specialized
    # implementation that handles carry bits and multi-bit operations properly


def example_byte_encryption():
    """Example demonstrating byte encryption and operations"""
    print("\n=== Byte Encryption Example ===")
    
    # Create an encryption context
    context = TFHEContext(polynomial_size=32).generate_keys()
    
    # Encrypt a byte value
    byte_value = 170  # 10101010 in binary
    cipher_byte = context.encrypt_byte(byte_value)
    
    # Decrypt the byte
    decrypted_byte = context.decrypt_to_byte(cipher_byte)
    
    print(f"Original byte: {byte_value} (binary: {bin(byte_value)[2:].zfill(8)})")
    print(f"Decrypted byte: {decrypted_byte} (binary: {bin(decrypted_byte)[2:].zfill(8)})")
    print(f"Correctly decrypted: {byte_value == decrypted_byte}")
    
    # Encrypt a string as bytes
    text = "Hello"
    byte_list = [ord(c) for c in text]
    encrypted_bytes = context.encrypt_bytes(byte_list)
    
    # Decrypt the bytes
    decrypted_bytes = context.decrypt_to_bytes(encrypted_bytes)
    decrypted_text = ''.join(chr(b) for b in decrypted_bytes)
    
    print(f"\nOriginal text: '{text}'")
    print(f"Byte values: {byte_list}")
    print(f"Decrypted bytes: {decrypted_bytes}")
    print(f"Decrypted text: '{decrypted_text}'")


def example_performance_comparison():
    """Example demonstrating performance with different parameters"""
    print("\n=== Performance Comparison Example ===")
    
    sizes = [8, 16, 32]
    operations = ["Key Generation", "Encryption", "Addition", "Multiplication", "Decryption"]
    results = {size: {op: 0 for op in operations} for size in sizes}
    
    for size in sizes:
        print(f"\nTesting with polynomial size = {size}...")
        
        # Create context
        start_time = time.time()
        context = TFHEContext(polynomial_size=size).generate_keys()
        results[size]["Key Generation"] = time.time() - start_time
        
        # Test encryption
        start_time = time.time()
        cipher1 = context.encrypt_bits([1, 0, 1])
        cipher2 = context.encrypt_bits([0, 1, 1])
        results[size]["Encryption"] = time.time() - start_time
        
        # Test addition
        start_time = time.time()
        sum_cipher = cipher1 + cipher2
        results[size]["Addition"] = time.time() - start_time
        
        # Test multiplication
        start_time = time.time()
        product_cipher = cipher1 * cipher2
        results[size]["Multiplication"] = time.time() - start_time
        
        # Test decryption
        start_time = time.time()
        context.decrypt(sum_cipher)
        context.decrypt(product_cipher)
        results[size]["Decryption"] = time.time() - start_time
    
    # Print the results table
    print("\n--- Performance Results (seconds) ---")
    print(f"{'Operation':<20}", end="")
    for size in sizes:
        print(f"{f'Size={size}':<15}", end="")
    print()
    
    for op in operations:
        print(f"{op:<20}", end="")
        for size in sizes:
            print(f"{results[size][op]:<15.6f}", end="")
        print()


if __name__ == "__main__":
    # Run all examples
    example_basic_encryption()
    example_binary_operations()
    example_arithmetic_operations()
    example_integer_encoding()
    example_byte_encryption()
    example_performance_comparison()