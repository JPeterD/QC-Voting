"""
TFHE Library - User-friendly interface for TFHE encryption scheme

This library provides a simple API for using the TFHE (Fully Homomorphic Encryption over the Torus)
encryption scheme. It wraps the lower-level functions in a more intuitive interface.

Disclaimer: This implementation is for educational purposes only and is not meant to be 
secure or optimized for efficiency in production environments.
"""

import numpy as np
import rlwe_he_scheme as rlwe


class TFHEContext:
    """TFHE encryption context that manages parameters and keys"""
    
    def __init__(self, 
                 polynomial_size=16, 
                 coefficient_modulus=2**14, 
                 plaintext_modulus=2, 
                 error_std_dev=1,
                 use_advanced_multiplication=True):
        """
        Initialize a TFHE encryption context with specified parameters
        
        Args:
            polynomial_size: Size of polynomials (degree + 1), higher means more security but slower
            coefficient_modulus: Ciphertext modulus (q), affects precision
            plaintext_modulus: Plaintext modulus (t), typically 2 for binary operations
            error_std_dev: Standard deviation for error distribution
            use_advanced_multiplication: Whether to use v2 (modulus switching) for multiplication
        """
        self.polynomial_size = polynomial_size
        self.coefficient_modulus = coefficient_modulus
        self.plaintext_modulus = plaintext_modulus
        self.error_std_dev = error_std_dev
        self.use_advanced_multiplication = use_advanced_multiplication
        
        # Initialize polynomial modulus (x^n + 1)
        self.polynomial_modulus = np.array([1] + [0] * (polynomial_size - 1) + [1])
        
        # Parameters for relinearization
        self.decomposition_base = int(np.sqrt(coefficient_modulus))  # for v1
        self.extra_modulus = coefficient_modulus ** 3  # for v2
        
        # Keys (initialized to None, generated when needed)
        self.public_key = None
        self.secret_key = None
        self.relin_key0_v1 = None
        self.relin_key1_v1 = None
        self.relin_key0_v2 = None
        self.relin_key1_v2 = None
    
    def generate_keys(self):
        """Generate encryption and evaluation keys"""
        # Generate public and secret keys
        self.public_key, self.secret_key = rlwe.keygen(
            self.polynomial_size, 
            self.coefficient_modulus, 
            self.polynomial_modulus, 
            self.error_std_dev
        )
        
        # Generate relinearization keys for v1 (base decomposition)
        self.relin_key0_v1, self.relin_key1_v1 = rlwe.evaluate_keygen_v1(
            self.secret_key, 
            self.polynomial_size, 
            self.coefficient_modulus, 
            self.decomposition_base, 
            self.polynomial_modulus, 
            self.error_std_dev
        )
        
        # Generate relinearization keys for v2 (modulus switching)
        self.relin_key0_v2, self.relin_key1_v2 = rlwe.evaluate_keygen_v2(
            self.secret_key, 
            self.polynomial_size, 
            self.coefficient_modulus, 
            self.polynomial_modulus, 
            self.extra_modulus, 
            self.error_std_dev
        )
        
        return self
    
    def encrypt(self, data):
        """
        Encrypt integer data
        
        Args:
            data: List of integers to encrypt (will be converted to binary if needed)
                 Length should be less than or equal to polynomial_size
        
        Returns:
            TFHECiphertext object containing the encrypted data
        """
        if self.public_key is None:
            self.generate_keys()
            
        # Convert data to list if it's a single value
        if not isinstance(data, list):
            data = [data]
        
        # Convert to binary representation if not already binary
        if self.plaintext_modulus == 2:
            # Ensure all values are 0 or 1
            data = [int(val > 0) for val in data]
        else:
            # Ensure values are within the plaintext modulus
            data = [val % self.plaintext_modulus for val in data]
        
        # Ensure data length does not exceed polynomial size
        if len(data) > self.polynomial_size:
            data = data[:self.polynomial_size]
        
        # Encrypt the data
        ciphertext = rlwe.encrypt(
            self.public_key,
            self.polynomial_size,
            self.coefficient_modulus,
            self.plaintext_modulus,
            self.polynomial_modulus,
            data,
            self.error_std_dev
        )
        
        return TFHECiphertext(ciphertext, self)
    
    def encrypt_bit(self, bit):
        """
        Encrypt a single bit (0 or 1)
        
        Args:
            bit: Value to encrypt (0 or 1)
        
        Returns:
            TFHECiphertext object containing the encrypted bit
        """
        return self.encrypt([int(bit > 0)])
    
    def encrypt_bits(self, bits):
        """
        Encrypt a list of bits
        
        Args:
            bits: List of bits (0s and 1s) to encrypt
        
        Returns:
            TFHECiphertext object containing the encrypted bits
        """
        return self.encrypt(bits)
    
    def encrypt_byte(self, byte):
        """
        Encrypt a byte as 8 bits
        
        Args:
            byte: Integer value to encrypt (0-255)
        
        Returns:
            TFHECiphertext object containing the encrypted byte as 8 bits
        """
        # Convert byte to binary (8 bits)
        bits = [(byte >> i) & 1 for i in range(8)]
        return self.encrypt(bits)
    
    def encrypt_bytes(self, data):
        """
        Encrypt a bytes object or list of bytes
        
        Args:
            data: Bytes object or list of integers (0-255) to encrypt
        
        Returns:
            List of TFHECiphertext objects, each containing one encrypted byte
        """
        return [self.encrypt_byte(b) for b in data]
    
    def encrypt_integer(self, value, bit_width=32):
        """
        Encrypt an integer as a series of bits
        
        Args:
            value: Integer to encrypt
            bit_width: Number of bits to use for representing the integer
        
        Returns:
            TFHECiphertext object containing the encrypted integer
        """
        # Convert integer to binary representation
        bits = [(value >> i) & 1 for i in range(bit_width)]
        return self.encrypt(bits)
    
    def decrypt(self, ciphertext):
        """
        Decrypt a ciphertext
        
        Args:
            ciphertext: TFHECiphertext object to decrypt
        
        Returns:
            Decrypted data as a list of integers
        """
        if self.secret_key is None:
            raise ValueError("No secret key available. Keys must be generated first.")
        
        # Get the raw ciphertext from the TFHECiphertext object
        raw_ciphertext = ciphertext.raw_ciphertext
        
        # Decrypt the data
        decrypted = rlwe.decrypt(
            self.secret_key,
            self.polynomial_size,
            self.coefficient_modulus,
            self.plaintext_modulus,
            self.polynomial_modulus,
            raw_ciphertext
        )
        
        # Convert to Python int list and trim trailing zeros
        result = [int(val) for val in decrypted]
        
        # Trim trailing zeros for cleaner output
        while len(result) > 1 and result[-1] == 0:
            result.pop()
            
        return result
    
    def decrypt_to_bit(self, ciphertext):
        """
        Decrypt a ciphertext to a single bit
        
        Args:
            ciphertext: TFHECiphertext object to decrypt
        
        Returns:
            Decrypted bit (0 or 1)
        """
        result = self.decrypt(ciphertext)
        return result[0] if result else 0
    
    def decrypt_to_bits(self, ciphertext):
        """
        Decrypt a ciphertext to a list of bits
        
        Args:
            ciphertext: TFHECiphertext object to decrypt
        
        Returns:
            Decrypted bits as a list of 0s and 1s
        """
        return self.decrypt(ciphertext)
    
    def decrypt_to_byte(self, ciphertext):
        """
        Decrypt a ciphertext to a byte value
        
        Args:
            ciphertext: TFHECiphertext object to decrypt
        
        Returns:
            Decrypted byte value (0-255)
        """
        bits = self.decrypt(ciphertext)
        # Pad to ensure we have at least 8 bits
        bits = bits + [0] * max(0, 8 - len(bits))
        # Convert bits to byte
        byte_value = sum((bits[i] & 1) << i for i in range(8))
        return byte_value
    
    def decrypt_to_bytes(self, ciphertexts):
        """
        Decrypt a list of ciphertexts to bytes
        
        Args:
            ciphertexts: List of TFHECiphertext objects to decrypt
        
        Returns:
            Decrypted bytes as a list of integers (0-255)
        """
        return [self.decrypt_to_byte(cipher) for cipher in ciphertexts]
    
    def decrypt_to_integer(self, ciphertext, signed=False):
        """
        Decrypt a ciphertext to an integer
        
        Args:
            ciphertext: TFHECiphertext object to decrypt
            signed: Whether the integer should be interpreted as signed
        
        Returns:
            Decrypted integer value
        """
        bits = self.decrypt(ciphertext)
        bit_width = len(bits)
        
        # Convert bits to integer
        value = sum((bits[i] & 1) << i for i in range(bit_width))
        
        # Handle signed interpretation if needed
        if signed and bits[-1] == 1:  # If most significant bit is set (negative)
            value = value - (1 << bit_width)
            
        return value


class TFHECiphertext:
    """Class representing an encrypted value in the TFHE scheme"""
    
    def __init__(self, raw_ciphertext, context):
        """
        Initialize a ciphertext
        
        Args:
            raw_ciphertext: Raw ciphertext tuple from the RLWE scheme
            context: TFHEContext that created this ciphertext
        """
        self.raw_ciphertext = raw_ciphertext
        self.context = context
    
    def __add__(self, other):
        """
        Add this ciphertext to another ciphertext or plaintext
        
        Args:
            other: TFHECiphertext or plaintext value to add
        
        Returns:
            New TFHECiphertext containing the sum
        """
        ctx = self.context
        
        if isinstance(other, TFHECiphertext):
            # Ciphertext-ciphertext addition
            result = rlwe.add_cipher(
                self.raw_ciphertext,
                other.raw_ciphertext,
                ctx.coefficient_modulus,
                ctx.polynomial_modulus
            )
        else:
            # Ciphertext-plaintext addition
            # Convert plaintext to list if necessary
            if not isinstance(other, list):
                other = [other]
                
            # Ensure plaintext values are within modulus
            other = [val % ctx.plaintext_modulus for val in other]
            
            result = rlwe.add_plain(
                self.raw_ciphertext,
                other,
                ctx.coefficient_modulus,
                ctx.plaintext_modulus,
                ctx.polynomial_modulus
            )
            
        return TFHECiphertext(result, ctx)
    
    def __mul__(self, other):
        """
        Multiply this ciphertext by another ciphertext or plaintext
        
        Args:
            other: TFHECiphertext or plaintext value to multiply
        
        Returns:
            New TFHECiphertext containing the product
        """
        ctx = self.context
        
        if isinstance(other, TFHECiphertext):
            # Ciphertext-ciphertext multiplication
            if ctx.use_advanced_multiplication:
                # Use v2 (modulus switching) method
                result = rlwe.mul_cipher_v2(
                    self.raw_ciphertext,
                    other.raw_ciphertext,
                    ctx.coefficient_modulus,
                    ctx.plaintext_modulus,
                    ctx.extra_modulus,
                    ctx.polynomial_modulus,
                    ctx.relin_key0_v2,
                    ctx.relin_key1_v2
                )
            else:
                # Use v1 (base decomposition) method
                result = rlwe.mul_cipher_v1(
                    self.raw_ciphertext,
                    other.raw_ciphertext,
                    ctx.coefficient_modulus,
                    ctx.plaintext_modulus,
                    ctx.decomposition_base,
                    ctx.polynomial_modulus,
                    ctx.relin_key0_v1,
                    ctx.relin_key1_v1
                )
        else:
            # Ciphertext-plaintext multiplication
            # Convert plaintext to list if necessary
            if not isinstance(other, list):
                other = [other]
                
            # Ensure plaintext values are within modulus
            other = [val % ctx.plaintext_modulus for val in other]
            
            result = rlwe.mul_plain(
                self.raw_ciphertext,
                other,
                ctx.coefficient_modulus,
                ctx.plaintext_modulus,
                ctx.polynomial_modulus
            )
            
        return TFHECiphertext(result, ctx)
    
    def __neg__(self):
        """
        Negate this ciphertext (for binary values, this is equivalent to NOT operation)
        
        Returns:
            New TFHECiphertext containing the negation
        """
        # For binary values, adding 1 inverts the bit
        if self.context.plaintext_modulus == 2:
            return self + 1
        else:
            # For general values, multiply by -1
            return self * (-1 % self.context.plaintext_modulus)
    
    def __sub__(self, other):
        """
        Subtract another ciphertext or plaintext from this ciphertext
        
        Args:
            other: TFHECiphertext or plaintext value to subtract
        
        Returns:
            New TFHECiphertext containing the difference
        """
        # Subtraction is addition with the negation
        return self + (-other)


# Helper functions for common homomorphic operations on binary values

def homomorphic_and(cipher1, cipher2):
    """
    Perform a homomorphic AND operation between two encrypted bits
    
    Args:
        cipher1, cipher2: TFHECiphertext objects containing encrypted bits
    
    Returns:
        TFHECiphertext containing the result of cipher1 AND cipher2
    """
    return cipher1 * cipher2


def homomorphic_or(cipher1, cipher2):
    """
    Perform a homomorphic OR operation between two encrypted bits
    
    Args:
        cipher1, cipher2: TFHECiphertext objects containing encrypted bits
    
    Returns:
        TFHECiphertext containing the result of cipher1 OR cipher2
    """
    # OR(a,b) = a + b - a*b
    return cipher1 + cipher2 - (cipher1 * cipher2)


def homomorphic_xor(cipher1, cipher2):
    """
    Perform a homomorphic XOR operation between two encrypted bits
    
    Args:
        cipher1, cipher2: TFHECiphertext objects containing encrypted bits
    
    Returns:
        TFHECiphertext containing the result of cipher1 XOR cipher2
    """
    # XOR(a,b) = a + b - 2*a*b
    product = cipher1 * cipher2
    return cipher1 + cipher2 - product - product


def homomorphic_not(cipher):
    """
    Perform a homomorphic NOT operation on an encrypted bit
    
    Args:
        cipher: TFHECiphertext object containing an encrypted bit
    
    Returns:
        TFHECiphertext containing the result of NOT cipher
    """
    # For binary values, 1 - a is the same as NOT a
    return -cipher