"""
TFHE (Fully Homomorphic Encryption over the Torus) Implementation

This implementation is inspired by the Fan-Vercauteren (FV) scheme: https://eprint.iacr.org/2012/144.pdf
The starting point of our implementation is: https://gist.github.com/youben11/f00bc95c5dde5e11218f14f7110ad289

Disclaimer: This implementation is for educational purposes only and is not meant to be 
secure or optimized for efficiency in production environments.

Key concepts:
- Ring-LWE (Ring Learning With Errors): A cryptographic primitive based on polynomial rings
- Homomorphic encryption: Allows computations on encrypted data without decryption
- Polynomial operations: Addition and multiplication in polynomial rings
"""

import numpy as np
from numpy.polynomial import polynomial as poly

#------ Polynomial operations modulo polynomial modulus ------
def polynomial_multiply_mod(poly1, poly2, polynomial_modulus):
    """Multiply two polynomials modulo the polynomial modulus only
    
    Args:
        poly1, poly2: Two polynomials to be multiplied (coefficient arrays)
        polynomial_modulus: Polynomial modulus (typically x^n + 1)
    
    Returns:
        Product polynomial in Z[X]/(polynomial_modulus)
    """
    return poly.polydiv(poly.polymul(poly1, poly2), polynomial_modulus)[1]

def polynomial_add_mod(poly1, poly2, polynomial_modulus):
    """Add two polynomials modulo the polynomial modulus only
    
    Args:
        poly1, poly2: Two polynomials to be added (coefficient arrays)
        polynomial_modulus: Polynomial modulus (typically x^n + 1)
    
    Returns:
        Sum polynomial in Z[X]/(polynomial_modulus)
    """
    return poly.polydiv(poly.polyadd(poly1, poly2), polynomial_modulus)[1]

#------ Polynomial operations modulo both polynomial modulus and coefficient modulus ------
def polynomial_multiply(poly1, poly2, coefficient_modulus, polynomial_modulus):
    """Multiply two polynomials modulo both polynomial modulus and coefficient modulus
    
    Args:
        poly1, poly2: Two polynomials to be multiplied (coefficient arrays)
        coefficient_modulus: Coefficient modulus (integer)
        polynomial_modulus: Polynomial modulus (typically x^n + 1)
    
    Returns:
        Product polynomial in Z_coefficient_modulus[X]/(polynomial_modulus)
    """
    return np.int64(
        np.round(poly.polydiv(poly.polymul(poly1, poly2) % coefficient_modulus, 
                             polynomial_modulus)[1] % coefficient_modulus)
    )

def polynomial_add(poly1, poly2, coefficient_modulus, polynomial_modulus):
    """Add two polynomials modulo both polynomial modulus and coefficient modulus
    
    Args:
        poly1, poly2: Two polynomials to be added (coefficient arrays)
        coefficient_modulus: Coefficient modulus (integer)
        polynomial_modulus: Polynomial modulus (typically x^n + 1)
    
    Returns:
        Sum polynomial in Z_coefficient_modulus[X]/(polynomial_modulus)
    """
    return np.int64(
        np.round(poly.polydiv(poly.polyadd(poly1, poly2) % coefficient_modulus, 
                             polynomial_modulus)[1] % coefficient_modulus)
    )

#------ Random polynomial generation functions ------
def generate_binary_polynomial(size):
    """Generate a polynomial with binary coefficients (0 or 1)
    
    Args:
        size: Number of coefficients (degree + 1)
    
    Returns:
        Binary polynomial as coefficient array
    """
    return np.random.randint(0, 2, size, dtype=np.int64)

def generate_uniform_polynomial(size, modulus):
    """Generate a polynomial with coefficients uniformly random in Z_modulus
    
    Args:
        size: Number of coefficients (degree + 1)
        modulus: Upper bound for coefficient values
    
    Returns:
        Uniform random polynomial as coefficient array
    """
    return np.random.randint(0, modulus, size, dtype=np.int64)

def generate_normal_polynomial(size, mean, standard_deviation):
    """Generate a polynomial with coefficients from normal distribution
    
    Args:
        size: Number of coefficients (degree + 1)
        mean: Mean of the normal distribution
        standard_deviation: Standard deviation of the normal distribution
    
    Returns:
        Gaussian polynomial as coefficient array (discretized)
    """
    return np.int64(np.random.normal(mean, standard_deviation, size=size))

#------ Base decomposition helper function ------
def integer_to_base(number, base):
    """Convert integer to its base representation
    
    Args:
        number: Integer to decompose
        base: Base for decomposition
    
    Returns:
        List of coefficients in base representation (least significant digit first)
    """
    if number < base:
        return [number]
    else:
        return [number % base] + integer_to_base(number // base, base)

#------ Core Homomorphic Encryption Functions ------

def keygen(polynomial_size, coefficient_modulus, polynomial_modulus, error_std_dev):
    """Generate public and secret keys for encryption
    
    Args:
        polynomial_size: Size of polynomials (degree + 1)
        coefficient_modulus: Coefficient modulus (q)
        polynomial_modulus: Polynomial modulus (typically x^n + 1)
        error_std_dev: Standard deviation for error distribution
    
    Returns:
        (public_key, secret_key): Public key (b, a) and secret key s
        
    Notes:
        - Secret key s is a binary polynomial
        - Public key is (b, a) where b = -(a*s + e) mod q and a is uniform random
        - This implements the RLWE assumption for security
    """
    # Secret key: binary polynomial
    secret_key = generate_binary_polynomial(polynomial_size)
    
    # Public key component: uniform random polynomial
    public_key_a = generate_uniform_polynomial(polynomial_size, coefficient_modulus)
    
    # Error polynomial from normal distribution
    error = generate_normal_polynomial(polynomial_size, 0, error_std_dev)
    
    # Public key component: b = -(a*s + e) mod q
    public_key_b = polynomial_add(
        polynomial_multiply(-public_key_a, secret_key, coefficient_modulus, polynomial_modulus), 
        -error, 
        coefficient_modulus, 
        polynomial_modulus
    )
    
    # Return public key (b, a) and secret key s
    return (public_key_b, public_key_a), secret_key

def evaluate_keygen_v1(secret_key, polynomial_size, coefficient_modulus, 
                        decomposition_base, polynomial_modulus, error_std_dev):
    """Generate relinearization key using decomposition in base T
    
    Args:
        secret_key: Secret key
        polynomial_size: Size of polynomials (degree + 1)
        coefficient_modulus: Coefficient modulus (q)
        decomposition_base: Base for decomposition (T)
        polynomial_modulus: Polynomial modulus
        error_std_dev: Standard deviation for error distribution
    
    Returns:
        (relin_key0, relin_key1): Relinearization key components
        
    Notes:
        - Used for homomorphic multiplication (relinearization step)
        - Decomposes s² in base T and encrypts each component under the public key
    """
    modulus_degree = len(polynomial_modulus) - 1
    # log_base(coefficient_modulus)
    log_decomposition = np.int64(np.log(coefficient_modulus) / np.log(decomposition_base))
    
    relin_key0 = np.zeros((log_decomposition + 1, modulus_degree), dtype=np.int64)
    relin_key1 = np.zeros((log_decomposition + 1, modulus_degree), dtype=np.int64)
    
    # For each power base^i, generate an encryption of (s² * base^i)
    for i in range(log_decomposition + 1):
        uniform_poly = generate_uniform_polynomial(polynomial_size, coefficient_modulus)
        error_poly = generate_normal_polynomial(polynomial_size, 0, error_std_dev)
        
        # The term we want to encrypt: s² * base^i
        secret_squared_scaled = decomposition_base ** i * poly.polymul(secret_key, secret_key)
        
        # Generate encryption of secret_squared_scaled
        b_component = np.int64(polynomial_add(
            polynomial_multiply_mod(-uniform_poly, secret_key, polynomial_modulus),
            polynomial_add_mod(-error_poly, secret_squared_scaled, polynomial_modulus),
            coefficient_modulus, polynomial_modulus))
        
        # Pad to ensure consistent size
        b_component = np.int64(np.concatenate((b_component, [0] * (modulus_degree - len(b_component)))))
        uniform_poly = np.int64(np.concatenate((uniform_poly, [0] * (modulus_degree - len(uniform_poly)))))
        
        relin_key0[i] = b_component
        relin_key1[i] = uniform_poly
        
    return relin_key0, relin_key1

def evaluate_keygen_v2(secret_key, polynomial_size, coefficient_modulus, 
                        polynomial_modulus, extra_modulus, error_std_dev):
    """Generate relinearization key using modulus switching technique
    
    Args:
        secret_key: Secret key
        polynomial_size: Size of polynomials (degree + 1)
        coefficient_modulus: Coefficient modulus (q)
        polynomial_modulus: Polynomial modulus
        extra_modulus: Additional modulus p for modulus switching
        error_std_dev: Standard deviation for error distribution
    
    Returns:
        (relin_key0, relin_key1): Relinearization key components
        
    Notes:
        - Alternative approach to relinearization using modulus switching
        - Generally more efficient than v1 for larger parameters
    """
    new_modulus = coefficient_modulus * extra_modulus
    
    uniform_poly = generate_uniform_polynomial(polynomial_size, new_modulus)
    error_poly = generate_normal_polynomial(polynomial_size, 0, error_std_dev)
    
    # The term we want to encrypt: s² * p
    secret_squared_scaled = extra_modulus * poly.polymul(secret_key, secret_key)
    
    # Generate encryption of secret_squared_scaled under the larger modulus
    b_component = np.int64(polynomial_add_mod(
        polynomial_multiply_mod(-uniform_poly, secret_key, polynomial_modulus),
        polynomial_add_mod(-error_poly, secret_squared_scaled, polynomial_modulus),
        polynomial_modulus)) % new_modulus
        
    return b_component, uniform_poly

def encrypt(public_key, polynomial_size, cipher_modulus, plain_modulus, 
            polynomial_modulus, plaintext, error_std_dev):
    """Encrypt a plaintext message
    
    Args:
        public_key: Public key (b, a)
        polynomial_size: Size of polynomials (degree + 1)
        cipher_modulus: Ciphertext modulus (q)
        plain_modulus: Plaintext modulus (t)
        polynomial_modulus: Polynomial modulus
        plaintext: Plaintext message as integer vector (will be converted to polynomial)
        error_std_dev: Standard deviation for error distribution
    
    Returns:
        (cipher0, cipher1): Ciphertext tuple
        
    Notes:
        - Implements RLWE encryption
        - Scales plaintext by delta = q/t to embed in larger ciphertext space
    """
    # Ensure message is padded to the right size
    message_padded = np.array(plaintext + [0] * (polynomial_size - len(plaintext)), 
                             dtype=np.int64) % plain_modulus
    
    # Scale factor between plaintext and ciphertext
    delta = cipher_modulus // plain_modulus
    scaled_message = delta * message_padded
    
    # Error polynomials
    error1 = generate_normal_polynomial(polynomial_size, 0, error_std_dev)
    error2 = generate_normal_polynomial(polynomial_size, 0, error_std_dev)
    
    # Random masking value (binary polynomial)
    random_mask = generate_binary_polynomial(polynomial_size)
    
    # cipher0 = pk[0]*u + e1 + scaled_m
    cipher0 = polynomial_add(
        polynomial_add(
            polynomial_multiply(public_key[0], random_mask, cipher_modulus, polynomial_modulus),
            error1, cipher_modulus, polynomial_modulus),
        scaled_message, cipher_modulus, polynomial_modulus
    )
    
    # cipher1 = pk[1]*u + e2
    cipher1 = polynomial_add(
        polynomial_multiply(public_key[1], random_mask, cipher_modulus, polynomial_modulus),
        error2, cipher_modulus, polynomial_modulus
    )
    
    return (cipher0, cipher1)

def decrypt(secret_key, polynomial_size, cipher_modulus, plain_modulus, 
            polynomial_modulus, ciphertext):
    """Decrypt a ciphertext to recover the plaintext
    
    Args:
        secret_key: Secret key
        polynomial_size: Size of polynomials (degree + 1)
        cipher_modulus: Ciphertext modulus (q)
        plain_modulus: Plaintext modulus (t)
        polynomial_modulus: Polynomial modulus
        ciphertext: Ciphertext as tuple (cipher0, cipher1)
    
    Returns:
        Decrypted plaintext polynomial
        
    Notes:
        - Computes ct[1]*s + ct[0] and scales back from q to t
        - Performs rounding to handle the scaling correctly
    """
    # Compute ct[1]*s + ct[0]
    scaled_plaintext = polynomial_add(
        polynomial_multiply(ciphertext[1], secret_key, cipher_modulus, polynomial_modulus),
        ciphertext[0], cipher_modulus, polynomial_modulus
    )
    
    # Scale back from q to t and round
    decrypted_poly = np.round(plain_modulus * scaled_plaintext / cipher_modulus) % plain_modulus
    
    # Ensure the result is properly padded to size
    decrypted_list = [i for i in decrypted_poly]
    result_length = len(decrypted_list)
    
    if result_length < polynomial_size:
        # Pad with zeros if needed
        zeros_to_pad = polynomial_size - result_length
        padding = [0] * zeros_to_pad
        padded_result = np.append(decrypted_poly, padding)
    else:
        padded_result = decrypted_poly
        
    return np.int64(padded_result)

#------ Homomorphic Operation Functions ------

def add_plain(ciphertext, plaintext, cipher_modulus, plain_modulus, polynomial_modulus):
    """Add a plaintext polynomial to an encrypted ciphertext
    
    Args:
        ciphertext: Ciphertext tuple (cipher0, cipher1)
        plaintext: Plaintext polynomial to add
        cipher_modulus: Ciphertext modulus (q)
        plain_modulus: Plaintext modulus (t)
        polynomial_modulus: Polynomial modulus
    
    Returns:
        New ciphertext encrypting the sum
        
    Notes:
        - Scales the plaintext by delta = q/t before adding
        - Only cipher[0] component needs modification
    """
    polynomial_size = len(polynomial_modulus) - 1
    
    # Ensure plaintext is padded to the right size
    message_padded = np.array(plaintext + [0] * (polynomial_size - len(plaintext)), 
                             dtype=np.int64) % plain_modulus
    
    # Scale plaintext to ciphertext space
    delta = cipher_modulus // plain_modulus
    scaled_message = delta * message_padded
    
    # Add scaled plaintext to cipher[0]
    new_cipher0 = polynomial_add(ciphertext[0], scaled_message, cipher_modulus, polynomial_modulus)
    
    # cipher[1] remains unchanged
    return (new_cipher0, ciphertext[1])

def add_cipher(ciphertext1, ciphertext2, cipher_modulus, polynomial_modulus):
    """Add two ciphertexts component-wise
    
    Args:
        ciphertext1, ciphertext2: Ciphertext tuples to add
        cipher_modulus: Ciphertext modulus (q)
        polynomial_modulus: Polynomial modulus
    
    Returns:
        New ciphertext encrypting the sum
        
    Notes:
        - Simple component-wise addition
    """
    # Component-wise addition
    new_cipher0 = polynomial_add(ciphertext1[0], ciphertext2[0], cipher_modulus, polynomial_modulus)
    new_cipher1 = polynomial_add(ciphertext1[1], ciphertext2[1], cipher_modulus, polynomial_modulus)
    
    return (new_cipher0, new_cipher1)

def mul_plain(ciphertext, plaintext, cipher_modulus, plain_modulus, polynomial_modulus):
    """Multiply a ciphertext by a plaintext polynomial
    
    Args:
        ciphertext: Ciphertext tuple (cipher0, cipher1)
        plaintext: Plaintext polynomial to multiply
        cipher_modulus: Ciphertext modulus (q)
        plain_modulus: Plaintext modulus (t)
        polynomial_modulus: Polynomial modulus
    
    Returns:
        New ciphertext encrypting the product
        
    Notes:
        - Component-wise multiplication of the ciphertext by the plaintext
    """
    polynomial_size = len(polynomial_modulus) - 1
    
    # Ensure plaintext is padded to the right size
    message_padded = np.array(plaintext + [0] * (polynomial_size - len(plaintext)), 
                             dtype=np.int64) % plain_modulus
    
    # Multiply each ciphertext component by the plaintext
    new_cipher0 = polynomial_multiply(ciphertext[0], message_padded, cipher_modulus, polynomial_modulus)
    new_cipher1 = polynomial_multiply(ciphertext[1], message_padded, cipher_modulus, polynomial_modulus)
    
    return (new_cipher0, new_cipher1)

def multiplication_coeffs(ciphertext1, ciphertext2, cipher_modulus, plain_modulus, polynomial_modulus):
    """Compute the raw coefficients of ciphertext multiplication before relinearization
    
    Args:
        ciphertext1, ciphertext2: Ciphertext tuples to multiply
        cipher_modulus: Ciphertext modulus (q)
        plain_modulus: Plaintext modulus (t)
        polynomial_modulus: Polynomial modulus
    
    Returns:
        (coeff0, coeff1, coeff2): Three components of the tensor product
        
    Notes:
        - Result has three components instead of two
        - coeff2 needs to be relinearized to return to normal form
    """
    # First component: cipher1[0] * cipher2[0]
    coeff0 = np.int64(np.round(
        polynomial_multiply_mod(ciphertext1[0], ciphertext2[0], polynomial_modulus) * 
        plain_modulus / cipher_modulus
    )) % cipher_modulus
    
    # Second component: cipher1[0] * cipher2[1] + cipher1[1] * cipher2[0]
    coeff1 = np.int64(np.round(
        polynomial_add_mod(
            polynomial_multiply_mod(ciphertext1[0], ciphertext2[1], polynomial_modulus),
            polynomial_multiply_mod(ciphertext1[1], ciphertext2[0], polynomial_modulus),
            polynomial_modulus
        ) * plain_modulus / cipher_modulus
    )) % cipher_modulus
    
    # Third component: cipher1[1] * cipher2[1]
    coeff2 = np.int64(np.round(
        polynomial_multiply_mod(ciphertext1[1], ciphertext2[1], polynomial_modulus) * 
        plain_modulus / cipher_modulus
    )) % cipher_modulus
    
    return coeff0, coeff1, coeff2

def mul_cipher_v1(ciphertext1, ciphertext2, cipher_modulus, plain_modulus, 
                  decomposition_base, polynomial_modulus, relin_key0, relin_key1):
    """Multiply two ciphertexts using relinearization technique v1 (base decomposition)
    
    Args:
        ciphertext1, ciphertext2: Ciphertext tuples to multiply
        cipher_modulus: Ciphertext modulus (q)
        plain_modulus: Plaintext modulus (t)
        decomposition_base: Base for decomposition (T)
        polynomial_modulus: Polynomial modulus
        relin_key0, relin_key1: Relinearization key from evaluate_keygen_v1
    
    Returns:
        New ciphertext encrypting the product
        
    Notes:
        - First computes the raw multiplication coefficients
        - Then applies relinearization to get back to 2-component form
        - Uses base-T decomposition of coeff2
    """
    modulus_degree = len(polynomial_modulus) - 1
    # log_base(cipher_modulus)
    log_decomposition = np.int64(np.log(cipher_modulus) / np.log(decomposition_base))
    
    # Get the raw multiplication coefficients
    coeff0, coeff1, coeff2 = multiplication_coeffs(
        ciphertext1, ciphertext2, cipher_modulus, plain_modulus, polynomial_modulus
    )
    
    # Pad coeff2 to the right size
    coeff2_padded = np.int64(np.concatenate((coeff2, [0] * (modulus_degree - len(coeff2)))))
    
    # Decompose each coefficient of coeff2 in base T
    base_representations = np.zeros((modulus_degree, log_decomposition + 1), dtype=np.int64)
    for i in range(modulus_degree):
        rep = integer_to_base(coeff2_padded[i], decomposition_base)
        padded_rep = rep + [0] * (log_decomposition + 1 - len(rep))  # Pad with zeros
        base_representations[i] = np.array(padded_rep, dtype=np.int64)
    
    # Initialize relinearization terms
    relin_term0 = np.zeros(shape=modulus_degree)
    relin_term1 = np.zeros(shape=modulus_degree)
    
    # For each power base^j, add relin_key[j] multiplied by the corresponding component
    for j in range(log_decomposition + 1):
        relin_term0 = polynomial_add_mod(
            relin_term0, 
            polynomial_multiply_mod(relin_key0[j], base_representations[:,j], polynomial_modulus), 
            polynomial_modulus
        )
        relin_term1 = polynomial_add_mod(
            relin_term1, 
            polynomial_multiply_mod(relin_key1[j], base_representations[:,j], polynomial_modulus), 
            polynomial_modulus
        )
    
    # Finalize the relinearization
    relin_term0 = np.int64(np.round(relin_term0)) % cipher_modulus
    relin_term1 = np.int64(np.round(relin_term1)) % cipher_modulus
    
    # Combine with original coeff0 and coeff1
    new_cipher0 = np.int64(polynomial_add_mod(coeff0, relin_term0, polynomial_modulus)) % cipher_modulus
    new_cipher1 = np.int64(polynomial_add_mod(coeff1, relin_term1, polynomial_modulus)) % cipher_modulus
    
    return (new_cipher0, new_cipher1)

def mul_cipher_v2(ciphertext1, ciphertext2, cipher_modulus, plain_modulus, 
                  extra_modulus, polynomial_modulus, relin_key0, relin_key1):
    """Multiply two ciphertexts using relinearization technique v2 (modulus switching)
    
    Args:
        ciphertext1, ciphertext2: Ciphertext tuples to multiply
        cipher_modulus: Ciphertext modulus (q)
        plain_modulus: Plaintext modulus (t)
        extra_modulus: Extra modulus for modulus switching (p)
        polynomial_modulus: Polynomial modulus
        relin_key0, relin_key1: Relinearization key from evaluate_keygen_v2
    
    Returns:
        New ciphertext encrypting the product
        
    Notes:
        - First computes the raw multiplication coefficients
        - Then applies relinearization to get back to 2-component form
        - Uses modulus switching rather than decomposition
    """
    # Get the raw multiplication coefficients
    coeff0, coeff1, coeff2 = multiplication_coeffs(
        ciphertext1, ciphertext2, cipher_modulus, plain_modulus, polynomial_modulus
    )
    
    # Apply modulus switching technique for relinearization
    relin_term0 = np.int64(np.round(
        polynomial_multiply_mod(coeff2, relin_key0, polynomial_modulus) / extra_modulus
    )) % cipher_modulus
    
    relin_term1 = np.int64(np.round(
        polynomial_multiply_mod(coeff2, relin_key1, polynomial_modulus) / extra_modulus
    )) % cipher_modulus
    
    # Combine with original coeff0 and coeff1
    new_cipher0 = np.int64(polynomial_add_mod(coeff0, relin_term0, polynomial_modulus)) % cipher_modulus
    new_cipher1 = np.int64(polynomial_add_mod(coeff1, relin_term1, polynomial_modulus)) % cipher_modulus
    
    return (new_cipher0, new_cipher1)