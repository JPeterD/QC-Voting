import rlwe_he_scheme as rlwe
import numpy as np
import time

def run_encryption_test(polynomial_size, verbose=True):
    """
    Run encryption test with a specific polynomial size and return timing results
    
    Args:
        polynomial_size: Size of the polynomial (degree + 1)
        verbose: Whether to print detailed output
    
    Returns:
        Dictionary with timing information for different operations
    """
    # Initialize timings dictionary
    timings = {
        'key_generation': 0,
        'relin_key_gen_v1': 0,
        'relin_key_gen_v2': 0,
        'encryption': 0,
        'homomorphic_addition': 0,
        'homomorphic_mult_v1': 0,
        'homomorphic_mult_v2': 0,
        'decryption': 0
    }
    
    # Scheme's parameters
    coefficient_modulus = 2 ** 14     # ciphertext modulus (q)
    plaintext_modulus = 2             # plaintext modulus (t)
    decomposition_base = int(np.sqrt(coefficient_modulus))  # base for relinearization v1 (T)
    extra_modulus = coefficient_modulus ** 3      # modulus switching modulus (p)
    
    # polynomial modulus x^n + 1
    polynomial_modulus = np.array([1] + [0] * (polynomial_size - 1) + [1])
    
    # standard deviation for errors
    error_std_dev1 = 1  # standard deviation for the error in encryption
    error_std_dev2 = 1  # standard deviation for the error in relinearization v2
    
    # Generate random plaintexts and constants of specified size
    plaintext1 = np.random.randint(0, 2, polynomial_size, dtype=np.int64).tolist()
    plaintext2 = np.random.randint(0, 2, polynomial_size, dtype=np.int64).tolist()
    constant1 = np.random.randint(0, 2, polynomial_size, dtype=np.int64).tolist()
    constant2 = np.random.randint(0, 2, polynomial_size, dtype=np.int64).tolist()
    
    if verbose:
        print(f"\n===== Testing with polynomial size: {polynomial_size} =====")
        print(f"Plaintext 1: {plaintext1}")
        print(f"Plaintext 2: {plaintext2}")
    
    # Key Generation
    start_time = time.time()
    public_key, secret_key = rlwe.keygen(
        polynomial_size, coefficient_modulus, polynomial_modulus, error_std_dev1
    )
    timings['key_generation'] = time.time() - start_time
    
    # Relinearization Key Generation v1
    start_time = time.time()
    relin_key0_v1, relin_key1_v1 = rlwe.evaluate_keygen_v1(
        secret_key, polynomial_size, coefficient_modulus, 
        decomposition_base, polynomial_modulus, error_std_dev1
    )
    timings['relin_key_gen_v1'] = time.time() - start_time
    
    # Relinearization Key Generation v2
    start_time = time.time()
    relin_key0_v2, relin_key1_v2 = rlwe.evaluate_keygen_v2(
        secret_key, polynomial_size, coefficient_modulus, 
        polynomial_modulus, extra_modulus, error_std_dev2
    )
    timings['relin_key_gen_v2'] = time.time() - start_time
    
    # Encryption
    start_time = time.time()
    ciphertext1 = rlwe.encrypt(
        public_key, polynomial_size, coefficient_modulus, plaintext_modulus, 
        polynomial_modulus, plaintext1, error_std_dev1
    )
    ciphertext2 = rlwe.encrypt(
        public_key, polynomial_size, coefficient_modulus, plaintext_modulus, 
        polynomial_modulus, plaintext2, error_std_dev1
    )
    timings['encryption'] = time.time() - start_time
    
    if verbose:
        print("\n[+] Encryption Results:")
        print(f"  Ciphertext1 (encryption of {plaintext1}):")
        print(f"    ciphertext1[0]: {ciphertext1[0]}")
        print(f"    ciphertext1[1]: {ciphertext1[1]}")
        print(f"  Ciphertext2 (encryption of {plaintext2}):")
        print(f"    ciphertext2[0]: {ciphertext2[0]}")
        print(f"    ciphertext2[1]: {ciphertext2[1]}")
    
    # Homomorphic Operations
    
    # Addition with plaintext and ciphertext operations
    start_time = time.time()
    ciphertext_add_plain = rlwe.add_plain(
        ciphertext1, constant1, coefficient_modulus, plaintext_modulus, polynomial_modulus
    )
    ciphertext_mul_plain = rlwe.mul_plain(
        ciphertext2, constant2, coefficient_modulus, plaintext_modulus, polynomial_modulus
    )
    ciphertext_combined = rlwe.add_cipher(
        ciphertext_add_plain, ciphertext_mul_plain, coefficient_modulus, polynomial_modulus
    )
    timings['homomorphic_addition'] = time.time() - start_time
    
    # Multiplication v1 (base decomposition)
    start_time = time.time()
    ciphertext_mul_v1 = rlwe.mul_cipher_v1(
        ciphertext1, ciphertext2, coefficient_modulus, plaintext_modulus,
        decomposition_base, polynomial_modulus, relin_key0_v1, relin_key1_v1
    )
    timings['homomorphic_mult_v1'] = time.time() - start_time
    
    # Multiplication v2 (modulus switching)
    start_time = time.time()
    ciphertext_mul_v2 = rlwe.mul_cipher_v2(
        ciphertext1, ciphertext2, coefficient_modulus, plaintext_modulus,
        extra_modulus, polynomial_modulus, relin_key0_v2, relin_key1_v2
    )
    timings['homomorphic_mult_v2'] = time.time() - start_time
    
    # Decryption
    start_time = time.time()
    decrypted_add_plain = rlwe.decrypt(
        secret_key, polynomial_size, coefficient_modulus, 
        plaintext_modulus, polynomial_modulus, ciphertext_add_plain
    )
    decrypted_mul_plain = rlwe.decrypt(
        secret_key, polynomial_size, coefficient_modulus, 
        plaintext_modulus, polynomial_modulus, ciphertext_mul_plain
    )
    decrypted_combined = rlwe.decrypt(
        secret_key, polynomial_size, coefficient_modulus, 
        plaintext_modulus, polynomial_modulus, ciphertext_combined
    )
    decrypted_mul_v1 = rlwe.decrypt(
        secret_key, polynomial_size, coefficient_modulus, 
        plaintext_modulus, polynomial_modulus, ciphertext_mul_v1
    )
    decrypted_mul_v2 = rlwe.decrypt(
        secret_key, polynomial_size, coefficient_modulus, 
        plaintext_modulus, polynomial_modulus, ciphertext_mul_v2
    )
    timings['decryption'] = time.time() - start_time
    
    if verbose:
        # Calculate expected results for verification
        expected_add_plain = rlwe.polynomial_add(
            plaintext1, constant1, plaintext_modulus, polynomial_modulus
        )
        expected_mul_plain = rlwe.polynomial_multiply(
            plaintext2, constant2, plaintext_modulus, polynomial_modulus
        )
        expected_combined = rlwe.polynomial_add(
            expected_add_plain,
            expected_mul_plain,
            plaintext_modulus, polynomial_modulus
        )
        expected_mul = rlwe.polynomial_multiply(
            plaintext1, plaintext2, plaintext_modulus, polynomial_modulus
        )
        
        print("\n[+] Decryption Results:")
        print(f"  Decrypted (ciphertext1 + constant1): {decrypted_add_plain}")
        print(f"  Expected result: {expected_add_plain}")
        print(f"  Decrypted (ciphertext2 * constant2): {decrypted_mul_plain}")
        print(f"  Expected result: {expected_mul_plain}")
        print(f"  Decrypted combined operation result: {decrypted_combined}")
        print(f"  Expected result: {expected_combined}")
        print(f"  Decrypted (ciphertext1 * ciphertext2) using method v1: {decrypted_mul_v1}")
        print(f"  Decrypted (ciphertext1 * ciphertext2) using method v2: {decrypted_mul_v2}")
        print(f"  Expected result: {expected_mul}")
    
    return timings

def compare_polynomial_sizes(sizes, num_runs=3):
    """
    Run tests with different polynomial sizes and compare performance
    
    Args:
        sizes: List of polynomial sizes to test
        num_runs: Number of test runs to average for more accurate results
    """
    all_timings = {}
    
    print("\n===== TFHE Homomorphic Encryption Performance Test =====")
    print(f"Testing different polynomial sizes to measure performance impact (average of {num_runs} runs)")
    
    for size in sizes:
        size_timings = {
            'key_generation': 0,
            'relin_key_gen_v1': 0,
            'relin_key_gen_v2': 0,
            'encryption': 0,
            'homomorphic_addition': 0,
            'homomorphic_mult_v1': 0,
            'homomorphic_mult_v2': 0,
            'decryption': 0
        }
        
        # Run multiple times to get a more stable measurement
        for run in range(num_runs):
            if run == 0:
                print(f"\nRunning tests for polynomial size n = {size}...")
            
            # Run with minimal output to avoid cluttering the console
            run_timings = run_encryption_test(size, verbose=False)
            
            # Accumulate the timings
            for operation in size_timings:
                size_timings[operation] += run_timings[operation]
        
        # Calculate the averages
        for operation in size_timings:
            size_timings[operation] /= num_runs
        
        all_timings[size] = size_timings
        
        # Print individual size results
        print(f"\n--- Average Results for polynomial size n = {size} ---")
        print(f"Key Generation:         {size_timings['key_generation']:.6f} seconds")
        print(f"Relin Key Gen v1:       {size_timings['relin_key_gen_v1']:.6f} seconds")
        print(f"Relin Key Gen v2:       {size_timings['relin_key_gen_v2']:.6f} seconds")
        print(f"Encryption:             {size_timings['encryption']:.6f} seconds")
        print(f"Homomorphic Addition:   {size_timings['homomorphic_addition']:.6f} seconds")
        print(f"Homomorphic Mult v1:    {size_timings['homomorphic_mult_v1']:.6f} seconds")
        print(f"Homomorphic Mult v2:    {size_timings['homomorphic_mult_v2']:.6f} seconds")
        print(f"Decryption:             {size_timings['decryption']:.6f} seconds")
        
        total_time = sum(size_timings.values())
        print(f"Total time:             {total_time:.6f} seconds")
    
    # Print comparative summary
    print("\n===== Performance Comparison (seconds) =====")
    print("Operation\t" + "\t".join([f"n={size}" for size in sizes]))
    
    for operation in all_timings[sizes[0]].keys():
        times = [all_timings[size][operation] for size in sizes]
        print(f"{operation}\t" + "\t".join([f"{time:.6f}" for time in times]))
    
    # Calculate the scaling factor compared to the smallest input size
    print("\n===== Scaling Factor (compared to smallest size) =====")
    print("Operation\t" + "\t".join([f"n={size}" for size in sizes]))
    
    for operation in all_timings[sizes[0]].keys():
        base_time = all_timings[sizes[0]][operation]
        if base_time == 0:
            # Avoid division by zero
            scaling = ["N/A"] * len(sizes)
        else:
            scaling = [all_timings[size][operation] / base_time for size in sizes]
        print(f"{operation}\t" + "\t".join([f"{factor:.2f}x" for factor in scaling]))

if __name__ == '__main__':
    # Demonstrate a single detailed run
    run_encryption_test(4, verbose=True)
    
    # Compare performance across different polynomial sizes
    # Powers of 2: 4, 8, 16, 32, 64, 128
    # Each run will be averaged over multiple iterations for more accurate results
    compare_polynomial_sizes([4, 8, 16, 32, 64, 128], num_runs=3)