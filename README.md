# TFHE Encryption Library

This repository contains a Python implementation of the TFHE (Fully Homomorphic Encryption over the Torus) scheme, which allows computations to be performed on encrypted data without decryption.

## Disclaimer

This implementation is for educational purposes only and is not meant to be secure or optimized for efficiency in production environments. For production use, consider established libraries like [OpenFHE](https://github.com/openfheorg/openfhe-development), [SEAL](https://github.com/microsoft/SEAL), or [PALISADE](https://gitlab.com/palisade/palisade-development).

## Features

- Homomorphic encryption and decryption
- Homomorphic operations (addition, multiplication)
- Binary operations (AND, OR, XOR, NOT)
- Various data type support (bits, bytes, integers)
- Simple user-friendly interface

## Requirements

- Python 3.7+
- NumPy

## Quick Start

```python
from tfhe_lib import TFHEContext, homomorphic_and, homomorphic_or

# Create encryption context and generate keys
context = TFHEContext().generate_keys()

# Encrypt values
bit1 = context.encrypt_bit(1)
bit2 = context.encrypt_bit(0)

# Perform homomorphic operations
result_and = homomorphic_and(bit1, bit2)
result_or = homomorphic_or(bit1, bit2)

# Decrypt results
print(context.decrypt_to_bit(result_and))  # Should print 0
print(context.decrypt_to_bit(result_or))   # Should print 1
```

## Examples

See `examples.py` for more detailed examples of:

- Basic encryption/decryption
- Binary operations
- Arithmetic operations
- Integer encoding
- Byte/string encryption
- Performance comparisons

## Technical Details

The implementation is based on the Ring Learning With Errors (RLWE) cryptographic primitive and is inspired by the Fan-Vercauteren (FV) scheme. Key components include:

- Polynomial operations in the ring Z[X]/(x^n + 1)
- Homomorphic addition and multiplication
- Relinearization for maintaining ciphertext size
- Two relinearization techniques (base decomposition and modulus switching)

## Implementation Notes

- The default parameters are configured for educational purposes, not security
- Increasing polynomial size improves security but decreases performance
- The plaintext modulus defaults to 2 for binary operations
- Full homomorphic capabilities are limited (no bootstrapping)

## License

This project is open source and available for educational and research purposes.

## References

- Fan-Vercauteren (FV) scheme: https://eprint.iacr.org/2012/144.pdf
- Original implementation inspiration: https://gist.github.com/youben11/f00bc95c5dde5e11218f14f7110ad289