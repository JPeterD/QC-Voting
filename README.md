# Quantum-Safe Voting Application

This is a secure voting application based on TFHE (Fully Homomorphic Encryption over the Torus) post-quantum cryptography. It allows admins to create elections where users can cast encrypted votes that can be tallied without decrypting individual ballots.

## Admin Access

Default administrator credentials:
- Username: `admin`
- Password: `password123` 

## Features

- Post-quantum secure voting using TFHE homomorphic encryption
- Role-based access with admin-only election creation
- CAPTCHA verification to prevent automated voting
- Private vote casting with encrypted ballot storage
- Secure tallying without decrypting individual votes
- Visual results with charts and statistics
- Mobile-responsive web interface

## Project Structure

```
QC-Voting/
├── app/                      # Application package
│   ├── __init__.py           # Application factory
│   ├── models/               # Data models
│   │   ├── admin.py          # Admin model and authentication
│   │   ├── election.py       # Election model
│   │   └── vote.py           # Vote model and encryption
│   ├── routes/               # Route handlers
│   │   ├── auth.py           # Authentication routes
│   │   ├── elections.py      # Election management routes
│   │   ├── main.py           # Main page routes
│   │   └── votes.py          # Voting routes
│   └── utils/                # Utility functions
├── templates/                # HTML templates
├── votes/                    # Encrypted votes storage
├── results/                  # Election results storage
├── rlwe_he_scheme.py         # RLWE homomorphic encryption library
├── tfhe_lib.py               # TFHE wrapper library
├── admins.json               # Admin credentials
├── elections.json            # Election data
├── app.py                    # Application entry point
├── main.py                   # Original test script
└── requirements.txt          # Python dependencies
```

## Requirements

- Python 3.7+
- Flask
- NumPy
- Other dependencies in requirements.txt

## Installation and Setup

1. Clone the repository
2. Install dependencies: `pip install -r requirements.txt`
3. (Production only) Replace the test reCAPTCHA keys with your own keys from [Google reCAPTCHA](https://www.google.com/recaptcha/admin)
4. Run the application: `python app.py`
5. Access the web interface at http://127.0.0.1:5000

## Usage Guide

### Admin Functions (requires login)

1. **Login**: Navigate to the admin login page and enter credentials.
2. **Create Elections**: Create new elections with custom candidates.
3. **Close Elections**: End active elections and trigger vote counting.

### Voter Functions (no login required)

1. **View Elections**: Browse current and past elections.
2. **Cast Votes**: Participate in active elections with encrypted ballots.
3. **View Results**: See tallied results for closed elections.

## Technical Details

The implementation uses TFHE (Fully Homomorphic Encryption over the Torus) cryptography with these key features:

- **Homomorphic Encryption**: Performs calculations on encrypted data without decryption
- **Post-Quantum Security**: Resistant to attacks from quantum computers
- **Zero-Knowledge Vote Counting**: Tallies votes while preserving ballot privacy
- **Secure Session Management**: Prevents double-voting with session-based tracking

The backend library is based on the Ring Learning With Errors (RLWE) cryptographic primitive and is inspired by the Fan-Vercauteren (FV) scheme:

- Polynomial operations in the ring Z[X]/(x^n + 1)
- Homomorphic addition for vote tallying
- Serialization of encrypted votes for storage

## Security Notes

- Default TFHE parameters are configured for demonstration purposes
- In a production environment, the polynomial size should be increased
- Sessions are used to track voters (could be enhanced with more robust authentication)
- Admin credentials should be changed from defaults
- No personal data is stored with votes, ensuring voter privacy

## License

This project is open source and available for educational and research purposes.
