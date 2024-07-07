# TimeLockCrypt
## A tool for encrypting files using puzzle based time-lock encryption and password
<img src="background.png" width="900">

<!-- DESCRIPTION -->
## Description:

Puzzle-based time-lock encryption offers a secure method for time-delayed data access by leveraging computational puzzles that require a predetermined amount of time to solve. This ensures that the encrypted information remains inaccessible until the puzzle is solved, preventing premature access. Unlike traditional time-lock methods reliant on synchronized clocks or external servers, puzzle-based encryption is self-contained, enhancing security and resilience against tampering or synchronization failures. Its deterministic nature guarantees that the delay is consistent and predictable, providing a reliable mechanism for enforcing timed release of sensitive data. This approach is particularly beneficial for applications requiring controlled information dissemination, such as scheduled disclosures, time-sensitive data sharing, or secure communication protocols.

<!-- FEATURES -->
## Features:

- Combines time-lock encryption with a password

- Uses AES-256-GCM for encryption

- Encrypts/decrypts text and file input

- Argon2id for key derivation using 8 threads, 100MB of memory and time cost of 4.

- Built in Python

<!-- INSTALLATION -->
## Installation:
```
git clone https://github.com/umutcamliyurt/TimeLockCrypt.git
cd TimeLockCrypt/
sudo apt-get update
sudo apt install python3 python3-tk
pip3 install -r requirements.txt
python3 timelockcrypt.py
```

<!-- USAGE -->
## Usage:
```
python3 timelockcrypt.py 
Enter password: 
Re-enter password: 
Enter 'et' for encrypting text, 'dt' for decrypting text, 'ef' for encrypting file, or 'df' for decrypting file: et
Enter text to encrypt: test   
Enter time-lock duration (e.g., '30s', '5m', '2h', '1d', '1w'): 10s
Proof-of-work iterations(save this): 18

Encrypted text: 5bEvHTZxM2dP/QKekbDLmmkXdps0cLmo5VNha7mRpaPBpv8k5qfJJlqEojOmQlvcyDRZRajF8ndPgKRGQxm8lTbUWpHX++oaSCNpSYaYp5TDZSVSckNpMLj2wyw=

```

<!-- LICENSE -->
## License

Distributed under the MIT License. See `LICENSE` for more information.
