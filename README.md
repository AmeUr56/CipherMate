# CipherMate - A Powerful Encryption CLI Tool

## About CipherMate

CipherMate is a command-line interface (CLI) tool that provides easy-to-use encryption functionalities, including both symmetric and asymmetric encryption, secure hashing, and key management.

## Features

*   🔹 **Symmetric Encryption (AES-GCM)**
*   🔹 **Asymmetric Encryption (RSA-OAEP)**
*   🔹 **Secure Hashing (SHA-256)**
*   🔹 **Key Management & Storage**

## Usage

### General Information

Run `python interface.py about` to see details about the interface.

### Symmetric Encryption
To encrypt text using the symmetric method:

```
python interface.py symmetric-encrypt
```
#### Options:
- **--save_keys**: Whether to store the key, tag, nonce in a file (default is yes).
- **--filename**: Filename for storing keys.
- **--key**: Key to encrypt data with.
- **text**: The text to be encrypted.

### Symmetric Decryption
To decrypt encrypted text using the symmetric method:

```
python interface.py symmetric-decrypt
```
#### Options:
- **--load_keys**: Whether to load saved keys (tag, key, nonce).
- **--filename**: Filename to store keys.
- **ciphertext**: The encrypted text to be decrypted.

### Asymmetric Encryption
To encrypt text using the asymmetric method:

```
python interface.py asymmetric-encrypt
```

#### Options:
- **--save_keys**: Whether to store the public and private keys to a file.
- **--filename**: Filename to store keys.
- **text**: The text to be encrypted.

### Asymmetric Decryption
To decrypt encrypted text using the asymmetric method:
```
python interface.py asymmetric-decrypt
```
#### Options:
- **--load_private_key**: Whether to load the private key from a file.
- **--filename**: Filename of the stored private key.
- **ciphertext**: The encrypted text to be decrypted.

### Hashing
To hash text:
```
python interface.py hash
```
#### Options:
- **--load_salt**: Whether to load salt from a file.
- **--save_salt**: Whether to store salt to a file.
- **--filename**: Filename to save or load salt.
- **text**: The text to be hashed.

## Note
All outputs are automatically copied.

## Installation
```
cd ciphermate
```
To install required libraries:
```
pip install -r requirements.txt
```
To build the CLI:
```
pip install .
```
Try it:
```
ciphermate about
```