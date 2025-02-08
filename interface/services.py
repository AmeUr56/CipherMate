from Crypto.Cipher import AES,PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
import ast
import json
#------------------------------------------------------Symmetric------------------------------------------------------#
# Save key, tag, and nonce to a file
def symmetric_save_to_file(filename, key, tag, nonce):
    data = {
        "key": key.hex(),
        "tag": tag.hex(),
        "nonce": nonce.hex()
    }
    with open(filename, "w") as file:
        json.dump(data, file)

# Load key, tag, and nonce from a file
def symmetric_load_from_file(filename):
    with open(filename, "r") as file:
        data = json.load(file)
    # Convert hex strings back to bytes
    key = bytes.fromhex(data["key"])
    tag = bytes.fromhex(data["tag"])
    nonce = bytes.fromhex(data["nonce"])
    return key, tag, nonce

def symmetric_encryption(text, save_keys=False, filename="keys.json"):
    text_bytes = text.encode('utf-8')
    
    key = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_GCM)

    
    nonce = cipher.nonce

    # Encrypt and get both ciphertext and tag
    ciphertext, tag = cipher.encrypt_and_digest(text_bytes)
    
    if save_keys:
        if ".json" in filename:
            symmetric_save_to_file(filename, key, tag, nonce)
        else:
            symmetric_save_to_file(filename+".json", key, tag, nonce)
            
    return (ciphertext, tag), key, nonce



def symmetric_decryption(ciphertext, tag=None, key=None, nonce=None, load_keys=False, filename="keys.json"):
    if load_keys:
        if ".json" not in filename:
            filename += ".json"
        key, tag, nonce = symmetric_load_from_file(filename)
    else:
        if tag is None or key is None or nonce is None:
            raise ValueError("Tag, Key, and Nonce are required when load_keys is False")
        else:
            key = bytes.fromhex(key)
            tag = bytes.fromhex(tag)
            nonce = bytes.fromhex(nonce)
    
    # Convert the ciphertext string to actual bytes
    ciphertext_bytes = ast.literal_eval(ciphertext)
    
    # Decrypt and verify the tag
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext_bytes, tag)
    
    return plaintext.decode()

#------------------------------------------------------Asymmetric------------------------------------------------------#
# Save keys to a file    
def asymmetric_save_to_file(filename, key):
    with open(filename, 'wb') as f:
        f.write(key)

# Load keys from a file
def asymmetric_load_from_file(filename):
    with open(filename, 'rb') as f:
        key = f.read()
    return key

def asymmetric_encryption(text, public_key=None, save_keys=False, filename="default.bin"):
    text_bytes = text.encode('utf-8')
    if public_key is None:
        # Generate RSA keys
        keys = RSA.generate(2048)
        # Export keys
        public_key = keys.publickey().export_key()
        private_key = keys.export_key()

        if save_keys:
            try:
                name = filename.split('.')[0]
                format = filename.split('.')[1]
            except:
                raise FileNotFoundError
            
            # Save public key
            asymmetric_save_to_file(f"{name}_public_key.{format}", public_key)
            # Save private key
            asymmetric_save_to_file(f"{name}_private_key.{format}", private_key)
            
        # Return the generated public key for encryption
        public_key_obj = keys.publickey()
    else:
        # Import the provided public key
        try:
            public_key_obj = RSA.import_key(public_key)
        except:
            raise ValueError("Invalid RSA Public key")
                
    # Encrypt the message with the public key
    cipher = PKCS1_OAEP.new(public_key_obj)
    
    ciphertext = cipher.encrypt(text_bytes)
    return ciphertext, public_key
    
def asymmetric_decryption(ciphertext,private_key=None,load_private_key=False,filename="default"):
    if private_key is None:
        if load_private_key:
            raise ValueError("Private Key is required")
        else:
            # Import RSA private key
            private_key = RSA.import_key(asymmetric_load_from_file(f"{filename}_private_key.bin"))
    
    # Decrypt the message with the private key
    cipher = PKCS1_OAEP.new(RSA.import_key(private_key))
    plaintext = cipher.decrypt(ciphertext)

    return plaintext

#------------------------------------------------------Hashing------------------------------------------------------#
# Save salt to a file    
def hashing_save_to_file(filename, salt):
    with open(filename, 'wb') as f:
        f.write(salt)

# Load salt from a file
def hashing_load_from_file(filename):
    with open(filename, 'rb') as f:
        salt = f.read()
    return salt

def hash_encryption(text,salt=None,save_salt=True,load_salt=False,filename="default_salt.bin"):
    if salt is None:
        if not load_salt:
            # Generate a random salt
            salt = get_random_bytes(16)
        
            # Save Salt to a file
            if save_salt:
                hashing_save_to_file(filename,salt)
        else:
            salt = hashing_load_from_file(filename)
            
    text = text.encode()
    # Combine data and salt
    text_with_salt = salt + text

    # Hash the combined data with SHA256
    hash_obj = SHA256.new(text_with_salt)

    return hash_obj.hexdigest(),salt