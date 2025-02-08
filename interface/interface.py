import click
import pyperclip
from rich.console import Console
from rich.layout import Layout

from .services import symmetric_encryption,symmetric_decryption,asymmetric_encryption,asymmetric_decryption,hash_encryption
from .scripts import ascii_banner,progress_bar

# Initialize Rich Console
console = Console()

@click.group()
def ciphermate():
    pass

@ciphermate.command(help="provide details about the CipherMate cli.")
def about():
    console.print(f"[bold magenta]{ascii_banner('Cipher',font='roman')}[/bold magenta][bold green]{ascii_banner('Mate',font='roman')}[/bold green]")

    console.print("[bold cyan]CipherMate - A Powerful Encryption CLI Tool[/bold cyan]\n")
    console.print("[bold white]Features:[/bold white]")
    console.print("🔹 Symmetric Encryption (AES-GCM)")
    console.print("🔹 Asymmetric Encryption (RSA-OAEP)")
    console.print("🔹 Secure Hashing (SHA-256)")
    console.print("🔹 Key Management & Storage")
    
    console.print("\n[bold white]Usage:[/bold white]")
    console.print("- Run [italic green]ciphermate about[/italic green] to see details about the interface.")

    console.print("- Run [italic green]ciphermate symmetric-encrypt[/italic green] to encrypt text with symmetric method.")
    console.print("  --save_keys    Whether to store the key, tag, nonce in file (default is yes).")
    console.print("  --filename     Filename of the stored keys.")
    console.print("  --key          Key to encrypt data with.")
    console.print("  text           The text to be encrypted.")

    console.print("- Run [italic green]ciphermate symmetric-decrypt[/italic green] to decrypt encrypted text with symmetric method.")
    console.print("  --load_keys    Whether to load saved keys (tag, key, nonce).")
    console.print("  --filename     Filename to store keys in.")
    console.print("  ciphertext     The encrypted text to be decrypted.")

    console.print("- Run [italic green]ciphermate asymmetric-encrypt[/italic green] to encrypt text with asymmetric method.")
    console.print("  --save_keys    Whether to store the public and private keys to a file.")
    console.print("  --filename     Filename to store keys in.")
    console.print("  text           The text to be encrypted.")

    console.print("- Run [italic green]ciphermate asymmetric-decrypt[/italic green] to decrypt encrypted text with asymmetric method.")
    console.print("  --load_private_key Whether to load the private key from a file.")
    console.print("  --filename        Filename of the stored private key.")
    console.print("  ciphertext        The encrypted text to be decrypted.")

    console.print("- Run [italic green]ciphermate hash[/italic green] to hash text.")
    console.print("  --load_salt   Whether to load salt from file.")
    console.print("  --save_salt   Whether to store salt to file.")
    console.print("  --filename    Filename to save or load salt.")
    console.print("  text          The text to be hashed.")

    console.print("[bold yellow]Note:[/bold yellow] All outputs are Auto Copied.")
    console.print("[italic red]Developed by Ameur[/italic red]")

    
@ciphermate.command(help="symmetric encryption.")
@click.option('--save_keys',is_flag=True,help="wheter to store the key, tag, nonce in file or no, default is yes.")
@click.option('--filename',help="filename of the stored keys.")
@click.option('--key',help="key to encrypt data with.")
@click.argument("text")
def symmetric_encrypt(text,save_keys,filename,key):
    progress_bar(30)
            
    # Encryption Logic
    if filename is not None:
        if key is not None:
            (ciphertext,_),_,_ = symmetric_encryption(text,save_keys=save_keys,filename=filename,key=key)

        else:
            (ciphertext,_),_,_ = symmetric_encryption(text,save_keys=save_keys,filename=filename)
    else:
        (ciphertext,_),_,_ = symmetric_encryption(text,save_keys=save_keys)

        
    pyperclip.copy(ciphertext)
    console.print(ciphertext)
    console.print("[Output is Auto Copied]")

@ciphermate.command(help="symmetric decryption.")
#@click.option("--tag",help="the encryption tag.")
#@click.option("--key",help="the encryption key.")
#@click.option("--nonce",help="the encryption nonce.")
@click.option("--load_keys",is_flag=True,help="to load saved keys(tag,key,nonce).")
@click.option("--filename",help="filename to store keys in.")
@click.argument("ciphertext")
def symmetric_decrypt(ciphertext,load_keys,filename):
    progress_bar(30)
    # Decryption Login
    try:
        try:
            if filename is not None:
                plaintext = symmetric_decryption(ciphertext=ciphertext,load_keys=load_keys,filename=filename)
                
            else:
                plaintext = symmetric_decryption(ciphertext=ciphertext,load_keys=load_keys)
        except FileNotFoundError:
            console.print("File not found.")
            exit()
            
    except ValueError:
        console.print("Tag, Key, Nonce are required.")
        exit()
            
    pyperclip.copy(plaintext)
    console.print(plaintext)
    console.print("[Output is Auto Copied]")


@ciphermate.command(help="asymmetric encryption.")
#@click.option("--public_key",help="the encryption public key.")
@click.option("--save_keys",is_flag=True,help="wheter to store the public key and private key to a file or no.")
@click.option("--filename",help="filename to store keys in.")
@click.argument("text")
def asymmetric_encrypt(text,save_keys,filename):
    progress_bar(100)
    if filename:
        try:
            ciphertext, _ = asymmetric_encryption(text, save_keys=save_keys, filename=filename)
        except FileNotFoundError:
            console.print("File not found.")
            exit()
    else:
        ciphertext, _ = asymmetric_encryption(text, save_keys=save_keys)
    
    pyperclip.copy(ciphertext)
    console.print(ciphertext)
    console.print("[Output is Auto Copied]")
    
@ciphermate.command(help="asymmetric decryption.")
@click.option("--load_private_key",is_flag=True,help="to load the private key from a file.")
@click.option("--filename",help="filename of the stored private key.")
@click.argument("ciphertext")
def asymmetric_decrypt(ciphertext,load_private_key,filename):
    progress_bar(100)
    if filename is not None:
        plaintext = asymmetric_decryption(ciphertext,load_private_key=load_private_key,filename=filename)
    else:
        plaintext = asymmetric_decryption(ciphertext,load_private_key=load_private_key)

    pyperclip.copy(plaintext)
    console.print(plaintext)
    console.print("[Output is Auto Copied]")


@ciphermate.command(help="hashing")
@click.option("--load_salt",is_flag=True,help="whether to load salt from file or no.")
@click.option("--save_salt",is_flag=True,help="whether to store salt to file or no.")
@click.option("--filename",help="filename to save or load salt.")
@click.argument("text")
def hash(text,load_salt,save_salt,filename):
    progress_bar(20)
    if filename is not None:
        hashtext,_ = hash_encryption(text,save_salt=save_salt,load_salt=load_salt,filename=filename)
    else:
        hashtext,_ = hash_encryption(text,save_salt=save_salt,load_salt=load_salt,filename=filename)

    pyperclip.copy(hashtext)
    console.print(hashtext)
    console.print("[Output is Auto Copied]")

def main():
    ciphermate()
    
if __name__ == "__main__":
    main()