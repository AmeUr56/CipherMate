import click
from rich.console import Console
import pyperclip

from services import symmetric_encryption,symmetric_decryption
from scripts import ascii_banner

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
    console.print("💡 Run [italic green]python interface.py --help[/italic green] to see available commands.")
    console.print("💡 Run [italic green]python interface.py encrypt[/italic green] to encrypt text.")
    console.print("💡 Run [italic green]python interface.py decrypt[/italic green] to decrypt text.")
    console.print("💡 Run [italic green]python interface.py hash[/italic green] to hash text.")
    
    
@ciphermate.command(help="symmetric encryption.")
@click.option('--save_keys',is_flag=True,help="wheter to store the key, tag, nonce in file or no, default is yes.")
@click.option('--filename',help="filename of the stored keys.")
@click.option('--key',help="key to encrypt data with.")
@click.argument("text")
def symmetric_encrypt(text,save_keys,filename,key):
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
@click.option("--tag",help="encryption tag.")
@click.option("--key",help="encryption key.")
@click.option("--nonce",help="encryption nonce.")
@click.option("--load_keys",is_flag=True,help="to load saved keys(tag,key,nonce).")
@click.option("--filename",help="filename of the stored keys.")
@click.argument("ciphertext")
def symmetric_decrypt(ciphertext,tag,key,nonce,load_keys,filename):
    if filename is not None:
        plaintext = symmetric_decryption(ciphertext=ciphertext,tag=tag,key=key,nonce=nonce,load_keys=load_keys,filename=filename)
    else:
        plaintext = symmetric_decryption(ciphertext=ciphertext,tag=tag,key=key,nonce=nonce,load_keys=load_keys)

    pyperclip.copy(plaintext)
    console.print(plaintext)
    console.print("[Output is Auto Copied]")
    
if __name__ == "__main__":
    ciphermate()
