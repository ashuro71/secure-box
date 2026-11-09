#!/usr/bin/env python3

import struct 
import secrets
import getpass
import zipfile
import shutil
from pathlib import Path
from argparse import ArgumentParser
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from argon2.low_level import hash_secret_raw, Type
from datetime import datetime, timezone
from rich.tree import Tree 
from rich.live import Live

parser = ArgumentParser()
subparsers = parser.add_subparsers(dest='command', required=True)

class SecureBox:
    def __init__(self):
        pass
    
    def zip(
        self, 
        src: Path, 
        dest: Path
    ) -> Path | None:
        """
        Compress a directory into a .zip file.

        Args:
            src (Path): The path of the directory
            dest (Path): The name of the output .zip file

        Returns:
            Path | None: Returns the path of the generated .zip file. None if src was a file.
            
        Raise:
            ValueError: Raised if src is not a directory
        """
        
        if src.is_dir():
            with zipfile.ZipFile(dest, mode='w', compression=zipfile.ZIP_DEFLATED) as zipf:
                for item in src.rglob('*'):
                    
                    item_rel = item.relative_to(src)
                    zipf.write(item, item_rel)
                    
            return dest
        else:
            raise ValueError(f'The input src must be a directory')
        
    def unzip(
        self, 
        src: Path,
        dest: Path
    ) -> None:
        """
        Unzips a compressed file.

        Args:
            src (Path) : The path to the .zip file
            dest (Path): The path to the directory where the contents of the .zip file will
                         be extracted to. 
        Raises:
            ValueError: Raised if the src is not a valid .zip file.
        """
        
        if src.is_file():
            
            with zipfile.ZipFile(src, mode='r') as zipf:
                zipf.extractall(dest)

        else:
            raise ValueError(f'The input must be a .zip file')
        
    def generate_key(
        self, 
        salt: bytes
    ) -> bytes:
        """
        Generates the encryption key using a password through a KDF function

        Args:
            salt (bytes): Salt used to generate the key

        Returns:
            bytes: The generated encryption key
        """
        
        password = getpass.getpass('Password: ')
            
        memory_cost = 65536
        time_cost = 3
        parallelism = 4
        key_length = 32
        
        derived_key = hash_secret_raw(
            secret=password.encode(),
            salt=salt,
            time_cost=time_cost,
            memory_cost=memory_cost,
            parallelism=parallelism,
            hash_len=key_length,
            type=Type.ID
        )
        
        return derived_key
    
    def generate_associated_data(self, fpath: Path):
        fname = fpath.stem 
        ctime = int(datetime.now(timezone.utc).timestamp())
        
        associated_data = str(fname + '_' + '_' + str(ctime)).encode('UTF-8')
        
        return associated_data
    
    def lock(
        self, 
        args
    ) -> None:
        """
        Zips the directory and then encrypts it.
        
        Args:
            args: Argparsers's arguments, src (directory) and dest (.zip file). 
        
        Returns:
            None
        """

        #Logging            
        root = Tree(f"[bold cyan]Directory lock initialized[/bold cyan] [dim](ID: 1)[/dim]")
        
        salt = secrets.token_bytes(16)
        nonce = secrets.token_bytes(12)
        
        key = self.generate_key(salt)
        aesgcm = AESGCM(key)
        
        src = Path(args.input).resolve() 
        dest = Path(args.output_dir).resolve() / Path(args.name).with_suffix('.zip')
        
        with Live(root, refresh_per_second=10) as live:
            zip_node = root.add("🗜️ [bold yellow]Zipping...[/bold yellow]")
            #Zip the directory first
            zip_node.add(f"source: [green]{src}[/green]")
            zip_node.add(f"output: [green]{dest}[/green]")
            try:
                zip_fpath = self.zip(src, dest)
                zip_node.add("status: [bold green]success[/bold green]")
            except (zipfile.error, ValueError) as e:
                zip_node.add(f"status: [bold red]failed[/bold red]")
                zip_node.add(f"reason: [bold red]{str(e)}[/bold red]")
                exit(1)
            
            #Generate the assoc_data and pack its length in a header
            assoc_data = self.generate_associated_data(src)
            header = struct.pack('I', len(assoc_data))
            
            if zip_fpath is not None:
                cipher_f = zip_fpath.with_name(f'{zip_fpath.name}.gcm')
                
                encrypt_node = root.add("🔒 [bold blue]Encryption...[/bold blue]")
                
                encrypt_node.add(f"source: [green]{zip_fpath}[/green]")
                encrypt_node.add(f"output: [green]{cipher_f}[/green]")
                
                #Generate the cipertext based on the .zip file
                try:
                    with open(zip_fpath, mode='rb') as f:
                        ciphertext = aesgcm.encrypt(nonce, f.read(), assoc_data)
                        
                    #Write the ciphertext to a .gcm file. Output: dest.zip.gcm
                    with open(cipher_f, mode='wb') as f:
                        data = nonce + salt + header + assoc_data + ciphertext 
                        f.write(data) 
                
                    encrypt_node.add(f"status: [bold green]success[/bold green]")
                except (ValueError, TypeError) as e:
                    encrypt_node.add(f'status: [bold red]failed[/bold red]')
                    encrypt_node.add(f'reason: [bold red]{str(e)}[/bold red]')
                    return 
                
                
                #Delete the .zip file
                delete_node = root.add("💥 [bold red]Deleting...[/bold red]")
                
                delete_node.add(f"source: [red]{zip_fpath}[/red]")
                zip_fpath.unlink()
                delete_node.add("status: [bold green]success[/bold green]")
                
                #Delete the input directory after zipping if --delete flag is set
                if args.delete:
                    delete_node.add(f"source: [red]{src}[/red]")
                    shutil.rmtree(src)
                    delete_node.add(f"status: [bold green]success[/bold green]")
                
    def unlock(
        self, 
        args
    ) -> None:
        
        """
        Decrypts the file and then unzips it.
        
        Args:
            args: Argparsers's arguments, src (.zip.gcm file) and dest (directory)
            
        Returns:
            None
        """
        
        root = Tree(f"[bold cyan]Directory unlock initialized[/bold cyan] [dim](ID: 1)[/dim]")
        
        gcm = Path(args.input).resolve()
        
        #Extract the nonce, ciphertext and the salt from the .zip.gcm file.
        with open(gcm, mode='rb') as f:
            data = f.read()
            
            nonce = data[:12]
            salt = data[12:28]
            header = data[28:32]
            ad_len = struct.unpack('I', header)[0]
            assoc_data = data[32:32+ad_len]
            ciphertext = data[32+ad_len:]
            
        #Generate the key
        key = self.generate_key(salt)
        
        aesgcm = AESGCM(key)
        
        uncrypted_zip_file = Path(args.output_dir).resolve() / Path(args.name).with_suffix('.zip')
        
        with Live(root, refresh_per_second=4) as live:
            #Decrypt the ciphertext
            decrypt_node = root.add("🔓 [bold blue]Decrypting...[/bold blue]")
            
            decrypt_node.add(f"source: [green]{gcm}[/green]")
            decrypt_node.add(f'output: [green]{uncrypted_zip_file}[/green]')
            try:
                plaintext = aesgcm.decrypt(nonce, ciphertext, assoc_data)   
                
                #Write the decrypted data to a .zip file
                with open(uncrypted_zip_file, mode='wb') as f:
                    f.write(plaintext)
                    
                decrypt_node.add('status: [bold green]success[/bold green]')
            except Exception as e:
                decrypt_node.add('status: [bold red]failed[/bold red]')
                decrypt_node.add(f'reason: [bold red]{str(e)}[/bold red]')
                return 
            
            #Unzip the file
            unzip_node = root.add("🗜️ [bold yellow]Unzipping...[/bold yellow]")
            try:
                unzip_node.add(f'source: [green]{uncrypted_zip_file}[/green]')
                unzip_node.add(f'output: [green]{uncrypted_zip_file.with_suffix("")}[/green]')
                self.unzip(uncrypted_zip_file, uncrypted_zip_file.with_suffix(""))  
                unzip_node.add(f'status: [bold green]success[/bold green]')
            except (zipfile.error, ValueError) as e:
                unzip_node.add(f'status: [bold red]failed[/bold red]')
                unzip_node.add(f'reason: [bold red]{str(e)}[/bold red]')
                exit(1)
                
            #Delete the .zip.gcm file
            delete_node = root.add("💥 [bold red]Deleting...[/bold red]")
            
            delete_node.add(f'source: [red]{gcm}[/red]')
            gcm.unlink()        
            delete_node.add(f'status: [bold green]success[/bold green]')
            
            #Delete the .zip file
            delete_node.add(f'source: [red]{uncrypted_zip_file}[/red]')
            uncrypted_zip_file.unlink()
            delete_node.add(f'source: [bold green]success[/bold green]')
        
if __name__ == '__main__':
    box = SecureBox()
    
    lock_parser = subparsers.add_parser(name='lock')
    lock_parser.add_argument('--input', dest='input', type=Path)
    lock_parser.add_argument('--output-dir', dest='output_dir', type=Path)
    lock_parser.add_argument('--name', dest='name', type=Path)
    lock_parser.add_argument('-d', '--delete', dest='delete', action='store_true')
    lock_parser.set_defaults(func=box.lock)
    
    unlock_parser = subparsers.add_parser(name='unlock')
    unlock_parser.add_argument('--input', dest='input', type=Path)
    unlock_parser.add_argument('--output-dir', dest='output_dir', type=Path)
    unlock_parser.add_argument('--name', dest='name', type=Path)
    unlock_parser.set_defaults(func=box.unlock)
    
    args = parser.parse_args()
    args.func(args)
    
         
        
        


