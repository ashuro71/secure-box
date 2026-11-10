#!/usr/bin/env python3

import struct 
import secrets
import getpass
import zipfile
import lzma 
import shutil
import logging 
from pathlib import Path
from argparse import ArgumentParser
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from argon2.low_level import hash_secret_raw, Type
from datetime import datetime, timezone
from rich.logging import RichHandler
from rich.console import Console

console = Console()

logging.basicConfig(level=logging.DEBUG,               
    format="%(message)s",              
    datefmt="[%X.%f]",                    
    handlers=[RichHandler(
        console=console, 
        rich_tracebacks=True,          
        tracebacks_show_locals=True    
    )])

logger = logging.getLogger('rich-secure-box')

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
            with zipfile.ZipFile(dest, mode='w', compression=zipfile.ZIP_LZMA) as zipf:
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
        
        if not zipfile.is_zipfile(src):
            raise ValueError(f'The input must be a .zip file')
            
        with zipfile.ZipFile(src, mode='r') as zipf:
            zipf.extractall(dest)  
            
    def verify(self, args):
        src = Path(args.input).resolve()
        
        dest = src.with_suffix("") 
        decrypted_src = self.decrypt(src, dest)
        
        logging.info(f'[*] Decrypted: {src} -> {dest}')
         
        if decrypted_src is not None:
            if not zipfile.is_zipfile(decrypted_src):
                raise ValueError(f'[*] Not a .zip file: {decrypted_src}')
            
            with zipfile.ZipFile(decrypted_src, mode='r') as zf:
                logger.info(f'[*] Start: Integrity check')
                for info in zf.infolist():
                    try:
                        with zf.open(info) as f:    
                            while f.read(1024 * 4):
                                pass 
                        logger.info(f'[*] OK: {info.filename}')
                        
                    except (zipfile.BadZipFile, lzma.LZMAError) as e:
                        logger.error(f'[x] Corrupt: {info.filename}')

            logger.info(f'[*] Complete: Integrity Check')
            
            dest.unlink()
            logger.info(f'[*] Deleted: {dest}')
        
    def generate_key(
        self, 
        salt: bytes,
        secret: bytes,
        memory_cost: int = 65536,
        time_cost: int = 3,
        parallelism: int = 4,
        key_length = 32
    ) -> bytes:
        """
        Generates the encryption key using a password through a KDF function

        Args:
            salt (bytes): Salt used to generate the key

        Returns:
            bytes: The generated encryption key
        """
            
        derived_key = hash_secret_raw(
            secret=secret,
            salt=salt,
            time_cost=time_cost,
            memory_cost=memory_cost,
            parallelism=parallelism,
            hash_len=key_length,
            type=Type.ID
        )
        
        return derived_key
    
    def generate_associated_data(self, fpath: Path):
        """
        Generate the associate data

        Args:
            fpath (Path): The path of input directory

        Returns:
            bytes : The assoc data generated through the name + datetime 
        """
        
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
                
        salt = secrets.token_bytes(16)
        nonce = secrets.token_bytes(12)
        
        password = getpass.getpass('Password: ').encode()
        
        key = self.generate_key(salt, password)
        aesgcm = AESGCM(key)
        
        src = Path(args.input).resolve() 
        dest = Path(args.output_dir).resolve() / Path(args.name).with_suffix('.zip')
        
        #Zip the directory first
        try:
            zip_fpath = self.zip(src, dest)
        except (zipfile.error, ValueError) as e:
            exit(1)
        
        #Generate the assoc_data and pack its length in a header
        assoc_data = self.generate_associated_data(src)
        header = struct.pack('I', len(assoc_data))
        
        if zip_fpath is not None:
            cipher_f = zip_fpath.with_name(f'{zip_fpath.name}.gcm')
        
            #Generate the cipertext based on the .zip file
            try:
                with open(zip_fpath, mode='rb') as f:
                    ciphertext = aesgcm.encrypt(nonce, f.read(), assoc_data)
                    
                #Write the ciphertext to a .gcm file. Output: dest.zip.gcm
                with open(cipher_f, mode='wb') as f:
                    data = nonce + salt + header + assoc_data + ciphertext 
                    f.write(data) 
            
            except (ValueError, TypeError) as e:
                return 
            
            
            #Delete the .zip file
            zip_fpath.unlink()
            
            #Delete the input directory after zipping if --delete flag is set
            if args.delete:
                shutil.rmtree(src)
    
    def decrypt(
        self, 
        src: Path, 
        dest: Path
    ) -> Path | None:
        
        src = Path(src).resolve()
        dest = Path(dest).resolve()
        
        #Extract the nonce, ciphertext and the salt from the .zip.gcm file.
        with open(src, mode='rb') as f:
            data = f.read()
            
            nonce = data[:12]
            salt = data[12:28]
            header = data[28:32]
            ad_len = struct.unpack('I', header)[0]
            assoc_data = data[32:32+ad_len]
            ciphertext = data[32+ad_len:]
            
        password = getpass.getpass('Password: ').encode()
        key = self.generate_key(salt, password)
                
        aesgcm = AESGCM(key)
        
        try:
            plaintext = aesgcm.decrypt(nonce, ciphertext, assoc_data) 
            with open(dest, mode='wb') as f:
                f.write(plaintext)
                
            return dest
        
        except Exception as e:
            print(f'[*] Exception while decrypting {src}: {str(e)}')
        
        
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
        
        src = Path(args.input).resolve()
        dest = Path(args.output_dir).resolve() / Path(args.name).with_suffix('.zip')
        
        try:
            unencrypted_zip_file = self.decrypt(src, dest)
            
            if unencrypted_zip_file is not None:
                self.unzip(unencrypted_zip_file, unencrypted_zip_file.with_suffix(""))  
                unencrypted_zip_file.unlink()
                
        except (zipfile.error, ValueError) as e:
            exit(1)
            
        if args.delete:
            src.unlink()        
        
if __name__ == '__main__':
    box = SecureBox()
    
    lock_parser = subparsers.add_parser(name='lock')
    lock_parser.add_argument('--input', dest='input', type=Path, required=True)
    lock_parser.add_argument('--output-dir', dest='output_dir', type=Path, required=True)
    lock_parser.add_argument('--name', dest='name', type=Path, required=True)
    lock_parser.add_argument('-d', '--delete', dest='delete', action='store_true')
    lock_parser.set_defaults(func=box.lock)
    
    unlock_parser = subparsers.add_parser(name='unlock')
    unlock_parser.add_argument('--input', dest='input', type=Path, required=True)
    unlock_parser.add_argument('--output-dir', dest='output_dir', type=Path, required=True)
    unlock_parser.add_argument('--name', dest='name', type=Path, required=True)
    unlock_parser.add_argument('-d', '--delete', dest='delete', action='store_true')
    unlock_parser.set_defaults(func=box.unlock)
    
    verify_parser = subparsers.add_parser(name='verify')
    verify_parser.add_argument('--input', dest='input', type=Path, required=True)
    verify_parser.set_defaults(func=box.verify)
    
    args = parser.parse_args()
    args.func(args)
    
         
        
        


