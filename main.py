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
from cryptography.exceptions import InvalidTag
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
        
        logger.info(f'[*] Start: Integrity check')
        logger.info(f'[*] Target: {src}')
        
        dest = src.with_suffix("") 
        self.decrypt(src, dest)
         
        if dest.exists():
            if not zipfile.is_zipfile(dest):
                raise ValueError(f'[*] Not a .zip file: {dest}')
            
            with zipfile.ZipFile(dest, mode='r') as zf:
                
                for info in zf.infolist():
                    try:
                        with zf.open(info) as f:    
                            while f.read(1024 * 4):
                                pass 
                        logger.info(f'[+] OK: {info.filename}')
                        
                    except (zipfile.BadZipFile, lzma.LZMAError) as e:
                        logger.error(f'[x] Corrupt: {info.filename}')
            
            dest.unlink()
            logger.info(f'[+] Deleted: {dest}')
            
            logger.info(f'[*] Complete: Integrity Check')
        
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
    
    def generate_associated_data(
        self, 
        fpath: Path
    ) -> bytes:
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
    
    def decrypt(
        self, 
        src: Path, 
        dest: Path
    ) -> None:
        """
        Decrypts a .gcm file.

        Args:
            src (Path): The path of the source .gcm file that has to be decrypted
            dest (Path): The path of the output .zip file

        Returns:
            None: Doesn't return anything
        """
            
        if src.suffix != '.gcm':
            raise ValueError(f'[x] src is not a .gcm file')
        
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
        
        plaintext = aesgcm.decrypt(nonce, ciphertext, assoc_data) 
        with open(dest, mode='wb') as f:
            f.write(plaintext)
            
    def encrypt(self, 
        src: Path,
        dest: Path,
        password: bytes
    ) -> Path | None:
        
        salt = secrets.token_bytes(16)
        nonce = secrets.token_bytes(12)
        
        key = self.generate_key(salt, password)
        
        aesgcm = AESGCM(key)
        logger.info(f'[+] Generated: Nonce, Salt, Key')
        
        assoc_data = self.generate_associated_data(src)
        header = struct.pack('I', len(assoc_data))
        
        with open(src, mode='rb') as f:
            cipher = aesgcm.encrypt(nonce, f.read(), assoc_data)
            
        with open(dest, mode='wb') as f:
            data = nonce + salt + header + assoc_data + cipher
            f.write(data)
        
    
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

        logger.info(f'[*] Start: Lock')
        
        src = Path(args.input).resolve() 
        dest = Path(args.output_dir).resolve() / Path(args.name).with_suffix('.zip')                
        
        logger.info(f'[+] Target: {src}')
        
        password = getpass.getpass('Password: ').encode()
        
        #Zip the directory first
        try:
            self.zip(src, dest)
            logger.info(f'[+] Zipped: {dest}')
            
            if dest.exists():
                gcm = dest.with_name(f'{dest.name}.gcm')
                
                self.encrypt(dest, gcm, password)     
                logger.info(f'[+] Encrypted: {gcm}')
                
                dest.unlink()
                logger.info(f'[+] Deleted: {dest}')
            
        except (zipfile.error, TypeError, ValueError) as e:
            logger.error(f'[x] Zipping/encrypting: {str(e)}')
            return 
            
        #Delete the input directory after zipping if --delete flag is set
        if args.delete:
            shutil.rmtree(src)
            logger.info(f'[+] Deleted: {src}')
            
        logger.info(f'[*] Completed: Lock')
            
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
        
        logger.info(f'[*] Start: Unlock')
        
        src = Path(args.input).resolve()
        dest = Path(args.output_dir).resolve() / Path(args.name).with_suffix('.zip')
        
        logger.info(f'[+] Target: {src}')
        
        #Decrypt the .zip.gcm file to .zip
        try:
            self.decrypt(src, dest)
            logger.info(f'[+] Decrypted: {dest}')
            
            self.unzip(dest, dest.with_suffix(""))  
            logger.info(f'[+] Unzipped: {dest.with_suffix("")}')   
            
            dest.unlink()
            logger.info(f'[+] Deleted: {dest}')             
                
        except (zipfile.error, InvalidTag, ValueError) as e:
            logger.error(f'[x] Error while decrypting: {str(e)}')
            return 
            
        if args.delete:
            src.unlink()        
            logger.info(f'[+] Deleted: {src}')
            
        logger.info(f'[*] Complete: Unlock')
            
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
    
         
        
        


