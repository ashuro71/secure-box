#!/usr/bin/env python3

import struct 
import secrets
import getpass
import zipfile
import shutil
import logging 
import re 
import tempfile
from pathlib import Path
from argparse import ArgumentParser
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag, InvalidKey
from argon2.low_level import hash_secret_raw, Type
from datetime import datetime, timezone
from rich.logging import RichHandler
from rich.console import Console

console = Console()

logging.basicConfig(
    level=logging.DEBUG,               
    format="%(message)s",              
    datefmt="[%X.%f]",                    
    handlers=[RichHandler(
        console=console, 
        rich_tracebacks=True          
        #tracebacks_show_locals=True    
)])

logger = logging.getLogger('rich-secure-box')

#Zip a directory, then wrap it in an AES-256-GCM container (.zip.gcm), and the reverse.
class SecureBox:
    def __init__(
        self, 
        mem_cost: int = 65536, 
        time_cost: int = 4, 
        parallelism: int = 4
    ):
        
        #Argon2id costs used when encrypting. decrypt() overwrites these with the
        #values recorded in whichever container it is opening.
        self.memory_cost = mem_cost
        self.time_cost = time_cost
        self.parallelism = parallelism
        self.key_length = 32
        self.version = 'v1' 
        
        self.validate_argon2_costs()
        self.parser = self.create_parser()
        
    def validate_argon2_costs(self) -> None:
        """
        Validate that the argon2 costs (time_cost, memory_cost, parallelism)
        are within certain paramters.

        Raises:
            ValueError: Raised when time_cost is outside the specified bounds
            ValueError: Raised when memory_cost is outside the specified bounds
            ValueError: Raised when parallelism is outside the specified bounds
        """
        if self.time_cost not in range(1,6):
            raise ValueError(f'[*] Time cost must be between 1 and 5 (inclusive)')
        
        if self.memory_cost not in range(16384, 1048577):
            raise ValueError(f'[*] Memory cost must be 16385 and 1048577 (inclusive)')
        
        if self.parallelism not in range(1, 5):
            raise ValueError(f'[*] Parallelism must be between 1 and 4 (inclusive)') 
       
    def validate_assoc_data(self, assoc_data: bytes):
        """
        Validates the format of the association data against a specific version.

        Args:
            assoc_data (bytes): The association data being validated

        Raises:
            InvalidAssocDataFormat: When the format doesn't match against the specified version
        """
        class InvalidAssocDataFormat(Exception):
            pass 
        
        decoded = assoc_data.decode()
        pattern = rf"{self.version}_[a-zA-Z0-9-_]+_\d+_\d+_\d+"     
        
        if not re.fullmatch(pattern, decoded):
            raise InvalidAssocDataFormat(f'[*] Format of the assoc data is invalid.')
        
    def validate_password_constraints(self, password: str) -> None:
        """
        Validates that the password follows certain standards.

        Args:
            password (str): The password being validated

        Raises:
            InvalidPasswordFormat: Also lists out the exact validations triggered
        """
        class InvalidPasswordFormat(Exception):
            pass 
        
        validations = []
        if not 8 <= len(password) <= 20:
            validations.append('Length must be between 8 and 20 (inclusive)')
        if not re.search(r'[a-z]', password):
            validations.append('Must contain atleast one lowercase character')
        if not re.search(r'[A-Z]', password):
            validations.append('Must contain atleast one uppercase character')
        if not re.search(r'[0-9]', password):
            validations.append('Must contain atleast one numerical character')
        if not re.search(r'[!@#$&?]', password):
            validations.append('Must contain atleast one special character')
        if re.search(r'\s', password):
            validations.append('Must not include spaces')
        
        if len(validations) > 0:
            raise InvalidPasswordFormat(validations)
            
    def zip(self, src: Path, dest: Path) -> Path | None:
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
                #Relative paths, so the archive holds src's contents at top level
                #rather than a containing folder.
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
        
        # if not zipfile.is_zipfile(src):
        #     raise ValueError(f'The input must be a .zip file')
            
        with zipfile.ZipFile(src, mode='r') as zipf:
            zipf.extractall(dest)  
            
    def verify(self, args):
        """
        Checks that the container (.zip.gcm) hasn't been corrupted.

        Args:
            args (input): Argparser args used to get the containter's (.zip.gcm) path
        """
        src = Path(args.input).resolve()
        
        logger.info(f'[*] Start: Integrity check')
        logger.info(f'[*] Target: {src}')
        
        try:
            with tempfile.NamedTemporaryFile(suffix='.zip', mode='w+') as f:
                dest = Path(f.name)
                
                self.decrypt(src, dest)
                logger.info(f'[*] OK: {src}')
    
        except InvalidTag as e:
            logger.exception(f'[x] Error while verifying/decrypting: {str(e)}')
            return
            
        logger.info(f'[*] Complete: Integrity Check')
        
    def generate_key(
        self, 
        salt: bytes,
        secret: bytes,
    ) -> bytes:
        """
        Generates the encryption key using a password through a KDF function

        Args:
            salt (bytes): Salt used to generate the key

        Returns:
            bytes: The generated encryption key
        """
            
        #Costs are taken from instance state, which decrypt() may have replaced.
        derived_key = hash_secret_raw(
            secret=secret,
            salt=salt,
            time_cost=self.time_cost,
            memory_cost=self.memory_cost,
            parallelism=self.parallelism,
            hash_len=self.key_length,
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
        version = self.version
        
        components = [version, fname, ctime, self.memory_cost, self.time_cost, self.parallelism]
        assoc_data = '_'.join(str(i) for i in components)
        
        return assoc_data.encode()
    
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
        
        #Fixed-offset layout: nonce(12) | salt(16) | ad_len(4) | ad(ad_len) | ciphertext+tag
        with open(src, mode='rb') as f:
            data = f.read()
            
            nonce = data[:12]
            salt = data[12:28]
            header = data[28:32]
            ad_len = struct.unpack('<I', header)[0]
            assoc_data = data[32:32+ad_len]
            ciphertext = data[32+ad_len:]
            
        #Re-derive using the costs recorded in the container, so archives written under
        #other defaults stay readable.
                
        self.validate_assoc_data(assoc_data)
        self.memory_cost, self.time_cost, self.parallelism = [int(i) for i in assoc_data.decode().split('_')[-3:]]
        self.validate_argon2_costs()
            
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
        
        #Generating the assoc data
        assoc_data = self.generate_associated_data(src)
        self.validate_assoc_data(assoc_data)
        
        header = struct.pack('<I', len(assoc_data))
        
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
        dest = Path(args.output_dir).resolve() / Path(args.name).with_suffix('.zip.gcm')                
        
        logger.info(f'[+] Target: {src}')
        
        password = getpass.getpass('Password: ')
        self.validate_password_constraints(password)
        
        #Zip the directory first
        try:
            with tempfile.NamedTemporaryFile(suffix='.zip', mode='w+') as f:
                zpath = Path(f.name)
        
                self.zip(src, zpath)      
                self.encrypt(zpath, dest, password.encode())     
                logger.info(f'[+] Locked: {dest}')
            
        except (zipfile.error, TypeError, ValueError) as e:
            logger.exception(f'[x] Zipping/encrypting: {str(e)}')
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
        dest = Path(args.output_dir).resolve() / Path(args.name)
        
        logger.info(f'[+] Target: {src}')
        
        #Decrypt the .zip.gcm file to .zip
        try:
            with tempfile.NamedTemporaryFile(suffix='.zip', mode='w+') as f:
                zpath = Path(f.name)
                
                self.decrypt(src, zpath)
                self.unzip(zpath, dest) 
                 
                logger.info(f'[+] Unlocked: {dest}')            
                
        except (zipfile.error, InvalidTag, ValueError, InvalidKey) as e:
            logger.exception(f'[x] Error while decrypting: {str(e)}')
            return 
            
        #--delete removes this operation's own input: the container here, the source
        #directory in lock().
        if args.delete:
            src.unlink()        
            logger.info(f'[+] Deleted: {src}')
            
        logger.info(f'[*] Complete: Unlock')
        
    #Subcommands: lock, unlock, verify.
    def create_parser(self):
        
        parser = ArgumentParser()
        subparsers = parser.add_subparsers(dest='command', required=True)
        
        lock_parser = subparsers.add_parser(name='lock')
        lock_parser.add_argument('--input', dest='input', type=Path, required=True)
        lock_parser.add_argument('--output-dir', dest='output_dir', type=Path, required=True)
        lock_parser.add_argument('--name', dest='name', type=Path, required=True)
        lock_parser.add_argument('-d', '--delete', dest='delete', action='store_true')
        lock_parser.set_defaults(func=self.lock)
        
        unlock_parser = subparsers.add_parser(name='unlock')
        unlock_parser.add_argument('--input', dest='input', type=Path, required=True)
        unlock_parser.add_argument('--output-dir', dest='output_dir', type=Path, required=True)
        unlock_parser.add_argument('--name', dest='name', type=Path, required=True)
        unlock_parser.add_argument('-d', '--delete', dest='delete', action='store_true')
        unlock_parser.set_defaults(func=self.unlock)
        
        verify_parser = subparsers.add_parser(name='verify')
        verify_parser.add_argument('--input', dest='input', type=Path, required=True)
        verify_parser.set_defaults(func=self.verify) 
    
        return parser
    
    def execute(self):
        args = self.parser.parse_args()
        args.func(args)
               
if __name__ == '__main__':
    _ = SecureBox().execute()
    
    
    
    
    
    
         
        
        


