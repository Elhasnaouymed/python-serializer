r"""

     ____               _         _  _
    / ___|   ___  _ __ (_)  __ _ | |(_) ____ ___  _ __
    \___ \  / _ \| '__|| | / _` || || ||_  // _ \| '__|
     ___) ||  __/| |   | || (_| || || | / /|  __/| |
    |____/  \___||_|   |_| \__,_||_||_|/___|\___||_|

    Email: elhasnaouymed@zp1.net
    PGP: 153BD139C5E2F511918C30B9B50EB46612EB6345

"""
import os
import hmac
import json
import base64
import bcrypt
import hashlib
from datetime import datetime, UTC
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from . import exceptions as errors

__author__ = 'Mohamed Elhasnaouy'
__email__ = 'elhasnaouymed@zp1.net'
__license__ = 'GNU GPLv2'
__summary__ = 'Simple class to use AES-GCM, HMAC, and timestamp + serialize information into url-safe tokens'
__version__ = '0.0.1'
__status__ = 'Development'
__title__ = 'serializer'

from .exceptions import SerializerTokenCorrupt


class Serializer:
    def __init__(self, secret: str = None):
        """
        Helps to turn simple text into a timestamped, encrypted, HMAC-signed and url-safe token.
        Also hashes/checks passwords.
        :param secret: Optional, the private key to be used for HMAC and for AES encryption.
        """
        self._initialized = False
        if secret is not None:
            self._secret = secret
            self._master_key = hashlib.sha256(self._secret.encode()).digest()  # for more entropy
            self._initialized = True

    def initialize(self, secret: str):
        """
        Initialize the serializer if not yet initialized.
        :param secret: the private key to be used for HMAC and for AES encryption.
        :return: None.
        :raise SerializerAlreadyInitialized: if the instance is already initialized.
        """
        if self._initialized:
            raise errors.SerializerAlreadyInitialized()
        self._secret = secret
        self._master_key = hashlib.sha256(self._secret.encode()).digest()  # for more entropy
        self._initialized = True

    def check_initialization(self):
        """
        Check if the serializer has already been initialized.
        :return: None.
        :raise SerializerNotInitialized: if the instance is not initialized.
        """
        if not self._initialized:
            raise errors.SerializerNotInitialized()

    @property
    def initialized(self):
        """
        Read only property, return initialization state (bool).
        :return: bool.
        """
        return self._initialized

    def _derive_key(self, salt: bytes) -> bytes:
        """
        Only used internally to derive keys for AES encryption.
        :param salt: your random salt.
        :return: key as bytes.
        """
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=200_000, backend=default_backend(), )
        return kdf.derive(self._master_key)

    def encrypt(self, plaintext: bytes) -> bytes:
        """
        Encrypt using AES-GCM.
        :param plaintext: bytes to encrypt.
        :return: ciphertext as bytes.
        """
        self.check_initialization()
        salt = os.urandom(16)
        iv = os.urandom(12)  # GCM standard
        key = self._derive_key(salt)
        aes = AESGCM(key)
        ciphertext = aes.encrypt(iv, plaintext, None)
        blob = salt + iv + ciphertext  # combine the parameters and the result data
        return blob

    def decrypt(self, data: bytes) -> bytes:
        """
        Decrypt using AES-GCM.
        :param data: bytes to decrypt.
        :return: plaintext as bytes.
        """
        self.check_initialization()
        salt = data[:16]
        iv = data[16:28]
        ciphertext = data[28:]
        key = self._derive_key(salt)
        aes = AESGCM(key)
        try:
            plaintext = aes.decrypt(iv, ciphertext, None)
            return plaintext
        except InvalidTag:
            raise errors.SerializerTokenCorrupt()

    def hmac_sign(self, text: bytes) -> bytes:
        """
        Sign using Hashed Message Authentication Code.
        :param text: your message to sign.
        :return: signature only as bytes.
        """
        self.check_initialization()
        hm = hmac.new(self._secret.encode(), text, hashlib.sha224)
        return hm.digest()

    def hmac_verify(self, text: bytes, signature: bytes) -> bool:
        """
        Verify signature using Hashed Message Authentication Code.
        :param text: original message.
        :param signature: arrived signature from the client to verify authenticity.
        :return: True or False.
        """
        self.check_initialization()
        hm = self.hmac_sign(text)
        return hm == signature

    def serialize(self, value, hmac=False) -> str:
        """
        Turn given value into a URLSafe encrypted/signed and timestamped token.
        :param value: any json serializable value (str, int, float, dict, list).
        :param hmac: use HMAC instead of AES for speed but not confidentiality.
        :return: url safe token.
        """
        self.check_initialization()
        data = json.dumps(value).encode()  # turn any value into a json string
        timestamp = int(datetime.now(UTC).timestamp()).to_bytes(8, 'little', signed=False)  # get current time as bytes (8-byte little-indian)
        stamped_data = timestamp + data  # concatenate both
        if hmac:  # if hmac is specified
            ciphertext = b'h' + self.hmac_sign(stamped_data) + stamped_data  # sign the cipher, make it start with 'h' for 'hmac'
        else:  # if aes was the option (default)
            ciphertext = b'a' + self.encrypt(stamped_data)  # encrypt and start the cipher with letter 'a' for 'aes'
        token = base64.urlsafe_b64encode(ciphertext).decode()  # make it url safe
        return token

    def deserialize(self, token: str, expiration_seconds: int = None) -> list:
        """
        Extract information from a URLSafe encrypted token.
        :param token: your urlsafe token.
        :param expiration_seconds: Optional, check expiration time.
        :return: your original information.
        """
        self.check_initialization()
        ciphertext = base64.urlsafe_b64decode(token)  # extract the bytes value
        method = chr(ciphertext[0])  # get the first letter that tells us which method was used (hmac or aes)
        ciphertext = ciphertext[1:]  # get the rest of the cipher (remove first letter)
        #
        if method == 'h':  # when HMAC was used
            hmac_signature = ciphertext[:28]  # extract the HMAC signature
            stamped_data = ciphertext[28:]  # extract the rest of the data (that was signed)
            if not self.hmac_verify(stamped_data, hmac_signature):  # verify signature and error out if invalud
                raise errors.SerializerTokenCorrupt()
        else:  # when AES was used
            stamped_data = self.decrypt(ciphertext)  # decrypt!
        #
        timestamp, data = stamped_data[:8], stamped_data[8:]  # separate timestamp from data
        timestamp = int.from_bytes(timestamp, 'little')  # get the meaningful integer from timestamp
        if expiration_seconds is not None:  # check expiration date if specified, and error out when expired
            if datetime.now(UTC).timestamp() - timestamp > expiration_seconds:
                raise errors.SerializerTokenExpired()
        values = json.loads(data)  # load json data into python datatype (the original message)
        return values

    @staticmethod
    def hash_password(password: str) -> str:
        """
        Hash passwords, this method doesn't rely on the initialized secret key of the instance.
        :param password: your password.
        :return: hashed password as str.
        """
        salt = bcrypt.gensalt(rounds=12)
        hashed = bcrypt.hashpw(password.encode(), salt)
        return hashed.decode()

    @staticmethod
    def verify_password(password: str, hashed: str) -> bool:
        """
        Verify passwords with its hash, this method doesn't rely on the initialized secret key of the instance.
        :param password: password to check.
        :param hashed: stored hash.
        :return: bool.
        """
        return bcrypt.checkpw(password.encode(), hashed.encode())
