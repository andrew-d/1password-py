from __future__ import print_function

import os
import base64
import logging
try:
    import json
except ImportError:
    import simplejson as json
from abc import ABCMeta, abstractmethod, abstractproperty

import Crypto.Cipher.AES
from Crypto.Hash import MD5

from .six import add_metaclass
from .exceptions import *
from .item import BaseItem
from . import pbkdf
from . import padding


log = logging.getLogger(__name__)


class SaltedString(object):
    """
    Helpful class that detects whether a string is salted, and
    provides the ability to extract the salt and data.
    """
    SALT_MARKER = 'Salted__'
    ZERO_IV = '\x00' * 16

    def __init__(self, b64_string):
        data = base64.b64decode(b64_string)
        if data.startswith(self.SALT_MARKER):
            self.salt = data[8:16]
            self.data = data[16:]
            self.is_salted = True
        else:
            self.salt = self.ZERO_IV
            self.data = data
            self.is_salted = False


class EncryptionKey(object):
    """
    A class representing a single encryption key.
    """
    DEFAULT_IV = '\x00' * 16

    def __init__(self, key):
        self.iterations = key.get('iterations', 1000)
        if self.iterations < 1000:
            self.iterations = 1000

        self.sstr = SaltedString(key['data'])
        self.validation = key['validation']
        self.identifier = key['identifier']
        self.key = None

    @property
    def is_unlocked(self):
        return self.key is not None

    def unlock(self, password):
        # We need 32 bytes - 16 for the AES key, and 16 for the IV.
        keys = pbkdf.pbkdf2_sha1(password, self.sstr.salt, 32, self.iterations)
        key, iv = keys[:16], keys[16:]

        # Try decrypting the data with our generated key/IV.
        cipher = Crypto.Cipher.AES.new(key, Crypto.Cipher.AES.MODE_CBC, iv)
        possible_key = padding.pkcs5_unpad(cipher.decrypt(self.sstr.data))

        # Validate the key by trying to decrypt the validation with it.
        decrypted_validation = self._internal_decrypt_item(self.validation,
                                                           possible_key)
        if decrypted_validation != possible_key:
            raise InvalidPasswordError("Validation did not match")

        self.key = possible_key

    def decrypt_item(self, item_data):
        return self._internal_decrypt_item(item_data, self.key)

    def _internal_decrypt_item(self, data, key):
        sstr = SaltedString(data)
        if sstr.is_salted:
            keys = pbkdf.pbkdf1_md5(key, sstr.salt, 32, 1)
            key, iv = keys[:16], keys[16:]
        else:
            key = MD5.new(key).digest()
            iv = self.DEFAULT_IV

        cipher = Crypto.Cipher.AES.new(key, Crypto.Cipher.AES.MODE_CBC, iv)
        data = cipher.decrypt(sstr.data)
        return padding.pkcs5_unpad(data)


@add_metaclass(ABCMeta)
class AbstractKeychain(object):
    def __init__(self, path):
        self.path = path
        self.unlocked = False
        self._verify()

    @abstractmethod
    def _verify(self):
        """
        This method should raise an InvalidKeychainException if the given path
        is not a valid keychain.
        """
        pass

    @abstractmethod
    def unlock(self, password):
        pass

    @abstractproperty
    def items(self):
        pass


class AgileKeychain(AbstractKeychain):
    """
    Class that handles reading the standard .agilekeychain format.
    """
    def __init__(self, *args, **kwargs):
        self._keys = {}
        self._items = []
        super(AgileKeychain, self).__init__(*args, **kwargs)

    def unlock(self, password, store='default'):
        self._load_keys(password, store)
        self._load_items(password, store)

    def _load_keys(self, password, store):
        keys_path = os.path.join(self.path, 'data', store, 'encryptionKeys.js')
        logging.info("Loading keys from: %s", keys_path)
        with open(keys_path, 'rb') as f:
            keys = json.load(f)

        for key_data in keys['list']:
            logging.info("Decrypting level: %s", key_data['level'])
            key = EncryptionKey(key_data)
            key.unlock(password)
            self._keys[key.identifier] = key

    def _load_items(self, password, store):
        contents_path = os.path.join(self.path, 'data', store, 'contents.js')
        logging.info("Loading contents from: %s", contents_path)
        with open(contents_path, 'rb') as f:
            contents = json.load(f)

        for item in contents:
            uuid, ty, name = item[0:3]
            path = os.path.join(self.path, 'data', store, uuid + '.1password')
            with open(path, 'rb') as f:
                item = json.load(f)

            kid = item['keyID']
            contents = self._keys[kid].decrypt_item(item['encrypted'])
            self._items.append(BaseItem(item, contents))

    def _verify(self):
        # TODO: handle different store while verifying?
        files = [
            os.path.join('data', 'default', 'encryptionKeys.js'),
            os.path.join('data', 'default', 'contents.js'),
        ]

        for f in files:
            p = os.path.join(self.path, f)
            if not os.path.exists(p) and os.path.isfile(p):
                raise InvalidKeychainException("File '%s' not found" % (p,))

    @property
    def items(self):
        return self._items


def open_keychain(path):
    if not os.path.exists(path):
        raise IOError("Keychain at '%s' does not exist" % (path,))

    _, ext = os.path.splitext(path)
    if ext == '.agilekeychain':
        cls = AgileKeychain
    # TODO:
    #elif ext == '.cloudkeychain':
    #    pass
    else:
        raise ValueError("Unknown keychain format '%s'" % (ext,))

    return cls(path)
