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
        super(AgileKeychain, self).__init__(*args, **kwargs)

    def unlock(self, password, store='default'):
        self._load_keys(password, store)
        self._load_items(password, store)

    def _load_keys(self, password, store):
        keys_path = os.path.join(self.path, 'data', store, 'encryptionKeys.js')
        logging.info("Loading keys from: %s", keys_path)
        with open(keys_path, 'rb') as f:
            keys = json.load(f)

        for level in keys['list']:
            logging.info("Decrypting level: %s", level['level'])

            sstr = SaltedString(level['data'])
            iterations = level.get('iterations', 1000)
            if iterations < 1000:
                iterations = 1000
            logging.debug("Level uses %d iterations", iterations)

            # This format uses AES-128, which is 16 bytes
            keys = pbkdf.pbkdf2_sha1(password, sstr.salt, 2*16, iterations)
            key, iv = keys[:16], keys[16:]

            cipher = Crypto.Cipher.AES.new(key, Crypto.Cipher.AES.MODE_CBC, iv)
            possible_key = padding.pkcs5_unpad(cipher.decrypt(sstr.data))

            decrypted_validation = self._decrypt_item(level['validation'], possible_key)
            if decrypted_validation != possible_key:
                raise InvalidPasswordError("Validation did not match")

            self._keys[level['identifier']] = possible_key

    def _load_items(self, password, store):
        # TODO: load items
        pass

    def _decrypt_item(self, data, key):
        sstr = SaltedString(data)
        if sstr.is_salted:
            keys = pbkdf.pbkdf1_md5(key, sstr.salt, 2*16, 1)
            key, iv = keys[:16], keys[16:]
        else:
            key = MD5.new(key).digest()
            iv = '\x00' * 16

        cipher = Crypto.Cipher.AES.new(key, Crypto.Cipher.AES.MODE_CBC, iv)
        data = cipher.decrypt(sstr.data)
        return padding.pkcs5_unpad(data)

    def _verify(self):
        # TODO: handle different store?
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
        return []


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
