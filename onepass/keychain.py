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
import Crypto.Hash.MD5

from .six import add_metaclass
from .exceptions import *
from . import pbkdf
from . import padding


log = logging.getLogger(__name__)
SALT_MARKER = 'Salted__'


@add_metaclass(ABCMeta)
class AbstractKeychain(object):
    def __init__(self, path):
        self.path = path
        self.unlocked = False
        self._verify()
        self._init()

    def _init(self):
        """
        Can be overridden in a base class to provide initialization.
        """
        pass

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
    def _init(self):
        self._keys = {}

    def unlock(self, password, store='default'):
        self._load_keys(password, store)

    def _load_keys(self, password, store):
        keys_path = os.path.join(self.path, 'data', store, 'encryptionKeys.js')
        logging.info("Loading keys from: %s", keys_path)
        with open(keys_path, 'rb') as f:
            keys = json.load(f)

        for level in keys['list']:
            logging.info("Decrypting level: %s", level['level'])
            data = base64.b64decode(level['data'])

            # Grab the salt, if necessary.  It defaults to 8 bytes of NULL.
            if data[0:8] == SALT_MARKER:
                logging.debug("Level is salted")
                salt = data[8:16]
                data = data[16:]
            else:
                logging.debug("Level is unsalted")
                salt = '\x00' * 8

            iterations = level.get('iterations', 1000)
            if iterations < 1000:
                iterations = 1000
            logging.debug("Level uses %d iterations", iterations)

            # This format uses AES-128, which is 16 bytes
            keys = pbkdf.pbkdf2_sha1(password, salt, 2*16, iterations)
            key, iv = keys[:16], keys[16:]
            print(key.encode('hex'), iv.encode('hex'))
            print(len(key), len(iv))

            cipher = Crypto.Cipher.AES.new(key, Crypto.Cipher.AES.MODE_CBC, iv)
            possible_key = padding.pkcs5_unpad(cipher.decrypt(data))

            validation = base64.b64decode(level['validation'])
            decrypted_validation = self._decrypt_item(validation, possible_key)

            if decrypted_validation != possible_key:
                raise InvalidPasswordError("Validation did not match")

            # TODO: multiple stores?
            self._keys[level['identifier']] = possible_key

    def _decrypt_item(self, data, key):
        if data[0:8] == SALT_MARKER:
            log.debug("Item is salted")
            salt = data[8:16]
            data = data[16:]
            keys = pbkdf.pbkdf1_md5(salt, data, 2*16, 1)
            key, iv = keys[:16], keys[16:]
        else:
            log.debug("Item is unsalted")
            key = MD5.new(key).digest()
            iv = '\x00' * 16

        cipher = Crypto.Cipher.AES.new(key, Crypto.Cipher.AES.MODE_CBC, iv)
        data = cipher.decrypt(data)
        return padding.pkcs5_unpad(data)


    def _verify(self):
        files = [
            os.path.join(self.path, 'config', 'buildnum'),
            os.path.join(self.path, 'data', 'default', 'encryptionKeys.js'),
        ]

        for f in files:
            if not os.path.exists(f) and os.path.isfile(f):
                raise InvalidKeychainException("File '%s' not found" % (f,))

        # Verify the build number.
        with open(files[0], 'rb') as f:
            version_num = int(f.read().strip())

        if not (30000 <= version_num < 40000):
            raise InvalidKeychainException("Build number %d not supported" % (
                version_num,))

    @property
    def items(self):
        return []


def open_keychain(path):
    if not os.path.exists(path):
        raise IOError("Keychain at '%s' does not exist" % (path,))

    _, ext = os.path.splitext(path)
    cls = None
    if ext == '.agilekeychain':
        cls = AgileKeychain
    elif ext == '.cloudkeychain':
        pass # TODO

    if cls is None:
        raise ValueError("Unknown keychain format '%s'" % (ext,))

    return cls(path)
