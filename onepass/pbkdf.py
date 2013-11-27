from math import ceil

from Crypto.Protocol.KDF import PBKDF1, PBKDF2
from Crypto.Hash import HMAC, MD5, SHA512
from Crypto.Hash import SHA as SHA1

from .log import wrap_function


@wrap_function
def pbkdf1_md5(password, salt, length, iterations):
    # Number of blocks of MD5 required to give us the required length.
    num_blocks = int(ceil(length / 16.0))

    data = password + salt
    md5 = []
    for i in range(num_blocks):
        h = data
        for i in range(iterations):
            h = MD5.new(h).digest()
        md5.append(h)
        data = md5[i] + password + salt

    # Join together the blocks and trim.
    return ''.join(md5)[-length:]


@wrap_function
def pbkdf2_sha1(password, salt, length, iterations):
    prf = lambda secret, salt: HMAC.new(secret, salt,
                                        digestmod=SHA1).digest()
    return PBKDF2(password=password,
                  salt=salt,
                  dkLen=length,
                  count=iterations,
                  prf=prf)


@wrap_function
def pbkdf2_sha512(password, salt, length, iterations):
    prf = lambda secret, salt: HMAC.new(secret, salt,
                                        digestmod=SHA512).digest()
    return PBKDF2(password=password,
                  salt=salt,
                  dkLen=length,
                  count=iterations,
                  prf=prf)
