#!/usr/bin/env python

from __future__ import print_function

import os
import sys
import getpass
import logging
import onepass.exceptions
from onepass.keychain import open_keychain

logging.basicConfig(level=logging.DEBUG,
                    format='[%(levelname)8s %(asctime)-15s] %(message)s')
log = logging.getLogger(__name__)
log.info("Started")

if len(sys.argv) > 1:
    akey = sys.argv[1]
    password = getpass.getpass()
else:
    root = os.path.abspath(os.path.dirname(__file__))
    akey = os.path.join(root, 'data', 'sample.agilekeychain')
    password = 'test'

k = open_keychain(akey)
try:
    k.unlock(password)

    for i in k.items:
        print(i.title)
        print(i.data)
except onepass.exceptions.InvalidPasswordError:
    log.error("Bad password")
