#!/usr/bin/env python

from __future__ import print_function

import os
import logging
import onepass.exceptions
from onepass.keychain import open_keychain

logging.basicConfig(level=logging.DEBUG,
                    format='[%(levelname)8s %(asctime)-15s] %(message)s')
log = logging.getLogger(__name__)
log.info("Started")

root = os.path.abspath(os.path.dirname(__file__))
akey = os.path.join(root, 'data', 'sample.agilekeychain')

k = open_keychain(akey)
try:
    k.unlock('test')

    for i in k.items:
        print(i.title)
except onepass.exceptions.InvalidPasswordError:
    log.error("Bad password")
