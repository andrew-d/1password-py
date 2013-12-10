from __future__ import print_function

import os
import sys
import getpass
import logging
import argparse

from . import __version__ as package_ver
from .keychain import open_keychain
from .item import WebItem
from .exceptions import *


def items_getter(keychain, args):
    return [x for x in keychain.items if x.title == args.title]


def items_lister(keychain, args):
    return keychain.items


def forms_getter(keychain, args):
    forms = (i for i in keychain.items if isinstance(i, WebItem))
    return [i for i in forms if i.location.lower() == args.address.lower()]


def forms_lister(keychain, args):
    forms = (i for i in keychain.items if isinstance(i, WebItem))
    return list(forms)


def main():
    # Top-level parser
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(help='sub-command help')

    # Global options
    parser.add_argument('--verbose', '-v', action='count',
                        help="Be more verbose (can be used multiple times)")
    parser.add_argument('--version', action='version', version=package_ver)
    parser.add_argument('--password', action='store',
                        help='The password to open the keychain (otherwise, '
                             'will read from the console')

    # This is a helper function for creating a parser, since most commands
    # expect a keychain as their first argument.
    def final_parser(root, name, func=None, **kwargs):
        # Create default help
        if 'help' not in kwargs:
            kwargs['help'] = '%s help' % (name,)

        # Create parser
        p = root.add_parser(name, **kwargs)

        # Add default arguments.
        p.add_argument('keychain', action='store', help='Path to the keychain')
        p.add_argument('--all', action='store_true',
                       help='Print the entire item')
        p.add_argument('--field', action='store',
                       help='Just print the given field')
        p.add_argument('--meta', action='store_true',
                       help="Print the item's metadata")
        p.add_argument('--bare', action='store_true',
                       help='Print just the bare information - e.g. just a '
                            'password, without the accompanying title')

        # Set function, if given.
        if func is not None:
            p.set_defaults(func=func)
        return p

    # Parser for 'items' command.
    items_parser = subparsers.add_parser('items').add_subparsers()
    g = final_parser(items_parser, 'get', items_getter)
    g.add_argument('title', action='store', help='Title of the item to get')
    final_parser(items_parser, 'list', items_lister)

    # Parser for 'forms' command.
    forms_parser = subparsers.add_parser('forms').add_subparsers()
    g = final_parser(forms_parser, 'get', forms_getter)
    g.add_argument('address', action='store',
                   help='Address of the site to search for')
    final_parser(forms_parser, 'list', forms_lister)

    # Parse arguments
    args = parser.parse_args()

    # Setup logging.
    level = logging.WARNING
    if args.verbose >= 2:
        level = logging.DEBUG
    elif args.verbose >= 1:
        level = logging.INFO
    logging.basicConfig(level=level,
                        format='[%(levelname)8s %(asctime)-15s] %(message)s')

    keychain = open_keychain(os.path.expanduser(args.keychain))

    if args.password:
        pwd = args.password
    else:
        pwd = getpass.getpass()

    try:
        keychain.unlock(pwd)
    except InvalidPasswordError:
        print("Invalid password", file=sys.stderr)
        return

    # Figure out how we're printing.
    if args.all:
        printer = lambda i: i.data
    elif args.meta:
        printer = lambda i: i.metadata
    elif args.field:
        printer = lambda i: i.data.get(args.field, '')
    elif args.bare:
        printer = lambda i: i.default
    else:
        printer = lambda i: i.title + ': ' + i.default

    # Get the list of items using our function.
    matching = args.func(keychain, args)

    # Print them all.
    if len(matching) > 0:
        for m in matching:
            print(printer(m))
    else:
        print("No items found")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
