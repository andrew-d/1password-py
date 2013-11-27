# Introduction

This project is a Python library to read keychain files used by the 1Password
program.

# Architecture

## Keychain

The base class is a Keychain, which represents an open instance of a keychain.
Each keychain object has the following properties:

* `keychain.unlocked`: whether or not the keychain has been unlocked
* `keychain.items`: a list of items contained in this keychain

The following methods are available:

* `keychain.unlock(pass)`: unlock the keychain with the given password.  If the
  password is invalid, then an InvalidPasswordError exception is raised.

## Item

All items in a keychain are subclasses of AbstractItem.  The following
properties are shared among all items:

* `item.name`: the name of the item
* `item.tag`: tag of the item, None if not given
* `item.folder`: TODO (how to organize?)

The following methods are available on a keychain item:

* TODO

An item in 1Password has a type associated with it, and each type is
represented by a different subclass:

* LoginItem
* SecureNoteItem
* CardItem
* IdentityItem
* LicenseItem
