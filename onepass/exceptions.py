class BaseException(Exception):
    pass

class InvalidKeychainError(ValueError, BaseException):
    pass

class InvalidPasswordError(ValueError, BaseException):
    pass
