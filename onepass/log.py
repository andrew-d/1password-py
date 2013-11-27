from contextlib import wraps
from logging import getLogger


def wrap_function(func):
    func_name = func.__name__
    logger = getLogger(func.__module__)

    def wrapper(*args, **kwargs):
        try:
            logger.debug("Started %s", func_name)
            return func(*args, **kwargs)
        finally:
            logger.debug("Finished %s", func_name)

    return wrapper
