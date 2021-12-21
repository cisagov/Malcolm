import os


basedir = os.path.abspath(os.path.dirname(__file__))


class Config(object):
    HELLO_WORLD = f"{os.getenv('HELLO_WORLD', 'Hello world!')}"
