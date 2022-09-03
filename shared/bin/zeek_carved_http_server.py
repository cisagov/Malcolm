#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Multithreaded simple HTTP directory server.
#
# The files can optionally be aes-256-cbc encrypted in a way that's compatible with:
#   openssl enc -aes-256-cbc -d -in encrypted.data -out decrypted.data

import argparse
import hashlib
import os
import sys
from threading import Thread
from socketserver import ThreadingMixIn
from http.server import HTTPServer, SimpleHTTPRequestHandler
from Crypto.Cipher import AES

KEY_SIZE = 32
OPENSSL_ENC_MAGIC = b'Salted__'
PKCS5_SALT_LEN = 8

###################################################################################################
args = None
debug = False
script_name = os.path.basename(__file__)
script_path = os.path.dirname(os.path.realpath(__file__))
orig_path = os.getcwd()

###################################################################################################
# print to stderr
def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)
    sys.stderr.flush()


###################################################################################################
# convenient boolean argument parsing
def str2bool(v):
    if v.lower() in ('yes', 'true', 't', 'y', '1'):
        return True
    elif v.lower() in ('no', 'false', 'f', 'n', '0'):
        return False
    else:
        raise argparse.ArgumentTypeError('Boolean value expected.')


###################################################################################################
# EVP_BytesToKey
#
# reference: https://github.com/openssl/openssl/blob/6f0ac0e2f27d9240516edb9a23b7863e7ad02898/crypto/evp/evp_key.c#L74
#            https://gist.github.com/chrono-meter/d122cbefc6f6248a0af554995f072460
def EVP_BytesToKey(key_length: int, iv_length: int, md, salt: bytes, data: bytes, count: int = 1) -> (bytes, bytes):
    assert data
    assert salt == b'' or len(salt) == PKCS5_SALT_LEN

    md_buf = b''
    key = b''
    iv = b''
    addmd = 0

    while key_length > len(key) or iv_length > len(iv):
        c = md()
        if addmd:
            c.update(md_buf)
        addmd += 1
        c.update(data)
        c.update(salt)
        md_buf = c.digest()
        for i in range(1, count):
            md_buf = md(md_buf)

        md_buf2 = md_buf

        if key_length > len(key):
            key, md_buf2 = key + md_buf2[: key_length - len(key)], md_buf2[key_length - len(key) :]

        if iv_length > len(iv):
            iv = iv + md_buf2[: iv_length - len(iv)]

    return key, iv


###################################################################################################
#
class HTTPHandler(SimpleHTTPRequestHandler):

    # return full path based on server base path and requested path
    def translate_path(self, path):
        path = SimpleHTTPRequestHandler.translate_path(self, path)
        relpath = os.path.relpath(path, os.getcwd())
        fullpath = os.path.join(self.server.base_path, relpath)
        return fullpath

    # override do_GET so that files are encrypted, if requested
    def do_GET(self):
        global debug
        global args

        fullpath = self.translate_path(self.path)

        if (not args.encrypt) or os.path.isdir(fullpath):
            # unencrypted, just use default implementation
            SimpleHTTPRequestHandler.do_GET(self)

        else:
            # encrypt file transfers
            if os.path.isfile(fullpath) or os.path.islink(fullpath):
                self.send_response(200)
                self.send_header('Content-type', 'application/octet-stream')
                self.send_header('Content-Disposition', f'attachment; filename={os.path.basename(fullpath)}.encrypted')
                self.end_headers()
                salt = os.urandom(PKCS5_SALT_LEN)
                key, iv = EVP_BytesToKey(KEY_SIZE, AES.block_size, hashlib.sha256, salt, args.key.encode('utf-8'))
                cipher = AES.new(key, AES.MODE_CBC, iv)
                encrypted = b""
                encrypted += OPENSSL_ENC_MAGIC
                encrypted += salt
                self.wfile.write(encrypted)
                with open(secure_fullpath(fullpath), 'rb') as f:
                    padding = b''
                    while True:
                        chunk = f.read(cipher.block_size)
                        if len(chunk) < cipher.block_size:
                            remaining = cipher.block_size - len(chunk)
                            padding = bytes([remaining] * remaining)
                        self.wfile.write(cipher.encrypt(chunk + padding))
                        if padding:
                            break

            else:
                self.send_error(404, "Not Found")


###################################################################################################
#
class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    def __init__(self, base_path, server_address, RequestHandlerClass=HTTPHandler):
        self.base_path = base_path
        HTTPServer.__init__(self, server_address, RequestHandlerClass)


###################################################################################################
#
def serve_on_port(path: str, port: int):
    server = ThreadingHTTPServer(path, ("", port))
    print(f"serving {path} at port {port}")
    server.serve_forever()


###################################################################################################
# main
def main():
    global args
    global debug
    global orig_path

    defaultDebug = os.getenv('EXTRACTED_FILE_HTTP_SERVER_DEBUG', 'false')
    defaultEncrypt = os.getenv('EXTRACTED_FILE_HTTP_SERVER_ENCRYPT', 'false')
    defaultPort = int(os.getenv('EXTRACTED_FILE_HTTP_SERVER_PORT', 8440))
    defaultKey = os.getenv('EXTRACTED_FILE_HTTP_SERVER_KEY', 'quarantined')
    defaultDir = os.getenv('EXTRACTED_FILE_HTTP_SERVER_PATH', orig_path)

    parser = argparse.ArgumentParser(
        description=script_name, add_help=False, usage='{} <arguments>'.format(script_name)
    )
    parser.add_argument(
        '-v',
        '--verbose',
        dest='debug',
        type=str2bool,
        nargs='?',
        const=True,
        default=defaultDebug,
        metavar='true|false',
        help=f"Verbose/debug output ({defaultDebug})",
    )
    parser.add_argument(
        '-p',
        '--port',
        dest='port',
        help=f"Server port ({defaultPort})",
        metavar='<port>',
        type=int,
        default=defaultPort,
    )
    parser.add_argument(
        '-d',
        '--directory',
        dest='serveDir',
        help=f'Directory to serve ({defaultDir})',
        metavar='<directory>',
        type=str,
        default=defaultDir,
    )
    parser.add_argument(
        '-e',
        '--encrypt',
        dest='encrypt',
        type=str2bool,
        nargs='?',
        const=True,
        default=defaultEncrypt,
        metavar='true|false',
        help=f"Encrypt files with aes-256-cbc ({defaultEncrypt})",
    )
    parser.add_argument(
        '-k', '--key', dest='key', help=f"File encryption key", metavar='<str>', type=str, default=defaultKey
    )
    try:
        parser.error = parser.exit
        args = parser.parse_args()
    except SystemExit:
        parser.print_help()
        exit(2)

    debug = args.debug
    if debug:
        eprint(os.path.join(script_path, script_name))
        eprint("Arguments: {}".format(sys.argv[1:]))
        eprint("Arguments: {}".format(args))
    else:
        sys.tracebacklimit = 0

    Thread(target=serve_on_port, args=[args.serveDir, args.port]).start()


###################################################################################################
if __name__ == '__main__':
    main()
