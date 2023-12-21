#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Multithreaded simple HTTP directory server.
#
# The files can optionally be aes-256-cbc encrypted in a way that's compatible with:
#   openssl enc -aes-256-cbc -d -in encrypted.data -out decrypted.data

import argparse
import hashlib
import os
import pyminizip
import sys
from Crypto.Cipher import AES
from datetime import datetime
from http.server import HTTPServer, SimpleHTTPRequestHandler
from socketserver import ThreadingMixIn
from stat import S_IFREG
from stream_zip import ZIP_32, stream_zip
from threading import Thread


from malcolm_utils import (
    str2bool,
    eprint,
    temporary_filename,
    EVP_KEY_SIZE,
    PKCS5_SALT_LEN,
    OPENSSL_ENC_MAGIC,
    EVP_BytesToKey,
)

###################################################################################################
args = None
debug = False
script_name = os.path.basename(__file__)
script_path = os.path.dirname(os.path.realpath(__file__))
orig_path = os.getcwd()


###################################################################################################
#
def LocalFilesForZip(names):
    now = datetime.now()

    def contents(name):
        with open(name, 'rb') as f:
            while chunk := f.read(65536):
                yield chunk

    return ((os.path.join('.', os.path.basename(name)), now, S_IFREG | 0o600, ZIP_32, contents(name)) for name in names)


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

        if os.path.isdir(fullpath):
            # directory listing
            SimpleHTTPRequestHandler.do_GET(self)

        elif os.path.isfile(fullpath) or os.path.islink(fullpath):
            if args.zip:
                # ZIP file
                self.send_response(200)
                self.send_header('Content-type', "application/zip")
                self.send_header('Content-Disposition', f'attachment; filename={os.path.basename(fullpath)}.zip')
                self.end_headers()

                if args.encrypt:
                    # password-protected ZIP file (temporarily persisted to disk)
                    with temporary_filename(suffix='.zip') as tmpFileName:
                        pyminizip.compress(fullpath, None, tmpFileName, args.key, 1)
                        with open(tmpFileName, 'rb') as f:
                            while chunk := f.read(65536):
                                self.wfile.write(chunk)

                else:
                    # encrypted ZIP file (streamed)
                    for chunk in stream_zip(LocalFilesForZip([fullpath])):
                        self.wfile.write(chunk)

            elif args.encrypt:
                # encrypted file
                self.send_response(200)
                self.send_header('Content-type', 'application/octet-stream')
                self.send_header('Content-Disposition', f'attachment; filename={os.path.basename(fullpath)}.encrypted')
                self.end_headers()
                salt = os.urandom(PKCS5_SALT_LEN)
                key, iv = EVP_BytesToKey(EVP_KEY_SIZE, AES.block_size, hashlib.sha256, salt, args.key.encode('utf-8'))
                cipher = AES.new(key, AES.MODE_CBC, iv)
                encrypted = b""
                encrypted += OPENSSL_ENC_MAGIC
                encrypted += salt
                self.wfile.write(encrypted)
                with open(fullpath, 'rb') as f:
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
                # unencrypted file
                SimpleHTTPRequestHandler.do_GET(self)

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
    defaultZip = os.getenv('EXTRACTED_FILE_HTTP_SERVER_ZIP', 'false')
    defaultPort = int(os.getenv('EXTRACTED_FILE_HTTP_SERVER_PORT', 8440))
    defaultKey = os.getenv('EXTRACTED_FILE_HTTP_SERVER_KEY', 'infected')
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
        help=f"Encrypt files (with -z/--zip, or with aes-256-cbc) ({defaultEncrypt})",
    )
    parser.add_argument(
        '-k',
        '--key',
        dest='key',
        help="File encryption key",
        metavar='<str>',
        type=str,
        default=defaultKey,
    )
    parser.add_argument(
        '-z',
        '--zip',
        dest='zip',
        type=str2bool,
        nargs='?',
        const=True,
        default=defaultZip,
        metavar='true|false',
        help=f"Zip file ({defaultZip})",
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
