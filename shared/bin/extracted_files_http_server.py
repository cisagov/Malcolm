#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Multithreaded simple HTTP directory server.
#
# The files can optionally be archived in a ZIP file, with or without a password, or
# be aes-256-cbc encrypted in a way that's compatible with:
#   openssl enc -aes-256-cbc -d -in encrypted.data -out decrypted.data

import argparse
import dominate
import hashlib
import magic
import os
import re
import sys
from Crypto.Cipher import AES
from datetime import datetime
from http.server import HTTPServer, SimpleHTTPRequestHandler
from socketserver import ThreadingMixIn
from stat import S_IFREG
from stream_zip import ZIP_32, stream_zip
from threading import Thread
from dominate.tags import *

from malcolm_utils import (
    str2bool,
    eprint,
    temporary_filename,
    EVP_KEY_SIZE,
    PKCS5_SALT_LEN,
    OPENSSL_ENC_MAGIC,
    EVP_BytesToKey,
    sizeof_fmt,
)

###################################################################################################
args = None
debug = False
script_name = os.path.basename(__file__)
script_path = os.path.dirname(os.path.realpath(__file__))
orig_path = os.getcwd()


###################################################################################################
#
def natural_sort_key(s, _nsre=re.compile('([0-9]+)')):
    return [int(text) if text.isdigit() else text.lower() for text in _nsre.split(s)]


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
        fileBaseName = os.path.basename(fullpath)

        carvedFileRegex = re.compile(
            r'^(?P<source>[^-]+)-(?P<fuid>F[a-zA-Z0-9]+|unknown)-(?P<uid>C[a-zA-Z0-9]+|unknown)-(?P<timestamp>\d+)(?P<ext>\..+)?$'
        )
        carvedFileRegexAlt = re.compile(r'^(?P<uid>C[a-zA-Z0-9]+)_(?P<fuid>F[a-zA-Z0-9]+)')

        if os.path.isdir(fullpath):
            # directory listing
            # SimpleHTTPRequestHandler.do_GET(self)
            self.send_response(200)
            self.send_header('Content-type', "text/html")
            self.end_headers()

            pageTitle = f"Directory listing for {fileBaseName if fileBaseName != '.' else '/'}"
            doc = dominate.document(title=pageTitle)

            with doc.head:
                meta(charset="utf-8")

            with doc:
                h1(pageTitle)
                hr()
                with div(id='listing'):
                    with table().add(tbody()):
                        t = tr()
                        t.add(th("Name"), th("Type" if args.magic else "Extension"), th("Size"))
                        if args.malcolm:
                            t.add(
                                th("Source", style="text-align: center;"),
                                th("UID", style="text-align: center;"),
                                th("FUID", style="text-align: center;"),
                                th("Timestamp", style="text-align: center;"),
                            )
                        if fileBaseName != '.':
                            tr().add(
                                td(a('..', href=f'..')),
                                td("Directory", style="text-align: center;"),
                                td(''),
                            )
                        for dirpath, dirnames, filenames in os.walk(fullpath):
                            for dirname in sorted(dirnames, key=natural_sort_key):
                                try:
                                    t = tr()
                                    child = os.path.join(dirpath, dirname)
                                    t.add(
                                        td(a(dirname, href=f'{dirname}/')),
                                        td("Directory"),
                                        td(''),
                                    )
                                except Exception as e:
                                    eprint(f'Error with directory "{dirname}"": {e}')
                            for filename in sorted(filenames, key=natural_sort_key):
                                try:
                                    t = tr()
                                    child = os.path.join(dirpath, filename)
                                    fileinfo = (
                                        magic.from_file(child, mime=True)
                                        if args.magic
                                        else os.path.splitext(filename)[1]
                                    )
                                    t.add(
                                        td(a(filename, href=f'{filename}')),
                                        td(fileinfo),
                                        td(sizeof_fmt(os.path.getsize(child)), style="text-align: right;"),
                                    )
                                    if args.malcolm:
                                        fmatch = carvedFileRegex.search(filename)
                                        if fmatch is None:
                                            fmatch = carvedFileRegexAlt.search(filename)
                                        if fmatch is not None:
                                            timestampStr = fmatch.groupdict().get('timestamp', '')
                                            try:
                                                timestamp = datetime.strptime(timestampStr, '%Y%m%d%H%M%S').isoformat()
                                            except Exception as te:
                                                if timestampStr:
                                                    eprint(f'Error with time "{timestampStr}": {te}')
                                                timestamp = timestampStr
                                            t.add(
                                                td(fmatch.groupdict().get('source', ''), style="text-align: center;"),
                                                td(fmatch.groupdict().get('uid', '')),
                                                td(fmatch.groupdict().get('fuid', '')),
                                                td(timestamp, style="text-align: center;"),
                                            )
                                        else:
                                            eprint(f'nope on {filename}')
                                except Exception as e:
                                    eprint(f'Error with file "{filename}": {e}')
                            break
                hr()

            self.wfile.write(str.encode(str(doc)))

        else:
            if args.recursive and (not os.path.isfile(fullpath)) and (not os.path.islink(fullpath)):
                for root, dirs, files in os.walk(os.path.dirname(fullpath)):
                    if fileBaseName in files:
                        fullpath = os.path.join(root, fileBaseName)
                        break

            if os.path.isfile(fullpath) or os.path.islink(fullpath):
                if args.zip:
                    # ZIP file (streamed, AES-encrypted with password or unencrypted)
                    self.send_response(200)
                    self.send_header('Content-type', "application/zip")
                    self.send_header('Content-Disposition', f'attachment; filename={fileBaseName}.zip')
                    self.end_headers()

                    for chunk in stream_zip(LocalFilesForZip([fullpath]), password=args.key if args.key else None):
                        self.wfile.write(chunk)

                elif args.key:
                    # openssl-compatible encrypted file
                    self.send_response(200)
                    self.send_header('Content-type', 'application/octet-stream')
                    self.send_header('Content-Disposition', f'attachment; filename={fileBaseName}.encrypted')
                    self.end_headers()
                    salt = os.urandom(PKCS5_SALT_LEN)
                    key, iv = EVP_BytesToKey(
                        EVP_KEY_SIZE, AES.block_size, hashlib.sha256, salt, args.key.encode('utf-8')
                    )
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
                    # original file, unencrypted
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
    defaultZip = os.getenv('EXTRACTED_FILE_HTTP_SERVER_ZIP', 'false')
    defaultRecursive = os.getenv('EXTRACTED_FILE_HTTP_SERVER_RECURSIVE', 'false')
    defaultMagic = os.getenv('EXTRACTED_FILE_HTTP_SERVER_MAGIC', 'false')
    defaultMalcolm = os.getenv('EXTRACTED_FILE_HTTP_SERVER_MALCOLM', 'false')
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
        '-m',
        '--magic',
        dest='magic',
        type=str2bool,
        nargs='?',
        const=True,
        default=defaultMagic,
        metavar='true|false',
        help=f"Get file MIME type ({defaultMagic})",
    )
    parser.add_argument(
        '-k',
        '--key',
        dest='key',
        help="File encryption key (for ZIP file if -z/--zip, otherwise openssl-compatible encryption",
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
    parser.add_argument(
        '-r',
        '--recursive',
        dest='recursive',
        type=str2bool,
        nargs='?',
        const=True,
        default=defaultRecursive,
        metavar='true|false',
        help=f"Recursively look for requested file if not found",
    )
    parser.add_argument(
        '--malcolm',
        dest='malcolm',
        type=str2bool,
        nargs='?',
        const=True,
        default=defaultMalcolm,
        metavar='true|false',
        help=f"Include columns for Zeek-extracted files in Malcolm",
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
