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
from datetime import datetime, UTC
from dominate.tags import *
from http.server import HTTPServer, SimpleHTTPRequestHandler
from socketserver import ThreadingMixIn
from stat import S_IFREG
from stream_zip import ZIP_32, stream_zip
from threading import Thread

from malcolm_utils import (
    eprint,
    EVP_BytesToKey,
    EVP_KEY_SIZE,
    OPENSSL_ENC_MAGIC,
    PKCS5_SALT_LEN,
    remove_prefix,
    sizeof_fmt,
    str2bool,
    temporary_filename,
)

###################################################################################################
args = None
debug = False
script_name = os.path.basename(__file__)
script_path = os.path.dirname(os.path.realpath(__file__))
orig_path = os.getcwd()
filename_truncate_len = 20


###################################################################################################
# a function for performing "natural" (case insensitive) sort
def natural_sort_key(s, _nsre=re.compile('([0-9]+)')):
    return [int(text) if text.isdigit() else text.lower() for text in _nsre.split(s)]


###################################################################################################
# return the names and flags for Zipping a list of files
def LocalFilesForZip(names):
    now = datetime.now(UTC)

    def contents(name):
        with open(name, 'rb') as f:
            while chunk := f.read(65536):
                yield chunk

    return ((os.path.join('.', os.path.basename(name)), now, S_IFREG | 0o600, ZIP_32, contents(name)) for name in names)


###################################################################################################
# a simple HTTP request handler for listing directories of files and serving those files for download
class HTTPHandler(SimpleHTTPRequestHandler):
    # return full path based on server base path and requested path
    def translate_path(self, path):
        path = SimpleHTTPRequestHandler.translate_path(self, path)
        relpath = os.path.relpath(path, os.getcwd())
        fullpath = os.path.join(self.server.base_path, relpath)
        return fullpath, relpath

    # override do_GET for fancy directory listing and so that files are encrypted/zipped, if requested
    def do_GET(self):
        global debug
        global args

        fullpath, relpath = self.translate_path(self.path)
        fileBaseName = os.path.basename(fullpath)

        nowStr = datetime.now(UTC).isoformat()

        # HTTP-FUID-UID-TIMESTAMP.ext
        carvedFileRegex = re.compile(
            r'^(?P<source>[^-]+)-(?P<fuid>F[a-zA-Z0-9]+|unknown)-(?P<uid>C[a-zA-Z0-9]+|unknown)-(?P<timestamp>\d+)(?P<ext>\..+)?$'
        )
        # UID-FUID-whatever
        carvedFileRegexAlt = re.compile(r'^(?P<uid>C[a-zA-Z0-9]+)_(?P<fuid>F[a-zA-Z0-9]+)')

        if os.path.isdir(fullpath) and (args.links or (not os.path.islink(fullpath))):
            # directory listing
            self.send_response(200)
            self.send_header('Content-type', "text/html")
            self.end_headers()

            pageTitle = f"Directory listing for {fileBaseName if fileBaseName != '.' else '/'}"
            doc = dominate.document(title=pageTitle)

            # <head>
            with doc.head:
                meta(charset="utf-8")
                meta(name="viewport", content="width=device-width, initial-scale=1, shrink-to-fit=no")
                link(rel="icon", href=f"{args.assetsDirRespReplacer}favicon.ico", type="image/x-icon")
                link(rel="stylesheet", href=f"{args.assetsDirRespReplacer}css/bootstrap-icons.css", type="text/css")
                link(rel="stylesheet", href=f"{args.assetsDirRespReplacer}css/google-fonts.css", type="text/css")
                link(rel="stylesheet", href=f"{args.assetsDirRespReplacer}css/styles.css", type="text/css")

            # <body>
            with doc:
                with nav(cls='navbar navbar-light bg-light static-top'):
                    div(cls='container')
                header(cls='masthead')
                with section(cls="features-icons bg-light"):
                    with div(cls='container'):
                        h1(pageTitle, cls='mb-5', style='text-align: center')
                        with div(cls='container').add(div(cls="row")).add(div(cls="col-lg-12")):
                            with table(cls='table-bordered', width='100%').add(tbody()):
                                # header row
                                t = tr(style="text-align: center")
                                t.add(
                                    th(
                                        f"Download{' (AE-2 zipped)' if (args.zip and args.key) else ' (zipped)' if args.zip else ' (encrypted)' if args.key else ''}"
                                    ),
                                    th("Type" if args.magic else "Extension"),
                                    th("Size"),
                                )
                                if args.malcolm:
                                    t.add(
                                        th("Source"),
                                        th("IDs"),
                                        th("Timestamp"),
                                    )
                                if fileBaseName != '.':
                                    t = tr()
                                    t.add(
                                        td(a(i(cls="bi bi-arrow-90deg-up"), href=f'..')),
                                        td("Directory"),
                                        td(''),
                                    )
                                    if args.malcolm:
                                        t.add(th(), th(), th())

                                # content rows (files and directories)
                                for dirpath, dirnames, filenames in os.walk(fullpath):
                                    # list directories first
                                    for dirname in sorted(dirnames, key=natural_sort_key):
                                        try:
                                            child = os.path.join(dirpath, dirname)
                                            if args.links or (not os.path.islink(child)):
                                                t = tr()
                                                t.add(
                                                    td(a(dirname, href=f'{dirname}/')),
                                                    td("Directory"),
                                                    td(''),
                                                )
                                                if args.malcolm:
                                                    t.add(th(), th(), th())
                                        except Exception as e:
                                            eprint(f'Error with directory "{dirname}"": {e}')

                                    # list files after directories
                                    for filename in sorted(filenames, key=natural_sort_key):
                                        try:
                                            child = os.path.join(dirpath, filename)
                                            if args.links or (not os.path.islink(child)):
                                                t = tr()

                                                # calculate some of the stuff for representing Malcolm files
                                                timestamp = None
                                                timestampStr = ''
                                                fmatch = None
                                                fsource = ''
                                                fids = list()
                                                if args.malcolm:
                                                    # determine if filename is in a pattern we recognize
                                                    fmatch = carvedFileRegex.search(filename)
                                                    if fmatch is None:
                                                        fmatch = carvedFileRegexAlt.search(filename)
                                                    if fmatch is not None:
                                                        # format timestamp as ISO date/time
                                                        timestampStr = fmatch.groupdict().get('timestamp', '')
                                                        try:
                                                            timestamp = datetime.strptime(timestampStr, '%Y%m%d%H%M%S')
                                                            timestampStr = timestamp.isoformat()
                                                        except Exception as te:
                                                            if timestampStr:
                                                                eprint(f'Error with time "{str(timestampStr)}": {te}')
                                                        fsource = fmatch.groupdict().get('source', '')
                                                        fids = list(
                                                            filter(
                                                                None,
                                                                [
                                                                    fmatch.groupdict().get('uid', ''),
                                                                    fmatch.groupdict().get('fuid', ''),
                                                                ],
                                                            )
                                                        )

                                                # only request mime type for files if specified in arguments
                                                fileinfo = (
                                                    magic.from_file(os.path.realpath(child), mime=True)
                                                    if args.magic
                                                    else os.path.splitext(filename)[1]
                                                )

                                                # show filename, file type (with link to IANA if MIME type is shown), and file size
                                                t.add(
                                                    td(
                                                        a(
                                                            (
                                                                (filename[:filename_truncate_len] + '...')
                                                                if len(filename) > filename_truncate_len
                                                                else filename
                                                            ),
                                                            href=f'{filename}',
                                                        ),
                                                        title=filename,
                                                    ),
                                                    (
                                                        td(
                                                            a(
                                                                fileinfo,
                                                                href=f'https://www.iana.org/assignments/media-types/{fileinfo}',
                                                            ),
                                                        )
                                                        if args.magic
                                                        else td(fileinfo)
                                                    ),
                                                    td(sizeof_fmt(os.path.getsize(child)), style="text-align: right"),
                                                )

                                                # show special malcolm columns if requested
                                                if args.malcolm and fmatch is not None:
                                                    # list carve source, IDs, and timestamp
                                                    t.add(
                                                        td(
                                                            fmatch.groupdict().get('source', ''),
                                                            style="text-align: center",
                                                        ),
                                                        td(
                                                            [
                                                                a(
                                                                    fid,
                                                                    href=f'/arkime/idark2dash/filter?start={timestampStr}&stop={nowStr}&field=event.id&value={fid}',
                                                                )
                                                                for fid in fids
                                                            ],
                                                            style="text-align: center",
                                                        ),
                                                        td(
                                                            (
                                                                timestamp.strftime("%Y-%m-%d %H:%M:%S")
                                                                if timestamp
                                                                else timestampStr
                                                            ),
                                                            title=timestampStr,
                                                            style="text-align: center",
                                                        ),
                                                    )
                                                else:
                                                    # file name format was not recognized, so extra columns are empty
                                                    t.add(th(), th(), th())

                                        except Exception as e:
                                            eprint(f'Error with file "{filename}": {e}')

                                    # our "walk" is not recursive right now, we only need to go one level deep
                                    break

                with footer(cls='footer bg-light').add(div(cls='container')).add(div(cls='row')):
                    with div(cls="col-lg-6 h-100 text-center text-lg-start my-auto"):
                        p(
                            "Malcolm © 2024 Battelle Energy Alliance, LLC; developed at INL and released through the cooperation of the Cybersecurity and Infrastructure Security Agency of the U.S. Department of Homeland Security.",
                            cls="text-muted small mb-4 mb-lg-0",
                        )

                    with div(cls="col-lg-6 h-100 text-center text-lg-end my-auto").add(ul(cls="list-inline mb-0")):
                        li(cls="list-inline-item").add(a(href=f'/readme/')).add(i(cls="bi bi-question-circle fs-3"))
                        li(cls="list-inline-item").add(
                            a(href=f'/dashboards/app/dashboards#/view/9ee51f94-3316-4fc5-bd89-93a52af69714')
                        ).add(i(cls="bi bi-bar-chart-line fs-3"))
                        li(cls="list-inline-item").add(a(href=f'https://github.com/idaholab/Malcolm/')).add(
                            i(cls="bi-github fs-3")
                        )

                script(type="text/javascript", src=f"{args.assetsDirRespReplacer}js/bootstrap.bundle.min.js")
                script(type="text/javascript", src=f"{args.assetsDirRespReplacer}js/scripts.js")

            # send directory listing HTML to web client
            self.wfile.write(str.encode(str(doc)))

        else:
            # serve a file for download

            # handle special case of requesting assets (css, js, etc.)
            satisfied = False
            tmpPath = os.path.join('/', relpath)
            if (
                (not os.path.isfile(fullpath))
                and (not os.path.islink(fullpath))
                and tmpPath.startswith(args.assetsDirReqReplacer)
                and os.path.isdir(str(args.assetsDir))
            ):
                # an asset was requested, so translate it into the real asset's path
                if (
                    (fullpath := os.path.join(args.assetsDir, remove_prefix(tmpPath, args.assetsDirReqReplacer)))
                    and os.path.isfile(fullpath)
                    and (args.links or (not os.path.islink(fullpath)))
                ):
                    # serve the asset file
                    satisfied = True
                    ctype = self.guess_type(fullpath)
                    with open(fullpath, 'rb') as fhandle:
                        fs = os.fstat(fhandle.fileno())
                        self.send_response(200)
                        self.send_header('Content-type', self.guess_type(fullpath))
                        self.send_header("Content-Length", str(fs[6]))
                        self.send_header("Last-Modified", self.date_time_string(fs.st_mtime))
                        self.end_headers()
                        while chunk := fhandle.read(1024):
                            self.wfile.write(chunk)

            # handle regular file downloads
            if not satisfied:
                # if the file doesn't exist as specified but recursive is enabled, go deeper to find the file
                if args.recursive and (not os.path.isfile(fullpath)) and (not os.path.islink(fullpath)):
                    for root, dirs, files in os.walk(os.path.dirname(fullpath)):
                        if fileBaseName in files:
                            fullpath = os.path.join(root, fileBaseName)
                            break

                if os.path.isfile(fullpath) and (args.links or (not os.path.islink(fullpath))):
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
    defaultLinks = os.getenv('EXTRACTED_FILE_HTTP_SERVER_LINKS', 'false')
    defaultMalcolm = os.getenv('EXTRACTED_FILE_HTTP_SERVER_MALCOLM', 'false')
    defaultPort = int(os.getenv('EXTRACTED_FILE_HTTP_SERVER_PORT', 8440))
    defaultKey = os.getenv('EXTRACTED_FILE_HTTP_SERVER_KEY', 'infected')
    defaultDir = os.getenv('EXTRACTED_FILE_HTTP_SERVER_PATH', orig_path)
    defaultAssetsDir = os.getenv('EXTRACTED_FILE_HTTP_SERVER_ASSETS_DIR', '/opt/assets')
    defaultAssetsDirReqReplacer = os.getenv('EXTRACTED_FILE_HTTP_SERVER_ASSETS_DIR_REQ_REPLACER', '/assets')
    defaultAssetsDirRespReplacer = os.getenv('EXTRACTED_FILE_HTTP_SERVER_ASSETS_DIR_RESP_REPLACER', '/assets')

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
        '-a',
        '--assets-directory',
        dest='assetsDir',
        help=f'Directory hosting assets ({defaultAssetsDir})',
        metavar='<directory>',
        type=str,
        default=defaultAssetsDir,
    )
    parser.add_argument(
        '--assets-directory-req-replacer',
        dest='assetsDirReqReplacer',
        help=f'Virtual directory name for requests to redirect to assets directory ({defaultAssetsDirReqReplacer})',
        metavar='<string>',
        type=str,
        default=defaultAssetsDirReqReplacer,
    )
    parser.add_argument(
        '--assets-directory-resp-replacer',
        dest='assetsDirRespReplacer',
        help=f'Virtual directory name for responses to indicate files in the assets directory ({defaultAssetsDirRespReplacer})',
        metavar='<string>',
        type=str,
        default=defaultAssetsDirRespReplacer,
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
        help=f"Recursively look for requested file if not found ({defaultRecursive})",
    )
    parser.add_argument(
        '-l',
        '--links',
        dest='links',
        type=str2bool,
        nargs='?',
        const=True,
        default=defaultLinks,
        metavar='true|false',
        help=f"Serve symlinks in addition to regular files ({defaultLinks})",
    )
    parser.add_argument(
        '--malcolm',
        dest='malcolm',
        type=str2bool,
        nargs='?',
        const=True,
        default=defaultMalcolm,
        metavar='true|false',
        help=f"Include columns for Zeek-extracted files in Malcolm ({defaultMalcolm})",
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

    if args.assetsDirReqReplacer:
        args.assetsDirReqReplacer = os.path.join(args.assetsDirReqReplacer, '')
    if args.assetsDirRespReplacer:
        args.assetsDirRespReplacer = os.path.join(args.assetsDirRespReplacer, '')

    Thread(target=serve_on_port, args=[args.serveDir, args.port]).start()


###################################################################################################
if __name__ == '__main__':
    main()
