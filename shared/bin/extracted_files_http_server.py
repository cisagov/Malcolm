#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Multithreaded simple HTTP directory server.
#
# The files can optionally be archived in a ZIP file, with or without a password, or
# be aes-256-cbc encrypted in a way that's compatible with:
#   openssl enc -aes-256-cbc -d -in encrypted.data -out decrypted.data

import atexit
import argparse
import dominate
import functools
import hashlib
import logging
import magic
import os
import re
import ssl
import sys
import time
from Crypto.Cipher import AES
from contextlib import nullcontext
from datetime import datetime, timedelta, UTC
from dominate.tags import *
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
from stat import S_IFREG
from stream_zip import ZIP_32, stream_zip
from tempfile import TemporaryDirectory
from urllib.parse import urlparse, parse_qs

from malcolm_utils import (
    EVP_BytesToKey,
    EVP_KEY_SIZE,
    OPENSSL_ENC_MAGIC,
    PKCS5_SALT_LEN,
    openssl_self_signed_keygen,
    pushd,
    remove_prefix,
    set_logging,
    get_verbosity_env_var_count,
    sizeof_fmt,
    str2bool,
)

###################################################################################################
args = None
script_name = os.path.basename(__file__)
script_path = os.path.dirname(os.path.realpath(__file__))
orig_path = os.getcwd()
filename_truncate_len_malcolm = 20
filename_truncate_len = 32
malcolm_forward_header = 'X-Malcolm-Forward'


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
        fullpath = os.path.join(self.directory, relpath)
        return fullpath, relpath

    # override do_GET for fancy directory listing and so that files are encrypted/zipped, if requested
    def do_GET(self):
        global args

        # SimpleHTTPRequestHandler's headers lookup is case-insensitive
        client_roles = [role for role in map(str.strip, self.headers.get('X-Forwarded-Roles', '').split(',')) if role]
        rolesSatisfied = (not args.rbacEnabled) or any(
            role in client_roles for role in [x for x in (os.getenv('ROLE_EXTRACTED_FILES', ''),) if x]
        )

        logging.debug(
            f"{rolesSatisfied=}; {client_roles=}; {os.getenv('ROLE_EXTRACTED_FILES', '')=}; {dict(self.headers)=}"
        )

        if rolesSatisfied:

            showMalcolmCols = args.malcolm or (malcolm_forward_header in dict(self.headers))
            assetsDirRespReplacer = (
                f"{str(dict(self.headers).get(malcolm_forward_header, ''))}{args.assetsDirRespReplacer}"
            )

            fullpath, relpath = self.translate_path(self.path)
            fileBaseName = os.path.basename(fullpath)
            fnameDispLen = filename_truncate_len_malcolm if showMalcolmCols else filename_truncate_len

            tomorrowStr = (datetime.now(UTC) + timedelta(days=1)).isoformat().split('.')[0]

            # HTTP-FUID-UID-TIMESTAMP.ext
            carvedFileRegex = re.compile(
                r'^(?P<source>[^-]+)-(?P<fuid>F[a-zA-Z0-9]+|unknown)-(?P<uid>C[a-zA-Z0-9]+|unknown)-(?P<timestamp>\d+)(?P<ext>\..+)?$'
            )
            # UID-FUID-whatever
            carvedFileRegexAlt = re.compile(r'^(?P<uid>C[a-zA-Z0-9]+)_(?P<fuid>F[a-zA-Z0-9]+)')
            # XOR decrypted from FEieEe1f1SI6YJk4H5
            xorRegex = re.compile(r'^(?P<source>XOR) decrypted from (?P<fuid>F[a-zA-Z0-9]+)')

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
                    link(rel="icon", href=f"{assetsDirRespReplacer}favicon.ico", type="image/x-icon")
                    link(rel="stylesheet", href=f"{assetsDirRespReplacer}css/bootstrap-icons.css", type="text/css")
                    link(rel="stylesheet", href=f"{assetsDirRespReplacer}css/google-fonts.css", type="text/css")
                    link(rel="stylesheet", href=f"{assetsDirRespReplacer}css/styles.css", type="text/css")

                # <body>
                with doc:
                    # header decoration
                    with nav(cls='navbar navbar-light bg-light static-top'):
                        div(cls='container')
                    header(cls='masthead')
                    with section(cls="features-icons bg-light"):
                        with div(cls='container'):
                            h1(pageTitle, cls='mb-5', style='text-align: center')
                            with div(cls='container').add(div(cls="row")).add(div(cls="col-lg-12")):

                                # parse the query parameters to get the page number
                                parsedUrl = urlparse(self.path)
                                queryParams = parse_qs(parsedUrl.query)
                                page = int(queryParams.get('page', ['1'])[0])
                                page = max(page, 1)

                                # now get # of elements to display per page
                                elements = int(queryParams.get('elements', ['1'])[0])
                                elements = max(elements, 50)
                                itemsPerPage = elements

                                items = []

                                for dirpath, dirnames, filenames in os.walk(fullpath):
                                    # list directories first
                                    for dirname in sorted(dirnames, key=str.casefold):
                                        try:
                                            child = os.path.join(dirpath, dirname)
                                            if args.links or (not os.path.islink(child)):
                                                items.append(('dir', dirname, child))
                                        except Exception as e:
                                            logging.error(f'Error with directory "{dirname}"": {e}')
                                    # list files
                                    for filename in sorted(filenames, key=str.casefold):
                                        try:
                                            child = os.path.join(dirpath, filename)
                                            if args.links or (not os.path.islink(child)):
                                                items.append(('file', filename, child))
                                        except Exception as e:
                                            logging.error(f'Error with file "{filename}"": {e}')
                                    # our "walk" is not recursive right now, we only need to go one level deep
                                    break

                                totalItems = len(items)
                                totalPages = (totalItems + itemsPerPage - 1) // itemsPerPage

                                # ensure the page number is within valid range
                                page = min(page, totalPages) if totalPages > 0 else 1

                                # get items for the current page
                                startIndex = (page - 1) * itemsPerPage
                                endIndex = startIndex + itemsPerPage
                                itemsOnPage = items[startIndex:endIndex]

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
                                    if showMalcolmCols:
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
                                        if showMalcolmCols:
                                            t.add(th(), th(), th())

                                    # content rows
                                    for itemType, filename, child in itemsOnPage:
                                        try:
                                            if itemType == 'dir':
                                                t = tr()
                                                t.add(
                                                    td(a(filename, href=f'{filename}/?page=1&elements={elements}')),
                                                    td("Directory"),
                                                    td(''),
                                                )

                                                if showMalcolmCols:
                                                    t.add(th(), th(), th())
                                            elif itemType == 'file':
                                                t = tr()

                                                # calculate some of the stuff for representing Malcolm files
                                                timestamp = None
                                                timestampStr = ''
                                                timestampStartFilterStr = ''
                                                fmatch = None
                                                fsource = ''
                                                fids = list()
                                                if showMalcolmCols:
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
                                                            timestampStartFilterStr = (
                                                                (timestamp - timedelta(days=1))
                                                                .isoformat()
                                                                .split('.')[0]
                                                            )
                                                        except Exception as te:
                                                            if timestampStr:
                                                                logging.error(
                                                                    f'Error with time "{str(timestampStr)}": {te}'
                                                                )
                                                        # put UIDs and FUIDs into a single event.id-filterable column
                                                        fids = list(
                                                            [
                                                                x
                                                                for x in [
                                                                    fmatch.groupdict().get('uid', ''),
                                                                    fmatch.groupdict().get('fuid', ''),
                                                                ]
                                                                if x and x != 'unknown'
                                                            ]
                                                        )
                                                        # massage source a little bit (remove '<error>' and handle
                                                        #   'XOR decrypted from...')
                                                        fsource = fmatch.groupdict().get('source', '')
                                                        if fsource == '<error>':
                                                            fsource = ''
                                                        elif xorMatch := xorRegex.search(fsource):
                                                            fsource = xorMatch.groupdict().get('source', '')
                                                            fids.append(xorMatch.groupdict().get('fuid', ''))

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
                                                                (filename[:fnameDispLen] + '...')
                                                                if len(filename) > fnameDispLen
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
                                                                target="_blank",
                                                            ),
                                                        )
                                                        if args.magic
                                                        else td(fileinfo)
                                                    ),
                                                    td(sizeof_fmt(os.path.getsize(child)), style="text-align: right"),
                                                )

                                                # show special malcolm columns if requested
                                                if showMalcolmCols:
                                                    if fmatch is not None:
                                                        # list carve source, IDs, and timestamp
                                                        t.add(
                                                            td(
                                                                fsource,
                                                                style="text-align: center",
                                                            ),
                                                            td(
                                                                [
                                                                    a(
                                                                        fid,
                                                                        href=f'/arkime/idark2dash/filter?start={timestampStartFilterStr}&stop={tomorrowStr}&field=event.id&value={fid}',
                                                                        target="_blank",
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
                                            logging.error(f'Error with file "{filename}": {e}')

                                # pagination controls
                                br()
                                with div(
                                    cls='pagination',
                                    style='text-align: center; display: flex; justify-content: center; padding: 0;',
                                ):
                                    with ul(
                                        cls='pagination-list',
                                        style='display: flex; list-style: none; justify-content: center; padding: 0;',
                                    ):
                                        # previous page link
                                        if page > 1:
                                            prevPageUrl = f'?page={page - 1}&elements={elements}'
                                            li(
                                                a(
                                                    f'Previous ({page - 1})',
                                                    href=prevPageUrl,
                                                    cls='page-link',
                                                ),
                                                cls='page-item',
                                            )
                                        else:
                                            li(span('Previous', cls='page-link disabled'), cls='page-item')

                                        # add a space between text
                                        li(' ', cls='page-item spacer', style='width: 10px;')

                                        # next page link
                                        if page < totalPages:
                                            nextPageUrl = f'?page={page + 1}&elements={elements}'
                                            li(
                                                a(
                                                    f'Next ({page + 1} of {totalPages})',
                                                    href=nextPageUrl,
                                                    cls='page-link',
                                                ),
                                                cls='page-item',
                                            )
                                        else:
                                            li(span('Next', cls='page-link disabled'), cls='page-item')

                    # footer decoration
                    with footer(cls='footer bg-light').add(div(cls='container')).add(div(cls='row')):
                        with div(cls="col-lg-6 h-100 text-center text-lg-start my-auto"):
                            p(
                                "Malcolm © 2025 Battelle Energy Alliance, LLC; developed at INL and released through the cooperation of the Cybersecurity and Infrastructure Security Agency of the U.S. Department of Homeland Security.",
                                cls="text-muted small mb-4 mb-lg-0",
                            )

                        with div(cls="col-lg-6 h-100 text-center text-lg-end my-auto").add(ul(cls="list-inline mb-0")):
                            if showMalcolmCols:
                                li(cls="list-inline-item").add(a(href=f'/', target="_blank")).add(
                                    i(cls="bi bi-house fs-3", title="Malcolm")
                                )
                                li(cls="list-inline-item").add(a(href=f'/readme/', target="_blank")).add(
                                    i(cls="bi bi-question-circle fs-3", title="Documentation")
                                )
                                li(cls="list-inline-item").add(
                                    a(
                                        href=f'/dashboards/app/dashboards#/view/9ee51f94-3316-4fc5-bd89-93a52af69714',
                                        target="_blank",
                                    )
                                ).add(i(cls="bi bi-bar-chart-line fs-3", title="Dashboards"))
                                li(cls="list-inline-item").add(a(href=f'/arkime/sessions/', target="_blank")).add(
                                    i(cls="bi bi-table fs-3", title="Arkime")
                                )
                            li(cls="list-inline-item").add(
                                a(href=f'https://github.com/idaholab/Malcolm/', target="_blank")
                            ).add(i(cls="bi-github fs-3", title="GitHub"))

                    script(type="text/javascript", src=f"{assetsDirRespReplacer}js/bootstrap.bundle.min.js")
                    script(type="text/javascript", src=f"{assetsDirRespReplacer}js/scripts.js")

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
                        with open(fullpath, 'rb') as f:
                            fs = os.fstat(f.fileno())
                            self.send_response(200)
                            self.send_header('Content-type', self.guess_type(fullpath))
                            self.send_header("Content-Length", str(fs[6]))
                            self.send_header("Last-Modified", self.date_time_string(fs.st_mtime))
                            self.end_headers()
                            while chunk := f.read(1024):
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
                            for chunk in stream_zip(
                                LocalFilesForZip([fullpath]), password=args.key if args.key else None
                            ):
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
                            with open(fullpath, 'rb') as f:
                                fs = os.fstat(f.fileno())
                                self.send_response(200)
                                self.send_header('Content-type', self.guess_type(fullpath))
                                self.send_header("Content-Length", str(fs[6]))
                                self.send_header("Last-Modified", self.date_time_string(fs.st_mtime))
                                self.end_headers()
                                while chunk := f.read(1024):
                                    self.wfile.write(chunk)

                    else:
                        self.send_error(404, "Not Found")
        else:
            self.send_error(403, "Forbidden")


###################################################################################################
#
def serve_on_port(
    path,
    port,
    tls=False,
    tls_key_file=None,
    tls_cert_file=None,
    server_class=ThreadingHTTPServer,
    handler_class=HTTPHandler,
):
    with (
        TemporaryDirectory() if (tls and tls_key_file is None and tls_cert_file is None) else nullcontext()
    ) as temp_cert_dir:
        if temp_cert_dir and openssl_self_signed_keygen(outdir=temp_cert_dir, ca_prefix=None, server_prefix="server"):
            tls_cert_file = os.path.join(temp_cert_dir, "server.crt")
            tls_key_file = os.path.join(temp_cert_dir, "server.key")
        with pushd(path):
            server = server_class(("", port), functools.partial(handler_class, directory=path))
            if tlsOk := (tls and os.path.isfile(str(tls_key_file)) and os.path.isfile(str(tls_cert_file))):
                ctx = ssl.SSLContext(protocol=ssl.PROTOCOL_TLS_SERVER)
                ctx.load_cert_chain(certfile=tls_cert_file, keyfile=tls_key_file)
                server.socket = ctx.wrap_socket(server.socket, server_side=True)
            if tls and not tlsOk:
                raise Exception.create('Unable to use or generate TLS certificates')
            print(f"serving {path} at port {port}{' over TLS' if tlsOk else ''}")
            server.serve_forever()


###################################################################################################
# main
def main():
    global args
    global orig_path

    defaultZip = os.getenv('EXTRACTED_FILE_HTTP_SERVER_ZIP', 'false')
    defaultRecursive = os.getenv('EXTRACTED_FILE_HTTP_SERVER_RECURSIVE', 'false')
    defaultMagic = os.getenv('EXTRACTED_FILE_HTTP_SERVER_MAGIC', 'false')
    defaultTls = os.getenv('EXTRACTED_FILE_HTTP_SERVER_TLS', 'false')
    defaultLinks = os.getenv('EXTRACTED_FILE_HTTP_SERVER_LINKS', 'false')
    defaultMalcolm = os.getenv('EXTRACTED_FILE_HTTP_SERVER_MALCOLM', 'false')
    defaultPort = int(os.getenv('EXTRACTED_FILE_HTTP_SERVER_PORT', 8006))
    defaultKey = os.getenv('EXTRACTED_FILE_HTTP_SERVER_KEY', 'infected')
    defaultDir = os.getenv('EXTRACTED_FILE_HTTP_SERVER_PATH', orig_path)
    defaultAssetsDir = os.getenv('EXTRACTED_FILE_HTTP_SERVER_ASSETS_DIR', '/opt/assets')
    defaultAssetsDirReqReplacer = os.getenv('EXTRACTED_FILE_HTTP_SERVER_ASSETS_DIR_REQ_REPLACER', '/assets')
    defaultAssetsDirRespReplacer = os.getenv('EXTRACTED_FILE_HTTP_SERVER_ASSETS_DIR_RESP_REPLACER', '/assets')
    defaultRBAC = os.getenv('ROLE_BASED_ACCESS', 'false')

    parser = argparse.ArgumentParser(description=script_name, add_help=True, usage='{} <arguments>'.format(script_name))
    parser.add_argument(
        '--verbose',
        '-v',
        action='count',
        default=get_verbosity_env_var_count("VERBOSITY"),
        help='Increase verbosity (e.g., -v, -vv, etc.)',
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
        '-t',
        '--tls',
        dest='tls',
        type=str2bool,
        nargs='?',
        const=True,
        default=defaultTls,
        metavar='true|false',
        help=f"Serve with TLS (specify --tls-keyfile and --tls-certfile, or a temporary self-signed certificate will be used)",
    )
    parser.add_argument(
        '--rbac',
        dest='rbacEnabled',
        type=str2bool,
        nargs='?',
        const=True,
        default=defaultRBAC,
        metavar='true|false',
        help=f"Enforce RBAC based on X-Forwarded-Roles header",
    )
    parser.add_argument(
        '--tls-keyfile',
        dest='tlsKeyFile',
        help=f'TLS Key File',
        metavar='<filename>',
        type=str,
        default=os.getenv('EXTRACTED_FILE_HTTP_SERVER_TLS_KEYFILE', None),
    )
    parser.add_argument(
        '--tls-certfile',
        dest='tlsCertFile',
        help=f'TLS Certificate File',
        metavar='<filename>',
        type=str,
        default=os.getenv('EXTRACTED_FILE_HTTP_SERVER_TLS_CERTFILE', None),
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
        args = parser.parse_args()
    except SystemExit as e:
        if e.code == 2:
            parser.print_help()
        sys.exit(e.code)

    args.verbose = set_logging(
        os.getenv('EXTRACTED_FILE_HTTP_SERVER_LOGLEVEL', ''), args.verbose, set_traceback_limit=True
    )
    logging.debug(os.path.join(script_path, script_name))
    logging.debug(f"Arguments: {sys.argv[1:]}")
    logging.debug(f"Arguments: {args}")

    if args.assetsDirReqReplacer:
        args.assetsDirReqReplacer = os.path.join(args.assetsDirReqReplacer, '')
    if args.assetsDirRespReplacer:
        args.assetsDirRespReplacer = os.path.join(args.assetsDirRespReplacer, '')

    serve_on_port(
        path=args.serveDir,
        port=args.port,
        tls=args.tls,
        tls_key_file=args.tlsKeyFile,
        tls_cert_file=args.tlsCertFile,
    )


###################################################################################################
if __name__ == '__main__':
    main()
