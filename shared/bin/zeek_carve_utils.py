#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2023 Battelle Energy Alliance, LLC.  All rights reserved.

import clamd
import hashlib
import json
import os
import re
import requests
import sys
import time
import yara
import zmq

from abc import ABC, abstractmethod
from bs4 import BeautifulSoup
from collections import Counter
from collections import deque
from collections import defaultdict
from datetime import datetime
from multiprocessing import RawValue
from subprocess import PIPE, Popen
from threading import get_ident
from threading import Lock

###################################################################################################
VENTILATOR_PORT = 5987
SINK_PORT = 5988
TOPIC_FILE_SCAN = "file"

###################################################################################################
# modes for file preservation settings
PRESERVE_QUARANTINED = "quarantined"
PRESERVE_ALL = "all"
PRESERVE_NONE = "none"

PRESERVE_QUARANTINED_DIR_NAME = "quarantine"
PRESERVE_PRESERVED_DIR_NAME = "preserved"

###################################################################################################
FILE_SCAN_RESULT_SCANNER = "scanner"
FILE_SCAN_RESULT_FILE = "file"
FILE_SCAN_RESULT_FILE_SIZE = "size"
FILE_SCAN_RESULT_FILE_TYPE = "type"
FILE_SCAN_RESULT_ENGINES = "engines"
FILE_SCAN_RESULT_HITS = "hits"
FILE_SCAN_RESULT_MESSAGE = "message"
FILE_SCAN_RESULT_DESCRIPTION = "description"

###################################################################################################
# the notice field for the signature.log we're writing out mimicing Zeek
ZEEK_SIGNATURE_NOTICE = "Signatures::Sensitive_Signature"

###################################################################################################
# VirusTotal public API
VTOT_MAX_REQS = 4  # maximum 4 public API requests (default)
VTOT_MAX_SEC = 60  # in 60 seconds (default)
VTOT_CHECK_INTERVAL = 0.05
VTOT_URL = 'https://www.virustotal.com/vtapi/v2/file/report'
VTOT_RESP_NOT_FOUND = 0
VTOT_RESP_FOUND = 1
VTOT_RESP_QUEUED = -2

###################################################################################################
# ClamAV Interface
CLAM_MAX_REQS = 8  # maximum scanning requests concurrently, should be <= clamd.conf MaxThreads
CLAM_SUBMIT_TIMEOUT_SEC = 10
CLAM_CHECK_INTERVAL = 0.1
CLAM_ENGINE_ID = 'ClamAV'
CLAM_FOUND_KEY = 'FOUND'

###################################################################################################
# Yara Interface
YARA_RULES_DIR = os.path.join(os.getenv('YARA_RULES_DIR', "/yara-rules"), '')
YARA_CUSTOM_RULES_DIR = os.path.join(YARA_RULES_DIR, "custom")
YARA_SUBMIT_TIMEOUT_SEC = 60
YARA_ENGINE_ID = 'Yara'
YARA_MAX_REQS = 8  # maximum scanning threads concurrently
YARA_CHECK_INTERVAL = 0.1
YARA_RUN_TIMEOUT_SEC = 300

###################################################################################################
# Capa
CAPA_MAX_REQS = 4  # maximum scanning threads concurrently
CAPA_SUBMIT_TIMEOUT_SEC = 60
CAPA_ENGINE_ID = 'Capa'
CAPA_CHECK_INTERVAL = 0.1
CAPA_MIMES_TO_SCAN = (
    'application/bat',
    'application/ecmascript',
    'application/javascript',
    'application/PowerShell',
    'application/vnd.microsoft.portable-executable',
    'application/x-bat',
    'application/x-dosexec',
    'application/x-elf',
    'application/x-executable',
    'application/x-msdos-program',
    'application/x-msdownload',
    'application/x-pe-app-32bit-i386',
    'application/x-sh',
    'text/jscript',
    'text/vbscript',
    'text/x-python',
    'text/x-shellscript',
)
CAPA_VIV_SUFFIX = '.viv'
CAPA_VIV_MIME = 'data'
CAPA_ATTACK_KEY = 'attack'
CAPA_RUN_TIMEOUT_SEC = 300

###################################################################################################


# a structure representing the fields of a line of Zeek's signatures.log, and the corresponding string formatting and type definitions
class BroSignatureLine:
    __slots__ = (
        'ts',
        'uid',
        'orig_h',
        'orig_p',
        'resp_h',
        'resp_p',
        'note',
        'signature_id',
        'event_message',
        'sub_message',
        'signature_count',
        'host_count',
    )

    def __init__(
        self,
        ts='-',
        uid='-',
        orig_h='-',
        orig_p='-',
        resp_h='-',
        resp_p='-',
        note='-',
        signature_id='-',
        event_message='-',
        sub_message='-',
        signature_count='-',
        host_count='-',
    ):
        self.ts = ts
        self.uid = uid
        self.orig_h = orig_h
        self.orig_p = orig_p
        self.resp_h = resp_h
        self.resp_p = resp_p
        self.note = note
        self.signature_id = signature_id
        self.event_message = event_message
        self.sub_message = sub_message
        self.signature_count = signature_count
        self.host_count = host_count

    def __str__(self):
        return "\t".join(
            map(
                str,
                [
                    self.ts,
                    self.uid,
                    self.orig_h,
                    self.orig_p,
                    self.resp_h,
                    self.resp_p,
                    self.note,
                    self.signature_id,
                    self.event_message,
                    self.sub_message,
                    self.signature_count,
                    self.host_count,
                ],
            )
        )

    @classmethod
    def signature_format_line(cls):
        return "\t".join(['{' + x + '}' for x in cls.__slots__])

    @classmethod
    def signature_types_line(cls):
        return "\t".join(
            ['time', 'string', 'addr', 'port', 'addr', 'port', 'enum', 'string', 'string', 'string', 'count', 'count']
        )


# AnalyzerScan
# .provider - a FileScanProvider subclass doing the scan/lookup
# .name - the filename to be scanned
# .size - the size (in bytes) of the file
# .fileType - the file's mime type
# .submissionResponse - a unique identifier to be returned by the provider with which to check status
class AnalyzerScan:
    __slots__ = ('provider', 'name', 'size', 'fileType', 'submissionResponse')

    def __init__(self, provider=None, name=None, size=None, fileType=None, submissionResponse=None):
        self.provider = provider
        self.name = name
        self.size = size
        self.fileType = fileType
        self.submissionResponse = submissionResponse


# AnalyzerResult
# .finished - the scan/lookup is no longer executing (whether or not it was successful or returned a "match")
# .success - requesting the status was done successfully (whether or not it was finished)
# .result - the "result" of the scan/lookup, in whatever format is native to the provider
class AnalyzerResult:
    __slots__ = ('finished', 'success', 'verbose', 'result')

    def __init__(self, finished=False, success=False, verbose=False, result=None):
        self.finished = finished
        self.success = success
        self.verbose = verbose
        self.result = result


# the filename parts used by our Zeek instance for extracted files:
#   source-fuid-uid-time.ext, eg., SSL-FTnzwn4hEPJi7BfzRk-CsRaviydrGyYROuX3-20190402105425.crt
class ExtractedFileNameParts:
    __slots__ = ('source', 'fid', 'uid', 'time', 'ext')

    def __init__(self, source=None, fid=None, uid=None, time=None, ext=None):
        self.source = source
        self.fid = fid
        self.uid = uid
        self.time = time
        self.ext = ext


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
# print to stderr
def eprint(*args, **kwargs):
    print(datetime.now().strftime("%Y-%m-%d %H:%M:%S"), *args, file=sys.stderr, **kwargs)


###################################################################################################
# calculate a sha256 hash of a file
def sha256sum(filename):
    h = hashlib.sha256()
    b = bytearray(64 * 1024)
    mv = memoryview(b)
    with open(filename, 'rb', buffering=0) as f:
        for n in iter(lambda: f.readinto(mv), 0):
            h.update(mv[:n])
    return h.hexdigest()


###################################################################################################
# recursive dictionary key search
def dictsearch(d, target):
    val = filter(
        None, [[b] if a == target else dictsearch(b, target) if isinstance(b, dict) else None for a, b in d.items()]
    )
    return [i for b in val for i in b]


###################################################################################################
# filespec to various fields as per the extractor zeek script (/opt/zeek/share/zeek/site/extractor.zeek)
#   source-fuid-uid-time.ext
#   eg.
#       SSL-FTnzwn4hEPJi7BfzRk-CsRaviydrGyYROuX3-20190402105425.crt
#
# there are other extracted files that come from the mitre-attack/bzar scripts, they are formatted like this:
#   local fname = fmt("%s_%s%s", c$uid, f$id, subst_string(smb_name, "\\", "_"));
#
#   CR7X4q2hmcXKqP0vVj_F3jZ2VjYttqhKaGfh__172.16.1.8_C$_WINDOWS_sny4u_un1zbd94ytwj99hcymmsad7j54gr4wdskwnqs0ki252jdsrf763zsm531b.exe
#   └----------------┘ └---------------┘└------------------------------------------------------------------------------------------┘
#           UID              FID          subst_string(smb_name, "\\", "_"))
#
#   (see https://github.com/mitre-attack/bzar/blob/master/scripts/bzar_files.zeek#L50)
def extracted_filespec_to_fields(filespec):
    baseFileSpec = os.path.basename(filespec)
    match = re.search(r'^(?P<source>.*)-(?P<fid>.*)-(?P<uid>.*)-(?P<time>\d+)\.(?P<ext>.*?)$', baseFileSpec)
    if match is not None:
        result = ExtractedFileNameParts(
            match.group('source'),
            match.group('fid'),
            match.group('uid'),
            time.mktime(datetime.strptime(match.group('time'), "%Y%m%d%H%M%S").timetuple()),
            match.group('ext'),
        )
    else:
        match = re.search(r'^(?P<uid>[0-9a-zA-Z]+)_(?P<fid>[0-9a-zA-Z]+).+\.(?P<ext>.*?)$', baseFileSpec)
        if match is not None:
            result = ExtractedFileNameParts(
                'MITRE', match.group('fid'), match.group('uid'), time.time(), match.group('ext')
            )
        else:
            result = ExtractedFileNameParts(None, None, None, time.time(), None)

    return result


###################################################################################################
# open a file and close it, updating its access time
def touch(filename):
    open(filename, 'a').close()
    os.utime(filename, None)


###################################################################################################
# run command with arguments and return its exit code, stdout, and stderr
def check_output_input(*popenargs, **kwargs):
    if 'stdout' in kwargs:
        raise ValueError('stdout argument not allowed, it will be overridden')

    if 'stderr' in kwargs:
        raise ValueError('stderr argument not allowed, it will be overridden')

    if 'input' in kwargs and kwargs['input']:
        if 'stdin' in kwargs:
            raise ValueError('stdin and input arguments may not both be used')
        inputdata = kwargs['input']
        kwargs['stdin'] = PIPE
    else:
        inputdata = None
    kwargs.pop('input', None)

    process = Popen(*popenargs, stdout=PIPE, stderr=PIPE, **kwargs)
    try:
        output, errput = process.communicate(input=inputdata)
    except:
        process.kill()
        process.wait()
        raise

    retcode = process.poll()

    return retcode, output, errput


###################################################################################################
# run command with arguments and return its exit code and output
def run_process(command, stdout=True, stderr=True, stdin=None, cwd=None, env=None, debug=False):
    retcode = -1
    output = []

    try:
        # run the command
        retcode, cmdout, cmderr = check_output_input(command, input=stdin.encode() if stdin else None, cwd=cwd, env=env)

        # split the output on newlines to return a list
        if stderr and (len(cmderr) > 0):
            output.extend(cmderr.decode(sys.getdefaultencoding()).split('\n'))
        if stdout and (len(cmdout) > 0):
            output.extend(cmdout.decode(sys.getdefaultencoding()).split('\n'))

    except (FileNotFoundError, OSError, IOError) as e:
        if stderr:
            output.append("Command {} not found or unable to execute".format(command))

    if debug:
        eprint(
            "{}{} returned {}: {}".format(
                command, "({})".format(stdin[:80] + bool(stdin[80:]) * '...' if stdin else ""), retcode, output
            )
        )

    return retcode, output


###################################################################################################
class AtomicInt:
    def __init__(self, value=0):
        self.val = RawValue('i', value)
        self.lock = Lock()

    def increment(self):
        with self.lock:
            self.val.value += 1
            return self.val.value

    def decrement(self):
        with self.lock:
            self.val.value -= 1
            return self.val.value

    def value(self):
        with self.lock:
            return self.val.value


###################################################################################################
class CarvedFileSubscriberThreaded:
    # ---------------------------------------------------------------------------------
    # constructor
    def __init__(
        self,
        debug=False,
        verboseDebug=False,
        host="localhost",
        port=VENTILATOR_PORT,
        context=None,
        topic='',
        rcvTimeout=5000,
        scriptName='',
    ):
        self.debug = debug
        self.verboseDebug = verboseDebug
        self.scriptName = scriptName

        self.lock = Lock()

        # initialize ZeroMQ context and socket(s) to receive filenames and send scan results
        self.context = context if (context is not None) else zmq.Context()

        # Socket to receive messages on
        self.newFilesSocket = self.context.socket(zmq.SUB)
        self.newFilesSocket.connect(f"tcp://{host}:{port}")
        self.newFilesSocket.setsockopt(zmq.SUBSCRIBE, bytes(topic, encoding='ascii'))
        self.newFilesSocket.RCVTIMEO = rcvTimeout
        if self.debug:
            eprint(f"{self.scriptName}:\tbound to ventilator at {port}")

    # ---------------------------------------------------------------------------------
    def Pull(self, scanWorkerId=0):
        fileinfo = defaultdict(str)

        with self.lock:
            # accept a fileinfo dict from newFilesSocket
            try:
                fileinfo.update(json.loads(self.newFilesSocket.recv_string()))
            except zmq.Again as timeout:
                # no file received due to timeout, return empty dict. which means no file available
                pass

        if self.verboseDebug:
            eprint(
                f"{self.scriptName}[{scanWorkerId}]:\t{'📨' if (FILE_SCAN_RESULT_FILE in fileinfo) else '🕑'}\t{fileinfo[FILE_SCAN_RESULT_FILE] if (FILE_SCAN_RESULT_FILE in fileinfo) else '(recv)'}"
            )

        return fileinfo


###################################################################################################
class FileScanProvider(ABC):
    @staticmethod
    @abstractmethod
    def scanner_name(cls):
        # returns this scanner name
        pass

    @abstractmethod
    def max_requests(self):
        # returns the maximum number of concurrently open requests this type of provider can handle
        pass

    @staticmethod
    @abstractmethod
    def check_interval(cls):
        # returns the amount of seconds you should sleep between checking for results
        pass

    @abstractmethod
    def submit(self, fileName=None, fileSize=None, fileType=None, block=False, timeout=0):
        # returns something that can be passed into check_result for checking the scan status
        pass

    @abstractmethod
    def check_result(self, submissionResponse):
        # returns AnalyzerResult based on submissionResponse
        pass

    @staticmethod
    @abstractmethod
    def format(cls, fileName, response):
        # returns result dict based on response (see FILE_SCAN_RESULT_* above)
        pass


###################################################################################################
# class for searching for a hash with a VirusTotal public API, handling rate limiting
class VirusTotalSearch(FileScanProvider):
    # ---------------------------------------------------------------------------------
    # constructor
    def __init__(self, apiKey, reqLimit=None, reqLimitSec=None):
        self.apiKey = apiKey
        self.lock = Lock()
        self.history = deque()
        self.reqLimit = reqLimit if reqLimit else VTOT_MAX_REQS
        self.reqLimitSec = reqLimitSec if reqLimitSec else VTOT_MAX_SEC

    @staticmethod
    def scanner_name():
        return 'virustotal'

    def max_requests(self):
        return self.reqLimit

    @staticmethod
    def check_interval():
        return VTOT_CHECK_INTERVAL

    # ---------------------------------------------------------------------------------
    # do a hash lookup against VirusTotal, respecting rate limiting
    # VirusTotalSearch does the request and gets the response immediately;
    # the subsequent call to check_result (using submit's response as input)
    # will always return "True" since the work has already been done
    def submit(self, fileName=None, fileSize=None, fileType=None, block=False, timeout=0):
        if timeout is None:
            timeout = self.reqLimitSec + 5

        allowed = False
        response = None

        # timeout only applies if block=True
        timeoutTime = int(time.time()) + timeout

        # while limit only repeats if block=True
        while (not allowed) and (response is None):
            with self.lock:
                # first make sure we haven't exceeded rate limits
                nowTime = int(time.time())

                if len(self.history) < self.reqLimit:
                    # we've done fewer than the allowed requests, so assume we're good to go
                    self.history.append(nowTime + self.reqLimitSec)
                    allowed = True

                elif self.history[0] < nowTime:
                    # we've done more than the allowed requests, but the oldest one is older than the window
                    _ = self.history.popleft()
                    self.history.append(nowTime + self.reqLimitSec)
                    allowed = True

            if allowed:
                try:
                    response = requests.get(VTOT_URL, params={'apikey': self.apiKey, 'resource': sha256sum(fileName)})
                except requests.exceptions.RequestException as e:
                    # things are bad
                    return None

            elif block and (nowTime < timeoutTime):
                # rate limited, wait for a bit and come around and try again
                time.sleep(1)

            else:
                break

        return response

    # ---------------------------------------------------------------------------------
    # see comment for VirusTotalSearch.submit, the work has already been done
    def check_result(self, submissionResponse):
        result = AnalyzerResult(finished=True)

        if submissionResponse is not None:
            try:
                result.success = submissionResponse.ok
            except:
                pass

            try:
                result.result = submissionResponse.json()
            except (ValueError, TypeError):
                result.success = False

        return result

    # ---------------------------------------------------------------------------------
    # static method for formatting the response JSON (from requests.get) as a dict
    @staticmethod
    def format(fileName, response):
        result = {
            FILE_SCAN_RESULT_SCANNER: VirusTotalSearch.scanner_name(),
            FILE_SCAN_RESULT_FILE: fileName,
            FILE_SCAN_RESULT_ENGINES: 0,
            FILE_SCAN_RESULT_HITS: 0,
            FILE_SCAN_RESULT_MESSAGE: None,
            FILE_SCAN_RESULT_DESCRIPTION: None,
        }

        if isinstance(response, AnalyzerResult):
            resp = response.result
        else:
            resp = response

        if isinstance(resp, str):
            try:
                resp = json.loads(resp)
            except (ValueError, TypeError):
                pass

        # see https://www.virustotal.com/en/documentation/public-api/
        if isinstance(resp, dict):
            if 'response_code' in resp:
                if (resp['response_code'] == VTOT_RESP_FOUND) and ('positives' in resp) and (resp['positives'] > 0):
                    result[FILE_SCAN_RESULT_HITS] = resp['positives']
                    if 'scans' in resp:
                        result[FILE_SCAN_RESULT_ENGINES] = len(resp['scans'])
                        scans = {
                            engine: resp['scans'][engine]
                            for engine in resp['scans']
                            if ('detected' in resp['scans'][engine]) and (resp['scans'][engine]['detected'] == True)
                        }
                        hits = defaultdict(list)
                        for k, v in scans.items():
                            hits[v['result'] if 'result' in v else 'unknown'].append(k)
                        if len(hits) > 0:
                            # short result is most common signature name
                            result[FILE_SCAN_RESULT_MESSAGE] = max(hits, key=lambda x: len(set(hits[x])))
                            # long result is list of the signature names and the engines which generated them
                            result[FILE_SCAN_RESULT_DESCRIPTION] = ";".join(
                                [f"{k}<{','.join(v)}>" for k, v in hits.items()]
                            )
                    else:
                        # we were reported positives, but no no details
                        result[FILE_SCAN_RESULT_MESSAGE] = "VirusTotal reported signature matches"
                        if 'permalink' in resp:
                            result[FILE_SCAN_RESULT_DESCRIPTION] = resp['permalink']
        else:
            # this shouldn't have happened after our checking above, so I guess just return the string
            # and let the caller deal with it
            result[FILE_SCAN_RESULT_MESSAGE] = "Invalid response"
            result[FILE_SCAN_RESULT_DESCRIPTION] = f"{resp}"

        return result


###################################################################################################
# class for scanning a file with ClamAV
class ClamAVScan(FileScanProvider):
    # ---------------------------------------------------------------------------------
    # constructor
    def __init__(self, debug=False, verboseDebug=False, socketFileName=None, reqLimit=None):
        self.scanningFilesCount = AtomicInt(value=0)
        self.debug = debug
        self.verboseDebug = verboseDebug
        self.socketFileName = socketFileName
        self.reqLimit = reqLimit if reqLimit else CLAM_MAX_REQS

    @staticmethod
    def scanner_name():
        return 'clamav'

    def max_requests(self):
        return self.reqLimit

    @staticmethod
    def check_interval():
        return CLAM_CHECK_INTERVAL

    # ---------------------------------------------------------------------------------
    # submit a file to scan with ClamAV, respecting rate limiting. return scan result
    def submit(self, fileName=None, fileSize=None, fileType=None, block=False, timeout=CLAM_SUBMIT_TIMEOUT_SEC):
        clamavResult = AnalyzerResult()
        allowed = False
        connected = False

        # timeout only applies if block=True
        timeoutTime = int(time.time()) + timeout

        # while limit only repeats if block=True
        while (not allowed) and (not clamavResult.finished):
            if not connected:
                if self.verboseDebug:
                    eprint(f"{get_ident()}: ClamAV attempting connection")
                clamAv = (
                    clamd.ClamdUnixSocket(path=self.socketFileName)
                    if self.socketFileName is not None
                    else clamd.ClamdUnixSocket()
                )
            try:
                clamAv.ping()
                connected = True
                if self.verboseDebug:
                    eprint(f"{get_ident()}: ClamAV connected!")
            except Exception as e:
                connected = False
                if self.debug:
                    eprint(f"{get_ident()}: ClamAV connection failed: {str(e)}")

            if connected:
                # first make sure we haven't exceeded rate limits
                if self.scanningFilesCount.increment() <= self.reqLimit:
                    # we've got fewer than the allowed requests open, so we're good to go!
                    allowed = True
                else:
                    self.scanningFilesCount.decrement()

            if connected and allowed:
                try:
                    if self.verboseDebug:
                        eprint(f'{get_ident()} ClamAV scanning: {fileName}')
                    clamavResult.result = clamAv.scan(fileName)
                    if self.verboseDebug:
                        eprint(f'{get_ident()} ClamAV scan result: {clamavResult.result}')
                    clamavResult.success = clamavResult.result is not None
                    clamavResult.finished = True
                except Exception as e:
                    if clamavResult.result is None:
                        clamavResult.result = str(e)
                    if self.debug:
                        eprint(f'{get_ident()} ClamAV scan error: {clamavResult.result}')
                finally:
                    self.scanningFilesCount.decrement()

            elif block and (nowTime < timeoutTime):
                # rate limited, wait for a bit and come around and try again
                time.sleep(1)

            else:
                break

        return clamavResult

    # ---------------------------------------------------------------------------------
    # return the result of the previously scanned file
    def check_result(self, clamavResult):
        return (
            clamavResult
            if isinstance(clamavResult, AnalyzerResult)
            else AnalyzerResult(finished=True, success=False, result=None)
        )

    # ---------------------------------------------------------------------------------
    # static method for formatting the response summaryDict (from check_result)
    @staticmethod
    def format(fileName, response):
        result = {
            FILE_SCAN_RESULT_SCANNER: ClamAVScan.scanner_name(),
            FILE_SCAN_RESULT_FILE: fileName,
            FILE_SCAN_RESULT_ENGINES: 1,
            FILE_SCAN_RESULT_HITS: 0,
            FILE_SCAN_RESULT_MESSAGE: None,
            FILE_SCAN_RESULT_DESCRIPTION: None,
        }

        if isinstance(response, AnalyzerResult):
            resp = response.result
        else:
            resp = response

        if isinstance(resp, dict):
            hits = []
            for filename, resultTuple in resp.items():
                if (len(resultTuple) == 2) and (resultTuple[0] == CLAM_FOUND_KEY):
                    hits.append(resultTuple[1])
            result[FILE_SCAN_RESULT_HITS] = len(hits)
            if len(hits) > 0:
                cnt = Counter(hits)
                # short message is most common signature name
                result[FILE_SCAN_RESULT_MESSAGE] = cnt.most_common(1)[0][0]
                # long description is list of the signature names and the engines which generated them
                result[FILE_SCAN_RESULT_DESCRIPTION] = ";".join([f"{x}<{CLAM_ENGINE_ID}>" for x in hits])

        else:
            result[FILE_SCAN_RESULT_MESSAGE] = "Error or invalid response"
            result[FILE_SCAN_RESULT_DESCRIPTION] = f"{resp}"

        return result


###################################################################################################
# class for scanning a file with Yara
class YaraScan(FileScanProvider):
    # ---------------------------------------------------------------------------------
    # constructor
    def __init__(self, debug=False, verboseDebug=False, rulesDirs=[], reqLimit=None):
        self.scanningFilesCount = AtomicInt(value=0)
        self.debug = debug
        self.verboseDebug = verboseDebug
        self.reqLimit = reqLimit if reqLimit else YARA_MAX_REQS
        self.ruleFilespecs = {}
        for yaraDir in rulesDirs:
            for root, dirs, files in os.walk(yaraDir):
                for file in files:
                    # skip hidden, backup or system related files
                    if file.startswith(".") or file.startswith("~") or file.startswith("_"):
                        continue
                    filename = os.path.join(root, file)
                    extension = os.path.splitext(file)[1].lower()
                    try:
                        testCompile = yara.compile(filename)
                        self.ruleFilespecs[filename] = filename
                    except yara.SyntaxError as e:
                        if self.debug:
                            eprint(f'{get_ident()} Ignored Yara compile error in {filename}: {e}')
        if self.verboseDebug:
            eprint(f"{get_ident()}: Initializing Yara with {len(self.ruleFilespecs)} rules files: {self.ruleFilespecs}")
        elif self.debug:
            eprint(f"{get_ident()}: Initializing Yara with {len(self.ruleFilespecs)} rules files")
        self.compiledRules = yara.compile(filepaths=self.ruleFilespecs)

    @staticmethod
    def scanner_name():
        return 'yara'

    def max_requests(self):
        return self.reqLimit

    @staticmethod
    def check_interval():
        return YARA_CHECK_INTERVAL

    # ---------------------------------------------------------------------------------
    # submit a file to scan with Yara, respecting rate limiting. return scan result
    def submit(self, fileName=None, fileSize=None, fileType=None, block=False, timeout=YARA_SUBMIT_TIMEOUT_SEC):
        yaraResult = AnalyzerResult()
        allowed = False
        matches = []

        # timeout only applies if block=True
        timeoutTime = int(time.time()) + timeout

        # while limit only repeats if block=True
        while (not allowed) and (not yaraResult.finished):
            # first make sure we haven't exceeded rate limits
            if self.scanningFilesCount.increment() <= self.reqLimit:
                # we've got fewer than the allowed requests open, so we're good to go!
                allowed = True
            else:
                self.scanningFilesCount.decrement()

            if allowed:
                try:
                    if self.verboseDebug:
                        eprint(f'{get_ident()} Yara scanning: {fileName}')
                    yaraResult.result = self.compiledRules.match(fileName, timeout=YARA_RUN_TIMEOUT_SEC)
                    if self.verboseDebug:
                        eprint(f'{get_ident()} Yara scan result: {yaraResult.result}')
                    yaraResult.success = yaraResult.result is not None
                    yaraResult.finished = True
                except Exception as e:
                    if yaraResult.result is None:
                        yaraResult.result = {"error": str(e)}
                    yaraResult.success = False
                    yaraResult.finished = True
                    if self.debug:
                        eprint(f'{get_ident()} Yara scan error: {yaraResult.result}')
                finally:
                    self.scanningFilesCount.decrement()

            elif block and (nowTime < timeoutTime):
                # rate limited, wait for a bit and come around and try again
                time.sleep(1)

            else:
                break

        return yaraResult

    # ---------------------------------------------------------------------------------
    # return the result of the previously scanned file
    def check_result(self, yaraResult):
        return (
            yaraResult
            if isinstance(yaraResult, AnalyzerResult)
            else AnalyzerResult(finished=True, success=False, result=None)
        )

    # ---------------------------------------------------------------------------------
    # static method for formatting the response summaryDict (from check_result)
    @staticmethod
    def format(fileName, response):
        result = {
            FILE_SCAN_RESULT_SCANNER: YaraScan.scanner_name(),
            FILE_SCAN_RESULT_FILE: fileName,
            FILE_SCAN_RESULT_ENGINES: 1,
            FILE_SCAN_RESULT_HITS: 0,
            FILE_SCAN_RESULT_MESSAGE: None,
            FILE_SCAN_RESULT_DESCRIPTION: None,
        }

        if isinstance(response, AnalyzerResult):
            resp = response.result
        else:
            resp = response

        if isinstance(resp, list):
            hits = [match.rule for match in resp if isinstance(match, yara.Match)]
            result[FILE_SCAN_RESULT_HITS] = len(hits)
            if len(hits) > 0:
                cnt = Counter(hits)
                # short message is most common signature name (todo: they won't have duplicate names, so I guess this is just going to take the first...)
                result[FILE_SCAN_RESULT_MESSAGE] = cnt.most_common(1)[0][0]
                # long description is list of the signature names and the engines which generated them
                result[FILE_SCAN_RESULT_DESCRIPTION] = ";".join([f"{x}<{YARA_ENGINE_ID}>" for x in hits])

        else:
            result[FILE_SCAN_RESULT_MESSAGE] = "Error or invalid response"
            result[FILE_SCAN_RESULT_DESCRIPTION] = f"{resp}"

        return result


###################################################################################################
# class for scanning a file with Capa
class CapaScan(FileScanProvider):
    # ---------------------------------------------------------------------------------
    # constructor
    def __init__(self, debug=False, verboseDebug=False, rulesDir=None, verboseHits=False, reqLimit=None):
        self.scanningFilesCount = AtomicInt(value=0)
        self.rulesDir = rulesDir
        self.debug = debug
        self.verboseDebug = verboseDebug
        self.verboseHits = verboseHits
        self.reqLimit = reqLimit if reqLimit else CAPA_MAX_REQS

    @staticmethod
    def scanner_name():
        return 'capa'

    def max_requests(self):
        return self.reqLimit

    @staticmethod
    def check_interval():
        return CAPA_CHECK_INTERVAL

    # ---------------------------------------------------------------------------------
    # submit a file to scan with Capa, respecting rate limiting. return scan result
    def submit(self, fileName=None, fileSize=None, fileType=None, block=False, timeout=CAPA_SUBMIT_TIMEOUT_SEC):
        capaResult = AnalyzerResult(verbose=self.verboseHits)

        if (fileType is not None) and (fileType in CAPA_MIMES_TO_SCAN):
            allowed = False

            # timeout only applies if block=True
            timeoutTime = int(time.time()) + timeout

            # while limit only repeats if block=True
            while (not allowed) and (not capaResult.finished):
                # first make sure we haven't exceeded rate limits
                if self.scanningFilesCount.increment() <= self.reqLimit:
                    # we've got fewer than the allowed requests open, so we're good to go!
                    allowed = True
                else:
                    self.scanningFilesCount.decrement()

                if allowed:
                    try:
                        if self.verboseDebug:
                            eprint(f'{get_ident()} Capa scanning: {fileName}')

                        if self.rulesDir is not None:
                            cmd = [
                                'timeout',
                                '-k',
                                '10',
                                '-s',
                                'TERM',
                                str(CAPA_RUN_TIMEOUT_SEC),
                                'capa',
                                '--quiet',
                                '-r',
                                self.rulesDir,
                                '--json',
                                '--color',
                                'never',
                                fileName,
                            ]
                        else:
                            cmd = [
                                'timeout',
                                '-k',
                                '10',
                                '-s',
                                'TERM',
                                str(CAPA_RUN_TIMEOUT_SEC),
                                'capa',
                                '--quiet',
                                '--json',
                                '--color',
                                'never',
                                fileName,
                            ]
                        capaErr, capaOut = run_process(cmd, stderr=False, debug=self.debug)
                        if (capaErr == 0) and (len(capaOut) > 0) and (len(capaOut[0]) > 0):
                            # load the JSON output from capa into the .result
                            try:
                                capaResult.result = json.loads(capaOut[0])
                            except (ValueError, TypeError):
                                capaResult.result = {"error": f"Invalid response: {'; '.join(capaOut)}"}

                        else:
                            # probably failed because it's not an executable, ignore it
                            capaResult.result = {"error": str(capaErr)}

                        if self.verboseDebug:
                            eprint(f'{get_ident()} Capa scan result: {capaResult.result}')
                        capaResult.success = capaResult.result is not None
                        capaResult.finished = True

                    except Exception as e:
                        if capaResult.result is None:
                            capaResult.result = str(e)
                        if self.debug:
                            eprint(f'{get_ident()} Capa scan error: {capaResult.result}')

                    finally:
                        self.scanningFilesCount.decrement()
                        try:
                            if os.path.isfile(fileName + CAPA_VIV_SUFFIX):
                                os.remove(fileName + CAPA_VIV_SUFFIX)
                        except Exception as fe:
                            pass

                elif block and (nowTime < timeoutTime):
                    # rate limited, wait for a bit and come around and try again
                    time.sleep(1)

                else:
                    break

        else:
            # not an executable, don't need to scan it
            capaResult.result = {}
            capaResult.success = True
            capaResult.finished = True

        return capaResult

    # ---------------------------------------------------------------------------------
    # return the result of the previously scanned file
    def check_result(self, capaResult):
        return (
            capaResult
            if isinstance(capaResult, AnalyzerResult)
            else AnalyzerResult(finished=True, success=False, result=None)
        )

    # ---------------------------------------------------------------------------------
    # static method for formatting the response summaryDict (from check_result)
    @staticmethod
    def format(fileName, response):
        result = {
            FILE_SCAN_RESULT_SCANNER: CapaScan.scanner_name(),
            FILE_SCAN_RESULT_FILE: fileName,
            FILE_SCAN_RESULT_ENGINES: 1,
            FILE_SCAN_RESULT_HITS: 0,
            FILE_SCAN_RESULT_MESSAGE: None,
            FILE_SCAN_RESULT_DESCRIPTION: None,
        }

        if isinstance(response, AnalyzerResult):
            resp = response.result
            verboseHits = response.verbose
        else:
            resp = response
            verboseHits = False

        if isinstance(resp, dict):
            hits = []
            if 'rules' in resp and isinstance(resp['rules'], dict):
                hits.extend(
                    [
                        f"{'::'.join(item['parts'])} [ATT&CK {item['id']}] "
                        for sublist in dictsearch(resp['rules'], CAPA_ATTACK_KEY)
                        for item in sublist
                    ]
                )
                if verboseHits:
                    hits.extend(list(resp['rules'].keys()))

            result[FILE_SCAN_RESULT_HITS] = len(hits)
            if len(hits) > 0:
                hits = list(set(hits))
                cnt = Counter(hits)
                # short message is most common signature name (todo: they won't have duplicate names, so I guess this is just going to take the first...)
                result[FILE_SCAN_RESULT_MESSAGE] = cnt.most_common(1)[0][0]
                # long description is list of the signature names and the engines which generated them
                result[FILE_SCAN_RESULT_DESCRIPTION] = ";".join([f"{x}<{CAPA_ENGINE_ID}>" for x in hits])

        else:
            result[FILE_SCAN_RESULT_MESSAGE] = "Error or invalid response"
            result[FILE_SCAN_RESULT_DESCRIPTION] = f"{resp}"

        return result
