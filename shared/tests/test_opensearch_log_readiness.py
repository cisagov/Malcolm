#!/usr/bin/env python3
# Copyright (c) 2026 Battelle Energy Alliance, LLC. All rights reserved.
"""Run the real readiness script against a local HTTP fixture, without OpenSearch."""

from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
import shlex
from pathlib import Path
import shutil
import subprocess
import tempfile
import threading
import unittest
from urllib.parse import parse_qs, unquote, urlsplit


_SCRIPT = Path(__file__).resolve().parents[2] / 'shared/bin/opensearch_status.sh'
_BASH = shutil.which('bash')
_JQ = shutil.which('jq')
_TOOLS = {name: shutil.which(name) for name in ('curl', 'sed', 'awk', 'wc')}
_ORIGINAL_PATH = os.environ.get('PATH', '')
_ORIGINAL_HOME = os.environ.get('HOME', '')


@unittest.skipUnless(_BASH and all(_TOOLS.values()), 'Requires Bash, curl, sed, awk and wc')
class OpenSearchLogReadinessTest(unittest.TestCase):

    def run_readiness(self, responses, use_jq=True, primary='logs-*', fallback=None):
        requests = []
        counts = Counter()

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def send_body(self, data, content_type='text/plain'):
                body = data.encode('utf-8')
                self.send_response(200)
                self.send_header('Content-Type', content_type)
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                if self.command != 'HEAD':
                    self.wfile.write(body)

            def do_HEAD(self):
                self.send_body('')

            def do_GET(self):
                parsed = urlsplit(self.path)
                if parsed.path == '/':
                    self.send_body('{}', 'application/json')
                elif parsed.path == '/_cat/health':
                    self.send_body('green\n')
                elif parsed.path.startswith('/_cat/indices/'):
                    pattern = unquote(parsed.path.removeprefix('/_cat/indices/'))
                    query = parse_qs(parsed.query)
                    requests.append((pattern, query))
                    counts[pattern] += 1
                    batches = responses[pattern]
                    rows = batches[min(counts[pattern] - 1, len(batches) - 1)]
                    if query.get('format') == ['json']:
                        self.send_body(json.dumps(rows), 'application/json')
                    elif query.get('h') == ['docs.count']:
                        self.send_body(''.join(str(row.get('docs.count') or '') + '\n' for row in rows))
                    else:
                        # The default CAT columns are not reliable when some
                        # fields are unavailable (for example, an unassigned shard).
                        lines = []
                        for row in rows:
                            value = row.get('docs.count')
                            if value is None:
                                lines.append('red open logs-1 uuid 1 0\n')
                            else:
                                lines.append(f'green open logs-1 uuid 1 0 {value} 0 1kb 1kb\n')
                        self.send_body(''.join(lines))
                else:
                    self.send_error(404)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bindir = root / 'bin'
            bindir.mkdir()
            # Wrap each tool rather than symlinking it: version-manager shims
            # (asdf, mise, etc.) are scripts that need the caller's real PATH and
            # HOME (to find ~/.tool-versions). curl still ignores the real HOME
            # because CURL_HOME points at the temporary directory below.
            tools = dict(_TOOLS, jq=_JQ) if use_jq else _TOOLS
            for name, executable in tools.items():
                wrapper = bindir / name
                wrapper.write_text(
                    f'#!/bin/sh\nHOME={shlex.quote(_ORIGINAL_HOME)} PATH={shlex.quote(_ORIGINAL_PATH)} '
                    f'exec {shlex.quote(executable)} "$@"\n'
                )
                wrapper.chmod(0o755)
            # Eliminate the script's retry delays; all network I/O is localhost.
            sleep = bindir / 'sleep'
            sleep.write_text('#!/bin/sh\nexit 0\n')
            sleep.chmod(0o755)
            env = {k: v for k, v in os.environ.items() if not k.lower().endswith('_proxy')}
            env.update({
                'PATH': str(bindir),
                'HOME': directory,
                'CURL_HOME': directory,
                'NO_PROXY': '127.0.0.1',
                'LC_ALL': 'C',
                'OPENSEARCH_PRIMARY': 'opensearch-local',
                'OPENSEARCH_CREDS_CONFIG_FILE': str(root / 'no-credentials'),
                'MALCOLM_NETWORK_INDEX_PATTERN': primary,
                'ARKIME_NETWORK_INDEX_PATTERN': fallback or primary,
            })
            server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
            worker = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': 0.01}, daemon=True)
            worker.start()
            try:
                env['OPENSEARCH_URL'] = f'http://127.0.0.1:{server.server_port}'
                result = subprocess.run(
                    [_BASH, str(_SCRIPT), '-w'], cwd=directory, env=env,
                    capture_output=True, text=True, timeout=10,
                )
            finally:
                server.shutdown()
                server.server_close()
                worker.join(timeout=2)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('Logs exist.', result.stdout)
        return requests

    @unittest.skipUnless(_JQ, 'Requires jq')
    def test_json_waits_for_a_positive_document_count(self):
        for initial in ({}, {'docs.count': None}, {'docs.count': 0},
                        {'docs.count': '0'}, {'docs.count': ''},
                        {'docs.count': '-'}, {'docs.count': '-1'}):
            with self.subTest(initial=initial):
                requests = self.run_readiness({'logs-*': [[initial], [{'docs.count': '2'}]]})
                self.assertEqual(len(requests), 2, requests)

    @unittest.skipUnless(_JQ, 'Requires jq')
    def test_json_accepts_positive_numeric_or_string_counts(self):
        for value in (1, '1'):
            with self.subTest(value=value):
                requests = self.run_readiness({'logs-*': [[{'docs.count': value}]]})
                self.assertEqual(len(requests), 1)

    @unittest.skipUnless(_JQ, 'Requires jq')
    def test_json_checks_the_distinct_arkime_fallback(self):
        requests = self.run_readiness(
            {'logs-*': [[{'docs.count': None}]], 'arkime-*': [[{'docs.count': '3'}]]},
            fallback='arkime-*',
        )
        self.assertEqual([pattern for pattern, _ in requests], ['logs-*', 'arkime-*'])

    def test_without_jq_waits_for_positive_counts(self):
        for value in (None, '', '0', '-', '-1'):
            with self.subTest(value=value):
                requests = self.run_readiness(
                    {'logs-*': [[{'docs.count': value}], [{'docs.count': '2'}]]}, use_jq=False,
                )
                self.assertEqual(len(requests), 2, requests)

    def test_without_jq_requests_a_stable_document_count_column(self):
        requests = self.run_readiness({'logs-*': [[{'docs.count': '2'}]]}, use_jq=False)
        self.assertEqual(len(requests), 1)
        self.assertEqual(requests[0][1].get('h'), ['docs.count'])

    def test_without_jq_checks_the_distinct_arkime_fallback(self):
        requests = self.run_readiness(
            {'logs-*': [[{'docs.count': None}]], 'arkime-*': [[{'docs.count': '3'}]]},
            use_jq=False, fallback='arkime-*',
        )
        self.assertEqual([pattern for pattern, _ in requests], ['logs-*', 'arkime-*'])

