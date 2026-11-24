# Copyright (c) 2026 Battelle Energy Alliance, LLC.  All rights reserved.

"""Everything update_pins.py fetches from the network goes through Net, which caches per run."""

import hashlib
import os
import re
import subprocess
import sys
import threading
import urllib.parse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from .core import PinError

USER_AGENT = 'malcolm-update-pins/1.0 (+https://github.com/cisagov/Malcolm)'

OCI_ACCEPT = ', '.join(
    [
        'application/vnd.oci.image.index.v1+json',
        'application/vnd.docker.distribution.manifest.list.v2+json',
        'application/vnd.oci.image.manifest.v1+json',
        'application/vnd.docker.distribution.manifest.v2+json',
    ]
)


def _memo(method):
    """Cache a Net method's result (or its PinError) per argument tuple, safely across threads."""

    def wrapper(self, *args):
        key = (method.__name__,) + args
        with self._lock:
            event = self._pending.get(key)
            if key in self._cache:
                ok, value = self._cache[key]
                if ok:
                    return value
                raise value
            if event is None:
                event = threading.Event()
                self._pending[key] = event
                owner = True
            else:
                owner = False
        if not owner:
            event.wait()
            ok, value = self._cache[key]
            if ok:
                return value
            raise value
        try:
            value = method(self, *args)
            result = (True, value)
        except PinError as e:
            result = (False, e)
        except (requests.RequestException, ValueError, KeyError, OSError) as e:
            result = (False, PinError(f'{method.__name__}{args}: {e}'))
        with self._lock:
            self._cache[key] = result
            del self._pending[key]
        event.set()
        if result[0]:
            return result[1]
        raise result[1]

    wrapper.__name__ = method.__name__
    return wrapper


class Net:
    def __init__(self, github_token=None, dockerhub_auth=None, timeout=30, verbose=False):
        self.github_token = github_token
        self.dockerhub_auth = dockerhub_auth  # (user, token) or None
        self.timeout = timeout
        self.verbose = verbose
        self._lock = threading.Lock()
        self._cache = {}
        self._pending = {}
        self._registry_tokens = {}
        self.session = requests.Session()
        retry = Retry(total=4, backoff_factor=1.0, status_forcelist=(429, 500, 502, 503, 504), allowed_methods=None)
        self.session.mount('https://', HTTPAdapter(max_retries=retry, pool_maxsize=32))
        self.session.headers['User-Agent'] = USER_AGENT

    def log(self, msg):
        if self.verbose:
            print(f'  [net] {msg}', file=sys.stderr)

    def get(self, url, **kwargs):
        kwargs.setdefault('timeout', self.timeout)
        self.log(f'GET {url}')
        return self.session.get(url, **kwargs)

    def get_json(self, url, headers=None):
        r = self.get(url, headers=headers or {})
        if r.status_code == 404:
            raise PinError(f'not found: {url}')
        r.raise_for_status()
        return r.json()

    ###############################################################################################
    # git

    @_memo
    def ls_remote(self, url):
        """{ref_name: commit} for tags and heads (annotated tags peeled), plus 'HEAD'."""
        env = dict(os.environ, GIT_TERMINAL_PROMPT='0', GIT_ASKPASS='/bin/true')
        self.log(f'git ls-remote {url}')
        try:
            out = subprocess.run(
                ['git', 'ls-remote', '--tags', '--heads', url],
                capture_output=True,
                text=True,
                timeout=120,
                env=env,
                check=True,
            ).stdout
            head = subprocess.run(
                ['git', 'ls-remote', url, 'HEAD'], capture_output=True, text=True, timeout=120, env=env, check=True
            ).stdout
        except FileNotFoundError:
            raise PinError('git is required for ls-remote lookups')
        except subprocess.CalledProcessError as e:
            raise PinError(f'git ls-remote {url} failed: {e.stderr.strip()}')
        except subprocess.TimeoutExpired:
            raise PinError(f'git ls-remote {url} timed out')
        refs, peeled = {}, {}
        for line in (out + head).splitlines():
            parts = line.split('\t')
            if len(parts) != 2:
                continue
            sha, name = parts
            if name.endswith('^{}'):
                peeled[name[:-3]] = sha
            else:
                refs[name] = sha
        refs.update(peeled)
        return refs

    def tags(self, url):
        """{tag_name: commit} (peeled)."""
        return {k[len('refs/tags/') :]: v for k, v in self.ls_remote(url).items() if k.startswith('refs/tags/')}

    def heads(self, url):
        return {k[len('refs/heads/') :]: v for k, v in self.ls_remote(url).items() if k.startswith('refs/heads/')}

    def ref_commit(self, url, ref):
        """Commit for a tag, branch or 'HEAD' (default branch)."""
        refs = self.ls_remote(url)
        for name in (ref, f'refs/tags/{ref}', f'refs/heads/{ref}'):
            if name in refs:
                return refs[name]
        raise PinError(f'{ref} not found in {url}')

    ###############################################################################################
    # GitHub

    def _gh_headers(self):
        h = {'Accept': 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28'}
        if self.github_token:
            h['Authorization'] = f'Bearer {self.github_token}'
        return h

    def gh_api(self, path):
        url = path if path.startswith('https://') else f'https://api.github.com/{path.lstrip("/")}'
        r = self.get(url, headers=self._gh_headers())
        if r.status_code == 403 and r.headers.get('X-RateLimit-Remaining') == '0':
            raise PinError('GitHub API rate limit exhausted (set GITHUB_TOKEN)')
        if r.status_code == 404:
            raise PinError(f'not found: {url}')
        r.raise_for_status()
        return r

    @_memo
    def gh_releases(self, repo, pages=3):
        """Published, non-draft releases (newest first), up to pages*100."""
        out = []
        url = f'repos/{repo}/releases?per_page=100'
        for _ in range(pages):
            r = self.gh_api(url)
            out.extend(rel for rel in r.json() if not rel.get('draft'))
            nxt = r.links.get('next', {}).get('url')
            if not nxt:
                break
            url = nxt
        return out

    @_memo
    def gh_release_by_tag(self, repo, tag):
        return self.gh_api(f'repos/{repo}/releases/tags/{urllib.parse.quote(tag, safe="")}').json()

    @_memo
    def gh_latest_release_tag(self, repo):
        """Tag of the release GitHub marks as latest, or None."""
        if self.github_token:
            try:
                return self.gh_api(f'repos/{repo}/releases/latest').json().get('tag_name')
            except PinError:
                return None
        # no token: follow the /releases/latest redirect, as zkg and the old refresh script do
        r = self.session.head(f'https://github.com/{repo}/releases/latest', allow_redirects=True, timeout=self.timeout)
        m = re.search(r'/releases/tag/([^/?#]+)$', r.url)
        return urllib.parse.unquote(m.group(1)) if m else None

    ###############################################################################################
    # downloads

    def sha256_of_url(self, url):
        print(f'    downloading {url}', file=sys.stderr)
        h = hashlib.sha256()
        with self.session.get(url, stream=True, timeout=self.timeout, allow_redirects=True) as r:
            if r.status_code != 200:
                raise PinError(f'download failed ({r.status_code}): {url}')
            for chunk in r.iter_content(chunk_size=1 << 20):
                h.update(chunk)
        return h.hexdigest()

    @_memo
    def gh_asset_sha256(self, repo, tag, asset_name):
        """SHA-256 of a release asset: GitHub's published digest when present, else download and hash."""
        rel = self.gh_release_by_tag(repo, tag)
        for asset in rel.get('assets', []):
            if asset.get('name') == asset_name:
                digest = asset.get('digest') or ''
                if digest.startswith('sha256:') and re.fullmatch(r'[0-9a-f]{64}', digest[7:]):
                    self.log(f'GitHub digest for {repo} {tag} {asset_name}')
                    return digest[7:]
                return self.sha256_of_url(asset['browser_download_url'])
        names = ', '.join(a.get('name', '?') for a in rel.get('assets', []))
        raise PinError(f'{repo} {tag} has no asset named {asset_name} (assets: {names})')

    @_memo
    def url_sha256(self, url):
        return self.sha256_of_url(url)

    ###############################################################################################
    # OCI registries

    @staticmethod
    def registry_host(registry):
        return 'registry-1.docker.io' if registry == 'docker.io' else registry

    def _registry_request(self, registry, repo, path, method='GET'):
        host = self.registry_host(registry)
        url = f'https://{host}/v2/{repo}/{path}'
        headers = {'Accept': OCI_ACCEPT}
        tok_key = (host, repo)
        if tok_key in self._registry_tokens:
            headers['Authorization'] = f'Bearer {self._registry_tokens[tok_key]}'
        self.log(f'{method} {url}')
        r = self.session.request(method, url, headers=headers, timeout=self.timeout)
        if r.status_code == 401 and 'Authorization' not in headers:
            token = self._registry_token(registry, repo, r.headers.get('WWW-Authenticate', ''))
            if token:
                self._registry_tokens[tok_key] = token
                headers['Authorization'] = f'Bearer {token}'
                r = self.session.request(method, url, headers=headers, timeout=self.timeout)
        if r.status_code == 404:
            raise PinError(f'not found: {registry}/{repo} {path}')
        if r.status_code == 429:
            raise PinError(f'{registry} rate limit hit (set DOCKERHUB_USERNAME/DOCKERHUB_TOKEN for Docker Hub)')
        r.raise_for_status()
        return r

    def _registry_token(self, registry, repo, challenge):
        if not challenge.lower().startswith('bearer '):
            return None
        params = dict(re.findall(r'(\w+)="([^"]*)"', challenge))
        realm = params.pop('realm', None)
        if not realm:
            return None
        params['scope'] = f'repository:{repo}:pull'
        auth = None
        if registry == 'docker.io' and self.dockerhub_auth:
            auth = self.dockerhub_auth
        elif registry == 'ghcr.io' and self.github_token:
            auth = ('token', self.github_token)
        r = self.session.get(realm, params=params, auth=auth, timeout=self.timeout)
        if r.status_code != 200 and auth:
            r = self.session.get(realm, params=params, timeout=self.timeout)
        r.raise_for_status()
        body = r.json()
        return body.get('token') or body.get('access_token')

    @_memo
    def registry_tags(self, registry, repo):
        tags = []
        path = 'tags/list?n=10000'
        for _ in range(50):
            r = self._registry_request(registry, repo, path)
            tags.extend(r.json().get('tags') or [])
            link = r.headers.get('Link', '')
            m = re.search(r'<([^>]+)>;\s*rel="next"', link)
            if not m:
                break
            nxt = m.group(1)
            path = nxt.split(f'/v2/{repo}/', 1)[1] if f'/v2/{repo}/' in nxt else nxt.lstrip('/')
        return tags

    @_memo
    def registry_digest(self, registry, repo, tag):
        """Digest of the manifest (index for multi-arch images) a tag points at."""
        try:
            r = self._registry_request(registry, repo, f'manifests/{tag}', method='HEAD')
            digest = r.headers.get('Docker-Content-Digest')
            if digest:
                return digest
        except requests.HTTPError:
            pass
        r = self._registry_request(registry, repo, f'manifests/{tag}')
        return r.headers.get('Docker-Content-Digest') or 'sha256:' + hashlib.sha256(r.content).hexdigest()

    ###############################################################################################
    # package indexes

    @_memo
    def pypi(self, name):
        return self.get_json(f'https://pypi.org/pypi/{urllib.parse.quote(name)}/json')

    @_memo
    def pypi_version(self, name, version):
        return self.get_json(f'https://pypi.org/pypi/{urllib.parse.quote(name)}/{urllib.parse.quote(version)}/json')

    @_memo
    def npm(self, name):
        return self.get_json(f'https://registry.npmjs.org/{name.replace("/", "%2f")}')

    @_memo
    def rubygems_versions(self, gem):
        return self.get_json(f'https://rubygems.org/api/v1/versions/{urllib.parse.quote(gem)}.json')

    @_memo
    def madison(self, package, suite):
        """[(version, suite, arches)] from Debian's madison service."""
        r = self.get(
            'https://qa.debian.org/madison.php',
            params={'package': package, 's': suite, 'text': 'on', 'table': 'debian'},
        )
        r.raise_for_status()
        rows = []
        for line in r.text.splitlines():
            cols = [c.strip() for c in line.split('|')]
            if len(cols) >= 4:
                rows.append((cols[1], cols[2], cols[3]))
        return rows
