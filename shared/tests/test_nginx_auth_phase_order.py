"""nginx auth gates must run before a location answers, and user-facing locations must have one (GHSA-93g5-g9r5-g78w).

nginx handles a request in fixed phases. The rewrite module (rewrite, return, set, if) runs in the REWRITE phase,
before the ACCESS phase where auth_basic, auth_ldap, access_by_lua, allow/deny and limit_except are evaluated, and
the order of directives inside a location doesn't change that. A location pairing one of those checks with a
"rewrite ... redirect" or a "return" answers before the check runs. The fix for GHSA-7j32-cf27-cp6h added the auth
include to two such locations, which had no effect.

These tests parse nginx/nginx.conf and nginx/nginx_readonly.conf statically, expanding includes and every alternative
a *_rt.conf runtime link can point to (read from nginx/scripts/docker_entrypoint.sh), so no nginx is needed.
"""

import itertools
import re
from pathlib import Path

import pytest

NGINX_DIR = Path(__file__).resolve().parents[2] / 'nginx'
TOP_LEVEL_CONFIGS = ('nginx.conf', 'nginx_readonly.conf')
CONF_PREFIX = '/etc/nginx/'

# The runtime auth links are an opaque access-phase gate rather than being expanded, because one of their alternatives
# (nginx_auth_disabled.conf) is deliberately no gate at all. test_auth_link_alternatives_are_access_phase_gates checks
# that the other alternatives really are gates.
AUTH_LINKS = frozenset({'nginx_auth_rt.conf', 'nginx_auth_service_acct_rt.conf'})
AUTH_DISABLED = frozenset({'nginx_auth_disabled.conf'})

# Locations in user-facing servers that are public by design, as (top-level config or '*', location spec).
COVERAGE_ALLOWLIST = frozenset(
    {
        # favicon, needed by the login page before authentication
        ('*', '= /favicon.ico'),
        # robots.txt is deliberately public
        ('*', '= /robots.txt'),
        # htadmin static assets for the login/account pages (read-only mode denies /auth outright)
        ('nginx.conf', r'~* ^/auth/.*\.(css|js|png|jpg|gif|ico|woff|woff2|ttf|svg)$'),
        # Keycloak's own login UI, which is how users authenticate
        ('nginx.conf', '/keycloak'),
        # NetBox API: requests carrying a NetBox token go to NetBox, which validates the token itself; all others are
        # sent through @auth_netbox or @auth_netbox_api (see $netbox_auth_redirect)
        ('nginx.conf', '/netbox/api'),
        ('nginx.conf', '/mapi/netbox/api/'),
        ('nginx.conf', '/mapi/netbox/'),
    }
)

# Gated locations allowed to answer in the rewrite phase, as (top-level config or '*', location spec, variant file).
PHASE_ALLOWLIST = frozenset(
    {
        # when OpenSearch is not local, the 9200 passthrough answers a fixed 501 to everyone; there is nothing behind it
        # to protect, and the port is only offered for publication when OpenSearch is local
        ('*', '/', 'nginx_opensearch_api_501.conf'),
    }
)

ACCESS_DIRECTIVES = frozenset(
    {
        'auth_basic',
        'auth_ldap',
        'auth_request',
        'allow',
        'deny',
        'limit_except',
        'access_by_lua',
        'access_by_lua_block',
        'access_by_lua_file',
    }
)
REWRITE_LUA = frozenset({'rewrite_by_lua', 'rewrite_by_lua_block', 'rewrite_by_lua_file'})
LUA_FINALIZERS = re.compile(r'\bngx\.(redirect|exit|say|print|exec)\s*\(')
USER_FACING_LISTENS = ('listen_443', 'listen_9200')


###################################################################################################
# Parsing. Follows ngx_conf_read_token closely enough for Malcolm's files: '#' starts a comment only at the start
# of a token, quotes and backslash escapes, ${var} inside unquoted tokens, and *_by_lua_block bodies are lexed as
# Lua so their braces and strings don't confuse the parser.


class ParseError(Exception):
    pass


class Node:
    def __init__(self, name, args, children=None, lua=None, source=''):
        self.name, self.args, self.children, self.lua, self.source = name, args, children, lua, source

    def describe(self, limit=100):
        text = f"{self.name} {' '.join(self.args)}".strip()
        return text if len(text) <= limit else text[:limit] + '...'


def skip_lua_block(text, i, where):
    """text[i] is just past the opening '{'; return (body, index past the closing '}')."""
    depth, start, n = 1, i, len(text)
    while i < n:
        c = text[i]
        if text.startswith('--', i):
            m = re.match(r'--\[(=*)\[', text[i:])
            if m:
                close = ']' + m.group(1) + ']'
                j = text.find(close, i + len(m.group(0)))
                if j < 0:
                    raise ParseError(f'{where}: unterminated Lua long comment')
                i = j + len(close)
            else:
                j = text.find('\n', i)
                i = n if j < 0 else j + 1
            continue
        if c == '[':
            m = re.match(r'\[(=*)\[', text[i:])
            if m:
                close = ']' + m.group(1) + ']'
                j = text.find(close, i + len(m.group(0)))
                if j < 0:
                    raise ParseError(f'{where}: unterminated Lua long string')
                i = j + len(close)
                continue
        if c in '"\'':
            i += 1
            while i < n and text[i] != c:
                i += 2 if text[i] == '\\' else 1
            i += 1
            continue
        if c == '{':
            depth += 1
        elif c == '}':
            depth -= 1
            if depth == 0:
                return text[start:i], i + 1
        i += 1
    raise ParseError(f'{where}: unterminated *_by_lua_block')


def tokenize(text, where):
    tokens, i, n = [], 0, len(text)
    while i < n:
        c = text[i]
        if c.isspace():
            i += 1
        elif c == '#':
            j = text.find('\n', i)
            i = n if j < 0 else j + 1
        elif c in ';{}':
            tokens.append(c)
            i += 1
            # the block after a *_by_lua_block directive is Lua, not nginx
            if c == '{' and len(tokens) >= 2 and isinstance(tokens[-2], str) and tokens[-2].endswith('_by_lua_block'):
                body, i = skip_lua_block(text, i, where)
                tokens[-1] = ('LUA', body)
        elif c in '"\'':
            j, buf = i + 1, []
            while j < n and text[j] != c:
                if text[j] == '\\' and j + 1 < n:
                    buf.append(text[j : j + 2])
                    j += 2
                else:
                    buf.append(text[j])
                    j += 1
            if j >= n:
                raise ParseError(f'{where}: unterminated quoted string')
            tokens.append(''.join(buf))
            i = j + 1
        else:
            j, buf = i, []
            while j < n and not text[j].isspace() and text[j] != ';':
                if text[j] == '{':
                    if buf and buf[-1] == '$':
                        k = text.find('}', j)
                        buf.append(text[j : k + 1])
                        j = k + 1
                        continue
                    break
                if text[j] == '}':
                    break
                if text[j] == '\\' and j + 1 < n:
                    buf.append(text[j : j + 2])
                    j += 2
                    continue
                buf.append(text[j])
                j += 1
            tokens.append(''.join(buf))
            i = j
    return tokens


def parse_tokens(tokens, where):
    pos = 0

    def block():
        nonlocal pos
        nodes = []
        while pos < len(tokens):
            t = tokens[pos]
            if t == '}':
                pos += 1
                return nodes
            if t in (';', '{') or isinstance(t, tuple):
                raise ParseError(f'{where}: unexpected {t!r}')
            name, args = t, []
            pos += 1
            while True:
                if pos >= len(tokens):
                    raise ParseError(f'{where}: unexpected end of file in {name}')
                t = tokens[pos]
                pos += 1
                if t == ';':
                    nodes.append(Node(name, args, source=where))
                    break
                if isinstance(t, tuple):
                    nodes.append(Node(name, args, lua=t[1], source=where))
                    break
                if t == '{':
                    nodes.append(Node(name, args, block(), source=where))
                    break
                if t == '}':
                    raise ParseError(f"{where}: unexpected '}}' in {name}")
                args.append(t)
        return nodes

    nodes = block()
    if pos != len(tokens):
        raise ParseError(f"{where}: unbalanced '}}'")
    return nodes


class NginxConfig:
    """The nginx configuration under one directory, with its runtime links read from scripts/docker_entrypoint.sh."""

    def __init__(self, nginx_dir):
        self.dir = Path(nginx_dir)
        self._parsed = {}
        self.runtime_links = self._load_runtime_links()

    def _load_runtime_links(self):
        text = (self.dir / 'scripts' / 'docker_entrypoint.sh').read_text()
        var_file = dict(re.findall(r'^\s*([A-Z0-9_]+)=\$\{NGINX_CONF_DIR\}/(\S+)\s*$', text, re.M))
        links = {}
        for src, dst in re.findall(r'ln\s+-sf\s+"\$([A-Z0-9_]+)"\s+"\$([A-Z0-9_]+)"', text):
            if src in var_file and dst in var_file:
                links.setdefault(var_file[dst], set()).add(var_file[src])
        return links

    def parse(self, fname):
        if fname not in self._parsed:
            self._parsed[fname] = parse_tokens(tokenize((self.dir / fname).read_text(), fname), fname)
        return self._parsed[fname]

    def include_alternatives(self, arg):
        """The files an include can resolve to; [] for files generated at build or startup (listen_443.conf, ...)."""
        if not arg.startswith(CONF_PREFIX):
            return []
        fname = arg[len(CONF_PREFIX) :]
        if fname in self.runtime_links:
            return sorted(f for f in self.runtime_links[fname] if (self.dir / f).exists())
        if fname.endswith('_rt.conf'):
            raise ParseError(f'{fname} looks like a runtime link but docker_entrypoint.sh never creates it')
        return [fname] if (self.dir / fname).exists() else []

    def expand_variants(self, nodes):
        """
        Expand includes in a location body, returning one (variant_files, flat_nodes) per combination of runtime-link
        alternatives. Auth links stay in place as opaque gates.
        """
        results = [((), [])]
        for node in nodes:
            if node.name == 'include' and not auth_link_name(node):
                alts = self.include_alternatives(node.args[0])
                if not alts:
                    continue
                results = [
                    (files + ((alt,) if len(alts) > 1 else ()) + sub_files, flat + sub_flat)
                    for files, flat in results
                    for alt in alts
                    for sub_files, sub_flat in self.expand_variants(self.parse(alt))
                ]
            else:
                results = [(files, flat + [node]) for files, flat in results]
        return results

    def server_locations(self, server_nodes):
        """Every location in a server, from each runtime alternative that can define it."""
        out = []

        def walk(nodes):
            for node in nodes:
                if node.name == 'location':
                    out.append(node)
                elif node.name == 'include' and not auth_link_name(node):
                    for alt in self.include_alternatives(node.args[0]):
                        walk(self.parse(alt))

        walk(server_nodes)
        return out

    def servers(self, top):
        http = [n for n in self.parse(top) if n.name == 'http']
        if len(http) != 1:
            raise ParseError(f'{top}: expected one http block')
        for server in (n for n in http[0].children if n.name == 'server'):
            listens = [n.args[0] for n in server.children if n.name == 'include' and n.args and 'listen_' in n.args[0]]
            label = f"{top} server({', '.join(Path(l).name for l in listens) or '?'})"
            yield label, any(s in l for l in listens for s in USER_FACING_LISTENS), server


###################################################################################################
# Phase classification


def auth_link_name(node):
    if node.name == 'include' and node.args and node.args[0].startswith(CONF_PREFIX):
        fname = node.args[0][len(CONF_PREFIX) :]
        if fname in AUTH_LINKS:
            return fname
    return None


def is_access_directive(node):
    return node.name in ACCESS_DIRECTIVES and not (node.name == 'auth_basic' and node.args[:1] == ['off'])


def has_gate(flat):
    return any(auth_link_name(n) or is_access_directive(n) for n in flat)


def is_internal(flat):
    return any(n.name == 'internal' for n in flat)


def rewrite_finalizers(flat):
    """Rewrite-phase directives that send the response themselves, directly or inside if blocks."""
    found = []
    for node in flat:
        if node.name == 'return':
            found.append(node)
        elif node.name == 'rewrite':
            replacement = node.args[1] if len(node.args) > 1 else ''
            flag = node.args[2] if len(node.args) > 2 else ''
            if flag in ('redirect', 'permanent') or (
                flag not in ('last', 'break') and re.match(r'(https?://|\$scheme)', replacement)
            ):
                found.append(node)
        elif node.name in REWRITE_LUA and node.lua and LUA_FINALIZERS.search(node.lua):
            found.append(node)
        elif node.name == 'if' and node.children is not None:
            found.extend(rewrite_finalizers(node.children))
    return found


def allowed(allowlist, top, *key):
    return (top, *key) in allowlist or ('*', *key) in allowlist


###################################################################################################
# Checks, each returning a list of failure messages so a run reports every problem at once


def phase_order_failures(cfg, top, phase_allowlist=PHASE_ALLOWLIST):
    failures = []
    for label, user_facing, server in cfg.servers(top):
        # server-level rewrite/return runs in SERVER_REWRITE, before any location's auth
        if user_facing:
            for _, flat in cfg.expand_variants([n for n in server.children if n.name != 'location']):
                failures += [
                    f'{label}: server-level {n.describe()} answers before any auth' for n in rewrite_finalizers(flat)
                ]
        for loc in cfg.server_locations(server.children):
            spec = ' '.join(loc.args)
            for files, flat in cfg.expand_variants(loc.children):
                if not has_gate(flat) or allowed(phase_allowlist, top, spec, files[-1] if files else ''):
                    continue
                where = f"{label} location {spec}" + (f" [{', '.join(files)}]" if files else '') + f' ({loc.source})'
                failures += [
                    f"{where}: '{n.describe()}' runs in the REWRITE phase, before the location's ACCESS-phase auth"
                    for n in rewrite_finalizers(flat)
                ]
    return failures


def coverage_failures(cfg, top, coverage_allowlist=COVERAGE_ALLOWLIST):
    failures = []
    for label, user_facing, server in cfg.servers(top):
        if not user_facing:
            continue
        for loc in cfg.server_locations(server.children):
            spec = ' '.join(loc.args)
            if spec.startswith('@') or allowed(coverage_allowlist, top, spec):
                continue
            for files, flat in cfg.expand_variants(loc.children):
                if not has_gate(flat) and not is_internal(flat):
                    variant = f" [{', '.join(files)}]" if files else ''
                    failures.append(f'{label} location {spec}{variant} ({loc.source}): no authentication gate')
    return failures


def duplicate_named_location_failures(cfg, top):
    """nginx refuses to start with a named location defined twice in one server."""
    failures = []
    for label, _, server in cfg.servers(top):
        seen = {}
        for loc in cfg.server_locations(server.children):
            spec = ' '.join(loc.args)
            if spec.startswith('@'):
                if spec in seen:
                    failures.append(f'{label}: named location {spec} defined in both {seen[spec]} and {loc.source}')
                seen[spec] = loc.source
    return failures


def assert_no_failures(failures):
    assert not failures, '\n'.join(failures)


###################################################################################################
# The repository's configuration


@pytest.fixture(scope='module')
def repo_config():
    return NginxConfig(NGINX_DIR)


def test_runtime_links_were_found(repo_config):
    # an entrypoint refactor that broke the parsing would otherwise quietly skip every alternative
    assert {'nginx_auth_rt.conf', 'nginx_idark2dash_rewrite_rt.conf', 'nginx_dashboards_rewrite_rt.conf'} <= set(
        repo_config.runtime_links
    )
    assert len(repo_config.runtime_links['nginx_dashboards_rewrite_rt.conf']) == 2


@pytest.mark.parametrize('link', sorted(AUTH_LINKS))
def test_auth_link_alternatives_are_access_phase_gates(repo_config, link):
    alternatives = repo_config.runtime_links.get(link, set()) - AUTH_DISABLED
    assert alternatives, f'docker_entrypoint.sh creates no alternatives for {link}'
    for alt in sorted(alternatives):
        flat = repo_config.parse(alt)
        assert any(is_access_directive(n) for n in flat), f'{alt} contains no access-phase directive'
        assert not rewrite_finalizers(flat), f'{alt} finalizes in the rewrite phase'


@pytest.mark.parametrize('top', TOP_LEVEL_CONFIGS)
def test_gated_locations_do_not_answer_in_rewrite_phase(repo_config, top):
    assert_no_failures(phase_order_failures(repo_config, top))


@pytest.mark.parametrize('top', TOP_LEVEL_CONFIGS)
def test_user_facing_locations_are_gated(repo_config, top):
    assert_no_failures(coverage_failures(repo_config, top))


@pytest.mark.parametrize('top', TOP_LEVEL_CONFIGS)
def test_named_locations_are_unique(repo_config, top):
    assert_no_failures(duplicate_named_location_failures(repo_config, top))


@pytest.mark.parametrize('top', TOP_LEVEL_CONFIGS)
def test_allowlists_are_not_stale(repo_config, top):
    specs = {
        ' '.join(loc.args)
        for _, _, server in repo_config.servers(top)
        for loc in repo_config.server_locations(server.children)
    }
    stale = [spec for config, spec in COVERAGE_ALLOWLIST if config in ('*', top) and spec not in specs]
    stale += [spec for config, spec, _ in PHASE_ALLOWLIST if config in ('*', top) and spec not in specs]
    assert not stale, f'allowlisted locations no longer in {top}: {stale}'


###################################################################################################
# The checks themselves, against small synthetic configurations


ENTRYPOINT = """
NGINX_RUNTIME_AUTH_LINK=${NGINX_CONF_DIR}/nginx_auth_rt.conf
NGINX_BASIC_AUTH_CONF=${NGINX_CONF_DIR}/nginx_auth_basic.conf
NGINX_NO_AUTH_CONF=${NGINX_CONF_DIR}/nginx_auth_disabled.conf
NGINX_RUNTIME_PIVOT_LINK=${NGINX_CONF_DIR}/pivot_rt.conf
NGINX_PIVOT_A_CONF=${NGINX_CONF_DIR}/pivot_a.conf
NGINX_PIVOT_B_CONF=${NGINX_CONF_DIR}/pivot_b.conf
ln -sf "$NGINX_BASIC_AUTH_CONF" "$NGINX_RUNTIME_AUTH_LINK"
ln -sf "$NGINX_NO_AUTH_CONF" "$NGINX_RUNTIME_AUTH_LINK"
ln -sf "$NGINX_PIVOT_A_CONF" "$NGINX_RUNTIME_PIVOT_LINK"
ln -sf "$NGINX_PIVOT_B_CONF" "$NGINX_RUNTIME_PIVOT_LINK"
"""

AUTH = 'include /etc/nginx/nginx_auth_rt.conf;'


@pytest.fixture
def synthetic(tmp_path):
    """Write a minimal nginx directory with one user-facing server holding the given locations."""

    def make(locations, **extra_files):
        (tmp_path / 'scripts').mkdir(exist_ok=True)
        (tmp_path / 'scripts' / 'docker_entrypoint.sh').write_text(ENTRYPOINT)
        (tmp_path / 'nginx_auth_basic.conf').write_text('auth_basic "Authentication Required";\n')
        (tmp_path / 'nginx_auth_disabled.conf').write_text('auth_basic off;\n')
        for name, text in extra_files.items():
            (tmp_path / name.replace('__', '.')).write_text(text)
        (tmp_path / 'nginx.conf').write_text(
            'http {\n  server {\n    include /etc/nginx/listen_443.conf;\n' + locations + '\n  }\n}\n'
        )
        return NginxConfig(tmp_path)

    return make


# the /iddash2ark block as shipped by the GHSA-7j32-cf27-cp6h fix
GHSA_7J32_IDDASH2ARK = r"""
    location ~* /iddash2ark/(.*) {
      include /etc/nginx/nginx_auth_rt.conf;
      set $forwarded_scheme $scheme;
      if ($http_x_forwarded_proto = 'https') {
          set $forwarded_scheme https;
      }
      rewrite (?i)^.*/iddash2ark/(.*) $forwarded_scheme://$host/arkime/sessions?expression=($1) redirect;
    }
"""


def test_detects_the_ghsa_7j32_fix_shape(synthetic):
    failures = phase_order_failures(synthetic(GHSA_7J32_IDDASH2ARK), 'nginx.conf')
    assert len(failures) == 1 and '/iddash2ark/' in failures[0]


def test_content_phase_handoff_to_named_location_passes(synthetic):
    cfg = synthetic(
        f"""
        location ~* /iddash2ark/(.*) {{
          {AUTH}
          content_by_lua_block {{ return ngx.exec("@iddash2ark_pivot") }}
        }}
        location @iddash2ark_pivot {{
          rewrite (?i)^.*/iddash2ark/(.*) $scheme://$host/arkime/sessions?expression=($1) redirect;
        }}
        """
    )
    assert_no_failures(phase_order_failures(cfg, 'nginx.conf') + coverage_failures(cfg, 'nginx.conf'))


@pytest.mark.parametrize(
    'body',
    [
        f'{AUTH} return 302 /elsewhere;',
        f"{AUTH} if ($arg_x) {{ return 403; }}",
        f'{AUTH} rewrite ^/a/(.*) https://$host/b/$1;',
        f'{AUTH} rewrite ^/a/(.*) /b/$1 permanent;',
        'limit_except GET { deny all; } return 200 ok;',
        'deny all; return 200 ok;',
        'auth_basic "x"; rewrite_by_lua_block { return ngx.redirect("/b") }',
    ],
)
def test_detects_rewrite_phase_finalizers(synthetic, body):
    assert phase_order_failures(synthetic(f'location /a {{ {body} }}'), 'nginx.conf')


@pytest.mark.parametrize(
    'body',
    [
        f'{AUTH} rewrite ^/a/(.*) /b/$1 break; proxy_pass http://upstream;',
        f'{AUTH} rewrite ^/a/(.*) /b/$1 last;',
        'internal; return 200 ok;',
        'auth_basic off; return 200 ok;',
        'auth_basic "x"; rewrite_by_lua_block { ngx.var.target = "/b" } proxy_pass http://upstream;',
    ],
)
def test_allows_non_finalizing_rewrites_and_ungated_returns(synthetic, body):
    assert not phase_order_failures(synthetic(f'location /a {{ {body} }}'), 'nginx.conf')


def test_detects_ungated_location_and_honors_allowlist(synthetic):
    cfg = synthetic('location /open { proxy_pass http://upstream; } location @named { return 200; }')
    assert len(coverage_failures(cfg, 'nginx.conf')) == 1
    assert not coverage_failures(cfg, 'nginx.conf', coverage_allowlist={('*', '/open')})


def test_checks_every_runtime_link_alternative(synthetic):
    cfg = synthetic(
        'location /pivot { include /etc/nginx/pivot_rt.conf; }',
        pivot_a__conf=f'{AUTH}\nproxy_pass http://upstream;\n',
        pivot_b__conf=f'{AUTH}\nrewrite ^/pivot/(.*) https://elsewhere/$1 redirect;\n',
    )
    failures = phase_order_failures(cfg, 'nginx.conf')
    assert len(failures) == 1 and 'pivot_b.conf' in failures[0]


def test_detects_duplicate_named_locations(synthetic):
    cfg = synthetic('location @x { return 200; } location @x { return 204; }')
    assert duplicate_named_location_failures(cfg, 'nginx.conf')


def test_parser_handles_lua_braces_strings_and_mid_token_hash(synthetic):
    cfg = synthetic(
        f"""
        location /lua {{
          {AUTH}
          content_by_lua_block {{
            local t = {{ a = "}}", b = '{{' }}  -- unbalanced }} in a comment
            local s = [[ }} ]] .. #"x"
            ngx.say(t.a .. s)
          }}
        }}
        location /hash {{
          {AUTH}
          rewrite ^/hash https://$host/app/dashboards#/view/1 redirect;
        }}
        """
    )
    failures = phase_order_failures(cfg, 'nginx.conf')
    # /lua parses cleanly and is fine; the '#' inside the /hash rewrite is part of the token, not a comment
    assert len(failures) == 1 and '#/view/1' in failures[0]
