#!/usr/bin/env lua
--
-- test_extracted_files_location.lua -- regression test for the
-- /extracted-files nginx location regex
--
-- GHSA-55hc-p6p7-pmx2: the location regex used \b (word boundary), which
-- also matches between "files" and a following ".", "-", "@", or ":" (all
-- non-word characters under PCRE's \w). A request like
-- /extracted-files.attacker.example/x therefore matched the location, and
-- the captured suffix was concatenated directly onto the fixed upstream
-- hostname in proxy_pass, letting an attacker splice in their own host
-- (and, via an explicit :port suffix, their own port). Because this
-- location also disables proxy_ssl_verify and (previously) forwarded
-- Cookie/Authorization unmodified, the splice chained into session replay,
-- credential disclosure, and SSRF. See the advisory for the full chain and
-- a local nginx-layer PoC.
--
-- This script does NOT exercise nginx_auth_helpers.lua. The vulnerable
-- regex lives directly in nginx.conf / nginx_readonly.conf, in the HTTP
-- core "location" directive -- it is parsed by nginx itself, before any
-- Lua access_by_lua_block ever runs, so the RBAC layer has no visibility
-- into it and can't be used to regression-test this bug. Instead, this
-- script extracts the live regex text out of the actual config files and
-- runs it through a real PCRE engine, so a future edit to either location
-- block is checked against the exact exploit strings from the advisory.
--
-- Usage (from nginx/lua/):
--   lua test_extracted_files_location.lua
--
-- Requires lua 5.1+ or luajit and the lrexlib PCRE binding (rex_pcre2 or
-- rex_pcre), since nginx location regexes are PCRE, not Lua patterns. On
-- Debian or Ubuntu:
--   apt-get install lua5.4 lua-rex-pcre2

local rex
for _, name in ipairs({ "rex_pcre2", "rex_pcre" }) do
    local ok, mod = pcall(require, name)
    if ok then rex = mod break end
end
if not rex then
    io.stderr:write("ERROR: need lrexlib PCRE (rex_pcre2 or rex_pcre).\n")
    os.exit(1)
end

-- ---------------------------------------------------------------------------
-- Pull the location regex straight out of the nginx config, rather than
-- hardcoding it here. If someone edits the location block (even to fix a
-- different bug) without updating this test, we want a clear parse failure
-- instead of a false pass against a stale copy of the pattern.
-- ---------------------------------------------------------------------------
local script_dir = (debug.getinfo(1, "S").source:match("@?(.*/)" ) or "./")
local nginx_dir = script_dir .. "../"

local function read_file(path)
    local f = io.open(path, "r")
    if not f then return nil, "could not open " .. path end
    local content = f:read("*a")
    f:close()
    return content
end

local function extract_location_regex(conf_path)
    local content, err = read_file(conf_path)
    if not content then
        return nil, err
    end
    -- Matches e.g.:  location ~* ^/extracted-files(/.*)?$ {
    -- but not the hh-extracted-files or dashboards/app/extracted-files locations,
    -- which have a different prefix before "extracted-files".
    local pattern = content:match("location%s+~%*%s+(%^/extracted%-files[^{\n]-)%s*{")
    if not pattern then
        return nil, "could not find '/extracted-files' location in " .. conf_path
    end
    return pattern:gsub("%s+$", "")
end

-- ---------------------------------------------------------------------------
-- Test runner
-- ---------------------------------------------------------------------------
local pass, fail = 0, 0

local function check(label, conf_label, nginx_regex, uri, expect_match)
    -- nginx location regexes are matched case-insensitively here because
    -- both locations use the "~*" modifier. lrexlib's find() takes a numeric
    -- init offset as its third argument, not a flags string, so the "i"
    -- flag can't be passed positionally there; use the inline PCRE modifier
    -- (?i) instead, which both rex_pcre and rex_pcre2 understand the same way.
    local matched = rex.find(uri, "(?i)" .. nginx_regex) ~= nil
    local ok = (matched == expect_match)
    if ok then
        io.write(string.format("[PASS] %-28s %-42s %s\n", conf_label, label, uri))
        pass = pass + 1
    else
        io.write(string.format(
            "[FAIL] %-28s %-42s %s\n         regex %q\n         expected match=%s, got match=%s\n",
            conf_label, label, uri, nginx_regex, tostring(expect_match), tostring(matched)))
        fail = fail + 1
    end
end

-- ---------------------------------------------------------------------------
-- Test cases, run against both nginx.conf and nginx_readonly.conf, since
-- GHSA-55hc-p6p7-pmx2 affected both profiles identically.
-- ---------------------------------------------------------------------------
local configs = {
    { label = "nginx.conf",          path = nginx_dir .. "nginx.conf" },
    { label = "nginx_readonly.conf", path = nginx_dir .. "nginx_readonly.conf" },
}

for _, conf in ipairs(configs) do
    local nginx_regex, err = extract_location_regex(conf.path)
    if not nginx_regex then
        io.write(string.format("[FAIL] %-28s could not extract location regex: %s\n", conf.label, err))
        fail = fail + 1
        goto continue
    end

    print(string.format("=== %s: %s ===", conf.label, nginx_regex))

    -- Legitimate requests must still work.
    check("plain path",                     conf.label, nginx_regex, "/extracted-files",                         true)
    check("trailing slash",                 conf.label, nginx_regex, "/extracted-files/",                        true)
    check("nested file path",               conf.label, nginx_regex, "/extracted-files/foo/bar.txt",             true)
    check("filename with space",            conf.label, nginx_regex, "/extracted-files/foo bar.txt",             true)
    check("case-insensitive prefix",        conf.label, nginx_regex, "/EXTRACTED-FILES/foo",                     true)
    check("dashboards redirect target",     conf.label, nginx_regex, "/extracted-files/some/path.txt",           true)

    -- GHSA-55hc-p6p7-pmx2: host-splice / SSRF exploit strings from the advisory.
    -- None of these may match -- a match means the captured suffix would be
    -- concatenated onto "extracted-file-http-server" in proxy_pass again.
    check("dotted host splice (PoC step 3)",       conf.label, nginx_regex, "/extracted-files.attacker.example/x.html",        false)
    check("dotted host + explicit port (PoC local)", conf.label, nginx_regex, "/extracted-files.127.0.0.1.nip.io:8081/somepath", false)
    check("blind SSRF variant (PoC)",              conf.label, nginx_regex, "/extracted-files.10.0.0.5.nip.io:8443/",          false)
    check("userinfo-style suffix",                 conf.label, nginx_regex, "/extracted-files@127.0.0.1:8081/userinfo",        false)
    check("bare hyphen suffix",                    conf.label, nginx_regex, "/extracted-files-anything",                       false)
    check("query string with no path separator",   conf.label, nginx_regex, "/extracted-files?a=1",                            false)
    check("prefix-only typo",                       conf.label, nginx_regex, "/extracted-filesXYZ",                             false)

    ::continue::
    print()
end

print("==============================")
print(string.format("PASSED: %d", pass))
print(string.format("FAILED: %d", fail))
print("==============================")
os.exit(fail > 0 and 1 or 0)
