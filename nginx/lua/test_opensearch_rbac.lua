#!/usr/bin/env lua
--
-- test_opensearch_rbac.lua -- regression tests for the /mapi/opensearch
-- entries in path_role_envs
--
-- Checks which roles the RBAC table grants for the OpenSearch proxy:
-- read-only query endpoints for data readers, everything else (cluster,
-- snapshot, index admin, writes, scroll and point-in-time management)
-- for ROLE_ADMIN only.
--
-- Usage (from nginx/lua/):
--   lua test_opensearch_rbac.lua
--
-- Requires lua 5.1+ or luajit and the lrexlib PCRE binding (rex_pcre2 or
-- rex_pcre), because the patterns in path_role_envs are PCRE. Does not
-- require nginx or OpenResty. On Debian or Ubuntu:
--   apt-get install lua5.4 lua-rex-pcre2
--
-- nginx_auth_helpers.lua must export the table for testing by including
-- this line after the path_role_envs definition:
--
--   _M._path_role_envs = path_role_envs  -- exported for unit testing only

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
-- Stubs: minimum ngx surface needed to load nginx_auth_helpers.lua without
-- nginx/OpenResty present. ngx.re.find is backed by PCRE so the patterns in
-- path_role_envs behave as they do in OpenResty.
-- ---------------------------------------------------------------------------
ngx = {
    unescape_uri = function(s)
        return (s:gsub("%%(%x%x)", function(h)
            return string.char(tonumber(h, 16))
        end))
    end,
    re   = {
        match = function() return nil end,
        find  = function(subject, pattern) return rex.find(subject, pattern) end,
    },
    log  = function() end,
    req  = { set_header = function() end, clear_header = function() end },
    var  = {},
    header = {},
    status = 200,
    INFO  = 6,
    DEBUG = 8,
    WARN  = 4,
    ERR   = 3,
    HTTP_OK                    = 200,
    HTTP_UNAUTHORIZED          = 401,
    HTTP_FORBIDDEN             = 403,
    HTTP_INTERNAL_SERVER_ERROR = 500,
}

package.loaded["cjson.safe"] = {
    encode = function(v) return tostring(v) end,
    decode = function(s) return nil, "stub" end,
}

local script_dir = (debug.getinfo(1, "S").source:match("@?(.*/)" ) or "./")
package.path = script_dir .. "?.lua;" .. package.path

local ok, helpers = pcall(require, "nginx_auth_helpers")
if not ok then
    io.stderr:write("ERROR: could not load nginx_auth_helpers.lua\n")
    io.stderr:write("  " .. tostring(helpers) .. "\n")
    io.stderr:write("Run this script from the nginx/lua/ directory.\n")
    os.exit(1)
end

local normalize = helpers._normalize_uri_for_rbac
local path_role_envs = helpers._path_role_envs
if not normalize or not path_role_envs then
    io.stderr:write("ERROR: _normalize_uri_for_rbac and _path_role_envs must be exported.\n")
    os.exit(1)
end

-- ---------------------------------------------------------------------------
-- Lookup: the same first-match rule check_rbac() uses, returning the set of
-- role environment variable names allowed for a request URI, or nil when no
-- rule matches (default allow).
-- ---------------------------------------------------------------------------
local function allowed_role_vars(raw_uri)
    local uri = normalize(raw_uri)
    for _, entry in ipairs(path_role_envs) do
        if ngx.re.find(uri, entry.pattern, "jo") then
            local set = {}
            for _, var_name in ipairs(entry.roles) do
                set[var_name] = true
            end
            return set
        end
    end
    return nil
end

local READER_ROLES = {
    "ROLE_DASHBOARDS_READ_ACCESS",
    "ROLE_DASHBOARDS_READ_ALL_APPS_ACCESS",
    "ROLE_DASHBOARDS_READ_WRITE_ACCESS",
    "ROLE_DASHBOARDS_READ_WRITE_ALL_APPS_ACCESS",
    "ROLE_READ_ACCESS",
    "ROLE_READ_WRITE_ACCESS",
}

-- Roles that must never reach the admin-only tier.
local NON_ADMIN_ROLES = {
    "ROLE_UPLOAD",
    "ROLE_EXTRACTED_FILES",
    "ROLE_NETBOX_READ_ACCESS",
    "ROLE_ARKIME_READ_ACCESS",
    "ROLE_ARKIME_ADMIN",
}
for _, r in ipairs(READER_ROLES) do NON_ADMIN_ROLES[#NON_ADMIN_ROLES + 1] = r end

-- ---------------------------------------------------------------------------
-- Test runner
-- ---------------------------------------------------------------------------
local pass, fail = 0, 0

local function record(ok, label, input, detail)
    if ok then
        io.write(string.format("[PASS] %-46s  %s\n", label, input))
        pass = pass + 1
    else
        io.write(string.format("[FAIL] %-46s  %s\n         %s\n", label, input, detail))
        fail = fail + 1
    end
end

-- Reader tier: admin and every reader role are allowed.
local function reader_ok(label, uri)
    local set = allowed_role_vars(uri)
    if not set then
        return record(false, label, uri, "no rule matched (default allow)")
    end
    local missing = {}
    if not set["ROLE_ADMIN"] then missing[#missing + 1] = "ROLE_ADMIN" end
    for _, r in ipairs(READER_ROLES) do
        if not set[r] then missing[#missing + 1] = r end
    end
    record(#missing == 0, label, uri, "missing: " .. table.concat(missing, ", "))
end

-- Admin tier: ROLE_ADMIN is allowed and no other role is.
local function admin_only(label, uri)
    local set = allowed_role_vars(uri)
    if not set then
        return record(false, label, uri, "no rule matched (default allow)")
    end
    local extra = {}
    for _, r in ipairs(NON_ADMIN_ROLES) do
        if set[r] then extra[#extra + 1] = r end
    end
    local ok = set["ROLE_ADMIN"] and #extra == 0
    record(ok, label, uri, ok and "" or ("ROLE_ADMIN=" .. tostring(set["ROLE_ADMIN"])
        .. " unexpected: " .. table.concat(extra, ", ")))
end

-- ---------------------------------------------------------------------------
-- Test cases
-- ---------------------------------------------------------------------------

print("=== reader tier: read-only query endpoints ===")
reader_ok("search, no index",              "/mapi/opensearch/_search")
reader_ok("search, one index",             "/mapi/opensearch/arkime_sessions3-*/_search")
reader_ok("search, wildcard index",        "/mapi/opensearch/malcolm_beats_*/_search")
reader_ok("search, index list",            "/mapi/opensearch/a,b/_search")
reader_ok("search, _all",                  "/mapi/opensearch/_all/_search")
reader_ok("search with query string",      "/mapi/opensearch/idx/_search?size=1&scroll=1m")
reader_ok("msearch",                       "/mapi/opensearch/_msearch")
reader_ok("msearch, one index",            "/mapi/opensearch/idx/_msearch")
reader_ok("count",                         "/mapi/opensearch/idx/_count")
reader_ok("count with query string",       "/mapi/opensearch/idx/_count?q=x")
reader_ok("field_caps",                    "/mapi/opensearch/idx/_field_caps?fields=*")
reader_ok("validate query",                "/mapi/opensearch/idx/_validate/query")

print()
print("=== admin tier: scroll and point-in-time management ===")
admin_only("scroll continue",              "/mapi/opensearch/_search/scroll")
admin_only("scroll clear all",             "/mapi/opensearch/_search/scroll/_all")
admin_only("scroll clear by id",           "/mapi/opensearch/_search/scroll/abc")
admin_only("pit create",                   "/mapi/opensearch/idx/_search/point_in_time")
admin_only("pit delete all",               "/mapi/opensearch/_search/point_in_time/_all")
admin_only("search template",              "/mapi/opensearch/_search/template")
admin_only("search trailing slash",        "/mapi/opensearch/_search/")
admin_only("msearch subpath",              "/mapi/opensearch/_msearch/template")

print()
print("=== admin tier: cluster, snapshot, index admin, writes ===")
admin_only("cat nodes",                    "/mapi/opensearch/_cat/nodes")
admin_only("cluster settings",             "/mapi/opensearch/_cluster/settings")
admin_only("cluster health",               "/mapi/opensearch/_cluster/health")
admin_only("snapshot",                     "/mapi/opensearch/_snapshot")
admin_only("snapshot repo",                "/mapi/opensearch/_snapshot/repo/snap1")
admin_only("mapping",                      "/mapi/opensearch/idx/_mapping")
admin_only("settings",                     "/mapi/opensearch/idx/_settings")
admin_only("document write",               "/mapi/opensearch/idx/_doc/1")
admin_only("bulk",                         "/mapi/opensearch/_bulk")
admin_only("delete by query",              "/mapi/opensearch/idx/_delete_by_query")
admin_only("update by query",              "/mapi/opensearch/idx/_update_by_query")
admin_only("index root",                   "/mapi/opensearch/idx")
admin_only("proxy root",                   "/mapi/opensearch/")
admin_only("no trailing slash",            "/mapi/opensearch")
admin_only("endpoint name prefix",         "/mapi/opensearch/_searchfoo")
admin_only("endpoint name prefix, count",  "/mapi/opensearch/idx/_countfoo")

print()
print("=== normalization still lands in the right tier ===")
reader_ok("uppercase search",              "/MAPI/OpenSearch/_SEARCH")
reader_ok("encoded search",                "/mapi/opensearch/%5fsearch")
reader_ok("doubled slashes, search",       "//mapi//opensearch//_search")
admin_only("encoded scroll clear",         "/mapi/opensearch/%5fsearch/scroll/%5fall")
admin_only("uppercase cat nodes",          "/MAPI/OPENSEARCH/_CAT/NODES")
admin_only("dot-dot out of reader endpoint", "/mapi/opensearch/idx/_search/../_cluster/settings")
admin_only("pct-encoded ? in search path",  "/mapi/opensearch/_search%3f/x")
admin_only("pct-encoded ? prefix match",    "/mapi/opensearch/_search%3f_cat/nodes")

print()
print("=== neighbouring routes are unaffected ===")
local function unaffected(label, uri)
    local set = allowed_role_vars(uri)
    -- The OpenSearch entries must not capture these: a match here would
    -- mean the only roles are admin-only.
    local admin_tier = set and set["ROLE_ADMIN"] and not set["ROLE_READ_ACCESS"]
        and not set["ROLE_UPLOAD"] and not set["ROLE_NETBOX_READ_ACCESS"]
    record(not admin_tier, label, uri, "captured by an admin-only rule")
end
unaffected("dashboards via mapi",          "/mapi/dashboards/app/home")
unaffected("dashboards",                   "/dashboards/app/home")
unaffected("arkime",                       "/arkime/sessions")
unaffected("upload",                       "/upload")

print()
print(string.format("%d passed, %d failed", pass, fail))
os.exit(fail == 0 and 0 or 1)
