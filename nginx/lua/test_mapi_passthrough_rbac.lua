#!/usr/bin/env lua
--
-- test_mapi_passthrough_rbac.lua -- regression tests for the /mapi/netbox and
-- /mapi/logstash entries in path_role_envs
--
-- nginx proxies /mapi/netbox/ and /mapi/logstash/ straight to their backends
-- rather than through the Malcolm API, so nginx RBAC is the only gate in front
-- of them. check_rbac() grants any path that matches no rule, so each of these
-- routes needs its own entry. This checks that the passthrough routes resolve
-- to the same roles as the routes they stand in for, and that no role outside
-- that set (ROLE_UPLOAD, for example) is let through.
--
-- Usage (from nginx/lua/):
--   lua test_mapi_passthrough_rbac.lua
--
-- Requires lua 5.1+ or luajit and the lrexlib PCRE binding (rex_pcre2 or
-- rex_pcre). Does not require nginx or OpenResty. On Debian or Ubuntu:
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


-- ---------------------------------------------------------------------------
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

local function set_to_string(set)
    if not set then return "nil (default allow)" end
    local keys = {}
    for k, _ in pairs(set) do keys[#keys + 1] = k end
    table.sort(keys)
    return "{" .. table.concat(keys, ", ") .. "}"
end

local function same_set(a, b)
    if not a or not b then return false end
    for k, _ in pairs(a) do if not b[k] then return false end end
    for k, _ in pairs(b) do if not a[k] then return false end end
    return true
end

-- The passthrough URI must resolve to exactly the role set of the reference URI.
local function same_roles_as(label, uri, reference_uri)
    local got = allowed_role_vars(uri)
    local want = allowed_role_vars(reference_uri)
    record(same_set(got, want), label, uri,
        "got " .. set_to_string(got) .. ", want " .. set_to_string(want))
end

-- The URI must match a rule, and none of the listed roles may be in it.
local function denies(label, uri, roles)
    local set = allowed_role_vars(uri)
    if not set then
        return record(false, label, uri, "no rule matched (default allow)")
    end
    local leaked = {}
    for _, r in ipairs(roles) do
        if set[r] then leaked[#leaked + 1] = r end
    end
    record(#leaked == 0, label, uri, "unexpectedly allowed: " .. table.concat(leaked, ", "))
end

-- ---------------------------------------------------------------------------
-- Test cases
-- ---------------------------------------------------------------------------

local NON_NETBOX_ROLES = {
    "ROLE_UPLOAD",
    "ROLE_EXTRACTED_FILES",
    "ROLE_ARKIME_READ_ACCESS",
    "ROLE_ARKIME_ADMIN",
    "ROLE_DASHBOARDS_READ_ACCESS",
    "ROLE_DASHBOARDS_READ_WRITE_ACCESS",
}

print("=== /mapi/netbox matches /netbox ===")
same_roles_as("api prefix form",            "/mapi/netbox/api/dcim/devices/", "/netbox/api/dcim/devices/")
same_roles_as("short form",                 "/mapi/netbox/dcim/devices/",     "/netbox/api/dcim/devices/")
same_roles_as("ipam",                       "/mapi/netbox/api/ipam/ip-addresses/", "/netbox/api/ipam/ip-addresses/")
same_roles_as("passthrough root",           "/mapi/netbox/",                  "/netbox/api/")
same_roles_as("query string",               "/mapi/netbox/api/dcim/devices/?limit=1000", "/netbox/api/dcim/devices/")
same_roles_as("uppercase",                  "/MAPI/NetBox/api/dcim/devices/", "/netbox/api/dcim/devices/")
same_roles_as("doubled slashes",            "//mapi//netbox//api/dcim/",      "/netbox/api/dcim/")
same_roles_as("percent-encoded",            "/mapi/%6eetbox/api/dcim/",       "/netbox/api/dcim/")
same_roles_as("dot segment",                "/mapi/./netbox/api/dcim/",       "/netbox/api/dcim/")

print()
print("=== /mapi/netbox does not admit non-NetBox roles ===")
denies("upload-only user",                  "/mapi/netbox/api/dcim/devices/", NON_NETBOX_ROLES)
denies("upload-only user, short form",      "/mapi/netbox/ipam/prefixes/",    NON_NETBOX_ROLES)

print()
print("=== /mapi/logstash is covered ===")
denies("node stats",                        "/mapi/logstash/_node/stats",     { "ROLE_UPLOAD", "ROLE_EXTRACTED_FILES" })
denies("root",                              "/mapi/logstash/",                { "ROLE_UPLOAD", "ROLE_EXTRACTED_FILES" })
denies("uppercase",                         "/MAPI/LOGSTASH/_node/pipelines", { "ROLE_UPLOAD", "ROLE_EXTRACTED_FILES" })

print()
print("=== neighbouring routes are unaffected ===")
local function default_allow(label, uri)
    local set = allowed_role_vars(uri)
    record(set == nil, label, uri, "expected no rule (Malcolm API enforces roles itself), got " .. set_to_string(set))
end
default_allow("malcolm api",                "/mapi/ping")
default_allow("malcolm api, fields",        "/mapi/fields")
same_roles_as("mapi dashboards",            "/mapi/dashboards/app/home",      "/dashboards/app/home")

print()
print(string.format("%d passed, %d failed", pass, fail))
os.exit(fail == 0 and 0 or 1)
