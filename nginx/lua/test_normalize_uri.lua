#!/usr/bin/env lua
--
-- test_normalize_uri.lua -- regression tests for normalize_uri_for_rbac
--
-- Tests the URI normalization function used by Malcolm's nginx RBAC layer
-- to agree with nginx's own ngx_http_parse_complex_uri before location
-- matching. Covers all bypass classes fixed across:
--
--   GHSA-jr6p-63pg-hr6g  -- percent-encoding, slash-doubling, case variation
--   CVE-2026-63177        -- /../ double-dot traversal
--   GHSA-v66f-cwcm-hf73  -- /./ single-dot segment
--
-- Usage (from nginx/lua/):
--   lua test_normalize_uri.lua
--
-- Requires lua 5.1+ or luajit. Does not require nginx or OpenResty.
--
-- nginx_auth_helpers.lua must export the function for testing by including
-- this line immediately after the normalize_uri_for_rbac function definition:
--
--   _M._normalize_uri_for_rbac = normalize_uri_for_rbac  -- exported for unit testing only

-- ---------------------------------------------------------------------------
-- Stubs: minimum ngx surface needed to load nginx_auth_helpers.lua without
-- nginx/OpenResty present. Only ngx.unescape_uri affects the function under
-- test; the rest are needed to satisfy module-level definitions.
-- ---------------------------------------------------------------------------
ngx = {
    unescape_uri = function(s)
        -- Single-pass percent-decode, matching OpenResty's ngx.unescape_uri.
        return (s:gsub("%%(%x%x)", function(h)
            return string.char(tonumber(h, 16))
        end))
    end,
    re   = { match = function() return nil end, find = function() return nil end },
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

-- Stub cjson.safe (used only for log formatting inside the module).
package.loaded["cjson.safe"] = {
    encode = function(v) return tostring(v) end,
    decode = function(s) return nil, "stub" end,
}

-- ---------------------------------------------------------------------------
-- Load module. Assumes this script lives in the same directory as
-- nginx_auth_helpers.lua. Adjust package.path if running from elsewhere.
-- ---------------------------------------------------------------------------
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
if not normalize then
    io.stderr:write("ERROR: _normalize_uri_for_rbac not exported.\n")
    io.stderr:write("Add this line after the function definition in nginx_auth_helpers.lua:\n")
    io.stderr:write("  _M._normalize_uri_for_rbac = normalize_uri_for_rbac\n")
    os.exit(1)
end

-- ---------------------------------------------------------------------------
-- Test runner
-- ---------------------------------------------------------------------------
local pass, fail = 0, 0

local function check(label, input, expected)
    local got = normalize(input)
    if got == expected then
        io.write(string.format("[PASS] %-50s  %s\n", label, input))
        pass = pass + 1
    else
        io.write(string.format("[FAIL] %-50s  %s\n         got  %q\n         want %q\n",
            label, input, got, expected))
        fail = fail + 1
    end
end

-- ---------------------------------------------------------------------------
-- Test cases
-- ---------------------------------------------------------------------------

print("=== identity: paths requiring no normalization ===")
check("root",                               "/",                          "/")
check("plain upload path",                  "/upload",                    "/upload")
check("upload with filename",               "/upload/capture.pcap",       "/upload/capture.pcap")
check("server/php path",                    "/server/php",                "/server/php")
check("htadmin with trailing slash",        "/htadmin/",                  "/htadmin/")
check("auth path",                          "/auth/login",                "/auth/login")
check("arkime sessions",                    "/arkime/sessions",           "/arkime/sessions")
check("arkime packet path",                 "/arkime/api/sessions/x/packets", "/arkime/api/sessions/x/packets")
check("unrestricted path",                  "/health",                    "/health")
check("unrestricted nested path",           "/static/app.js",             "/static/app.js")

print()
print("=== percent-encoding (GHSA-jr6p-63pg-hr6g) ===")
check("first char encoded",                 "/%75pload",                  "/upload")
check("encoded dot-dot",                    "/%2e%2e/upload",             "/upload")
check("encoded single dot",                 "/%2e/upload",                "/upload")
check("uppercase hex encoding",             "/%55PLOAD",                  "/upload")
check("encoded full word",                  "/%61rk%69me/sessions",       "/arkime/sessions")
check("encoded htadmin",                    "/%68tadmin/",                "/htadmin/")
check("encoded dot-dot slash",              "/%2e%2e%2fupload",           "/upload")

print()
print("=== repeated slashes (GHSA-jr6p-63pg-hr6g) ===")
check("double slash prefix",                "//upload",                   "/upload")
check("triple slash prefix",                "///upload",                  "/upload")
check("double slash mid-path",              "/upload//file",              "/upload/file")
check("double slash htadmin",               "//htadmin/",                 "/htadmin/")
check("double slash server/php",            "//server/php",               "/server/php")

print()
print("=== case variation (CVE-2026-63177) ===")
check("all uppercase",                      "/UPLOAD",                    "/upload")
check("mixed case",                         "/UpLoAd",                    "/upload")
check("uppercase htadmin",                  "/HTADMIN/",                  "/htadmin/")
check("uppercase auth",                     "/AUTH/login",                "/auth/login")
check("uppercase arkime",                   "/ARKIME/sessions",           "/arkime/sessions")
check("mixed case server/php",              "/Server/PHP",                "/server/php")

print()
print("=== double-dot traversal (CVE-2026-63177) ===")
check("simple traversal",                   "/x/../upload",               "/upload")
check("two-segment traversal",              "/x/y/../../upload",          "/upload")
check("deep traversal",                     "/a/b/c/../../../upload",     "/upload")
check("leading double-dot",                 "/../upload",                 "/upload")
check("traversal to htadmin",               "/x/../htadmin/",             "/htadmin/")
check("traversal to auth",                  "/x/../auth/login",           "/auth/login")
check("traversal to server/php",            "/x/../server/php",           "/server/php")
check("double-dot mid-path preserved role", "/arkime/x/../sessions",      "/arkime/sessions")

print()
print("=== single-dot segment (GHSA-v66f-cwcm-hf73) ===")
check("leading dot to upload",              "/./upload",                  "/upload")
check("leading dot with sub-path",          "/./upload/capture.pcap",     "/upload/capture.pcap")
check("percent-encoded dot",                "/%2e/upload",                "/upload")
check("dot plus doubled slash",             "/.//upload",                 "/upload")
check("dot to server/php",                  "/./server/php",              "/server/php")
check("dot to htadmin",                     "/./htadmin/",                "/htadmin/")
check("dot to auth",                        "/./auth/x",                  "/auth/x")
check("dot to arkime packets",              "/./arkime/api/sessions/abc/packets", "/arkime/api/sessions/abc/packets")
check("dot to arkime sessions.pcap",        "/./arkime/api/sessions.pcap",        "/arkime/api/sessions.pcap")
check("dot to upload/file (reporter path)", "/./upload/file",                     "/upload/file")
check("multiple leading dot segments",      "/./././upload",              "/upload")
check("trailing dot",                       "/upload/.",                  "/upload")
check("trailing dot-slash",                 "/upload/./",                 "/upload/")
check("trailing double-dot",               "/upload/x/..",               "/upload")
check("dot in middle of path",              "/upload/./file",             "/upload/file")
-- admin_login (third arm of auth/htadmin/admin_login pattern)
check("dot to admin_login",                 "/./admin_login",             "/admin_login")
-- arkime restricted sub-paths
check("dot to arkime esadmin",              "/./arkime/api/esadmin",      "/arkime/api/esadmin")
check("dot to arkime cron",                 "/./arkime/api/cron",         "/arkime/api/cron")
check("dot to arkime delete",              "/./arkime/api/delete",       "/arkime/api/delete")
check("dot to arkime upload",              "/./arkime/api/upload",       "/arkime/api/upload")
check("dot to arkime addtags",             "/./arkime/api/sessions/x/addtags", "/arkime/api/sessions/x/addtags")
check("dot to arkime hunts",               "/./arkime/api/hunts",        "/arkime/api/hunts")
-- wise
check("dot to wise",                       "/./wise",                    "/wise")
check("dot to wise config/save",           "/./wise/config/save",        "/wise/config/save")
check("dot to wise source put",            "/./wise/source/x/put",       "/wise/source/x/put")
-- netbox
check("dot to netbox",                     "/./netbox",                  "/netbox")
check("dot to netbox api",                 "/./netbox/api/dcim/",        "/netbox/api/dcim/")
-- dashboards variants
check("dot to mapi/dashboards",            "/./mapi/dashboards",         "/mapi/dashboards")
check("dot to idark2dash",                 "/./idark2dash/foo",          "/idark2dash/foo")
check("dot to iddash2ark",                 "/./iddash2ark/foo",          "/iddash2ark/foo")
-- extracted-files with dashboards/app prefix
check("dot to dashboards/app/extracted-files",    "/./dashboards/app/extracted-files/foo",    "/dashboards/app/extracted-files/foo")
check("dot to dashboards/app/hh-extracted-files", "/./dashboards/app/hh-extracted-files/foo", "/dashboards/app/hh-extracted-files/foo")

print()
print("=== interleaved dot and double-dot (GHSA-v66f-cwcm-hf73, broke two-line fix) ===")
check("dot then double-dot",                "/x/./../upload",             "/upload")
check("leading dot then double-dot",        "/./x/../upload",             "/upload")
check("dot-slash then double-dot",          "/x/.//../upload",            "/upload")
check("dot between segments then pop",      "/a/./b/../../upload",        "/upload")
check("double-dot then dot",               "/a/b/./../../upload",        "/upload")
check("complex interleaving",               "/x/.././y/./../upload",      "/upload")
check("dot then double-dot to htadmin",     "/x/./../htadmin/",           "/htadmin/")
check("double leading dot then traversal",  "/./x/.././upload",           "/upload")

print()
print("=== combinations of multiple bypass classes ===")
check("percent + case",                     "/%75PLOAD",                  "/upload")
check("slash + traversal",                  "//x/../upload",              "/upload")
check("dot + case",                         "/./UPLOAD",                  "/upload")
check("dot + percent",                      "/%2e/%75pload",              "/upload")
check("slash + dot + traversal",            "//./x/../upload",            "/upload")
check("percent dot + case",                 "/%2e/UPLOAD",                "/upload")
check("slash + double-dot + case",          "//X/../UPLOAD",              "/upload")
check("all classes combined",               "//%2e%2e/%75PLOAD",          "/upload")

print()
print("=== should not over-block: unrestricted paths remain accessible ===")
check("root",                               "/",                          "/")
check("plain unrestricted",                 "/health",                    "/health")
check("dot on unrestricted",                "/./health",                  "/health")
check("double-dot on unrestricted",         "/x/../health",               "/health")
check("case on unrestricted",               "/HEALTH",                    "/health")
check("interleaved on unrestricted",        "/./x/../health",             "/health")

print()
print("==============================")
print(string.format("PASSED: %d", pass))
print(string.format("FAILED: %d", fail))
print("==============================")
os.exit(fail > 0 and 1 or 0)
