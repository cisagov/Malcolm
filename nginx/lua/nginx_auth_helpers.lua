local _M = {}

local cjson = require("cjson.safe")

-- URI -> ENV VARS mapping for RBAC (ordered, specific to general)
local path_role_envs = {
    -- Special cases (if you add deeper patterns, put them up here)

    -- Arkime PCAP view/export
    { pattern = "^/arkime/(api/)?sessions?/.+/packets(?:$|[/?])", roles = {
        "ROLE_ADMIN",
        "ROLE_ARKIME_ADMIN",
        "ROLE_ARKIME_PCAP_ACCESS",
        "ROLE_READ_ACCESS",
        "ROLE_READ_WRITE_ACCESS"
    }},
    { pattern = "^/arkime/(api/)?sessions?[./]pcap", roles = {
        "ROLE_ADMIN",
        "ROLE_ARKIME_ADMIN",
        "ROLE_ARKIME_PCAP_ACCESS",
        "ROLE_READ_ACCESS",
        "ROLE_READ_WRITE_ACCESS"
    }},
    { pattern = "^/arkime/(api/)?sessions?/(add|remove)tags", roles = {
        "ROLE_ADMIN",
        "ROLE_ARKIME_ADMIN",
        "ROLE_READ_WRITE_ACCESS",
        "ROLE_ARKIME_READ_WRITE_ACCESS"
    }},
    { pattern = "^/arkime/(api/)?(cron|delete|upload)", roles = {
        "ROLE_ADMIN",
        "ROLE_ARKIME_ADMIN",
        "ROLE_READ_WRITE_ACCESS",
        "ROLE_ARKIME_READ_WRITE_ACCESS"
    }},
    { pattern = "^/arkime/(api/)?esadmin", roles = {
        "ROLE_ADMIN",
        "ROLE_ARKIME_ADMIN"
    }},

    -- Arkime Hunt
    { pattern = "^/arkime/(api/)?hunts?", roles = {
        "ROLE_ADMIN",
        "ROLE_ARKIME_ADMIN",
        "ROLE_ARKIME_HUNT_ACCESS",
        "ROLE_READ_WRITE_ACCESS"
    }},

    -- Arkime WISE
    { pattern = "^/wise/(config/save|source/.+/put)", roles = {
        "ROLE_ADMIN",
        "ROLE_ARKIME_ADMIN",
        "ROLE_ARKIME_WISE_READ_WRITE_ACCESS",
        "ROLE_READ_WRITE_ACCESS"
    }},
    { pattern = "^/wise", roles = {
        "ROLE_ADMIN",
        "ROLE_ARKIME_ADMIN",
        "ROLE_ARKIME_WISE_READ_WRITE_ACCESS",
        "ROLE_ARKIME_WISE_READ_ACCESS",
        "ROLE_READ_WRITE_ACCESS",
        "ROLE_READ_ACCESS"
    }},

    -- Upload endpoints
    { pattern = "^/(server/php|upload)", roles = {
        "ROLE_ADMIN",
        "ROLE_READ_WRITE_ACCESS",
        "ROLE_UPLOAD"
    }},

    -- NetBox
    { pattern = "^/netbox", roles = {
        "ROLE_ADMIN",
        "ROLE_NETBOX_READ_ACCESS",
        "ROLE_NETBOX_READ_WRITE_ACCESS",
        "ROLE_READ_ACCESS",
        "ROLE_READ_WRITE_ACCESS"
    }},

    -- Extracted files
    { pattern = "^/(dashboards/app/)?(hh-)?extracted-files", roles = {
        "ROLE_ADMIN",
        "ROLE_READ_ACCESS",
        "ROLE_READ_WRITE_ACCESS",
        "ROLE_EXTRACTED_FILES"
    }},

    -- Dashboards & related paths
    { pattern = "^/((mapi/)?dashboards|idark2dash)", roles = {
        "ROLE_ADMIN",
        "ROLE_DASHBOARDS_READ_ACCESS",
        "ROLE_DASHBOARDS_READ_ALL_APPS_ACCESS",
        "ROLE_DASHBOARDS_READ_WRITE_ACCESS",
        "ROLE_DASHBOARDS_READ_WRITE_ALL_APPS_ACCESS",
        "ROLE_READ_ACCESS",
        "ROLE_READ_WRITE_ACCESS"
    }},

    -- Arkime & related paths
    { pattern = "^/(arkime|iddash2ark)", roles = {
        "ROLE_ADMIN",
        "ROLE_ARKIME_ADMIN",
        "ROLE_ARKIME_HUNT_ACCESS",
        "ROLE_ARKIME_PCAP_ACCESS",
        "ROLE_ARKIME_READ_ACCESS",
        "ROLE_ARKIME_READ_WRITE_ACCESS",
        "ROLE_ARKIME_WISE_READ_ACCESS",
        "ROLE_ARKIME_WISE_READ_WRITE_ACCESS",
        "ROLE_READ_ACCESS",
        "ROLE_READ_WRITE_ACCESS"
    }}
}

-- Define URI pattern → role mappings (i.e., helps us turn "read_access" into "netbox_read_access")
--   For some other services (e.g., opensearch in roles_mapping.yml.orig) we are more explicit and just
--   define all the roles, but this is a convenient way to avoid duplication.
local uri_role_mappings = {
    ["^/(arkime|iddash2ark|wise)"] = {
        { from = "ROLE_ADMIN", to = { "ROLE_ARKIME_ADMIN",
                                      "ROLE_ARKIME_READ_WRITE_ACCESS",
                                      "ROLE_ARKIME_PCAP_ACCESS",
                                      "ROLE_ARKIME_HUNT_ACCESS",
                                      "ROLE_ARKIME_WISE_READ_ACCESS",
                                      "ROLE_ARKIME_WISE_READ_WRITE_ACCESS" } },
        { from = "ROLE_READ_ACCESS", to = { "ROLE_ARKIME_READ_ACCESS",
                                            "ROLE_ARKIME_PCAP_ACCESS",
                                            "ROLE_ARKIME_WISE_READ_ACCESS" } },
        { from = "ROLE_READ_WRITE_ACCESS", to = { "ROLE_ARKIME_READ_WRITE_ACCESS",
                                                  "ROLE_ARKIME_PCAP_ACCESS",
                                                  "ROLE_ARKIME_HUNT_ACCESS",
                                                  "ROLE_ARKIME_WISE_READ_ACCESS",
                                                  "ROLE_ARKIME_WISE_READ_WRITE_ACCESS" } }
    },
    ["^/(dashboards/app/)?(hh-)?extracted-files"] = {
        { from = "ROLE_ADMIN", to = "ROLE_EXTRACTED_FILES" },
        { from = "ROLE_READ_ACCESS", to = "ROLE_EXTRACTED_FILES" },
        { from = "ROLE_READ_WRITE_ACCESS", to = "ROLE_EXTRACTED_FILES" }
    },
    ["^/netbox"] = {
        { from = "ROLE_READ_ACCESS", to = "ROLE_NETBOX_READ_ACCESS" },
        { from = "ROLE_READ_WRITE_ACCESS", to = "ROLE_NETBOX_READ_WRITE_ACCESS" }
    }
}
local role_expansion_map = {}

-- Helper to safely get non-empty env vars
function _M.get_environment_variable(name)
    local val = os.getenv(name)
    return (val and val ~= "") and val or nil
end

local role_based_access_enabled = false

function _M.is_role_based_access_enabled()
    return role_based_access_enabled
end

function _M.init()
    -- Determine if role base access is enabled vi environment variable
    local rbac_enabled_env_match, err = ngx.re.match(_M.get_environment_variable("ROLE_BASED_ACCESS"), "^(1|true|yes|on)$", "ijo")
    if rbac_enabled_env_match ~= nil then
        role_based_access_enabled = true
    else
        role_based_access_enabled = false
    end
    ngx.log(ngx.INFO, "RBAC enabled by ROLE_BASED_ACCESS: " .. tostring(role_based_access_enabled))

    -- Build the role expansion map dynamically from environment variables
    for pattern, mappings in pairs(uri_role_mappings) do
        for _, map in ipairs(mappings) do
            local from_role = _M.get_environment_variable(map.from)
            local to_roles = map.to
            if from_role and to_roles then
                role_expansion_map[pattern] = role_expansion_map[pattern] or {}
                role_expansion_map[pattern][from_role] = role_expansion_map[pattern][from_role] or {}
                if type(to_roles) == "table" then
                    for _, to_role_env in ipairs(to_roles) do
                        local to_role = _M.get_environment_variable(to_role_env)
                        if to_role then
                            table.insert(role_expansion_map[pattern][from_role], to_role)
                        end
                    end
                else
                    local to_role = _M.get_environment_variable(to_roles)
                    if to_role then
                        table.insert(role_expansion_map[pattern][from_role], to_role)
                    end
                end
            end
        end
    end
    ngx.log(ngx.INFO, "Initialized role expansion map: " .. cjson.encode(role_expansion_map))
end

function _M.set_headers(username, token, groups, roles)
    if username ~= nil and username ~= '' then
        ngx.req.set_header("X-Forwarded-User", username)
    end
    if token ~= nil and token ~= '' then
        ngx.req.set_header("Authorization", "Bearer " .. token)
    end
    if groups ~= nil and next(groups) ~= nil then
        ngx.req.set_header("X-Forwarded-Groups", table.concat(groups, ","))
    end
    if role_based_access_enabled then
        if roles and next(roles) then
            -- Build deduplicated role set from provided roles
            local role_set = {}
            for _, role in ipairs(roles) do
                role_set[role] = true
            end
            -- Apply role expansion logic based on current request URI
            local request_uri = ngx.var.request_uri:match("^[^?]+") or ""
            for pattern, expansion in pairs(role_expansion_map) do
                local m, err = ngx.re.match(request_uri, pattern)
                if m then
                    for base_role, extra_roles in pairs(expansion) do
                        if role_set[base_role] then
                            for _, extra in ipairs(extra_roles) do
                                role_set[extra] = true
                            end
                        end
                    end
                end
            end
            -- Flatten deduplicated roles into a list
            local final_roles = {}
            for r, _ in pairs(role_set) do
                table.insert(final_roles, r)
            end
            ngx.log(ngx.DEBUG, "Final rules for user " .. username .. " (" .. request_uri .. ": " .. cjson.encode(final_roles))
            -- Set the header with the final expanded roles
            ngx.req.set_header("X-Forwarded-Roles", table.concat(final_roles, ","))
        else
            ngx.req.clear_header("X-Forwarded-Roles")
        end
    else
        local role_admin_env = _M.get_environment_variable("ROLE_ADMIN")
        ngx.req.set_header("X-Forwarded-Roles", role_admin_env or "admin")
    end
end

function _M.refresh_token(httpc, token_url, client_id, client_secret, refresh_token)
    local result = false

    if refresh_token then
        local res, err = httpc:request_uri(token_url, {
            method = "POST",
            body = ngx.encode_args({
                grant_type = "refresh_token",
                client_id = client_id,
                client_secret = client_secret,
                refresh_token = refresh_token
            }),
            headers = { ["Content-Type"] = "application/x-www-form-urlencoded" },
            ssl_verify = false
        })
        httpc:set_keepalive(60000, 10)

        if res then
            local token_response = cjson.decode(res.body)
            if token_response and token_response.access_token then
                ngx.log(ngx.INFO, "Access token refreshed, request allowed")
                ngx.req.set_header("Authorization", "Bearer " .. token_response.access_token)
                -- Store new refresh token (if provided)
                if token_response.refresh_token then
                    ngx.header["Set-Cookie"] = "REFRESH_TOKEN=" .. ngx.escape_uri(token_response.refresh_token) .. "; Path=/; HttpOnly; Secure"
                else
                    ngx.log(ngx.WARN, "No new refresh token received from provider")
                end
                result = true
            else
                ngx.log(ngx.WARN, "Access token refresh failed, falling back to Basic Auth")
            end
        else
            ngx.log(ngx.ERR, "Error refreshing access token: ", err or "unknown error")
        end
    end

    return result
end

function _M.introspect_token(httpc, introspect_url, access_token, client_id, client_secret)
    local res, err = httpc:request_uri(introspect_url, {
        method = "POST",
        body = ngx.encode_args({
            token = access_token,
            client_id = client_id,
            client_secret = client_secret
        }),
        headers = { ["Content-Type"] = "application/x-www-form-urlencoded" },
        ssl_verify = false
    })
    httpc:set_keepalive(60000, 10)
    if not res then
        ngx.log(ngx.ERR, "Access token validation request failed: ", err or "unknown error")
        ngx.status = 500
        return ngx.HTTP_INTERNAL_SERVER_ERROR, nil
    end
    if res.status ~= 200 then
        ngx.log(ngx.ERR, "Introspection request failed with status ", res.status, ": ", res.body or "No response body")
        ngx.status = 401
        return ngx.HTTP_UNAUTHORIZED, nil
    end
    local token_data, decode_err = cjson.decode(res.body)
    if not token_data then
        ngx.log(ngx.ERR, "Failed to parse introspection response: ", decode_err or "unknown error")
        ngx.status = 500
        return ngx.HTTP_INTERNAL_SERVER_ERROR, nil
    end
    return ngx.HTTP_OK, token_data
end

function _M.check_groups_and_roles(token_data)
    local username = token_data.preferred_username or ""
    local groups = token_data.groups or {}
    local roles = (token_data.realm_access and token_data.realm_access.roles) or {}
    if next(groups) ~= nil then
        ngx.log(ngx.INFO, "User " .. username .. " has groups " .. cjson.encode(groups))
    end
    if next(roles) ~= nil then
        ngx.log(ngx.INFO, "User " .. username .. " has roles " .. cjson.encode(roles))
    end

    local required_groups_str = _M.get_environment_variable("NGINX_REQUIRE_GROUP")
    if required_groups_str then
        local required_groups = {}
        for group in required_groups_str:gmatch("[^,]+") do
            table.insert(required_groups, group)
        end
        local user_groups = {}
        for _, group in ipairs(groups) do
            user_groups[group] = true
        end
        for _, required_group in ipairs(required_groups) do
            if not user_groups[required_group] then
                ngx.log(ngx.WARN, "User " .. username .. " does not belong to required group: " .. required_group)
                ngx.status = 403
                return ngx.HTTP_FORBIDDEN, username, groups, roles
            end
        end
    end
    local required_roles_str = _M.get_environment_variable("NGINX_REQUIRE_ROLE")
    if required_roles_str then
        local required_roles = {}
        for role in required_roles_str:gmatch("[^,]+") do
            table.insert(required_roles, role)
        end
        local user_roles = {}
        for _, role in ipairs(roles) do
            user_roles[role] = true
        end
        for _, required_role in ipairs(required_roles) do
            if not user_roles[required_role] then
                ngx.log(ngx.WARN, "User " .. username .. " does not have required role: " .. required_role)
                ngx.status = 403
                return ngx.HTTP_FORBIDDEN, username, groups, roles
            end
        end
    end

    return ngx.HTTP_OK, username, groups, roles
end

-- check_rbac is a top-level check for URI access based on roles, but it is not the final line of
--   defense. Individual applications should do additional checking of X-Forwarded-Roles internally.
function _M.check_rbac(token_data)

    -- RBAC toggle
    if not role_based_access_enabled then
        return ngx.HTTP_OK
    end

    -- URI -> ENV VARS mapping
    local uri = ngx.var.request_uri:match("^[^?]+") or ""
    local username = token_data.preferred_username or ""
    local roles = (token_data.realm_access and token_data.realm_access.roles) or {}

    -- Match prefix and collect allowed roles for this route.
    -- path_role_envs is ordered from more-to-less specific, so
    -- this will return the first matching rule.
    local function get_allowed_roles_for_path(uri_path)
        for _, entry in ipairs(path_role_envs) do
            local from, to, err = ngx.re.find(uri_path, entry.pattern, "jo")
            if from then
                local allowed = {}
                for _, var_name in ipairs(entry.roles) do
                    local role = _M.get_environment_variable(var_name)
                    if role then
                        allowed[role] = true
                    end
                end
                return allowed
            end
        end
        return nil
    end

    local allowed_roles = get_allowed_roles_for_path(uri)

    if not allowed_roles then
        ngx.log(ngx.INFO, "No role restrictions, access granted")
        return ngx.HTTP_OK
    end

    if next(allowed_roles) == nil then
        ngx.log(ngx.INFO, "No environment roles, access granted")
        return ngx.HTTP_OK
    end

    -- Check for role match
    for _, user_role in ipairs(roles) do
        if allowed_roles[user_role] then
            ngx.log(ngx.INFO, "User " .. username .. " with " .. user_role .. ", access granted")
            return ngx.HTTP_OK
        end
    end

    ngx.log(ngx.WARN, "User " .. username .. " does not have required role")
    return ngx.HTTP_FORBIDDEN
end

return _M