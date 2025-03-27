local _M = {}

local cjson = require("cjson.safe")

function _M.set_headers(username, token, groups, roles)
    if username ~= nil and username ~= '' then
        ngx.req.set_header("http_auth_http_user", username)
        ngx.req.set_header("X-Remote-Auth", username)
        ngx.req.set_header("X-Remote-User", username)
        ngx.req.set_header("X-Forwarded-User", username)
    end
    if token ~= nil and token ~= '' then
        ngx.req.set_header("Authorization", "Bearer " .. token)
    end
    if roles ~= nil and next(roles) ~= nil then
        ngx.req.set_header("X-Forwarded-Roles", table.concat(roles, ","))
    end
    if groups ~= nil and next(groups) ~= nil then
        ngx.req.set_header("X-Forwarded-Groups", table.concat(groups, ","))
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

    local required_groups_str = os.getenv("NGINX_REQUIRE_GROUP")
    if required_groups_str and required_groups_str ~= "" then
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
                ngx.log(ngx.ERR, "User " .. username .. " does not belong to required group: " .. required_group)
                ngx.status = 403
                return ngx.HTTP_FORBIDDEN, username, groups, roles
            end
        end
    end
    local required_roles_str = os.getenv("NGINX_REQUIRE_ROLE")
    if required_roles_str and required_roles_str ~= "" then
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
                ngx.log(ngx.ERR, "User " .. username .. " does not have required role: " .. required_role)
                ngx.status = 403
                return ngx.HTTP_FORBIDDEN, username, groups, roles
            end
        end
    end

    return ngx.HTTP_OK, username, groups, roles
end

return _M