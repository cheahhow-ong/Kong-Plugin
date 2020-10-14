local kong_session = require "kong.plugins.custom-session.session"


local ngx = ngx
local kong = kong
local type = type
local assert = assert
local string_find = string.find

local ACCESS_TOKEN = "access_token"


local function get_authenticated_groups()
  local authenticated_groups = ngx.ctx.authenticated_groups
  if authenticated_groups == nil then
    return nil
  end

  assert(type(authenticated_groups) == "table",
         "invalid authenticated_groups, a table was expected")

  return authenticated_groups
end

local function retrieve_parameters()
    -- OAuth2 parameters could be in both the querystring or body
    local uri_args = kong.request.get_query()
    local method   = kong.request.get_method()

    if method == "POST" or method == "PUT" or method == "PATCH" then
        local body_args = kong.request.get_body()
        return kong.table.merge(uri_args, body_args)
    end

    return uri_args
end

local function parse_access_token()
    local found_in = {}

    local access_token = kong.request.get_header("Authorization")
    if access_token then
        local parts = {}
        for v in access_token:gmatch("%S+") do -- Split by space
            table.insert(parts, v)
        end

        if #parts == 2 and (parts[1]:lower() == "token" or
                parts[1]:lower() == "bearer") then
            access_token = parts[2]
            found_in.authorization_header = true
        end

    else
        access_token = retrieve_parameters()[ACCESS_TOKEN]
        if type(access_token) ~= "string" then
            return
        end
    end

    -- if conf.hide_credentials then
    --     if found_in.authorization_header then
    --         kong.service.request.clear_header(conf.auth_header_name)

    --     else
    --         -- Remove from querystring
    --         local parameters = kong.request.get_query()
    --         parameters[ACCESS_TOKEN] = nil
    --         kong.service.request.set_query(parameters)

    --         local content_type = kong.request.get_header("content-type")
    --         local is_form_post = content_type and
    --                 string_find(content_type, "application/x-www-form-urlencoded", 1, true)

    --         if kong.request.get_method() ~= "GET" and is_form_post then
    --             -- Remove from body
    --             parameters = kong.request.get_body() or {}
    --             parameters[ACCESS_TOKEN] = nil
    --             kong.service.request.set_body(parameters)
    --         end
    --     end
    -- end

    return access_token
end


local _M = {}

function _M.execute(conf)
    local backend_response = kong.ctx.shared.backend_response
    local access_token = parse_access_token()
    local current_session = kong.db.sessions:select_by_userRefId(backend_response.userRefId)

    -- create new session and save the data
    local s = kong_session.open_session(conf)
    s.access_token = access_token
    s.userRefId = backend_response.userRefId
    s.corporateRefId = backend_response.corporateRefId
    s:save()

    if current_session then
        kong.db.sessions:delete({ id = current_session.id })
    end
end


-- function _M.execute(conf)
--   local credential = kong.client.get_credential()
--   local consumer = kong.client.get_consumer()

--   if not credential then
--     -- don't open sessions for anonymous users
--     kong.log.debug("anonymous: no credential.")
--     return
--   end

--   local credential_id = credential.id
--   local consumer_id = consumer and consumer.id

--   -- if session exists and the data in the session matches the ctx then
--   -- don't worry about saving the session data or sending cookie
--   local s = kong.ctx.shared.authenticated_session
--   if s and s.present then
--     local cid, cred_id = kong_session.retrieve_session_data(s)
--     if cred_id == credential_id and cid == consumer_id
--     then
--       return
--     end
--   end

--   -- session is no longer valid
--   -- create new session and save the data / send the Set-Cookie header
--   if consumer_id then
--     local groups = get_authenticated_groups()
--     s = s or kong_session.open_session(conf)
--     kong_session.store_session_data(s,
--                                     consumer_id,
--                                     credential_id or consumer_id,
--                                     groups)
--     s:save()
--   end
-- end


return _M
