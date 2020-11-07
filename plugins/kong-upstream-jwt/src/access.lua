-- © Optum 2018
local json = require "cjson"
local openssl_hmac = require "resty.openssl.hmac"
local table_concat = table.concat
local encode_base64 = ngx.encode_base64
local utils = require "kong.tools.utils"
local kong = kong
local _M = {}

--- Supported algorithms for signing tokens. Currently only HS256 is in use.
-- from https://github.com/Kong/kong/blob/master/kong/plugins/jwt/jwt_parser.lua
local alg_sign = {
  HS256 = function(data, key) return openssl_hmac.new(key, "sha256"):final(data) end,
  HS384 = function(data, key) return openssl_hmac.new(key, "sha384"):final(data) end,
  HS512 = function(data, key) return openssl_hmac.new(key, "sha512"):final(data) end
}

-- from https://github.com/Kong/kong/blob/master/kong/plugins/jwt/jwt_parser.lua
local function load_credential(jwt_secret_key)
  local row, err = kong.db.jwt_secrets:select_by_key(jwt_secret_key)
  if err then
    return nil, err
  end
  return row
end

--- base 64 encoding
-- @param input String to base64 encode
-- @return Base64 encoded string
local function b64_encode(input)
  local result = encode_base64(input) -- TODO: Set no padding?
  result = result:gsub("+", "-"):gsub("/", "_"):gsub("=", "") -- TODO: Do not omit "="?
  return result
end

--- Base64 encode the JWT token
-- @param payload the payload of the token
-- @param key the key to sign the token with
-- @return the encoded JWT token
-- The JWT is segmented into three distinct concatenated base64 strings. (i.e. header.payload.signature)
local function encode_jwt_token(payload, key)
  local header = {
    typ = "JWT",
    alg = "HS256"
  }
  local segments = {
    b64_encode(json.encode(header)),
    b64_encode(json.encode(payload))
  }
  local signing_input = table_concat(segments, ".")
  local signature = alg_sign["HS256"](signing_input, key)
  segments[#segments+1] = b64_encode(signature)
  return table_concat(segments, ".")
end

--- Build the JWT token payload based off fields that are required by the backend
-- @return the payload to be used in encode_jwt_token
local function build_jwt_payload()
  local current_time = ngx.time() -- Much better performance improvement over os.time()
  local payload = {}

  -- adds all required field (specified by BE) for JWT payload
  payload["deviceId"] = kong.ctx.shared.device_id or "SYSTEM"
  payload["loginScope"] = kong.ctx.shared.login_scope -- hardcoded to prelogin because this function will only be used in prelogin flow, other flows will use the add_existing_jwt_header_hs256 function
  payload["userRefId"] = "SYSTEM"
  payload["userId"] = "SYSTEM"
  payload["corporateRefId"] = "SYSTEM"
  payload["corporateId"] = "SYSTEM"
  payload["mobileNo"] = "SYSTEM"

  return payload
end

local function build_header_value(conf, jwt)
  if conf.include_credential_type then
    return "Bearer " .. jwt
  else
    return jwt
  end
end

-- Retrieve jwt secret of the current authenticated consumer
-- Store the jwt secret as credential to current request context data, to be used in custom-response-transformer
local function get_jwt_credential()
  local consumer = kong.client.get_consumer()
  local credential = load_credential(consumer.username)
  kong.ctx.shared.credential = credential
  return credential
end

--- Add the JWT header to the request
-- @param conf the configuration
local function add_jwt_header(conf)
  local payload = build_jwt_payload()
  local credential = get_jwt_credential()
  local jwt = encode_jwt_token(payload, credential.secret)
  ngx.req.set_header(conf.header, build_header_value(conf, jwt))
end

--- Appends JWT that was found in db using access_token to the header of request to be sent to BE
local function add_existing_jwt_header(conf)
  local _ = get_jwt_credential()
  local token_details = kong.ctx.shared.access_token_row or kong.db.oauth2_tokens:select_by_access_token(kong.ctx.shared.access_token_string)
  ngx.req.set_header(conf.header, build_header_value(conf, token_details.jwt))
end

--- Stores x-device-id received from FE's request header in temporary table to be used in custom response transformer when upserting data (access token) into db
local function retrieve_device_id()
  local channel_id_header, err = kong.request.get_header("x-channel-id")
  if channel_id_header == "WB" then
    kong.ctx.shared.login_scope = "prelogin.web"
    return
  elseif channel_id_header == "MB" then
    local token_details = {}
    -- FYI, Header names in are case-insensitive and are normalized to lowercase, and dashes (-) can be written as underscores (_); that is, the header X-Custom-Header can also be retrieved as x_custom_header.
    local device_id_header, err, mimetype = kong.request.get_header("x-device-id")
    if device_id_header == nil then
      token_details = kong.ctx.shared.access_token_row or kong.db.oauth2_tokens:select_by_access_token(kong.ctx.shared.access_token_string)
    end
    -- This is also used in custom-reponse-transformer to upsert the oauth2_token's device_id column.
    kong.ctx.shared.device_id = token_details.device_id or device_id_header
    kong.ctx.shared.login_scope = "prelogin.mobile"
  end
end

--- Execute the script
-- @param conf kong configuration
function _M.execute(conf)
  retrieve_device_id()
  add_jwt_header(conf)
end

function _M.add_existing_jwt(conf)
  retrieve_device_id() -- make sure this function executes before appending jwt in request's auth header because it requires access token from request coming from FE
  add_existing_jwt_header(conf)
end

return _M
