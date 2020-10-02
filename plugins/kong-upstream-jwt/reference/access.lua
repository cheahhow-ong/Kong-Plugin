local json = require "cjson"
local openssl_hmac = require "resty.openssl.hmac"
local table_concat = table.concat
local encode_base64 = ngx.encode_base64
local utils = require "kong.tools.utils"
local request = kong.request
local client = kong.client
local kong = kong
local table = table
local ngx = ngx
local _M = {}

local alg_sign = {
  HS256 = function(data, key) return openssl_hmac.new(key, "sha256"):final(data) end,
  HS384 = function(data, key) return openssl_hmac.new(key, "sha384"):final(data) end,
  HS512 = function(data, key) return openssl_hmac.new(key, "sha512"):final(data) end
}

---@param username utilizes the authenticated consumer's username to retrieve the jwt_secret for signing purposes
--@return the jwt_secret tied to the consumer
local function load_credential(username)
  local row, err = kong.db.jwt_secrets:select_by_key(username)
  if err then
    return nil, err
  end
  return row
end

--- base 64 encoding
-- @param input String to base64 encode
-- @return Base64 encoded string
local function b64_encode(input)
  local result = encode_base64(input, true)
  result = result:gsub("+", "-"):gsub("/", "_")
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
  local payload = {
    exp = current_time + 900,
    jti = utils.uuid(),
    iat = current_time,
    channelId = "NB",
    language = request.get_header("Accept-Language"),
    clientVersion = request.get_header("X-Client-Version"),
    deviceId = request.get_header("X-Device-ID")
  }

    -- adds "scope" to the payload based on the request grant type.
    local body, err, mimetype = kong.request.get_body()
      if body then
        payload["userRefId"] = request.get_header("X-Device-ID")
        if body.pin then
          payload["scope"] = "pin"
        end
        if body.biometricUuid then
          payload["scope"] = "biometric"
        end
      end
    return payload
  end

  local function build_header_value(conf, jwt)
    if conf.include_credential_type then
      return "Bearer " .. jwt
    else
      return jwt
    end
  end


local function parse_access_token(conf)
  local found_in = {}

  local access_token = kong.request.get_header(conf.header)
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
  end
  return access_token
end

--- Replaces the existing 'Authorization' header with a JWT unless specified in the configuration
-- @param conf specify header name
local function add_jwt_header(conf)
  local payload = build_jwt_payload()
  local consumer = client.get_consumer()
  local credential = load_credential(consumer.username)
  -- credential is stored and used in custom-response-transformer
  kong.ctx.shared.credential = credential
  local jwt = encode_jwt_token(payload, credential.secret)
  ngx.req.set_header(conf.header, build_header_value(conf, jwt))
end

local function add_existing_jwt_header(conf)
  local access_token = parse_access_token(conf)
  local token_details = kong.db.oauth2_tokens:select_by_access_token(access_token)
  ngx.req.set_header(conf.header, build_header_value(conf, token_details.jwt))
end

--- Execute the script
-- @param conf kong configuration
function _M.execute(conf)
  add_jwt_header(conf)
end

function _M.add_existing_jwt(conf)
  add_existing_jwt_header(conf)
end

return _M