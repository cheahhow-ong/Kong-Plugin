-- © Optum 2018
local resty_sha256 = require "resty.sha256"
local str = require "resty.string"
local singletons = require "kong.singletons"
local pl_file = require "pl.file"
local json = require "cjson"
local openssl_digest = require "resty.openssl.digest"
local openssl_hmac = require "resty.openssl.hmac"
local openssl_pkey = require "resty.openssl.pkey"
local table_concat = table.concat
local encode_base64 = ngx.encode_base64
local env_private_key_location = os.getenv("KONG_SSL_CERT_KEY")
local env_public_key_location = os.getenv("KONG_SSL_CERT_DER")
local utils = require "kong.tools.utils"
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

--- Get the private key location either from the environment or from configuration
-- @param conf the kong configuration
-- @return the private key location
local function get_private_key_location(conf)
  if env_private_key_location then
    return env_private_key_location
  end
  return conf.private_key_location
end

--- Get the public key location either from the environment or from configuration
-- @param conf the kong configuration
-- @return the public key location
local function get_public_key_location(conf)
  if env_public_key_location then
    return env_public_key_location
  end
  return conf.public_key_location
end

--- base 64 encoding
-- @param input String to base64 encode
-- @return Base64 encoded string
local function b64_encode(input)
  local result = encode_base64(input) -- TODO: Set no padding?
  result = result:gsub("+", "-"):gsub("/", "_"):gsub("=", "") -- TODO: Do not omit "="?
  return result
end

--- Read contents of file from given location
-- @param file_location the file location
-- @return the file contents
local function read_from_file(file_location)
  local content, err = pl_file.read(file_location)
  if not content then
    ngx.log(ngx.ERR, "Could not read file contents", err)
    return nil, err
  end
  return content
end

--- Get the Kong key either from cache or the given `location`
-- @param key the cache key to lookup first
-- @param location the location of the key file
-- @return the key contents
local function get_kong_key(key, location)
  -- This will add a non expiring TTL on this cached value
  -- https://github.com/thibaultcha/lua-resty-mlcache/blob/master/README.md
  local pkey, err = singletons.cache:get(key, { ttl = 0 }, read_from_file, location)

  if err then
    ngx.log(ngx.ERR, "Could not retrieve pkey: ", err)
    return
  end

  return pkey
end

--- Base64 encode the JWT token
-- @param payload the payload of the token
-- @param key the key to sign the token with
-- @return the encoded JWT token
local function encode_jwt_token(conf, payload, key)
  local header = {
    typ = "JWT",
    alg = "RS256",
    x5c = {
      b64_encode(get_kong_key("pubder", get_public_key_location(conf)))
    }
  }
  if conf.key_id then
    header.kid = conf.key_id
  end
  local segments = {
    b64_encode(json.encode(header)),
    b64_encode(json.encode(payload))
  }
  local signing_input = table_concat(segments, ".")
  local digest = openssl_digest.new("sha256")
  assert(digest:update(signing_input))
  local signature = assert(openssl_pkey.new(key):sign(digest))
  -- local signature = openssl_pkey.new(key):sign(openssl_digest.new("sha256"):update(signing_input))
  segments[#segments+1] = b64_encode(signature)
  return table_concat(segments, ".")
end

--- Base64 encode the JWT token
-- @param payload the payload of the token
-- @param key the key to sign the token with
-- @return the encoded JWT token
-- The JWT is segmented into three distinct concatenated base64 strings. (i.e. header.payload.signature)
local function encode_jwt_token_hs256(payload, key)
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

--- Build the JWT token payload based off the `payload_hash`
-- @param conf the configuration
-- @param payload_hash the payload hash
-- @return the JWT payload (table)
local function build_jwt_payload(conf, payload_hash)
  local current_time = ngx.time() -- Much better performance improvement over os.time()
  local payload = {
    exp = current_time + 60,
    jti = utils.uuid(),
    payloadhash = payload_hash
  }

  if conf.issuer then
    payload.iat = current_time
    payload.iss = conf.issuer
  end

  if ngx.ctx.service then
    payload.aud = ngx.ctx.service.name
  end

  local consumer = kong.client.get_consumer()
  if consumer then
    payload.consumerid = consumer.id
    payload.consumername = consumer.username
  end

  return payload
end

--- Build the JWT token payload based off fields that are required by the backend
-- @return the payload to be used in encode_jwt_token
local function build_jwt_payload_hs256()
  local current_time = ngx.time() -- Much better performance improvement over os.time()
  local payload = {
    exp = current_time + 900,
    jti = utils.uuid(),
    iat = current_time
  }

  -- adds all field from request body into JWT payload
  local body, err, mimetype = kong.request.get_body()
  if body ~= nil then
    for key, value in pairs(body) do
      payload[key] = value
    end
  end

  -- adds all headers of request into JWT payload
  local headers, err, mimetype = kong.request.get_headers()
  if headers ~= nil then
    for key, value in pairs(headers) do
      payload[key] = value
    end
  end

  -- adds all required field (specified by BE) for JWT payload
  local device_id_header, err, mimetype = kong.request.get_header("x-device-id")
  if device_id_header ~= nil then
    payload["deviceId"] = device_id_header
  else
    payload["deviceId"] = "SYSTEM"
  end
  payload["loginScope"] = "prelogin" -- hardcoded to prelogin because this function will only be used in prelogin flow, other flows will use the add_existing_jwt_header_hs256 function
  payload["userRefId"] = "SYSTEM"
  payload["userId"] = "SYSTEM"
  payload["corporateRefId"] = "SYSTEM"
  payload["companyId"] = "SYSTEM"
  payload["mobileNo"] = "SYSTEM"

  return payload
end

--- Build the payload hash
-- @return SHA-256 hash of the request body data
local function build_payload_hash()
  ngx.req.read_body()
  local req_body  = ngx.req.get_body_data()
  local payload_digest = ""
  if req_body then
    local sha256 = resty_sha256:new()
    sha256:update(req_body)
    payload_digest = sha256:final()
  end
  return str.to_hex(payload_digest)
end

local function build_header_value(conf, jwt)
  if conf.include_credential_type then
    return "Bearer " .. jwt
  else
    return jwt
  end
end

--- Retrieve access token from FE's request Authorization Header
local function parse_access_token_hs265(conf)
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

--- Add the JWT header to the request
-- @param conf the configuration
local function add_jwt_header(conf)
  local payload_hash = build_payload_hash()
  local payload = build_jwt_payload(conf, payload_hash)
  local kong_private_key = get_kong_key("pkey", get_private_key_location(conf))
  local jwt = encode_jwt_token(conf, payload, kong_private_key)
  ngx.req.set_header(conf.header, build_header_value(conf, jwt))
end

-- Retrieve jwt secret of the current authenticated consumer
-- Store the jwt secret as credential to current request context data, to be used in custom-response-transformer
local function get_jwt_credential()
  local consumer = kong.client.get_consumer()
  local credential = load_credential(consumer.username)
  kong.ctx.shared.credential = credential

  return credential
end

--- Replaces the existing 'Authorization' header with a JWT unless specified in the configuration
-- @param conf specify header name
local function add_jwt_header_hs256(conf)

  local credential = get_jwt_credential()
  local payload = build_jwt_payload_hs256()

  local jwt = encode_jwt_token_hs256(payload, (credential.secret))
  ngx.req.set_header(conf.header, build_header_value(conf, jwt))
end

--- Appends JWT that was found in db using access_token to the header of request to be sent to BE
local function add_existing_jwt_header_hs256(conf)
  -- -- Retrieve jwt secret of the current authenticated consumer
  -- -- Store the jwt secret as credential to current request context data, to be used in custom-response-transformer
  -- local consumer = kong.client.get_consumer()
  -- kong.log("consumer: ", consumer)
  -- kong.log("consumer.username: ", consumer.username)

  -- local credential = load_credential(consumer.username)
  -- kong.ctx.shared.credential = credential
  -- kong.log("load_credential(consumer.username): ", load_credential(consumer.username))

  local access_token = parse_access_token_hs265(conf)
  local token_details = kong.db.oauth2_tokens:select_by_access_token(access_token)
  ngx.req.set_header(conf.header, build_header_value(conf, token_details.jwt))
end

--- Stores x-device-id received from FE's request header in temporary table to be used in custom response transformer when upserting data (access token) into db
local function save_device_id_from_header()
  -- FYI, Header names in are case-insensitive and are normalized to lowercase, and dashes (-) can be written as underscores (_); that is, the header X-Custom-Header can also be retrieved as x_custom_header.
  local device_id_header, err, mimetype = kong.request.get_header("x-device-id")
  if device_id_header ~= nil then
    kong.ctx.shared.device_id = device_id_header

  end
end

--- Stores device_id in temporary table to be used in custom response transformer when upserting data (access token) into db, device_id is found using access_token from FE
local function save_device_id_from_table(conf)
  local access_token = parse_access_token_hs265(conf)
  local token_details = kong.db.oauth2_tokens:select_by_access_token(access_token)
  kong.ctx.shared.device_id = token_details.device_id
end

--- Execute the script
-- @param conf kong configuration
function _M.execute(conf)
  add_jwt_header(conf)
end

function _M.execute_hs256(conf)
  save_device_id_from_header(conf)
  add_jwt_header_hs256(conf)  
end

function _M.add_existing_jwt_hs256(conf)
  save_device_id_from_table(conf) -- make sure this function executes before appending jwt in request's auth header because it requires access token from request coming from FE
  add_existing_jwt_header_hs256(conf)  
end

function _M.execute_get_jwt_credential()
  get_jwt_credential()  
end

return _M
