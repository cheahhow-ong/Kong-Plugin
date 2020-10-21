local cjson = require("cjson.safe").new()

local find = string.find
local lower = string.lower
local kong = kong

local openssl_hmac = require "resty.openssl.hmac"
local table_concat = table.concat
local encode_base64 = ngx.encode_base64
local utils = require "kong.tools.utils"

local luasql = require "luasql.postgres"

cjson.decode_array_with_array_mt(true)

local _M = {}


-- TODO: Update scope table
local scope = {
  ["30017"] = "registration",
  ["30018"] = "tnc",
  ["30090"] = "resetpin",
  ["30253"] = "mnp",
  ["30254"] = "ekyc",
  ["30255"] = "mnp_ekyc"
}

local unwanted_fields = {
  ["x-kong-proxy-latency"] = "x-kong-proxy-latenc",
  ["date"] = "date",
  ["transfer-encoding"] = "transfer-encoding",
  ["via"] = "via",
  ["content-type"] = "content-type",
  ["connection"] = "connection",
  ["x-kong-upstream-latency"] = "x-kong-upstream-latency",
}


local alg_sign = {
  HS256 = function(data, key) return openssl_hmac.new(key, "sha256"):final(data) end,
  HS384 = function(data, key) return openssl_hmac.new(key, "sha384"):final(data) end,
  HS512 = function(data, key) return openssl_hmac.new(key, "sha512"):final(data) end
}

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
local function encode_jwt_token_hs256(payload, key)
  local header = {
    typ = "JWT",
    alg = "HS256"
  }
  local segments = {
    b64_encode(cjson.encode(header)),
    b64_encode(cjson.encode(payload))
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
local function build_jwt_payload(response_body, headers)
  local current_time = ngx.time() -- Much better performance improvement over os.time()
  local payload = {
    exp = current_time + 900,
    jti = utils.uuid(),
    iat = current_time,
    -- channelId = "NB", -- TODO: Explain what is "NB"
    -- language = headers["Accept-Language"],
    -- clientVersion = headers["X-Client-Version"],
    -- deviceId = headers["X-Device-ID"]
  }

  if response_body ~= nil then
    for key, value in pairs(response_body) do
      if key == "userRefId" then
        payload["userRefId"] = value
      else
        payload[key] = value
      end
    end
  end

  if headers ~= nil then
    for key, value in pairs(headers) do
      payload[key] = value
    end

    for key, _ in pairs(unwanted_fields) do
      payload[key] = nil
    end
  end
  -- for key, value in pairs(response_body) do
    -- if key == "additionalInfo" then
    --   for key, value  in pairs(value) do
    --     payload[key] = value
    --   end
    -- end
    -- if key == "scope" and value ~= nil then
    --   payload["loginScope"] = value
    -- end
    -- if key ~= "additionalInfo" and key ~= "scope" and value ~= nil then
    --   payload[key] = value
    -- end
    -- if payload["loginScope"] ~= "prelogin" then
    --   for key, _ in pairs(unwanted_fields) do
    --     payload[key] = nil
    --   end
    -- end
    -- -- TODO: Check whether this logic is required
    -- if payload["loginScope"] == "pin" then
    --   payload["language"] = "en-TH" -- is needed in the pin grant flow
    -- end    
  -- end
  return payload
end

--- Add the JWT header to the request
-- @param conf the configuration
-- Grab the value of secret from the shared kong.ctx.plugin.credential table
local function add_jwt_body_hs256(response_body, key, headers)
  local payload = build_jwt_payload(response_body, headers)
  return encode_jwt_token_hs256(payload, key)
end

local function read_json_body(body)
  if body then
    return cjson.decode(body)
  end
end

local function delete_old_oauth2_token(body)
  kong.log.inspect("userRefId: ", body.userRefId)
  kong.log.inspect("scope: ", body.scope)

  ngx.timer.at(0, function(premature)
    local scope = "prelogin"
    local authenticated_userid = "random"
    -- sql query to delete by body.userrefid and body.scope
    local env = assert (luasql.postgres())
    local con = assert (env:connect("kong", "kong", "password"))
    local query = "DELETE from oauth2_tokens WHERE scope = '" .. scope .. "' AND authenticated_userid = '" .. authenticated_userid .. "';"
    local cur = assert (con:execute(query))

    -- close everything
    cur:close()
    con:close()
    env:close()
  end)
end

local function upsert_oauth2_token(body)
  local token = {}
  local credential = {}

  for key,value in pairs(kong.ctx.shared.token) do
    token[key] = value
  end

  for key, value in pairs(kong.ctx.shared.token.credential) do
    credential.id = value
  end

  if body.additionalInfo then
    for key, value in pairs (body.additionalInfo) do
      body[key] = value
    end
  end

  ngx.timer.at(0, function(premature)
    local token, err = kong.db.oauth2_tokens:upsert({
      id = token.id
    },{
      service = token.service_id and { id = token.service_id } or nil,
      access_token = token.access_token,
      credential = { id = credential.id },
      authenticated_userid = body.userRefId,
      expires_in = token.expires_in,
      refresh_token = token.refresh_token,
      scope = body.scope,
      jwt = body.jwt
    },{
      -- Access tokens (and their associated refresh token) are being
      -- permanently deleted after 'refresh_token_ttl' seconds
      ttl = token.expires_in > 0 and token.ttl or nil
    })
  end)
end


function _M.is_json_body(content_type)
  return content_type and find(lower(content_type), "application/json", nil, true)
end

--- 'scope[json_body["code"]]' essentially determines whether the value of the 'code' field is contained within the 'scope' table.
-- If so, the relevant scope will be added into the json_body. 
function _M.transform_json_body(buffered_data, credential, headers)
  -- frontend_responses will be populated with relevant values i.e: scope & jwt
  local frontend_response = {}

  local json_body = read_json_body(buffered_data)

  kong.ctx.shared.backend_response = json_body
  local path = kong.request.get_path()
  local prelogin = find(path, "/v1/prelogin/grant", nil, true)
  local pin = find(path, "/v1/pin/grant", nil, true)
  local biometric = find(path, "/v1/biometric/grant", nil, true)
  local password = find(path, "/v1/password/grant", nil, true)
  
  if json_body == nil then
    return
  end

  if json_body["code"] and scope[json_body["code"]]then
    json_body["scope"] = scope[json_body["code"]]
    json_body["jwt"] = add_jwt_body_hs256(json_body, credential.secret, headers)

    frontend_response["scope"] = json_body["scope"]
    frontend_response["jwt"] = json_body["jwt"]
  end

  if not json_body["code"] and kong.service.response.get_status() == 200 then
    if prelogin then
      json_body["scope"] = "prelogin"
    elseif pin then
      json_body["scope"] = "pin"
    elseif biometric then
      json_body["scope"] = "biometric"
    elseif password then
      json_body["scope"] = "password"
    end

    json_body["jwt"] = add_jwt_body_hs256(json_body, credential.secret, headers)

    frontend_response["scope"] = json_body["scope"]
    frontend_response["jwt"] = json_body["jwt"]
  end

  -- Delete old token based on the scope and userRefId before upserting into the access token generated during this session
  if not prelogin then
    delete_old_oauth2_token(json_body)
  end
  
  -- based on the logic, once json_body completes its checks, this function will be called to upsert the scope & jwt values into the db.
  upsert_oauth2_token(json_body)
  
  -- frontend_responses is populated with other necesssary values taken from custom-oauth2 to be returned to the frontend
  for key, value in pairs(kong.ctx.shared.frontend_response) do
    frontend_response[key] = value
  end

  return cjson.encode(frontend_response)
end


return _M