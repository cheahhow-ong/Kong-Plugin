local body_transformer = require "kong.plugins.custom-response-transformer.body_transformer"
local header_transformer = require "kong.plugins.custom-response-transformer.header_transformer"

local is_json_body = header_transformer.is_json_body
local concat = table.concat
local kong = kong
local ngx = ngx


local ResponseTransformerHandler = {}

function ResponseTransformerHandler:access()
  kong.service.request.enable_buffering()
  kong.ctx.plugin.headers = kong.request.get_headers()
end

function ResponseTransformerHandler:header_filter(conf)
  header_transformer.transform_headers(conf, kong.response.get_headers())

  --[[ TODO: Check if this logic still applies
  local prelogin = string.find(kong.request.get_path(), "/v1/auth/prelogin/grant", nil, true)
  if prelogin then
    local body = kong.service.response.get_body()
    if (kong.response.get_status()==409 and body["code"]~="30020") then
        kong.response.set_status(200)
    end
  end --]]
end

--- As kong.db is inaccessible in the body filter phase, kong.ctx.shared.credential which was indexed in kong-upstream-jwt is use to pass in the credential
function ResponseTransformerHandler:body_filter()

  local path = kong.request.get_path()
  local first_time_path = string.find(path, "/v1/first-time/mobile/password/grant", nil, true)
  local biometric_path = string.find(path, "/v1/biometric/grant", nil, true)
  local password_path = string.find(path, "/v1/password/grant", nil, true)
  local pin_path = string.find(path, "/v1/pin/grant", nil, true)
  
  
  local grant_type = kong.request.get_query_arg("grant_type")
  local refresh_token = kong.request.get_query_arg("refresh_token")
  
  -- if prelogin_path or login_path or biometric_path then
  --   local body = body_transformer.transform_json_body(chunks, kong.ctx.shared.credential, kong.ctx.plugin.headers)
  --   -- local body = kong.service.response.get_body()
  --   kong.log("body: ", body)
  --   kong.log("body.isVerified: ", body.isVerified)
  --   kong.log("body.userRefNo: ", body.userRefNo)
  -- end

  -- If BE returns an error it will immediately be displayed to the FE and this segment of code will not execute.
  -- Reason refresh token flow is NOT allowed in this if block is because refresh token flow only generates new access token, 
  -- it does not need to go through the body_transformer function, all neccessary information is saved in the db, 
  -- by selecting refresh token from db, it can retrieve all info as seen in custom-oauth2 access.lua line 551,
  -- then, all that's left for kong to do is insert those necessary info and send back to FE, as seen in custom-oauth2 access.lua line 579
  if is_json_body(kong.response.get_header("Content-Type"))
    and kong.response.get_status() == 200
    and not ((first_time_path or biometric_path or password_path or pin_path) and grant_type == "refresh_token" and refresh_token) then
  
  -- if kong.response.get_status() == 200 then

    local ctx = ngx.ctx
    local chunk, eof = ngx.arg[1], ngx.arg[2]

    ctx.rt_body_chunks = ctx.rt_body_chunks or {}
    ctx.rt_body_chunk_number = ctx.rt_body_chunk_number or 1

    if eof then
      local chunks = concat(ctx.rt_body_chunks)
      local body = body_transformer.transform_json_body(chunks, kong.ctx.shared.credential, kong.ctx.plugin.headers)
      ngx.arg[1] = body or chunks

    else
      ctx.rt_body_chunks[ctx.rt_body_chunk_number] = chunk
      ctx.rt_body_chunk_number = ctx.rt_body_chunk_number + 1
      ngx.arg[1] = nil
    end
  end
end

function ResponseTransformerHandler:log()
end

ResponseTransformerHandler.PRIORITY = 802 -- Original was 800. Need to be larger than request-transformer (801) to store all request headers before being modified/removed.
ResponseTransformerHandler.VERSION = "1.0.6"


return ResponseTransformerHandler