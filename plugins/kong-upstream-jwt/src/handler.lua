local BasePlugin = require "kong.plugins.base_plugin"
local access = require "kong.plugins.kong-upstream-jwt.access"
local luasql = require "luasql.postgres"

-- Extend Base Plugin and instantiate with a name of "kong-upstream-jwt"
-- Ref: https://docs.konghq.com/latest/plugin-development/custom-logic/#handlerlua-specifications
local KongUpstreamJWTHandler = BasePlugin:extend()
function KongUpstreamJWTHandler:new()
  KongUpstreamJWTHandler.super.new(self, "upstream-jwt")
end

function KongUpstreamJWTHandler:access(conf)
  KongUpstreamJWTHandler.super.access(self)

  -- If request path matches one of the routes, a new empty JWT will be provisioned
  -- Else, an existing JWT tied to the access token will be loaded
  local path = kong.request.get_path()
  local string_find = string.find
  local prelogin = string_find(path, "/v1/prelogin/grant", nil, true)
  local activationPassword = string_find(path, "/v1/activation/password/grant", nil, true)
  local pin = string_find(path, "/v1/pin/grant", nil, true)
  local biometric = string_find(path, "/v1/biometric/grant", nil, true)
  local password = string_find(path, "/v1/password/grant", nil, true)

  if prelogin then
    access.execute_get_jwt_credential()
    access.execute_hs256(conf)
  elseif activationPassword or pin or biometric or password then
    access.execute_get_jwt_credential()
    access.add_existing_jwt_hs256(conf)
  else
    access.add_existing_jwt_hs256(conf)
  end

end

KongUpstreamJWTHandler.PRIORITY = 899 -- This plugin needs to run after auth plugins so it has access to `ngx.ctx.authenticated_consumer`, and needs to run after rate limiting
KongUpstreamJWTHandler.VERSION = "1.2"

return KongUpstreamJWTHandler
