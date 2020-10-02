local BasePlugin = require "kong.plugins.base_plugin"
local access = require "kong.plugins.custom-upstream-jwt.access"
local string_find = string.find
local kong = kong

local CustomUpstreamJWTHandler = BasePlugin:extend()

CustomUpstreamJWTHandler.PRIORITY = 899 -- This plugin needs to run after auth plugins so it has access to `ngx.ctx.authenticated_consumer`
CustomUpstreamJWTHandler.VERSION = "1.0.3"

function CustomUpstreamJWTHandler:new()
  CustomUpstreamJWTHandler.super.new(self, "custom-upstream-jwt")
end

function CustomUpstreamJWTHandler:access(conf)
  CustomUpstreamJWTHandler.super.access(self)

  local path = kong.request.get_path()

  -- If request path matches one of the 'grant' routes, a new empty JWT will be provisioned
  -- Else, an existing JWT tied to the access token will be loaded
  local from = string_find(path, "/v1/auth/prelogin/grant", nil, true)
          or string_find(path, "/v1/auth/pin/grant", nil, true)
          or string_find(path, "/v1/auth/biometric/grant", nil, true)
  if from then
    access.execute(conf)
  else
    access.add_existing_jwt(conf)
  end
end

return CustomUpstreamJWTHandler
