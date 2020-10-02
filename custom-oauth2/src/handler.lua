local access = require "kong.plugins.custom-oauth2.access"
local kong = kong

local OAuthHandler = {}

--- kong.ctx.shared.foo tables are used in response-transformer-custom when values are being upserted in body_trasnformer.lua
-- make sure oauth2-token-generator's
function OAuthHandler:access(conf)
    kong.ctx.shared.token_expiration = conf.token_expiration
    kong.ctx.shared.refresh_token_ttl = conf.refresh_token_ttl
    access.execute(conf)
end

OAuthHandler.PRIORITY = 1000 -- Higher than upstream-jwt (999), lower than basic-auth (1001)
OAuthHandler.VERSION = "1.0.5"

return OAuthHandler