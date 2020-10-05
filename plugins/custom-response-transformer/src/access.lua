local _M = {}

-- from https://github.com/Kong/kong/blob/master/kong/plugins/jwt/jwt_parser.lua
local function load_credential(jwt_secret_key)
  local row, err = kong.db.jwt_secrets:select_by_key(jwt_secret_key)
  if err then
    return nil, err
  end
  return row
end

-- Retrieve jwt secret of the current authenticated consumer
-- Store the jwt secret as credential to current request context data, to be used in later life-cycle of custom-response-transformer ie: body-filter phase
local function store_credentials()
    local consumer = kong.client.get_consumer()
    local credential = load_credential(consumer.username)
    kong.ctx.shared.credential = credential

end

function _M.execute()
    store_credentials()
end

return _M