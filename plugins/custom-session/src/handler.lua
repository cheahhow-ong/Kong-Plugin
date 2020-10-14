local access = require "kong.plugins.custom-session.access"
local body_filter = require "kong.plugins.custom-session.body_filter"
-- local header_filter = require "kong.plugins.session.header_filter"

local KongSessionHandler = {
  PRIORITY = 800,
  VERSION  = "2.4.2",
}

function KongSessionHandler.body_filter(_, conf)
  local kong = kong
  local string_find = string.find
  local path = kong.request.get_path()
  local grant_flow = string_find(path, "/v1/password/grant", nil, true)

  if grant_flow then
    body_filter.execute(conf)
  else
    return
  end
end

function KongSessionHandler.access(_, conf)
  local kong = kong
  local string_find = string.find
  local path = kong.request.get_path()
  local grant_flow = string_find(path, "/v1/password/grant", nil, true)

  if grant_flow then
    return
  else
    access.execute(conf)
  end
end

-- function KongSessionHandler.header_filter(_, conf)
--   header_filter.execute(conf)
-- end

-- function KongSessionHandler.access(_, conf)
--   access.execute(conf)
-- end

-- function KongSessionHandler.body_filter(_, conf)
--   body_filter.execute(conf)
-- end


return KongSessionHandler
