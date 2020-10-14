local access = require "kong.plugins.session.access"
local body_filter = require "kong.plugins.session.body_filter"
-- local header_filter = require "kong.plugins.session.header_filter"
local kong = kong
local string_find = string.find

local path = kong.request.get_path()
local grant_flow = string_find(path, "/v1/password/grant", nil, true)

local KongSessionHandler = {
  PRIORITY = 800,
  VERSION  = "2.4.2",
}

if grant_flow then
  function KongSessionHandler.body_filter(_, conf)
    body_filter.execute(conf)
  end
else
  function KongSessionHandler.access(_, conf)
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
