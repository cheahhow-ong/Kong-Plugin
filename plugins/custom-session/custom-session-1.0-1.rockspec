package = "custom-session"
version = "1.0-1"
source = {
   url = ""
}
description = {
  summary = "Custom Session plugin"
}
dependencies = {}
build = {
  type = "builtin",
  modules = {
    ["kong.plugins.custom-session.handler"] = "src/handler.lua",
    ["kong.plugins.custom-session.access"] = "src/access.lua",
    ["kong.plugins.custom-session.daos"] = "src/daos.lua",
    ["kong.plugins.custom-session.body_filter"] = "src/body_filter.lua",
    ["kong.plugins.custom-session.header_filter"] = "src/header_filter.lua",
    ["kong.plugins.custom-session.schema"] = "src/schema.lua",
    ["kong.plugins.custom-session.session"] = "src/session.lua",
    ["kong.plugins.custom-session.storage.kong"] = "src/storage/kong.lua",
    ["kong.plugins.custom-session.migrations.000_base_custom_session"] = "src/migrations/000_base_custom_session.lua",
    ["kong.plugins.custom-session.migrations.init"] = "src/migrations/init.lua"
	}
}
