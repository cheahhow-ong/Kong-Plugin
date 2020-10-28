package = "custom-oauth2"
version = "1.0-5"
source = {
   url = ""
}
description = {
  summary = "Custom OAuth2 plugin"
}
dependencies = {}
build = {
  type = "builtin",
  modules = {
    ["kong.plugins.custom-oauth2.daos.oauth2_tokens"] = "src/daos/oauth2_tokens.lua",
    ["kong.plugins.custom-oauth2.migrations.init"] = "src/migrations/init.lua",
    ["kong.plugins.custom-oauth2.migrations.000_base_custom_oauth2"] = "src/migrations/000_base_custom_oauth2.lua",
    ["kong.plugins.custom-oauth2.migrations.001_100_to_110"] = "src/migrations/001_100_to_110.lua",
    ["kong.plugins.custom-oauth2.migrations.002_110_to_120"] = "src/migrations/002_110_to_120.lua",
    ["kong.plugins.custom-oauth2.migrations.003_120_to_130"] = "src/migrations/003_120_to_130.lua",
    ["kong.plugins.custom-oauth2.access"] = "src/access.lua",
    ["kong.plugins.custom-oauth2.daos"] = "src/daos.lua",
    ["kong.plugins.custom-oauth2.error"] = "src/error.lua",
    ["kong.plugins.custom-oauth2.handler"] = "src/handler.lua",
    ["kong.plugins.custom-oauth2.schema"] = "src/schema.lua"
	}
}

