package = "custom-response-transformer"
version = "1.0-6"
source = {
   url = ""
}
description = {
  summary = "Transforms the upstream response and consolidates FE response into a JWT",
}
dependencies = {}
build = {
  type = "builtin",
  modules = {
    ["kong.plugins.custom-response-transformer.body_transformer"] = "src/body_transformer.lua",
    ["kong.plugins.custom-response-transformer.handler"] = "src/handler.lua",
    ["kong.plugins.custom-response-transformer.header_transformer"] = "src/header_transformer.lua",
    ["kong.plugins.custom-response-transformer.schema"] = "src/schema.lua"
  }
}
