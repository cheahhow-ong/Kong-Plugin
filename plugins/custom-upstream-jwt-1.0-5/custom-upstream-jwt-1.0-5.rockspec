package = "custom-upstream-jwt"
version = "1.0-5"
source = {
   url = ""
}
description = {
   summary = "Replaces the 'Authorization' header with a JWT containing relevant fields to be passed to the backend"
}
dependencies = {}
build = {
   type = "builtin",
   modules = {
      ["kong.plugins.custom-upstream-jwt.access"] = "src/access.lua",
      ["kong.plugins.custom-upstream-jwt.handler"]  = "src/handler.lua",
      ["kong.plugins.custom-upstream-jwt.schema"]= "src/schema.lua"
   }
}