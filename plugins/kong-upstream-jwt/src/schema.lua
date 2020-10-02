-- © Optum 2020
local typedefs = require "kong.db.schema.typedefs"

return {
  name = "upstream-jwt",
  fields = {
    -- TODO: To find out why commented out
    -- { protocols = typedefs.protocols_http },
    { config = {
        type = "record",
        fields = {
          -- 'issuer', 'private_key_location', 'public_key_location', and 'key_id' are not required for HS256
          { issuer = { type = "string", required = false }, },
          { private_key_location = { type = "string", required = false }, },
          { public_key_location = { type = "string", required = false }, },
          { key_id = { type = "string", required = false}, },
          { header = { type = "string", default = "JWT"}, },
          { include_credential_type = { type = "boolean", default = false}, },
          }, }, },
    },
 }
