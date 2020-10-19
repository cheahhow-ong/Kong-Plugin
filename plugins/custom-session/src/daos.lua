local typedefs = require "kong.db.schema.typedefs"

return {
  sessions = {
    primary_key = { "id" },
    name = "sessions",
    cache_key = { "session_id" },
    ttl = true,
    fields = {
      { id = typedefs.uuid },
      { session_id = { type = "string", unique = true, required = true } },
      { expires = { type = "integer" } },
      { data = { type = "string" } },
      { access_token = { type = "string", unique = true, required = true  } },
      { user_ref_id = { type = "string", unique = true, required = true  } },
      { corporate_ref_id = { type = "string", unique = true, required = true  } },
      { created_at = typedefs.auto_timestamp_s },
    }
  }
}
