return {
  postgres = {
    up = [[
      DO $$
      BEGIN
        ALTER TABLE IF EXISTS ONLY "oauth2_tokens" ADD "is_valid" BOOLEAN NOT NULL DEFAULT TRUE;
      EXCEPTION WHEN DUPLICATE_COLUMN THEN
        -- Do nothing, accept existing state
      END$$;

    ]],
  },
  cassandra = {
    up = [[
      ALTER TABLE oauth2_tokens ADD is_valid set<text>;
    ]],
  }
}
