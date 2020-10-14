return {
    postgres = {
      up = [[
        DO $$
        BEGIN
          ALTER TABLE IF EXISTS ONLY "sessions" ADD "access_token" TEXT UNIQUE,
                                                ADD "userRefId" TEXT UNIQUE,
                                                ADD "corporateRefId" TEXT UNIQUE;
        EXCEPTION WHEN DUPLICATE_COLUMN THEN
          -- Do nothing, accept existing state
        END$$;
  
      ]],
    },
    cassandra = {
      up = [[
        ALTER TABLE oauth2_tokens ADD jwt set<text>;
      ]],
    }
  }
  