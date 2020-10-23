return {
    postgres = {
      up = [[ 
        DO $$
        BEGIN
          ALTER TABLE IF EXISTS ONLY "oauth2_tokens" ADD "device_id" TEXT;
        EXCEPTION WHEN DUPLICATE_COLUMN THEN
          -- Do nothing, accept existing state
        END$$;
  
      ]],
    },
    cassandra = {
      up = [[
        ALTER TABLE oauth2_tokens ADD device_id set<text>;
      ]],
    }
  }
  