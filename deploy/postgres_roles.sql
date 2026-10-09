-- Run as the database administrator. Set each LOGIN password with psql's
-- interactive \password command; no sample/default password is installed.
DO $$
DECLARE role_name text;
BEGIN
  FOREACH role_name IN ARRAY ARRAY['fk_collector','fk_runtime','fk_projector','fk_agent','fk_reviewer','fk_graph','fk_knowledge'] LOOP
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname=role_name) THEN
      EXECUTE format('CREATE ROLE %I LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT', role_name);
    END IF;
  END LOOP;
END $$;
