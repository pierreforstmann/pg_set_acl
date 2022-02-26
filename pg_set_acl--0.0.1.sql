--
-- pg_set_acl.sql
--
DROP SCHEMA IF EXISTS set_acl CASCADE;
--
CREATE SCHEMA set_acl;
--
CREATE TABLE set_acl.privs
(
	privilege	text default 'SET',
	parameter_name	text not null,
	user_name	text not null
);
--
GRANT USAGE ON SCHEMA set_acl TO PUBLIC;
GRANT SELECT ON set_acl.privs TO PUBLIC;
REVOKE EXECUTE ON FUNCTION set_config FROM PUBLIC;
--
CREATE FUNCTION set_acl.grant(cstring, cstring) RETURNS bool
 AS 'pg_set_acl.so', 'pgsa_grant'
 LANGUAGE C STRICT;
--
CREATE FUNCTION set_acl.revoke(cstring, cstring) RETURNS bool
 AS 'pg_set_acl.so', 'pgsa_revoke'
 LANGUAGE C STRICT;
--
CREATE FUNCTION set_acl.read_acl(cstring, cstring) RETURNS bool
 AS 'pg_set_acl.so', 'pgsa_read_acl'
 LANGUAGE C STRICT;
--
