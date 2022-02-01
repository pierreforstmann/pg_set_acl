--
-- pg_set_acl.sql
--
DROP TABLE IF EXISTS pg_set_acl;
DROP FUNCTION IF EXISTS pgsa_grant;
--
CREATE TABLE public.pg_set_acl
(
	privilege	text default 'SET',
	parameter_name	text not null,
	user_name	text not null
);
--
GRANT SELECT on pg_set_acl to PUBLIC;
--
CREATE FUNCTION pgsa_grant(cstring, cstring) RETURNS bool
 AS 'pg_set_acl.so', 'pgsa_grant'
 LANGUAGE C STRICT;
--
