drop extension if exists pg_set_acl;
--
create extension pg_set_acl;
--
create user test;
--
select pgsa_grant('work_mem','test');
select * from pg_set_acl;
select pgsa_revoke('work_mem','test');
--
drop extension pg_set_acl;
