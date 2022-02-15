--
create user postgres superuser;
--
\c contrib_regression postgres
drop extension if exists pg_set_acl;
--
create extension pg_set_acl;
--
select pgsa_grant('s','u');
select pgsa_grant('work_mem','u');
--
create user test;
--
\c contrib_regression test
set work_mem='1GB';
--
\c contrib_regression postgres 
select pgsa_grant('work_mem','test');
select * from pg_set_acl;
--
\c contrib_regression test
set work_mem='1GB';
show work_mem;
--
\c contrib_regression postgres
select pgsa_revoke('work_mem','test');
--
\c contrib_regression test
set work_mem='1GB';
--
\c contrib_regression postgres
drop extension pg_set_acl;
--

