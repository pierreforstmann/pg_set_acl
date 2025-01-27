--
create user postgres superuser;
--
\c contrib_regression postgres
drop extension if exists pg_set_acl;
--
create extension pg_set_acl;
--
set search_path='set_acl';
--
set search_path='"$user", public';
--
select set_acl.grant('s','u');
select set_acl.grant('work_mem','u');
--
create user test;
--
\c contrib_regression test
set work_mem='1GB';
reset work_mem;
reset all;
--
\c contrib_regression postgres 
select set_acl.grant('work_mem','test');
select * from set_acl.privs;
--
\c contrib_regression test
set work_mem='1GB';
show work_mem;
select set_config('work_mem', '500MB', false);
show work_mem;
reset work_mem;
show work_mem;
reset all;
--
\c contrib_regression postgres
select set_acl.revoke('work_mem','test');
--
\c contrib_regression test
set work_mem='1GB';
select set_config('work_mem', '500MB', false);
show work_mem;
reset work_mem;
reset all;
--
\c contrib_regression postgres
drop extension pg_set_acl;
--

