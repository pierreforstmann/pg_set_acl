# pg_set_acl
PostgreSQL extension that implements a SET command access control list.
# Installation

## Compiling

This module can be built using the standard PGXS infrastructure. For this to work, the `pg_config` program must be available in your $PATH:

```
git clone https://github.com/pierreforstmann/pg_set_acl.git
cd pg_set_acl
make
make install
```

This extension has been validated with PostgreSQL 10, 11, 12, 13 and 14.

## PostgreSQL setup

Extension should be loaded at server level with `shared_preload_libraries` parameter:
```
shared_preload_libraries='pg_set_acl'
```
Extension must be created in each database with:
```
create extension pg_set_acl;
```

# Usage

`pg_set_acl` has no specific GUC setting.
Note that installing `pg_set_acl` removes execution privilege on `set_config` function from PUBLIC.

`pg_set_acl` checks that all SET commands are in the access control list materialized by `set_acl.privs` table (for all users who are not superusers):

```
 \d set_acl.privs;
                   Table "set_acl.privs"
     Column     | Type | Collation | Nullable |   Default   
----------------+------+-----------+----------+-------------
 privilege      | text |           |          | 'SET'::text
 parameter_name | text |           | not null | 
 user_name      | text |           | not null | 

# 
```
If this table is empty, only superusers can use the SET command. In other words, user must have been explicitly granted privilege to  use SET command with a given setting using `set_acl.grant` function:
```
select set_acl.grant(setting, user);
```
To revoke privilege to use SET command with a given setting use:
```
select set_acl.revoke(setting, user);
```
Only superusers can execute `set_acl.grant` and `set_acl.revoke`.

# Example
```
testdb=# \c testdb postgres
You are now connected to database "testdb" as user "postgres".
testdb=# create extension pg_set_acl;
CREATE EXTENSION
testdb=# \c testdb testuser;
You are now connected to database "testdb" as user "testuser".
testdb=> select * from set_acl.privs;
 privilege | parameter_name | user_name 
-----------+----------------+-----------
(0 rows)

testdb=> set work_mem='1GB';
ERROR:  pg_set_acl: permission denied for (work_mem,testuser)
testdb=> \c testdb postgres
You are now connected to database "testdb" as user "postgres".
testdb=# select set_acl.grant('work_mem','testuser');
 grant 
-------
 t
(1 row)

testdb=# \c testdb testuser;
You are now connected to database "testdb" as user "testuser".
testdb=> select * from set_acl.privs;
 privilege | parameter_name | user_name 
-----------+----------------+-----------
 SET       | work_mem       | testuser
(1 row)

testdb=> set work_mem='1GB';
SET
testdb=> show work_mem;
 work_mem 
----------
 1GB
(1 row)

testdb=> 
```
