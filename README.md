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
