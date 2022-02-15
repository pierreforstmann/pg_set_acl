#
# Makefile
# 
MODULES = pg_set_acl
EXTENSION = pg_set_acl  # the extension's name
DATA = pg_set_acl--0.0.1.sql    # script file to install


REGRESS_OPTS = --temp-instance=/tmp/5454 --port=5454 --temp-config pg_set_acl.conf
REGRESS=test0 

# for posgres build
PG_CONFIG = pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
