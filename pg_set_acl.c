/*-------------------------------------------------------------------------
 *  
 * pg_set_acl is a PostgreSQL extension which allows to define 
 * an access control list for the SET command 
 *  
 * This program is open source, licensed under the PostgreSQL license.
 * For license terms, see the LICENSE file.
 *          
 * Copyright (c) 2022 Pierre Forstmann.
 *            
 *-------------------------------------------------------------------------
*/
#include "postgres.h"
#include "parser/analyze.h"
#include "nodes/nodes.h"
#include "storage/proc.h"
#include "access/xact.h"

#include "tcop/tcopprot.h"
#include "tcop/utility.h"
#include "utils/guc.h"
#include "utils/snapmgr.h"
#include "utils/memutils.h"
#if PG_VERSION_NUM <= 90600
#include "storage/lwlock.h"
#endif
#if PG_VERSION_NUM < 120000 
#include "access/transam.h"
#endif
#include "utils/varlena.h"
#include "utils/hsearch.h"

#include "utils/queryenvironment.h"
#include "tcop/cmdtag.h"

#include "nodes/nodes.h"

#include "storage/ipc.h"
#include "storage/spin.h"
#include "miscadmin.h"
#include "storage/procarray.h"
#include "executor/executor.h"
#include "catalog/objectaccess.h"
#include "utils/catcache.h"
#include "utils/syscache.h"
#include "catalog/pg_proc.h"
#include "executor/spi.h"
#include "miscadmin.h"
#include "utils/builtins.h"

PG_MODULE_MAGIC;

/* Saved hook values in case of unload */
static ProcessUtility_hook_type prev_process_utility_hook = NULL;

static bool pgsa_enabled = true;

/*---- Function declarations ----*/

void		_PG_init(void);
void		_PG_fini(void);

static void pgsa_exec(
#if PG_VERSION_NUM < 100000
		      Node *parsetree,
#else
		      PlannedStmt *pstmt,
#endif
		      const char *queryString,
#if PG_VERSION_NUM >= 140000
                      bool readOnlyTree,
#endif
		      ProcessUtilityContext context,
		      ParamListInfo params,
#if PG_VERSION_NUM > 100000
	              QueryEnvironment *queryEnv,
#endif
		      DestReceiver *dest,
#if PG_VERSION_NUM < 130000
                      char *CompletionTag
#else
	              QueryCompletion *qc
#endif
);

PG_FUNCTION_INFO_V1(pgsa_grant);
PG_FUNCTION_INFO_V1(pgsa_revoke);
PG_FUNCTION_INFO_V1(pgsa_read_acl);

static bool pgsa_check_priv(char *parameter_name, char *user_name);

/*
 * Module load callback
 */
void
_PG_init(void)
{

	elog(LOG, "pg_set_acl:_PG_init(): entry");

	/*
 	 * Install hooks
	 */

	if (pgsa_enabled == true)
	{
		prev_process_utility_hook = ProcessUtility_hook;
 		ProcessUtility_hook = pgsa_exec;	

		elog(LOG, "pg_set_acl:_PG_init(): pg_set_acl is enabled");
	}

	if (pgsa_enabled == false)
	{
		elog(LOG, "pg_set_acl:_PG_init(): pg_set_acl is disabled");
	}
	elog(LOG, "pg_set_acl:_PG_init(): exit");
}


/*
 *  Module unload callback
 */
void
_PG_fini(void)
{
	elog(LOG, "pg_set_acl: _PG_fini(): entry");

	/* Uninstall hooks. */
	ProcessUtility_hook = prev_process_utility_hook;

	elog(LOG, "pg_set_acl: _PG_fini(): exit");
}

static void
pgsa_exec(
#if PG_VERSION_NUM < 100000
	  Node *parsetree,
#else
	  PlannedStmt *pstmt,
#endif
	  const char *queryString,
#if PG_VERSION_NUM >= 140000
	  bool readOnlyTree,
#endif
	  ProcessUtilityContext context,
	  ParamListInfo params,
#if PG_VERSION_NUM > 100000
	  QueryEnvironment *queryEnv,
#endif
	  DestReceiver *dest,
#if PG_VERSION_NUM < 130000
	  char *CompletionTag)
#else
	  QueryCompletion *qc)
#endif

{
#if PG_VERSION_NUM > 100000
	Node	   	*parsetree;
#endif
	VariableSetStmt	*setstmt;

	elog(DEBUG1, "pg_set_acl: pgsa_exec: entry");
#if PG_VERSION_NUM > 100000
	parsetree = pstmt->utilityStmt;
#endif

	if (nodeTag(parsetree) == T_VariableSetStmt)
	{
		setstmt = (VariableSetStmt *)parsetree;
		if (setstmt->kind == VAR_SET_VALUE || setstmt->kind == VAR_SET_CURRENT)
		{
			bool priv_exists;

			elog(DEBUG1, "pg_set_acl pgsa_exec: setstmt->name=%s", setstmt->name);

			SPI_connect();
			priv_exists = pgsa_check_priv(setstmt->name, GetUserNameFromId(GetUserId(), false));
		        if (priv_exists == false)
		                elog(ERROR, "pg_set_acl: permission denied for (%s,%s)",
					    setstmt->name, 
					    GetUserNameFromId(GetUserId(), false));
			SPI_finish();

		}
	}


	/*
 	 * see src/backend/tcop/utility.c
 	 */

	if (prev_process_utility_hook)

                (*prev_process_utility_hook) (
#if PG_VERSION_NUM < 100000
						  parsetree,
#else
						  pstmt, 
#endif
						  queryString,
#if PG_VERSION_NUM >= 140000
						  readOnlyTree,
#endif
						  context, 
						  params,
#if PG_VERSION_NUM > 100000
						  queryEnv,
#endif
					   	  dest, 
#if PG_VERSION_NUM < 130000
						  CompletionTag);
#else
                                                  qc);
#endif
	else	standard_ProcessUtility(
#if PG_VERSION_NUM < 100000
					parsetree,
#else
					pstmt, 
#endif
					queryString,
#if PG_VERSION_NUM >= 140000
					readOnlyTree,
#endif
				       	context,
					params, 
#if PG_VERSION_NUM > 100000
					queryEnv,
#endif
					dest, 
#if PG_VERSION_NUM < 130000
					CompletionTag);
#else
                                        qc);
#endif

	elog(DEBUG1, "pg_set_acl: pgsa_exec: exit");
}

static bool pgsa_check_setting(char *parameter_name)
{
	StringInfoData 	buf_select_parameter;
	int ret_code;

	initStringInfo(&buf_select_parameter);
	appendStringInfo(&buf_select_parameter, "SELECT name FROM pg_settings WHERE name = '%s' ", parameter_name);

	ret_code = SPI_execute(buf_select_parameter.data, false, 0);
	if (ret_code != SPI_OK_SELECT)
		elog(ERROR, "SELECT FROM pg_settings failed");
	if (SPI_processed != 1)
		elog(ERROR, "Cannot find setting %s", parameter_name);
	return true;

}

static bool pgsa_check_user(char *user_name)
{
	StringInfoData 	buf_select_user;
	int ret_code;

	initStringInfo(&buf_select_user);
	appendStringInfo(&buf_select_user, "SELECT rolname FROM pg_authid WHERE rolname = '%s' and rolcanlogin = true", user_name);

	ret_code = SPI_execute(buf_select_user.data, false, 0);
	if (ret_code != SPI_OK_SELECT)
		elog(ERROR, "SELECT FROM pg_authid failed");
	if (SPI_processed != 1)
		elog(ERROR, "Cannot find user %s", user_name);
	return true;
}

static bool pgsa_check_priv(char *parameter_name, char *user_name)
{
	StringInfoData 	buf_select_acl;
	int ret_code;

	initStringInfo(&buf_select_acl);
	appendStringInfo(&buf_select_acl, "SELECT parameter_name, user_name FROM set_acl.privs WHERE parameter_name = '%s' and user_name = '%s'", 
			                  parameter_name,
					  user_name);
	ret_code = SPI_execute(buf_select_acl.data, false, 0);
	if (ret_code != SPI_OK_SELECT)
		elog(ERROR, "SELECT FROM set_acl.privs failed");
	if (SPI_processed == 0)
		return false;
	else if (SPI_processed == 1)
		return true;
	else
		elog(ERROR, "SELECT FROM set_acl.privs returned more than 1 row");

}

static bool pgsa_grant_internal(char *parameter_name, char *user_name)
{
	StringInfoData 	buf_insert;
	int	ret_code;	
	bool	priv_exists;


	initStringInfo(&buf_insert);
	appendStringInfo(&buf_insert, "INSERT INTO set_acl.privs(parameter_name, user_name)");
	appendStringInfo(&buf_insert, " VALUES('%s','%s')", parameter_name, user_name);

	SPI_connect();

	pgsa_check_setting(parameter_name);
	pgsa_check_user(user_name);
	priv_exists = pgsa_check_priv(parameter_name, user_name);	

	if (priv_exists == true)
		elog(ERROR, "ACL already exist for (%s,%s)", parameter_name, user_name);

	ret_code = SPI_execute(buf_insert.data, false, 0);
	if (ret_code != SPI_OK_INSERT)
		elog(ERROR, "INSERT failed: %d", ret_code);			
	SPI_finish();

	return true;

}

Datum pgsa_grant(PG_FUNCTION_ARGS)
{
	char *parameter_name;
	char *user_name;

	parameter_name = PG_GETARG_CSTRING(0);
        user_name = PG_GETARG_CSTRING(1);
        return (pgsa_grant_internal(parameter_name, user_name));
}



static bool pgsa_revoke_internal(char *parameter_name, char *user_name)
{
        StringInfoData  buf_delete;
        int     ret_code;
	bool	priv_exists;

        initStringInfo(&buf_delete);
        appendStringInfo(&buf_delete, "DELETE FROM set_acl.privs WHERE parameter_name='%s' and user_name='%s'", parameter_name, user_name);

        SPI_connect();

	pgsa_check_setting(parameter_name);
	pgsa_check_user(user_name);
	priv_exists = pgsa_check_priv(parameter_name, user_name);
        if (priv_exists == false)
                elog(ERROR, "Cannot find ACL for (%s,%s)", parameter_name, user_name);


        ret_code = SPI_execute(buf_delete.data, false, 0);
        if (ret_code != SPI_OK_DELETE)
                elog(ERROR, "DELETE failed: %d", ret_code);
        SPI_finish();

        return true;

}



Datum pgsa_revoke(PG_FUNCTION_ARGS)
{
	char *parameter_name;
	char *user_name;

	parameter_name = PG_GETARG_CSTRING(0);
        user_name = PG_GETARG_CSTRING(1);
        return (pgsa_revoke_internal(parameter_name, user_name));
}




static bool pgsa_read_acl_internal(char *parameter_name, char *user_name)
{

	StringInfoData buf_select_acl;
	Oid argtypes[2] = { TEXTOID, TEXTOID };
	SPIPlanPtr plan_ptr;
	Datum values[2];
	int ret_code;

        initStringInfo(&buf_select_acl);
        appendStringInfo(&buf_select_acl, "SELECT parameter_name, user_name FROM set_acl.privs WHERE parameter_name = $1 and user_name = $2");

        SPI_connect();

        plan_ptr = SPI_prepare(buf_select_acl.data, 2, argtypes);
	values[0] = CStringGetTextDatum(parameter_name);
	values[1] = CStringGetTextDatum(user_name);
	ret_code = SPI_execute_plan(plan_ptr, values, NULL, false, 0);
        if (ret_code != SPI_OK_SELECT)
                  elog(ERROR, "SELECT FROM set_acl.privs failed");
        if (SPI_processed == 0)
                elog(INFO, "pg_set_acl: acl not found for (%s,%s)", parameter_name, user_name);
        if (SPI_processed == 1)
                elog(INFO,  "pg_set_acl: acl found for (%s,%s)", parameter_name, user_name);

        SPI_finish();
	return true;
}

Datum pgsa_read_acl(PG_FUNCTION_ARGS)
{
        char *parameter_name;
        char *user_name;

        parameter_name = PG_GETARG_CSTRING(0);
        user_name = PG_GETARG_CSTRING(1);
        return (pgsa_read_acl_internal(parameter_name, user_name));
}

