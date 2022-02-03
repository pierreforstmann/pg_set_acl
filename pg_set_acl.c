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

PG_MODULE_MAGIC;

/* Saved hook values in case of unload */
static ProcessUtility_hook_type prev_process_utility_hook = NULL;
static object_access_hook_type prev_object_access_hook = NULL;

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

static void pgsa_object_access_hook(ObjectAccessType access,
				    Oid classId,
				    Oid objectId,
				    int subId,
				    void *arg);

PG_FUNCTION_INFO_V1(pgsa_grant);
PG_FUNCTION_INFO_V1(pgsa_revoke);

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

		prev_object_access_hook = object_access_hook;
		object_access_hook = pgsa_object_access_hook;

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
	object_access_hook = prev_object_access_hook;

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
			StringInfoData buf_select_acl;
			int ret_code;

			elog(DEBUG1, "pg_set_acl pgsa_exec: setstmt->name=%s", setstmt->name);
			initStringInfo(&buf_select_acl);
                        appendStringInfo(&buf_select_acl, "SELECT parameter_name, user_name FROM pg_set_acl WHERE parameter_name = '%s' and user_name = '%s'",
                                         setstmt->name ,
                                         GetUserNameFromId(GetUserId(), false));
			SPI_connect();
			ret_code = SPI_execute(buf_select_acl.data, false, 0);
		        if (ret_code != SPI_OK_SELECT)
                		elog(ERROR, "SELECT FROM pg_set_acl failed");
		        if (SPI_processed == 0)
		                elog(ERROR, "pg_set_actl: permission denied for (%s,%s)",
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

static void
pgsa_object_access_hook(ObjectAccessType access,
		        Oid classId,
			Oid objectId,
			int subId,
			void *arg)
{
	CatCList   *catlist;
	Oid	functionOid = 0;
	int	i;

	/*
	 * retrieve OID of set_config function
	 */
	catlist = SearchSysCacheList1(PROCNAMEARGSNSP, CStringGetDatum("set_config"));	
	for (i = 0; i < catlist->n_members; i++)
	{
		HeapTuple       proctup = &catlist->members[i]->tuple;
		Form_pg_proc 	procform = (Form_pg_proc) GETSTRUCT(proctup);

		functionOid = procform->oid;
	}
	ReleaseSysCacheList(catlist);

	if ( i == 0 )
		elog(FATAL, "pg_set_acl: function set_config not found");
	if ( i > 1 )
		elog(WARNING, "pg_set_acl: found %d functions set_config", i);



	/*
	 * set_config oid = 2078
	 */
	if (superuser() == false && access == OAT_FUNCTION_EXECUTE && objectId == functionOid)
		elog(ERROR, "pg_set_acl: execution permission denied for set_config. ");

}

static bool pgsa_grant_internal(char *parameter_name, char *user_name)
{
	StringInfoData 	buf_insert;
	StringInfoData 	buf_select_parameter;
	StringInfoData 	buf_select_user;
	StringInfoData 	buf_select_acl;
	int	ret_code;

	initStringInfo(&buf_select_parameter);
	appendStringInfo(&buf_select_parameter, "SELECT name FROM pg_settings WHERE name = '%s' ", parameter_name);

	initStringInfo(&buf_select_user);
	appendStringInfo(&buf_select_user, "SELECT rolname FROM pg_authid WHERE rolname = '%s' and rolcanlogin = true", user_name);

	initStringInfo(&buf_select_acl);
	appendStringInfo(&buf_select_acl, "SELECT parameter_name, user_name FROM pg_set_acl WHERE parameter_name = '%s' and user_name = '%s'", 
			                  parameter_name,
					  user_name);

	initStringInfo(&buf_insert);
	appendStringInfo(&buf_insert, "INSERT INTO pg_set_acl(parameter_name, user_name)");
	appendStringInfo(&buf_insert, " VALUES('%s','%s')", parameter_name, user_name);

	SPI_connect();

	ret_code = SPI_execute(buf_select_parameter.data, false, 0);
	if (ret_code != SPI_OK_SELECT)
		elog(ERROR, "SELECT FROM pg_settings failed");
	if (SPI_processed != 1)
		elog(ERROR, "Cannot find setting %s", parameter_name);

	ret_code = SPI_execute(buf_select_user.data, false, 0);
	if (ret_code != SPI_OK_SELECT)
		elog(ERROR, "SELECT FROM pg_authid failed");
	if (SPI_processed != 1)
		elog(ERROR, "Cannot find user %s", user_name);

	ret_code = SPI_execute(buf_select_acl.data, false, 0);
	if (ret_code != SPI_OK_SELECT)
		elog(ERROR, "SELECT FROM pg_set_acl failed");
	if (SPI_processed != 0)
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
        StringInfoData  buf_select_parameter;
        StringInfoData  buf_select_user;
        StringInfoData  buf_select_acl;
        int     ret_code;

        initStringInfo(&buf_select_parameter);
        appendStringInfo(&buf_select_parameter, "SELECT name FROM pg_settings WHERE name = '%s' ", parameter_name);

        initStringInfo(&buf_select_user);
        appendStringInfo(&buf_select_user, "SELECT rolname FROM pg_authid WHERE rolname = '%s' and rolcanlogin = true", user_name);

        initStringInfo(&buf_select_acl);
        appendStringInfo(&buf_select_acl, "SELECT parameter_name, user_name FROM pg_set_acl WHERE parameter_name = '%s' and user_name = '%s'", 
                                          parameter_name,
                                          user_name);

        initStringInfo(&buf_delete);
        appendStringInfo(&buf_delete, "DELETE FROM pg_set_acl WHERE parameter_name='%s' and user_name='%s'", parameter_name, user_name);

        SPI_connect();

        ret_code = SPI_execute(buf_select_parameter.data, false, 0); 
        if (ret_code != SPI_OK_SELECT)
                elog(ERROR, "SELECT FROM pg_settings failed");
        if (SPI_processed != 1)
                elog(ERROR, "Cannot find setting %s", parameter_name);

        ret_code = SPI_execute(buf_select_user.data, false, 0);
        if (ret_code != SPI_OK_SELECT)
                elog(ERROR, "SELECT FROM pg_authid failed");
        if (SPI_processed != 1)
                elog(ERROR, "Cannot find user %s", user_name);

        ret_code = SPI_execute(buf_select_acl.data, false, 0);
        if (ret_code != SPI_OK_SELECT)
                elog(ERROR, "SELECT FROM pg_set_acl failed");
        if (SPI_processed != 1)
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
