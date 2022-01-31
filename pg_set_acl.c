/*-------------------------------------------------------------------------
 *  
 * pg_set_acl is a PostgreSQL extension which allows to define 
 * an access control list for the SET command 
 *  
 * This program is open source, licensed under the PostgreSQL license.
 * For license terms, see the LICENSE file.
 *          
 * Copyright (c) 2020, 2021, 2022 Pierre Forstmann.
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

			elog(DEBUG1, "pg_set_acl pgsa_exec: setstmt->name=%s", setstmt->name);
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
