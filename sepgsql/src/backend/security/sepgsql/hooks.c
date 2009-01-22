/*
 * src/backend/security/sepgsql/hooks.c
 *	  implementations of PGACE framework
 *
 * Portions Copyright (c) 1996-2008, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 */
#include "postgres.h"

#include "access/heapam.h"
#include "access/genam.h"
#include "access/skey.h"
#include "catalog/indexing.h"
#include "catalog/pg_aggregate.h"
#include "catalog/pg_database.h"
#include "catalog/pg_largeobject.h"
#include "catalog/pg_proc.h"
#include "catalog/pg_security.h"
#include "miscadmin.h"
#include "nodes/makefuncs.h"
#include "security/pgace.h"
#include "utils/fmgroids.h"
#include "utils/syscache.h"
#include "utils/tqual.h"
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

/*******************************************************************************
 * Extended SQL statement hooks
 *******************************************************************************/
bool
sepgsqlIsGramSecurityItem(DefElem *defel)
{
	Assert(IsA(defel, DefElem));

	if (defel->defname &&
		strcmp(defel->defname, SecurityLabelAttributeName) == 0)
		return true;

	return false;
}

static void
putExplicitContext(HeapTuple tuple, DefElem *defel)
{
	if (defel)
	{
		Oid sid  = pgaceSecurityLabelToSid(strVal(defel->arg));

		HeapTupleSetSecLabel(tuple, sid);
	}
}

void
sepgsqlGramCreateRelation(Relation rel, HeapTuple tuple, DefElem *defel)
{
	putExplicitContext(tuple, defel);
}

void
sepgsqlGramCreateAttribute(Relation rel, HeapTuple tuple, DefElem *defel)
{
	putExplicitContext(tuple, defel);
}

void
sepgsqlGramAlterRelation(Relation rel, HeapTuple tuple, DefElem *defel)
{
	putExplicitContext(tuple, defel);
}

void
sepgsqlGramAlterAttribute(Relation rel, HeapTuple tuple, DefElem *defel)
{
	putExplicitContext(tuple, defel);
}

void
sepgsqlGramCreateDatabase(Relation rel, HeapTuple tuple, DefElem *defel)
{
	putExplicitContext(tuple, defel);
}

void
sepgsqlGramAlterDatabase(Relation rel, HeapTuple tuple, DefElem *defel)
{
	putExplicitContext(tuple, defel);
}

void
sepgsqlGramCreateFunction(Relation rel, HeapTuple tuple, DefElem *defel)
{
	putExplicitContext(tuple, defel);
}

void
sepgsqlGramAlterFunction(Relation rel, HeapTuple tuple, DefElem *defel)
{
	putExplicitContext(tuple, defel);
}

/*******************************************************************************
 * DATABASE object related hooks
 *******************************************************************************/

void
sepgsqlGetDatabaseParam(const char *name)
{
	HeapTuple	tuple;
	const char *audit_name;

	tuple = SearchSysCache(DATABASEOID,
						   ObjectIdGetDatum(MyDatabaseId), 0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "SELinux: cache lookup failed for database %u",
			 MyDatabaseId);

	audit_name = sepgsqlTupleName(DatabaseRelationId, tuple);
	sepgsqlClientHasPermission(HeapTupleGetSecLabel(tuple),
							   SECCLASS_DB_DATABASE,
							   DB_DATABASE__GET_PARAM,
							   audit_name);
	ReleaseSysCache(tuple);
}

void
sepgsqlSetDatabaseParam(const char *name, char *argstring)
{
	HeapTuple	tuple;
	const char *audit_name;

	tuple = SearchSysCache(DATABASEOID,
						   ObjectIdGetDatum(MyDatabaseId), 0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "SELinux: cache lookup failed for database %u",
			 MyDatabaseId);

	audit_name = sepgsqlTupleName(DatabaseRelationId, tuple);
	sepgsqlClientHasPermission(HeapTupleGetSecLabel(tuple),
							   SECCLASS_DB_DATABASE,
							   DB_DATABASE__SET_PARAM,
							   audit_name);
	ReleaseSysCache(tuple);
}

/*******************************************************************************
 * RELATION(Table)/ATTRIBTUE(column) object related hooks
 *******************************************************************************/
void
sepgsqlLockTable(Oid relid)
{
	HeapTuple	tuple;

	tuple = SearchSysCache(RELOID,
						   ObjectIdGetDatum(relid),
						   0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "SELinux: cache lookup failed for relation %u", relid);

	if (((Form_pg_class) GETSTRUCT(tuple))->relkind == RELKIND_RELATION)
	{
		const char *audit_name
			= sepgsqlTupleName(RelationRelationId, tuple);
		sepgsqlClientHasPermission(HeapTupleGetSecLabel(tuple),
								   SECCLASS_DB_TABLE,
								   DB_TABLE__LOCK,
								   audit_name);
	}
	ReleaseSysCache(tuple);
}

void
sepgsqlExecTruncate(List *trunc_rels)
{
	ListCell *l;

	foreach (l, trunc_rels)
	{
		const char *audit_name;
		HeapTuple tuple;
		HeapScanDesc scan;
		Relation rel = (Relation) lfirst(l);

		if (RelationGetForm(rel)->relkind != RELKIND_RELATION)
			continue;

		/*
		 * check db_table:{delete}
		 */
		tuple = SearchSysCache(RELOID,
							   ObjectIdGetDatum(RelationGetRelid(rel)),
							   0, 0, 0);
		if (!HeapTupleIsValid(tuple))
			elog(ERROR, "SELinux: cache lookup failed for relation %u",
				 RelationGetRelid(rel));

		audit_name = sepgsqlTupleName(RelationRelationId, tuple);
		sepgsqlClientHasPermission(HeapTupleGetSecLabel(tuple),
								   SECCLASS_DB_TABLE,
								   DB_TABLE__DELETE,
								   audit_name);
		ReleaseSysCache(tuple);

		/*
		 * check db_tuple:{delete}
		 */
		scan = heap_beginscan(rel, SnapshotNow, 0, NULL);

		while ((tuple = heap_getnext(scan, ForwardScanDirection)) != NULL)
		{
			sepgsqlCheckTuplePerms(rel, tuple, NULL,
								   SEPGSQL_PERMS_DELETE, true);
		}
		heap_endscan(scan);
	}
}

/*******************************************************************************
 * PROCEDURE related hooks
 *******************************************************************************/

typedef struct
{
	PGFunction			fn_addr;
	security_context_t	fn_con;
} sepgsql_fn_info;

static Datum
invokeTrustedProcedure(PG_FUNCTION_ARGS)
{
	sepgsql_fn_info *sefinfo = fcinfo->flinfo->fn_pgaceItem;
	security_context_t orig_context;
	Datum		retval;

	/*
	 * set new domain
	 */
	orig_context = sepgsqlSwitchClientContext(sefinfo->fn_con);

	PG_TRY();
	{
		retval = sefinfo->fn_addr(fcinfo);
	}
	PG_CATCH();
	{
		sepgsqlSwitchClientContext(orig_context);
		PG_RE_THROW();
	}
	PG_END_TRY();
	sepgsqlSwitchClientContext(orig_context);

	return retval;
}

void
sepgsqlCallFunction(FmgrInfo *finfo)
{
	MemoryContext		oldctx;
	HeapTuple			tuple;
	security_context_t	newcon;
	access_vector_t		perms = DB_PROCEDURE__EXECUTE;
	const char		   *audit_name;

	if (IsBootstrapProcessingMode())
		return;		/* under initialization of pg_proc */

	tuple = SearchSysCache(PROCOID,
						   ObjectIdGetDatum(finfo->fn_oid),
						   0, 0, 0);
	Assert(HeapTupleIsValid(tuple));
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "SELinux: cache lookup failed for procedure %u", finfo->fn_oid);

	oldctx = MemoryContextSwitchTo(finfo->fn_mcxt);
	/*
	 * check trusted procedure
	 */
	newcon = sepgsqlClientCreateContext(HeapTupleGetSecLabel(tuple),
										SECCLASS_PROCESS);
	if (strcmp(newcon, sepgsqlGetClientContext()) != 0)
	{
		sepgsql_fn_info *sefinfo
			= palloc0(sizeof(sepgsql_fn_info));

		sefinfo->fn_addr = finfo->fn_addr;
		sefinfo->fn_con = newcon;
		finfo->fn_addr = invokeTrustedProcedure;
		finfo->fn_pgaceItem = sefinfo;

		perms |= DB_PROCEDURE__ENTRYPOINT;
	}
	else
		pfree(newcon);

	MemoryContextSwitchTo(oldctx);

	audit_name = sepgsqlTupleName(ProcedureRelationId, tuple);
	sepgsqlClientHasPermission(HeapTupleGetSecLabel(tuple),
							   SECCLASS_DB_PROCEDURE,
							   perms,
							   audit_name);
	ReleaseSysCache(tuple);
}

void
sepgsqlCallAggFunction(HeapTuple aggTuple)
{
	Form_pg_aggregate aggForm
		= (Form_pg_aggregate) GETSTRUCT(aggTuple);
	HeapTuple tuple;
	const char *audit_name;

	/* check pg_proc.oid = pg_aggregate.aggfnoid */
	tuple = SearchSysCache(PROCOID,
						   ObjectIdGetDatum(aggForm->aggfnoid),
						   0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "SELinux: cache lookup failed for procedure %u",
			 aggForm->aggfnoid);

	audit_name = sepgsqlTupleName(ProcedureRelationId, tuple);
	sepgsqlClientHasPermission(HeapTupleGetSecLabel(tuple),
							   SECCLASS_DB_PROCEDURE,
							   DB_PROCEDURE__EXECUTE,
							   audit_name);
	ReleaseSysCache(tuple);
}

bool
sepgsqlCallTriggerFunction(TriggerData *tgdata)
{
	Relation	rel = tgdata->tg_relation;
	HeapTuple	newtup = NULL;
	HeapTuple	oldtup = NULL;

	/*
	 * We don't need to check tuple permissions for
	 * statement triggers
	 */
	if (TRIGGER_FIRED_FOR_STATEMENT(tgdata->tg_event))
		return true;

	if (TRIGGER_FIRED_BY_INSERT(tgdata->tg_event))
	{
		if (TRIGGER_FIRED_AFTER(tgdata->tg_event))
			newtup = tgdata->tg_trigtuple;
	}
	else if (TRIGGER_FIRED_BY_UPDATE(tgdata->tg_event))
	{
		oldtup = tgdata->tg_trigtuple;
		if (TRIGGER_FIRED_AFTER(tgdata->tg_event))
		{
			Oid securityId = HeapTupleGetSecLabel(tgdata->tg_newtuple);

			if (HeapTupleGetSecLabel(oldtup) != securityId)
				newtup = tgdata->tg_newtuple;
		}
	}
	else if (TRIGGER_FIRED_BY_DELETE(tgdata->tg_event))
	{
		if (TRIGGER_FIRED_AFTER(tgdata->tg_event))
			oldtup = tgdata->tg_trigtuple;
	}
	else
	{
		elog(ERROR, "SELinux: unexpected trigger event type (%u)",
			 tgdata->tg_event);
	}
	if (oldtup && !sepgsqlCheckTuplePerms(rel, oldtup, NULL,
										  SEPGSQL_PERMS_SELECT, false))
		return false;
	if (newtup && !sepgsqlCheckTuplePerms(rel, newtup, NULL,
										  SEPGSQL_PERMS_SELECT, false))
		return false;

	return true;
}

bool sepgsqlAllowFunctionInlined(Oid fnoid, HeapTuple func_tuple)
{
	security_context_t	newcon;
	const char *audit_name;

	/*
	 * If function is defined as trusted procedure, we always should
	 * not allow it to be inlined, and actual permission checks are
	 * done later phase.
	 */
	newcon = sepgsqlClientCreateContext(HeapTupleGetSecLabel(func_tuple),
										SECCLASS_PROCESS);
	if (strcmp(newcon, sepgsqlGetClientContext()) != 0)
		return false;

	audit_name = sepgsqlTupleName(ProcedureRelationId, func_tuple);
	sepgsqlClientHasPermission(HeapTupleGetSecLabel(func_tuple),
							   SECCLASS_DB_PROCEDURE,
							   DB_PROCEDURE__EXECUTE,
							   audit_name);
	return true;
}

/*******************************************************************************
 * LOAD shared library module hook
 *******************************************************************************/
void
sepgsqlLoadSharedModule(const char *filename)
{
	security_context_t filecon;

	if (getfilecon_raw(filename, &filecon) < 0)
		ereport(ERROR,
				(errcode_for_file_access(),
				 errmsg("could not access file \"%s\": %m", filename)));
	PG_TRY();
	{
		sepgsqlComputePermission(sepgsqlGetDatabaseContext(),
								 filecon,
								 SECCLASS_DB_DATABASE,
								 DB_DATABASE__LOAD_MODULE,
								 filename);
	}
	PG_CATCH();
	{
		freecon(filecon);
		PG_RE_THROW();
	}
	PG_END_TRY();
	freecon(filecon);
}

/*******************************************************************************
 * Binary Large Object hooks
 *******************************************************************************/

void
sepgsqlLargeObjectCreate(Relation rel, HeapTuple tuple)
{
	const char *audit_name;

	sepgsqlSetDefaultContext(rel, tuple);

	audit_name = sepgsqlTupleName(LargeObjectRelationId, tuple);
	sepgsqlClientHasPermission(HeapTupleGetSecLabel(tuple),
							   SECCLASS_DB_BLOB,
							   DB_BLOB__CREATE,
							   audit_name);
}

void
sepgsqlLargeObjectDrop(Relation rel, HeapTuple tuple, void **pgaceItem)
{
	Oid			security_id = HeapTupleGetSecLabel(tuple);
	List	   *okList = (List *) (*pgaceItem);
	ListCell   *l;
	const char *audit_name;

	foreach (l, okList)
	{
		if (security_id == lfirst_oid(l))
			return;		/* already allowed */
	}

	audit_name = sepgsqlTupleName(LargeObjectRelationId, tuple);
	sepgsqlClientHasPermission(security_id,
							   SECCLASS_DB_BLOB,
							   DB_BLOB__DROP,
							   audit_name);

	*pgaceItem = lappend_oid(okList, security_id);
}

static void
checkLargeObjectPages(Oid loid, Snapshot snapshot,
					  int32 start_pageno, int32 end_pageno,
					  access_vector_t perms)
{
	Relation		rel;
	HeapTuple		tuple;
	SysScanDesc		sd;
	ScanKeyData		skey[2];
	List		   *okList = NIL;

	rel = heap_open(LargeObjectRelationId, AccessShareLock);

	ScanKeyInit(&skey[0],
				Anum_pg_largeobject_loid,
				BTEqualStrategyNumber, F_OIDEQ,
				ObjectIdGetDatum(loid));

	if (start_pageno <= 0)
		sd = systable_beginscan(rel, LargeObjectLOidPNIndexId,
								true, snapshot, 1, skey);
	else
	{
		ScanKeyInit(&skey[1],
					Anum_pg_largeobject_pageno,
					BTGreaterEqualStrategyNumber, F_INT4GE,
					Int32GetDatum(start_pageno));

		sd = systable_beginscan(rel, LargeObjectLOidPNIndexId,
								true, snapshot, 2, skey);
	}

	while ((tuple = systable_getnext(sd)) != NULL)
	{
		Form_pg_largeobject loForm
			= (Form_pg_largeobject) GETSTRUCT(tuple);
		Oid			security_id;
		ListCell	*l;
		const char  *audit_name;

		if (end_pageno >= 0 && loForm->pageno > end_pageno)
			break;

		security_id = HeapTupleGetSecLabel(tuple);

		foreach (l, okList)
		{
			if (security_id == lfirst_oid(l))
				goto skip;
		}
		okList = lappend_oid(okList, security_id);

		audit_name = sepgsqlTupleName(LargeObjectRelationId, tuple);
		sepgsqlClientHasPermission(security_id,
								   SECCLASS_DB_BLOB,
								   perms,
								   audit_name);
	skip:
		;
	}
	systable_endscan(sd);

	list_free(okList);

	heap_close(rel, NoLock);
}

void
sepgsqlLargeObjectRead(LargeObjectDesc *lodesc, int32 length)
{
	int32 start_pageno	= lodesc->offset / LOBLKSIZE;
	int32 end_pageno	= (lodesc->offset + length + LOBLKSIZE - 1) / LOBLKSIZE;

	checkLargeObjectPages(lodesc->id, lodesc->snapshot,
						  start_pageno, end_pageno, DB_BLOB__READ);
}

void
sepgsqlLargeObjectWrite(LargeObjectDesc *lodesc, int32 length)
{
	int32 start_pageno	= lodesc->offset / LOBLKSIZE;
	int32 end_pageno	= (lodesc->offset + length + LOBLKSIZE - 1) / LOBLKSIZE;

	checkLargeObjectPages(lodesc->id, lodesc->snapshot,
						  start_pageno, end_pageno, DB_BLOB__WRITE);
}

void
sepgsqlLargeObjectTruncate(LargeObjectDesc *lodesc, int32 offset)
{
	int32 start_pageno	= lodesc->offset / LOBLKSIZE;

	checkLargeObjectPages(lodesc->id, lodesc->snapshot,
						  start_pageno, -1, DB_BLOB__WRITE);
}

void
sepgsqlLargeObjectImport(Oid loid, int fdesc, const char *filename)
{
	security_context_t	tcontext;
	security_class_t tclass
		= sepgsqlFileObjectClass(fdesc, filename);

	if (fgetfilecon_raw(fdesc, &tcontext) < 0)
		ereport(ERROR,
				(errcode_for_file_access(),
				 errmsg("could not get security context \"%s\": %m", filename)));
	PG_TRY();
	{
		sepgsqlComputePermission(sepgsqlGetClientContext(),
								 tcontext,
								 tclass,
								 FILE__READ,
								 filename);
	}
	PG_CATCH();
	{
		freecon(tcontext);
		PG_RE_THROW();
	}
	PG_END_TRY();
	freecon(tcontext);

	checkLargeObjectPages(loid, SnapshotNow, -1, -1,
						  DB_BLOB__WRITE | DB_BLOB__IMPORT);
}

void
sepgsqlLargeObjectExport(Oid loid, int fdesc, const char *filename)
{
	security_context_t	tcontext;
	security_class_t tclass
		= sepgsqlFileObjectClass(fdesc, filename);

	if (fgetfilecon_raw(fdesc, &tcontext) < 0)
		ereport(ERROR,
				(errcode_for_file_access(),
				 errmsg("could not security context \"%s\": %m", filename)));
	PG_TRY();
	{
		sepgsqlComputePermission(sepgsqlGetClientContext(),
								 tcontext,
								 tclass,
								 FILE__WRITE,
								 filename);
	}
	PG_CATCH();
	{
		freecon(tcontext);
		PG_RE_THROW();
	}
	PG_END_TRY();
	freecon(tcontext);

	checkLargeObjectPages(loid, SnapshotNow, -1, -1,
						  DB_BLOB__READ | DB_BLOB__EXPORT);
}

void
sepgsqlLargeObjectGetSecurity(Relation rel, HeapTuple tuple)
{
	const char *audit_name
		= sepgsqlTupleName(LargeObjectRelationId, tuple);

	sepgsqlClientHasPermission(HeapTupleGetSecLabel(tuple),
							   SECCLASS_DB_BLOB,
							   DB_BLOB__GETATTR,
							   audit_name);
}

void
sepgsqlLargeObjectSetSecurity(Relation rel, HeapTuple newtup, HeapTuple oldtup)
{
	const char *audit_name;

	if (HeapTupleGetSecLabel(newtup) == HeapTupleGetSecLabel(oldtup))
		return;

	audit_name = sepgsqlTupleName(LargeObjectRelationId, oldtup);
	sepgsqlClientHasPermission(HeapTupleGetSecLabel(oldtup),
							   SECCLASS_DB_BLOB,
							   DB_BLOB__SETATTR | DB_BLOB__RELABELFROM,
							   audit_name);
	/*
	 * check db_blob:{setattr relabelto}
	 */
	audit_name = sepgsqlTupleName(LargeObjectRelationId, newtup);
	sepgsqlClientHasPermission(HeapTupleGetSecLabel(newtup),
							   SECCLASS_DB_BLOB,
							   DB_BLOB__RELABELTO,
							   audit_name);
}

/*******************************************************************************
 * ExecScan hooks
 *******************************************************************************/
static bool abort_on_violated_tuple = false;

bool
sepgsqlExecScan(Scan *scan, Relation rel, TupleTableSlot *slot)
{
	HeapTuple	tuple;
	uint32		perms = (scan->pgaceTuplePerms & SEPGSQL_PERMS_MASK);

	if (perms == 0)
		return true;

	tuple = ExecMaterializeSlot(slot);

	return sepgsqlCheckTuplePerms(rel, tuple, NULL, perms,
								  abort_on_violated_tuple);
}

/* ----------------------------------------------------------
 * special cases for Foreign Key constraint
 * ---------------------------------------------------------- */
Datum
sepgsqlBeginPerformCheckFK(Relation rel, bool is_primary, Oid save_userid)
{
	Datum save_pgace = BoolGetDatum(abort_on_violated_tuple);

	/*
	 * NOTE: when a tuple is inserted/updated on FK relation, all we should
	 * do is simply filtering violated tuples on PK relation, as normal
	 * row-level access controls doing.
	 * At the result, INSERT/UPDATE with invisible tuple will be failed.
	 */
	if (is_primary)
		abort_on_violated_tuple = true;

	return save_pgace;
}

void
sepgsqlEndPerformCheckFK(Relation rel, Datum save_pgace)
{
	abort_on_violated_tuple = DatumGetBool(save_pgace);
}

/*******************************************************************************
 * security_label hooks
 *******************************************************************************/
bool
sepgsqlTupleDescHasSecLabel(Relation rel, List *relopts)
{
	/*
	 * Newly created table via SELECT INTO/CREATE TABLE AS
	 */
	if (rel == NULL)
		return sepostgresql_row_level;

	if (RelationGetForm(rel)->relkind != RELKIND_RELATION &&
		RelationGetForm(rel)->relkind != RELKIND_SEQUENCE)
		return false;

	if (RelationGetRelid(rel) == DatabaseRelationId ||
		RelationGetRelid(rel) == RelationRelationId ||
		RelationGetRelid(rel) == AttributeRelationId ||
		RelationGetRelid(rel) == ProcedureRelationId ||
		RelationGetRelid(rel) == LargeObjectRelationId)
		return true;

	return sepostgresql_row_level;
}

char *
sepgsqlTranslateSecurityLabelIn(const char *context)
{
	security_context_t i_context;
	char	   *result;

	if (selinux_trans_to_raw_context((security_context_t) context, &i_context) < 0)
		ereport(ERROR,
				(errcode(ERRCODE_SELINUX_ERROR),
				 errmsg("SELinux: could not translate mls label")));
	PG_TRY();
	{
		result = pstrdup(i_context);
	}
	PG_CATCH();
	{
		freecon(i_context);
		PG_RE_THROW();
	}
	PG_END_TRY();
	freecon(i_context);

	return result;
}

char *
sepgsqlTranslateSecurityLabelOut(const char *context)
{
	security_context_t o_context;
	char	   *result;

	if (selinux_raw_to_trans_context((security_context_t) context, &o_context) < 0)
		ereport(ERROR,
				(errcode(ERRCODE_SELINUX_ERROR),
				 errmsg("SELinux: could not translate mls label")));
	PG_TRY();
	{
		result = pstrdup(o_context);
	}
	PG_CATCH();
	{
		freecon(o_context);
		PG_RE_THROW();
	}
	PG_END_TRY();
	freecon(o_context);

	return result;
}

/*
 * sepgsqlCheckValidSecurityLabel() checks whether the given
 * security context is valid on the current working security
 * policy, or not.
 * If it's invalid, sepgsqlUnlabeledSecurityLabel() is invoked
 * at the next to get an alternative security label.
 */
bool
sepgsqlCheckValidSecurityLabel(char *context)
{
	if (security_check_context_raw((security_context_t) context) < 0)
		return false;

	return true;
}

char *
sepgsqlUnlabeledSecurityLabel(void)
{
	security_context_t unlabeled;
	char *result;

	if (security_get_initial_context_raw("unlabeled", &unlabeled) < 0)
		ereport(ERROR,
				(errcode(ERRCODE_SELINUX_ERROR),
				 errmsg("SELinux: could not get unlabeled initial context")));
	PG_TRY();
	{
		result = pstrdup(unlabeled);
	}
	PG_CATCH();
	{
		freecon(unlabeled);
		PG_RE_THROW();
	}
	PG_END_TRY();
	freecon(unlabeled);

	return result;
}

char *
sepgsqlSecurityLabelOfLabel(void)
{
	security_context_t table_context, tuple_context;
	HeapTuple	tuple;

	/*
	 * obtain security context of pg_security
	 */
	tuple = SearchSysCache(RELOID,
						   ObjectIdGetDatum(SecurityRelationId), 0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "SELinux: cache lookup failed for relation %u",
					SecurityRelationId);

	table_context = pgaceLookupSecurityLabel(HeapTupleGetSecLabel(tuple));
	if (!table_context || !pgaceCheckValidSecurityLabel(table_context))
		table_context = pgaceUnlabeledSecurityLabel();

	tuple_context = sepgsqlComputeCreateContext(sepgsqlGetServerContext(),
												table_context, SECCLASS_DB_TUPLE);
	pfree(table_context);

	ReleaseSysCache(tuple);

	return tuple_context;
}

/******************************************************************
 * HeapTuple modification hooks
 ******************************************************************/
static HeapTuple
getHeapTupleFromItemPointer(Relation rel, ItemPointer tid)
{
	/*
	 * obtain an old tuple
	 */
	Buffer		buffer;
	PageHeader	dp;
	ItemId		lp;
	HeapTupleData tuple;
	HeapTuple	oldtup;

	buffer = ReadBuffer(rel, ItemPointerGetBlockNumber(tid));
	LockBuffer(buffer, BUFFER_LOCK_SHARE);

	dp = (PageHeader) BufferGetPage(buffer);
	lp = PageGetItemId(dp, ItemPointerGetOffsetNumber(tid));

	Assert(ItemIdIsNormal(lp));

	tuple.t_data = (HeapTupleHeader) PageGetItem((Page) dp, lp);
	tuple.t_len = ItemIdGetLength(lp);
	tuple.t_self = *tid;
	tuple.t_tableOid = RelationGetRelid(rel);
	oldtup = heap_copytuple(&tuple);

	LockBuffer(buffer, BUFFER_LOCK_UNLOCK);
	ReleaseBuffer(buffer);

	return oldtup;
}

static bool
isTrustedRelation(Relation rel, bool is_internal)
{
	if (!is_internal)
		return false;

	if (RelationGetForm(rel)->relkind != RELKIND_RELATION)
		return true;

	switch (RelationGetRelid(rel))
	{
		case LargeObjectRelationId:
		case SecurityRelationId:
			return true;
	}
	return false;
}

bool
sepgsqlHeapTupleInsert(Relation rel, HeapTuple tuple,
					   bool is_internal, bool with_returning)
{
	uint32		perms;

	/*
	 * default context for no explicit labeled tuple
	 */
	if (!OidIsValid(HeapTupleGetSecLabel(tuple)))
	{
		/*
		 * If user gives no valid security context,
		 * it assigns a default one on the new tuple.
		 */
		if (HeapTupleHasSecLabel(tuple))
			sepgsqlSetDefaultContext(rel, tuple);
	}
	else if (!is_internal && RelationGetRelid(rel) == LargeObjectRelationId)
		ereport(ERROR,
				(errcode(ERRCODE_SELINUX_ERROR),
				 errmsg("SELinux: unable to insert "
						"pg_largeobject.security_context")));

	if (isTrustedRelation(rel, is_internal))
		return true;

	perms = SEPGSQL_PERMS_INSERT;
	if (with_returning)
		perms |= SEPGSQL_PERMS_SELECT;

	return sepgsqlCheckTuplePerms(rel, tuple, NULL, perms, is_internal);
}

bool
sepgsqlHeapTupleUpdate(Relation rel, ItemPointer otid, HeapTuple newtup,
					   bool is_internal, bool with_returning)
{
	Oid			relid = RelationGetRelid(rel);
	HeapTuple	oldtup;
	uint32		perms;
	bool		rc = true;
	bool		relabel = false;

	oldtup = getHeapTupleFromItemPointer(rel, otid);

	if (!OidIsValid(HeapTupleGetSecLabel(newtup)))
	{
		/*
		 * If user does not specify new security context
		 * explicitly, it preserves a security context of
		 * older tuple.
		 */
		Oid sid = HeapTupleGetSecLabel(oldtup);

		if (HeapTupleHasSecLabel(newtup))
			HeapTupleSetSecLabel(newtup, sid);
	}
	else if (!is_internal && RelationGetRelid(rel) == LargeObjectRelationId)
		ereport(ERROR,
				(errcode(ERRCODE_SELINUX_ERROR),
				 errmsg("SELinux: unable to update "
						"pg_largeobject.security_context")));

	if (isTrustedRelation(rel, is_internal))
		return true;

	if (HeapTupleGetSecLabel(newtup) != HeapTupleGetSecLabel(oldtup) ||
		sepgsqlTupleObjectClass(relid, newtup) != sepgsqlTupleObjectClass(relid, oldtup))
		relabel = true;

	perms = SEPGSQL_PERMS_UPDATE;
	if (relabel)
		perms |= SEPGSQL_PERMS_RELABELFROM;
	rc = sepgsqlCheckTuplePerms(rel, oldtup, newtup, perms, is_internal);
	if (!rc)
		goto out;

	if (relabel)
	{
		perms = SEPGSQL_PERMS_RELABELTO;
		if (with_returning)
			perms |= SEPGSQL_PERMS_SELECT;
		rc = sepgsqlCheckTuplePerms(rel, newtup, NULL, perms, is_internal);
	}
  out:
	heap_freetuple(oldtup);
	return rc;
}

bool
sepgsqlHeapTupleDelete(Relation rel, ItemPointer otid,
					   bool is_internal, bool with_returning)
{
	HeapTuple	oldtup;
	uint32		perms = SEPGSQL_PERMS_DELETE;
	bool		rc;

	if (isTrustedRelation(rel, is_internal))
		return true;

	oldtup = getHeapTupleFromItemPointer(rel, otid);
	rc = sepgsqlCheckTuplePerms(rel, oldtup, NULL, perms, is_internal);
	heap_freetuple(oldtup);

	return rc;
}
