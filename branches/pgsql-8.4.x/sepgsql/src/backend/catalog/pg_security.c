/*
 * src/backend/catalog/pg_security.c
 *    routines to support security label management
 *
 * Portions Copyright (c) 1996-2009, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 */
#include "postgres.h"

#include "access/genam.h"
#include "access/heapam.h"
#include "access/sysattr.h"
#include "access/xact.h"
#include "catalog/catalog.h"
#include "catalog/indexing.h"
#include "catalog/pg_proc.h"
#include "catalog/pg_security.h"
#include "catalog/pg_type.h"
#include "executor/spi.h"
#include "miscadmin.h"
#include "security/rowlevel.h"
#include "security/sepgsql.h"
#include "utils/builtins.h"
#include "utils/fmgroids.h"
#include "utils/memutils.h"
#include "utils/rel.h"
#include "utils/lsyscache.h"
#include "utils/syscache.h"
#include "utils/tqual.h"

bool
securityTupleDescHasSecid(Oid relid, char relkind)
{
	return sepgsqlTupleDescHasSecid(relid, relkind);
}

/*
 * securityOnCreateDatabase
 *   copies all the entries refered by source database
 */
void
securityOnCreateDatabase(Oid src_datid, Oid dst_datid)
{
	Relation	rel;
	ScanKeyData	keys[1];
	SysScanDesc	scan;
	HeapTuple	oldtup, newtup;
	Datum		values[Natts_pg_security];
	bool		nulls[Natts_pg_security];
	bool		replaces[Natts_pg_security];

	/* Scan all entries with pg_security.datid = src_datid */
	ScanKeyInit(&keys[0],
				Anum_pg_security_datid,
				BTEqualStrategyNumber, F_OIDEQ,
                ObjectIdGetDatum(src_datid));

	rel = heap_open(SecurityRelationId, RowExclusiveLock);

	scan = systable_beginscan(rel, SecuritySecidIndexId, true,
							  SnapshotNow, 1, keys);

	/* pg_security.datid shall be replaced */
	memset(values, 0, sizeof(values));
	memset(nulls, false, sizeof(nulls));
	memset(replaces, false, sizeof(replaces));

	values[Anum_pg_security_datid - 1] = ObjectIdGetDatum(dst_datid);
	replaces[Anum_pg_security_datid - 1] = true;

	while (HeapTupleIsValid(oldtup = systable_getnext(scan)))
	{
		newtup = heap_modify_tuple(oldtup, RelationGetDescr(rel),
								   values, nulls, replaces);
		simple_heap_insert(rel, newtup);

		CatalogUpdateIndexes(rel, newtup);

		heap_freetuple(newtup);
	}
	systable_endscan(scan);

	heap_close(rel, RowExclusiveLock);
}

/*
 * securityOnDropDatabase
 *   drops all the entries refered by dropped database
 */
void
securityOnDropDatabase(Oid datid)
{
	Relation	rel;
	ScanKeyData	keys[1];
	SysScanDesc	scan;
	HeapTuple	tuple;

	/* Scan all entries with pg_security.datid = datid */
	ScanKeyInit(&keys[0],
				Anum_pg_security_datid,
				BTEqualStrategyNumber, F_OIDEQ,
                ObjectIdGetDatum(datid));

	rel = heap_open(SecurityRelationId, RowExclusiveLock);

	scan = systable_beginscan(rel, SecuritySecidIndexId, true,
							  SnapshotNow, 1, keys);

	while (HeapTupleIsValid(tuple = systable_getnext(scan)))
	{
		simple_heap_delete(rel, &tuple->t_self);
	}

	systable_endscan(scan);

	heap_close(rel, RowExclusiveLock);
}

/*
 * InputSecurityAttr
 */
static Oid
InputSecurityAttr(Oid relid, const char *secattr)
{
	LOCKMODE		lockmode = AccessShareLock;
	Relation		rel;
	ScanKeyData		skey[3];
	SysScanDesc		scan;
	HeapTuple		tuple;
	Oid				datid;
	Oid				secid;
	Datum			values[Natts_pg_security];
	bool			nulls[Natts_pg_security];

	datid = (IsSharedRelation(relid) ? InvalidOid : MyDatabaseId);

retry:
	/*
	 * Lookup pg_security catalog first
	 */
	rel = heap_open(SecurityRelationId, lockmode);

	ScanKeyInit(&skey[0],
				Anum_pg_security_datid,
				BTEqualStrategyNumber, F_OIDEQ,
				ObjectIdGetDatum(datid));
	ScanKeyInit(&skey[1],
				Anum_pg_security_relid,
				BTEqualStrategyNumber, F_OIDEQ,
				ObjectIdGetDatum(relid));
	ScanKeyInit(&skey[2],
				Anum_pg_security_secattr,
				BTEqualStrategyNumber, F_TEXTEQ,
				CStringGetTextDatum(secattr));

	scan = systable_beginscan(rel, SecuritySecattrIndexId, true,
							  SnapshotToast, 3, skey);

	tuple = systable_getnext(scan);
	if (HeapTupleIsValid(tuple))
	{
		secid = ((Form_pg_security) GETSTRUCT(tuple))->secid;

		systable_endscan(scan);

		heap_close(rel, lockmode);

		return secid;
	}

	systable_endscan(scan);

	/*
	 * If not exist, try to insert a new entry.
	 */
	if (lockmode == AccessShareLock)
	{
		heap_close(rel, lockmode);

		lockmode = RowExclusiveLock;

		goto retry;
	}

	memset(nulls, false, sizeof(nulls));
	secid = GetNewOidWithIndex(rel, SecuritySecidIndexId,
							   Anum_pg_security_secid);
	values[Anum_pg_security_secid - 1] = ObjectIdGetDatum(secid);
	values[Anum_pg_security_datid - 1] = ObjectIdGetDatum(datid);
	values[Anum_pg_security_relid - 1] = ObjectIdGetDatum(relid);
	values[Anum_pg_security_secattr - 1] = CStringGetTextDatum(secattr);

	tuple = heap_form_tuple(RelationGetDescr(rel), values, nulls);

	simple_heap_insert(rel, tuple);

	CatalogUpdateIndexes(rel, tuple);

	heap_close(rel, lockmode);

	return secid;
}

static char *
OutputSecurityAttr(Oid relid, Oid secid)
{
	Relation		rel;
	ScanKeyData		skey[3];
	SysScanDesc		scan;
	HeapTuple		tuple;
	Oid				datid;
	char		   *result = NULL;

	datid = (IsSharedRelation(relid) ? InvalidOid : MyDatabaseId);

	/*
	 * Lookup pg_security catalog first
	 */
	rel = heap_open(SecurityRelationId, AccessShareLock);

	ScanKeyInit(&skey[0],
				Anum_pg_security_secid,
				BTEqualStrategyNumber, F_OIDEQ,
				ObjectIdGetDatum(secid));
	ScanKeyInit(&skey[1],
				Anum_pg_security_datid,
				BTEqualStrategyNumber, F_OIDEQ,
				ObjectIdGetDatum(datid));
	ScanKeyInit(&skey[2],
				Anum_pg_security_relid,
				BTEqualStrategyNumber, F_OIDEQ,
				ObjectIdGetDatum(relid));

	scan = systable_beginscan(rel, SecuritySecidIndexId, true,
							  SnapshotToast, 3, skey);

	tuple = systable_getnext(scan);
	if (HeapTupleIsValid(tuple))
	{
		Datum	datum;
		bool	isnull;

		datum = heap_getattr(tuple,
							 Anum_pg_security_secattr,
							 RelationGetDescr(rel), &isnull);
		if (!isnull)
			result = TextDatumGetCString(datum);
	}

	systable_endscan(scan);

	heap_close(rel, AccessShareLock);

	return result;
}

/*
 * input/output handler
 */
Oid
securityRawSecLabelIn(Oid relid, char *seclabel)
{
	seclabel = sepgsqlRawSecLabelIn(seclabel);

	return InputSecurityAttr(relid, seclabel);
}

char *
securityRawSecLabelOut(Oid relid, Oid secid)
{
	char   *seclabel = OutputSecurityAttr(relid, secid);

	return sepgsqlRawSecLabelOut(seclabel);
}

Oid
securityTransSecLabelIn(Oid relid, char *seclabel)
{
	seclabel = sepgsqlTransSecLabelIn(seclabel);

	return securityRawSecLabelIn(relid, seclabel);
}

char *
securityTransSecLabelOut(Oid relid, Oid secid)
{
	char   *seclabel = securityRawSecLabelOut(relid, secid);

	return sepgsqlTransSecLabelOut(seclabel);
}

/*
 * Output handler for system columns
 */
Datum
securitySysattSecLabelOut(Oid relid, HeapTuple tuple)
{
	char   *seclabel;

	seclabel = sepgsqlSysattSecLabelOut(relid, tuple);
	if (!seclabel)
		seclabel = "unlabled";

	return CStringGetTextDatum(seclabel);
}

/*
 * securityReclaimOnDropTable
 *   drop orphan entries within pg_security on drop table
 */
void
securityReclaimOnDropTable(Oid relid)
{
	Relation	rel;
	SysScanDesc	scan;
	ScanKeyData	key[2];
	HeapTuple	tuple;
	Oid			database_oid;

	database_oid = (IsSharedRelation(relid) ? InvalidOid : MyDatabaseId);
	ScanKeyInit(&key[0],
				Anum_pg_security_datid,
				BTEqualStrategyNumber, F_OIDEQ,
				ObjectIdGetDatum(database_oid));
	ScanKeyInit(&key[1],
				Anum_pg_security_relid,
				BTEqualStrategyNumber, F_OIDEQ,
				ObjectIdGetDatum(relid));

	rel = heap_open(SecurityRelationId, RowExclusiveLock);
	scan = systable_beginscan(rel, SecuritySecattrIndexId, true,
							  SnapshotNow, 2, key);
	while (HeapTupleIsValid(tuple = systable_getnext(scan)))
		simple_heap_delete(rel, &tuple->t_self);

	systable_endscan(scan);

	heap_close(rel, RowExclusiveLock);
}

/*
 * security_quote_relation
 *   returns palloc'de identifier with explicit namespace
 */
static char *
security_quote_relation(Oid relid)
{
	Oid		nspoid = get_rel_namespace(relid);
	char   *nspname;
	char   *relname;

	nspname = get_namespace_name(nspoid);
	relname = get_rel_name(relid);

	return quote_qualified_identifier(nspname, relname);
}

/*
 * security_reclaim_table
 *   reclaims orphan entries associated to a certain table
 */
static int
seclabelRelationReclaimExec(Oid relOid)
{
	StringInfoData	query;
	SPIPlanPtr		plan;
	Oid				types[2];
	Datum			values[2];
	Oid				proc_oid;
	Oid				database_oid;
	char		   *relname_full;
	char		   *attname_datid;
	char		   *attname_relid;
	char		   *attname_secid;
	char		   *attname_seckind;
	char		   *attname_secattr;
	char		   *sec_proname;
	char		   *sec_nspname;
	Form_pg_proc	proForm;
	HeapTuple		protup;

	/*
	 * LOCK the target table
	 */
	initStringInfo(&query);
	relname_full = security_quote_relation(relOid);
	appendStringInfo(&query, "LOCK %s IN SHARE MODE", relname_full);
	if (SPI_execute(query.data, false, 0) != SPI_OK_UTILITY)
		elog(ERROR, "SPI_execute failed on %s", query.data);

	/*
	 * DELETE orphan entries
	 */
	initStringInfo(&query);
	attname_secid = get_attname(SecurityRelationId, Anum_pg_security_secid);
	attname_datid = get_attname(SecurityRelationId, Anum_pg_security_datid);
	attname_relid = get_attname(SecurityRelationId, Anum_pg_security_relid);
	attname_secattr = get_attname(SecurityRelationId, Anum_pg_security_secattr);

	appendStringInfo(&query,
					 "DELETE FROM %s "
					 "WHERE %s = $1 AND %s = $2 AND %s NOT IN ",
					 security_quote_relation(SecurityRelationId),
					 quote_identifier(attname_datid),
					 quote_identifier(attname_relid),
					 quote_identifier(attname_secid));

	protup = SearchSysCache(PROCOID,
							ObjectIdGetDatum(F_SECLABEL_TO_SECID),
							0, 0, 0);
	if (!HeapTupleIsValid(protup))
		elog(ERROR, "cache lookup failed for procedure: %u", F_SECLABEL_TO_SECID);

	proForm = (Form_pg_proc) GETSTRUCT(protup);
	sec_proname = NameStr(proForm->proname);
	sec_nspname = get_namespace_name(proForm->pronamespace);

	appendStringInfo(&query,
					 "(SELECT %s.%s(%s) FROM ONLY %s)",
					 quote_identifier(sec_nspname),
					 quote_identifier(sec_proname),
					 quote_identifier(get_rel_name(relOid)),
					 relname_full);
	ReleaseSysCache(protup);

	/*
	 * Setup and execute query
	 */
	types[0] = OIDOID;
	types[1] = OIDOID;
	plan = SPI_prepare(query.data, 2, types);
	if (!plan)
		elog(ERROR, "SPI_prepare failed on %s", query.data);

	database_oid = (IsSharedRelation(relOid) ? InvalidOid : MyDatabaseId);

	values[0] = ObjectIdGetDatum(database_oid);
	values[1] = ObjectIdGetDatum(relOid);
	if (SPI_execute_plan(plan, values, NULL, false, 0) != SPI_OK_DELETE)
		elog(ERROR, "SPI_execute_plan failed on %s", query.data);

	SPI_freetuptable(SPI_tuptable);

	return SPI_processed;
}

void
seclabelRelationReclaim(Oid relOid)
{
	int		save_mode;

	if (!superuser() ||
		get_rel_relkind(relOid) != RELKIND_RELATION)
		return;

	save_mode = sepostgresql_mode;
	sepostgresql_mode = SEPGSQL_MODE_INTERNAL;
	PG_TRY();
	{
		if (SPI_connect() != SPI_OK_CONNECT)
			elog(ERROR, "SPI_connect failed");

		seclabelRelationReclaimExec(relOid);

		if (SPI_finish() != SPI_OK_FINISH)
			elog(ERROR, "SPI_finish failed");
	}
	PG_CATCH();
	{
		sepostgresql_mode = save_mode;
		PG_RE_THROW();
	}
	PG_END_TRY();
	sepostgresql_mode = save_mode;
}

Datum
seclabel_to_secid(PG_FUNCTION_ARGS)
{
	HeapTupleHeader tuphdr = PG_GETARG_HEAPTUPLEHEADER(0);

	PG_RETURN_OID(HeapTupleHeaderGetSecid(tuphdr));
}
