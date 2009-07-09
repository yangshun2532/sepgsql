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
#include "security/rowacl.h"
#include "security/sepgsql.h"
#include "utils/builtins.h"
#include "utils/fmgroids.h"
#include "utils/memutils.h"
#include "utils/rel.h"
#include "utils/lsyscache.h"
#include "utils/syscache.h"
#include "utils/tqual.h"

bool
securityTupleDescHasSecLabel(Oid relid, char relkind)
{
	return sepgsqlTupleDescHasSecLabel(relid, relkind);
}

bool
securityTupleDescHasRowAcl(Relation rel)
{
	return RelationGetRowLevelAcl(rel);
}

static char *
securityMetaSecurityLabel(void)
{
	return sepgsqlMetaSecurityLabel();
}

/*
 * security attribute management at the initdb phase.
 */
typedef struct earlySecAttr
{
	struct earlySecAttr	   *next;
	Oid		secid;
	Oid		datid;
	Oid		relid;
	char	seckind;
	char	secattr[1];
} earlySecAttr;

static earlySecAttr *earlySecAttrList = NULL;

static Oid
earlyInputSecurityAttr(Oid datid, Oid relid, char seckind, const char *secattr)
{
	static Oid		dummySecid = SecurityRelationId;
	earlySecAttr   *es;

	for (es = earlySecAttrList; es; es = es->next)
	{
		if (es->datid == datid &&
			es->relid == relid &&
			es->seckind == seckind &&
			strcmp(es->secattr, secattr) == 0)
			return es->secid;
	}
	/* Not found */
	es = MemoryContextAlloc(TopMemoryContext,
							sizeof(*es) + strlen(secattr));
	es->secid = --dummySecid;
	es->datid = datid;
	es->relid = relid;
	es->seckind = seckind;
	strcpy(es->secattr, secattr);

	es->next = earlySecAttrList;
	earlySecAttrList = es;

	return es->secid;
}

static char *
earlyOutputSecurityAttr(Oid datid, Oid relid, char seckind, Oid secid)
{
	earlySecAttr   *es;

	for (es = earlySecAttrList; es; es = es->next)
	{
		if (es->datid == datid &&
			es->relid == relid &&
			es->seckind == seckind &&
			es->secid == secid)
			return pstrdup(es->secattr);
	}
	return NULL;	/* Not found */
}

void
securityPostBootstrapingMode(void)
{
	Relation		rel;
	HeapTuple		tuple;
	earlySecAttr   *es;
	char		   *meta_label;
	Oid				meta_secid = InvalidOid;
	Datum			values[Natts_pg_security];
	bool			nulls[Natts_pg_security];

	if (!earlySecAttrList)
		return;		/* do nothing */

	StartTransactionCommand();

	/* security_label on the pg_security */
	meta_label = securityMetaSecurityLabel();
	if (meta_label)
		meta_secid = securityTransSecLabelIn(SecurityRelationId, meta_label);

	/* flush all the cached entries */
	rel = heap_open(SecurityRelationId, RowExclusiveLock);
	for (es = earlySecAttrList; es; es = es->next)
	{
		memset(nulls, false, sizeof(nulls));
		values[Anum_pg_security_secid - 1] = ObjectIdGetDatum(es->secid);
		values[Anum_pg_security_datid - 1] = ObjectIdGetDatum(es->datid);
		values[Anum_pg_security_relid - 1] = ObjectIdGetDatum(es->relid);
		values[Anum_pg_security_seckind - 1] = CharGetDatum(es->seckind);
		values[Anum_pg_security_secattr - 1] = CStringGetTextDatum(es->secattr);

		tuple = heap_form_tuple(RelationGetDescr(rel), values, nulls);
		if (HeapTupleHasSecLabel(tuple))
			HeapTupleSetSecLabel(tuple, meta_secid);

		simple_heap_insert(rel, tuple);
		CatalogUpdateIndexes(rel, tuple);
		heap_freetuple(tuple);
	}
	heap_close(rel, RowExclusiveLock);

	CommitTransactionCommand();
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
InputSecurityAttr(Oid relid, char seckind, const char *secattr)
{
	Relation		rel;
	HeapTuple		tuple;
	Oid				datid;
	Oid				secid;
	char		   *meta_label;
	Oid				meta_secid = InvalidOid;
	Datum			values[Natts_pg_security];
	bool			nulls[Natts_pg_security];

	datid = (IsSharedRelation(relid) ? InvalidOid : MyDatabaseId);

	if (IsBootstrapProcessingMode())
		return earlyInputSecurityAttr(datid, relid, seckind, secattr);

	/*
	 * Lookup the syscache first
	 */
	tuple = SearchSysCache(SECURITYATTR,
						   ObjectIdGetDatum(datid),
						   ObjectIdGetDatum(relid),
						   CharGetDatum(seckind),
						   CStringGetTextDatum(secattr));
	if (HeapTupleIsValid(tuple))
	{
		secid = ((Form_pg_security) GETSTRUCT(tuple))->secid;

		ReleaseSysCache(tuple);

		return secid;
	}

	/*
	 * Insert a new tuple, if not exist
	 */
	rel = heap_open(SecurityRelationId, RowExclusiveLock);

	memset(nulls, false, sizeof(nulls));
	secid = GetNewOidWithIndex(rel, SecuritySecidIndexId,
							   Anum_pg_security_secid);
	values[Anum_pg_security_secid - 1] = ObjectIdGetDatum(secid);
	values[Anum_pg_security_datid - 1] = ObjectIdGetDatum(datid);
	values[Anum_pg_security_relid - 1] = ObjectIdGetDatum(relid);
	values[Anum_pg_security_seckind - 1] = CharGetDatum(seckind);
	values[Anum_pg_security_secattr - 1] = CStringGetTextDatum(secattr);

	meta_label = securityMetaSecurityLabel();
	if (meta_label)
	{
		if (datid == InvalidOid &&
			relid == SecurityRelationId &&
			seckind == SECKIND_SECURITY_LABEL &&
			strcmp(meta_label, secattr) == 0)
			meta_secid = secid;
		else
			meta_secid = securityTransSecLabelIn(SecurityRelationId, meta_label);
	}

	tuple = heap_form_tuple(RelationGetDescr(rel), values, nulls);
	if (HeapTupleHasSecLabel(tuple))
		HeapTupleSetSecLabel(tuple, meta_secid);

	simple_heap_insert(rel, tuple);
	CatalogUpdateIndexes(rel, tuple);

	/*
	 * NOTE:
	 * We also need to insert the new entry into system cache for
	 * temporary usage, because user tries to use an identical
	 * security attributes twice or more within a single command
	 * identifier. The syscache mechanism scans the pg_security with
	 * SnapshotNow, so the entry newly inserted is not visible for
	 * the second trial. Then, it tries to insert an identical
	 * security attribute twice and get failed.
	 * The temporary cache entry shall be invalidated on the next
	 * CommandIdIncrement(). The purpose of InsertSysCache() is
	 * to avoid duplication of insertion (and undesirable error).
	 */
	InsertSysCache(RelationGetRelid(rel), tuple);

	heap_close(rel, RowExclusiveLock);

	return secid;
}

static char *
OutputSecurityAttr(Oid relid, char seckind, Oid secid)
{
	Form_pg_security	secForm;
	Oid			datid;
	HeapTuple	tuple;
	Datum		datum;
	bool		isnull;
	char	   *result;

	datid = (IsSharedRelation(relid) ? InvalidOid : MyDatabaseId);

	if (IsBootstrapProcessingMode())
		return earlyOutputSecurityAttr(datid, relid, seckind, secid);

	tuple = SearchSysCache(SECURITYSECID,
						   ObjectIdGetDatum(secid),
						   ObjectIdGetDatum(datid),
						   0, 0);
	if (!HeapTupleIsValid(tuple))
		return NULL;

	/*
	 * Integrity checks
	 */
	secForm = (Form_pg_security) GETSTRUCT(tuple);
	if (secForm->relid != relid)
		goto error;
	if (secForm->seckind != seckind)
		goto error;
	datum = SysCacheGetAttr(SECURITYSECID, tuple,
							Anum_pg_security_secattr,
							&isnull);
	if (isnull)
		goto error;

	result = TextDatumGetCString(datum);

	ReleaseSysCache(tuple);

	return result;

error:
	ReleaseSysCache(tuple);

	elog(NOTICE,
		 "invalid pg_security (secid=%u, datid=%u, relid=%u, seckind=%c)"
		 " for relid=%u, seckind=%c secid=%u",
		 secForm->secid, secForm->datid, secForm->relid, secForm->seckind,
		 relid, seckind, secid);

	return NULL;
}

/*
 * input/output handler
 */
Oid
securityRawSecLabelIn(Oid relid, char *seclabel)
{
	seclabel = sepgsqlRawSecLabelIn(seclabel);

	return InputSecurityAttr(relid, SECKIND_SECURITY_LABEL, seclabel);
}

char *
securityRawSecLabelOut(Oid relid, Oid secid)
{
	char   *seclabel = OutputSecurityAttr(relid, SECKIND_SECURITY_LABEL, secid);

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

Oid
securityMoveSecLabel(Oid dstid, Oid srcid, Oid secid)
{
	char   *seclabel = securityRawSecLabelOut(srcid, secid);

	if (!seclabel)
		return InvalidOid;

	return securityRawSecLabelIn(dstid, seclabel);
}

Oid
securityTransRowAclIn(Oid relid, Acl *acl)
{
	char   *secacl = rowaclTransRowAclIn(acl);

	return InputSecurityAttr(relid, SECKIND_SECURITY_ACL, secacl);
}

Acl *
securityTransRowAclOut(Oid relid, Oid secid, Oid ownid)
{
	char   *secacl = OutputSecurityAttr(relid, SECKIND_SECURITY_ACL, secid);
	Acl	   *acl = rowaclTransRowAclOut(secacl);

	if (!acl)
		acl = acldefault(ACL_OBJECT_TUPLE, ownid);

	return acl;
}

/*
 * Output handler for system columns
 */
Datum
securityHeapGetSecLabelSysattr(HeapTuple tuple)
{
	Oid		secid = HeapTupleGetSecLabel(tuple);
	char   *seclabel;

	seclabel = securityTransSecLabelOut(tuple->t_tableOid, secid);
	if (!seclabel)
		seclabel = pstrdup("unlabeled");

	return CStringGetTextDatum(seclabel);
}

Datum
securityHeapGetRowAclSysattr(HeapTuple tuple)
{
	HeapTuple	reltup;
	Oid			secid = HeapTupleGetRowAcl(tuple);
	Oid			ownid;
	Acl		   *acl;

	reltup = SearchSysCache(RELOID,
							ObjectIdGetDatum(tuple->t_tableOid),
							0, 0, 0);
	if (!HeapTupleIsValid(reltup))
		elog(ERROR, "cache lookup failed for relation: %u", tuple->t_tableOid);

	ownid = ((Form_pg_class) GETSTRUCT(reltup))->relowner;

	ReleaseSysCache(reltup);

	acl = securityTransRowAclOut(tuple->t_tableOid, secid, ownid);

	return PointerGetDatum(acl);
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
							  SnapshotNow, 1, key);
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
security_reclaim_table(Oid relid, char seckind)
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
	relname_full = security_quote_relation(relid);
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
	attname_seckind = get_attname(SecurityRelationId, Anum_pg_security_seckind);
	attname_secattr = get_attname(SecurityRelationId, Anum_pg_security_secattr);

	appendStringInfo(&query,
					 "DELETE FROM %s "
					 "WHERE %s = $1 AND %s = $2 "
					 "  AND %s = $3 AND %s NOT IN ",
					 security_quote_relation(SecurityRelationId),
					 quote_identifier(attname_datid),
					 quote_identifier(attname_relid),
					 quote_identifier(attname_seckind),
					 quote_identifier(attname_secid));
	switch (seckind)
	{
	case SECKIND_SECURITY_LABEL:
		proc_oid = F_SECURITY_LABEL_TO_SECID;
		break;
	case SECKIND_SECURITY_ACL:
		proc_oid = F_SECURITY_ACL_TO_SECID;
		break;
	default:
		elog(ERROR, "unexpected seckind: %c", seckind);
		proc_oid = InvalidOid;	/* to compiler silent */
		break;
	}

	protup = SearchSysCache(PROCOID,
							ObjectIdGetDatum(proc_oid),
							0, 0, 0);
	if (!HeapTupleIsValid(protup))
		elog(ERROR, "cache lookup failed for procedure: %u", proc_oid);
	proForm = (Form_pg_proc) GETSTRUCT(protup);
	sec_proname = NameStr(proForm->proname);
	sec_nspname = get_namespace_name(proForm->pronamespace);

	appendStringInfo(&query,
					 "(SELECT %s.%s(%s) FROM ONLY %s)",
					 quote_identifier(sec_nspname),
					 quote_identifier(sec_proname),
					 quote_identifier(get_rel_name(relid)),
					 relname_full);
	ReleaseSysCache(protup);

	/*
	 * Setup and execute query
	 */
	types[0] = OIDOID;
	types[1] = OIDOID;
	types[2] = CHAROID;
	plan = SPI_prepare(query.data, 2, types);
	if (!plan)
		elog(ERROR, "SPI_prepare failed on %s", query.data);

	database_oid = (IsSharedRelation(relid) ? InvalidOid : MyDatabaseId);

	values[0] = ObjectIdGetDatum(database_oid);
	values[1] = ObjectIdGetDatum(relid);
	values[2] = CharGetDatum(seckind);
	if (SPI_execute_plan(plan, values, NULL, false, 0) != SPI_OK_DELETE)
		elog(ERROR, "SPI_execute_plan failed on %s", query.data);

	SPI_freetuptable(SPI_tuptable);

	return SPI_processed;
}

static int
security_reclaim_all_tables(char seckind)
{
	StringInfoData	query;
	char	   *attname_datid;
	char	   *attname_relid;
	int			index;
	Datum		datum;
	bool		isnull;
	int			count = 0;
	List	   *relidList = NIL;
	ListCell   *l;

	initStringInfo(&query);

	attname_datid = get_attname(SecurityRelationId, Anum_pg_security_datid);
	attname_relid = get_attname(SecurityRelationId, Anum_pg_security_relid);
	appendStringInfo(&query,
					 "SELECT DISTINCT %s FROM %s WHERE %s = %u OR %s = %u",
					 attname_relid,
					 security_quote_relation(SecurityRelationId),
					 attname_datid, InvalidOid,
					 attname_datid, MyDatabaseId);

	if (SPI_execute(query.data, true, 0) != SPI_OK_SELECT)
		elog(ERROR, "SPI_execute failed on %s", query.data);

	for (index = 0; index < SPI_processed; index++)
	{
		datum = SPI_getbinval(SPI_tuptable->vals[index],
							  SPI_tuptable->tupdesc, 1, &isnull);
		if (isnull)
			continue;
		relidList = lappend_oid(relidList, DatumGetObjectId(datum));
	}
	SPI_freetuptable(SPI_tuptable);

	foreach (l, relidList)
		count += security_reclaim_table(lfirst_oid(l), seckind);

	return count;
}

static int
security_reclaim(Oid relid, char seckind)
{
	bool		sepgsql_saved;
	int			count;

	if (!superuser())
		ereport(ERROR,
				(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
				 errmsg("must be superuser to reclaim security attributes")));
	/*
	 * Disable SE-PostgreSQL temporary
	 */
	sepgsql_saved = sepgsqlSetExceptionMode(true);

	PG_TRY();
	{
		if (SPI_connect() != SPI_OK_CONNECT)
			elog(ERROR, "SPI_connect failed");

		if (OidIsValid(relid))
			count = security_reclaim_table(relid, seckind);
		else
			count = security_reclaim_all_tables(seckind);

		if (SPI_finish() != SPI_OK_FINISH)
			elog(ERROR, "SPI_finish failed");
	}
	PG_CATCH();
	{
		sepgsqlSetExceptionMode(sepgsql_saved);
		PG_RE_THROW();
	}
	PG_END_TRY();

	sepgsqlSetExceptionMode(sepgsql_saved);

	return count;
}

Datum
security_reclaim_acl(PG_FUNCTION_ARGS)
{
	PG_RETURN_INT32(security_reclaim(InvalidOid, SECKIND_SECURITY_ACL));
}

Datum
security_reclaim_table_acl(PG_FUNCTION_ARGS)
{
	PG_RETURN_INT32(security_reclaim(PG_GETARG_OID(0), SECKIND_SECURITY_ACL));
}

Datum
security_reclaim_label(PG_FUNCTION_ARGS)
{
	PG_RETURN_INT32(security_reclaim(InvalidOid, SECKIND_SECURITY_LABEL));
}

Datum
security_reclaim_table_label(PG_FUNCTION_ARGS)
{
	PG_RETURN_INT32(security_reclaim(PG_GETARG_OID(0), SECKIND_SECURITY_LABEL));
}

Datum
security_acl_to_secid(PG_FUNCTION_ARGS)
{
	HeapTupleHeader	tuphdr = PG_GETARG_HEAPTUPLEHEADER(0);

	PG_RETURN_OID(HeapTupleHeaderGetRowAcl(tuphdr));
}

Datum
security_label_to_secid(PG_FUNCTION_ARGS)
{
	HeapTupleHeader tuphdr = PG_GETARG_HEAPTUPLEHEADER(0);

	PG_RETURN_OID(HeapTupleHeaderGetSecLabel(tuphdr));
}

