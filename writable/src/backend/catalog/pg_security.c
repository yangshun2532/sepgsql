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
#include "access/xact.h"
#include "catalog/catalog.h"
#include "catalog/indexing.h"
#include "catalog/pg_security.h"
#include "miscadmin.h"
#include "security/sepgsql.h"
#include "utils/builtins.h"
#include "utils/fmgroids.h"
#include "utils/memutils.h"
#include "utils/rel.h"
#include "utils/syscache.h"
#include "utils/tqual.h"

bool
securityTupleDescHasSecLabel(Oid relid, char relkind)
{
	return sepgsqlTupleDescHasSecLabel(relid, relkind);
}

/*
 * security attribute management at the initdb phase.
 */
typedef struct earlySecAttr
{
	struct earlySecAttr	   *next;
	Oid		relid;
	Oid		secid;
	char	seckind;
	char	secattr[1];
} earlySecAttr;

static earlySecAttr *earlySecAttrList = NULL;

static Oid
earlyInputSecurityAttr(Oid relid, char seckind, const char *secattr)
{
	static Oid		dummySecid = SecurityRelationId;
	earlySecAttr   *es;

	for (es = earlySecAttrList; es; es = es->next)
	{
		if (es->relid == relid &&
			es->seckind == seckind &&
			strcmp(es->secattr, secattr) == 0)
			return es->secid;
	}
	/* Not found */
	es = MemoryContextAlloc(TopMemoryContext,
							sizeof(*es) + strlen(secattr));
	es->relid = relid;
	es->secid = --dummySecid;
	es->seckind = seckind;
	strcpy(es->secattr, secattr);

	es->next = earlySecAttrList;
	earlySecAttrList = es;

	return es->secid;
}

static char *
earlyOutputSecurityAttr(Oid relid, char seckind, Oid secid)
{
	earlySecAttr   *es;

	for (es = earlySecAttrList; es; es = es->next)
	{
		if (es->relid == relid &&
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
	Datum			values[Natts_pg_security];
	bool			nulls[Natts_pg_security];

	if (!earlySecAttrList)
		return;		/* do nothing */

	StartTransactionCommand();

	/* flush all the cached entries */
	rel = heap_open(SecurityRelationId, RowExclusiveLock);
	for (es = earlySecAttrList; es; es = es->next)
	{
		memset(nulls, false, sizeof(nulls));
		values[Anum_pg_security_secid - 1] = ObjectIdGetDatum(es->secid);
		values[Anum_pg_security_datid - 1] = ObjectIdGetDatum(MyDatabaseId);
		values[Anum_pg_security_relid - 1] = ObjectIdGetDatum(es->relid);
		values[Anum_pg_security_seckind - 1] = CharGetDatum(es->seckind);
		values[Anum_pg_security_secattr - 1] = CStringGetTextDatum(es->secattr);

		tuple = heap_form_tuple(RelationGetDescr(rel), values, nulls);

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
	Oid				secid;
	Datum			values[Natts_pg_security];
	bool			nulls[Natts_pg_security];

	if (IsBootstrapProcessingMode())
		return earlyInputSecurityAttr(relid, seckind, secattr);

	/*
	 * Lookup the syscache first
	 */
	tuple = SearchSysCache(SECURITYATTR,
						   ObjectIdGetDatum(MyDatabaseId),
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
	values[Anum_pg_security_datid - 1] = ObjectIdGetDatum(MyDatabaseId);
	values[Anum_pg_security_relid - 1] = ObjectIdGetDatum(relid);
	values[Anum_pg_security_seckind - 1] = CharGetDatum(seckind);
	values[Anum_pg_security_secattr - 1] = CStringGetTextDatum(secattr);

	tuple = heap_form_tuple(RelationGetDescr(rel), values, nulls);

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
	HeapTuple	tuple;
	Datum		datum;
	bool		isnull;
	char	   *result;

	if (IsBootstrapProcessingMode())
		return earlyOutputSecurityAttr(relid, seckind, secid);

	tuple = SearchSysCache(SECURITYSECID,
						   ObjectIdGetDatum(secid),
						   ObjectIdGetDatum(MyDatabaseId),
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

