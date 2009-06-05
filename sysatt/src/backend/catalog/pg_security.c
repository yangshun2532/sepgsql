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
#include "utils/builtins.h"
#include "utils/fmgroids.h"
#include "utils/memutils.h"
#include "utils/rel.h"
#include "utils/syscache.h"
#include "utils/tqual.h"

bool
securityTupleDescHasRowAcl(Relation rel)
{
	/*
	 * TODO: check "row_level_acl" reloption here
	 */
	return false;
}

bool
securityTupleDescHasSecLabel(Relation rel)
{
	/*
	 * TODO: check SE-PostgreSQL's state here
	 */
	return false;
}

static char *
securityMetaSecurityLabel(void)
{
	/*
	 * It returns the security label of tuples within
	 * pg_security system catalog
	 */
	return NULL;
}

/*
 * security attribute management at the initdb phase.
 */
typedef struct earlySecAttr
{
	struct earlySecAttr	   *next;
	Oid		datid;
	Oid		secid;
	char	seckind;
	char	secattr[1];
} earlySecAttr;

static earlySecAttr *earlySecAttrList = NULL;

static Oid
earlyInputSecurityAttr(Oid datid, char seckind, const char *secattr)
{
	static Oid		dummySecid = SecurityRelationId;
	earlySecAttr   *es;

	for (es = earlySecAttrList; es; es = es->next)
	{
		if (es->datid == datid &&
			strcmp(es->secattr, secattr) == 0)
			return es->secid;
	}
	/* Not found */
	es = MemoryContextAlloc(TopMemoryContext,
							sizeof(*es) + strlen(secattr));
	es->datid = datid;
	es->secid = --dummySecid;
	es->seckind = seckind;
	strcpy(es->secattr, secattr);

	es->next = earlySecAttrList;
	earlySecAttrList = es;

	return es->secid;
}

static char *
earlyOutputSecurityAttr(Oid datid, char seckind, Oid secid)
{
	earlySecAttr   *es;

	for (es = earlySecAttrList; es; es = es->next)
	{
		if (es->datid == datid &&
			es->secid == secid &&
			es->seckind == seckind)
			return pstrdup(es->secattr);
	}
	return NULL;	/* Not found */
}

void
securityPostBootstrapingMode(void)
{
	Relation			rel;
	CatalogIndexState	ind;
	HeapTuple			tuple;
	earlySecAttr	   *es;
	Datum				values[Natts_pg_security];
	bool				nulls[Natts_pg_security];
	Oid					meta_secid = InvalidOid;
	char			   *meta_label;

	if (!earlySecAttrList)
		return;		/* do nothing */

	StartTransactionCommand();

	meta_label = securityMetaSecurityLabel();
	if (meta_label)
		meta_secid = securityTransSecLabelIn(SecurityRelationId, meta_label);

	rel = heap_open(SecurityRelationId, RowExclusiveLock);

	ind = CatalogOpenIndexes(rel);

	for (es = earlySecAttrList; es; es = es->next)
	{
		memset(nulls, false, sizeof(nulls));

		values[Anum_pg_security_datid - 1] = ObjectIdGetDatum(es->datid);
		values[Anum_pg_security_secid - 1] = ObjectIdGetDatum(es->secid);
		values[Anum_pg_security_secinuse - 1] = BoolGetDatum(true);
		values[Anum_pg_security_seckind - 1] = CharGetDatum(es->seckind);
		values[Anum_pg_security_secattr - 1] = CStringGetTextDatum(es->secattr);

		tuple = heap_form_tuple(RelationGetDescr(rel), values, nulls);
		if (HeapTupleHasSecLabel(tuple))
			HeapTupleSetSecLabel(tuple, meta_secid);

		simple_heap_insert(rel, tuple);
		CatalogIndexInsert(ind, tuple);

		heap_freetuple(tuple);
	}

	CatalogCloseIndexes(ind);

	heap_close(rel, RowExclusiveLock);

	CommitTransactionCommand();
}

/*
 * InputSecurityAttr
 */
static Oid
InputSecurityAttr(Oid relid, char seckind, const char *secattr)
{
	Relation		rel;
	CatalogIndexState	ind;
	HeapTuple		tuple;
	Datum			values[Natts_pg_security];
	bool			nulls[Natts_pg_security];
	Oid				datid;
	Oid				secid;
	Oid				meta_secid = InvalidOid;
	char		   *meta_label;

	datid = (IsSharedRelation(relid) ? InvalidOid : MyDatabaseId);
	if (IsBootstrapProcessingMode())
		return earlyInputSecurityAttr(datid, seckind, secattr);

	/*
	 * Lookup syscache first
	 */
	tuple = SearchSysCache(SECURITYATTR,
						   ObjectIdGetDatum(datid),
						   CStringGetTextDatum(secattr),
						   0, 0);
	if (HeapTupleIsValid(tuple))
	{
		secid = ((Form_pg_security) GETSTRUCT(tuple))->secid;

		ReleaseSysCache(tuple);

		return secid;
	}
	/*
	 * Insert a new tuple, if not found
	 */
	rel = heap_open(SecurityRelationId, RowExclusiveLock);

	ind = CatalogOpenIndexes(rel);

	secid = GetNewOidWithIndex(rel, SecuritySecidIndexId,
							   Anum_pg_security_secid);

	/*
	 * set up self security context
	 */
	meta_label = securityMetaSecurityLabel();
	if (meta_label != NULL)
	{
		if (seckind == SECKIND_SECURITY_LABEL &&
			strcmp(meta_label, secattr) == 0)
			meta_secid = secid;
		else
			meta_secid = securityTransSecLabelIn(SecurityRelationId, meta_label);
	}

	memset(nulls, false, sizeof(nulls));
	values[Anum_pg_security_datid - 1] = ObjectIdGetDatum(datid);
	values[Anum_pg_security_secid - 1] = ObjectIdGetDatum(secid);
	values[Anum_pg_security_seckind - 1] = CharGetDatum(seckind);
	values[Anum_pg_security_secinuse - 1] = BoolGetDatum(true);
	values[Anum_pg_security_secattr - 1] = CStringGetTextDatum(secattr);

	tuple = heap_form_tuple(RelationGetDescr(rel),
							values, nulls);
	if (HeapTupleHasSecLabel(tuple))
		HeapTupleSetSecLabel(tuple, meta_secid);

	simple_heap_insert(rel, tuple);

	CatalogIndexInsert(ind, tuple);

	/*
	 * NOTE:
	 * We also need to insert the new tuple into the system cache
	 * for temporary usage.
	 * When user tries to apply same security attribute twice or
	 * more within a single command id, it cannot determine whether
	 * the given security attribute is already inserted, or not.
	 *
	 * The cache entry shall be invalidated on the next
	 * CommandIdIncrement(). The purpose of InsertSysCache() is
	 * to prevent duplicate insertion (and undesirable error).
	 */
	InsertSysCache(RelationGetRelid(rel), tuple);

	CatalogCloseIndexes(ind);

	heap_close(rel, RowExclusiveLock);

	return secid;
}

static char *
OutputSecurityAttr(Oid relid, char seckind, Oid secid)
{
	HeapTuple	tuple;
	Datum		datum;
	char	   *result;
	Oid			datid;
	bool		isnull;

	datid = (IsSharedRelation(relid) ? InvalidOid : MyDatabaseId);
	if (IsBootstrapProcessingMode())
		return earlyOutputSecurityAttr(datid, seckind, secid);

	tuple = SearchSysCache(SECURITYSECID,
						   ObjectIdGetDatum(datid),
						   ObjectIdGetDatum(secid),
						   0, 0);
	if (!HeapTupleIsValid(tuple))
		return NULL;

	datum = SysCacheGetAttr(SECURITYSECID, tuple,
							Anum_pg_security_secattr,
							&isnull);
	Assert(!isnull);

	result = TextDatumGetCString(datum);
	ReleaseSysCache(tuple);

	return result;
}

/*
 * input/output handler
 */
Oid
securityRawSecLabelIn(Oid relid, const char *seclabel)
{
	return InputSecurityAttr(relid, SECKIND_SECURITY_LABEL, seclabel);
}

char *
securityRawSecLabelOut(Oid relid, Oid secid)
{
	char *seclabel = OutputSecurityAttr(relid, SECKIND_SECURITY_LABEL, secid);

	return seclabel;
}

Oid
securityTransSecLabelIn(Oid relid, const char *seclabel)
{
	return securityRawSecLabelIn(relid, seclabel);
}

char *
securityTransSecLabelOut(Oid relid, Oid secid)
{
	char *seclabel = securityRawSecLabelOut(relid, secid);

	return seclabel;
}

Oid
securityTransRowAclIn(Oid relid, Acl *acl)
{
	char   *secacl = NULL;

	return InputSecurityAttr(relid, SECKIND_SECURITY_ACL, secacl);
}

Acl *
securityTransRowAclOut(Oid relid, Oid secid, Oid ownid)
{
	char   *secacl = OutputSecurityAttr(relid, SECKIND_SECURITY_ACL, secid);
	Acl	   *acl = NULL;

	if (!acl)
		acl = acldefault(ACL_OBJECT_TUPLE, ownid);

	return acl;
}

/*
 * Output handler for system columns
 */
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

/*
 * Create/Drop database event handler
 */
void
securityOnDatabaseCreate(Oid tmpid, Oid newid)
{
	Relation		rel;
	CatalogIndexState	ind;
	SysScanDesc		scan;
	ScanKeyData		key[1];
	HeapTuple		oldtup, newtup;
	Datum			values[Natts_pg_security];
	bool			nulls[Natts_pg_security];
	bool			repls[Natts_pg_security];

	rel = heap_open(SecurityRelationId, RowExclusiveLock);
	ind = CatalogOpenIndexes(rel);

	/* Scan all the entries with tmpid == pg_security.datid */
	ScanKeyInit(&key[0],
				Anum_pg_security_datid,
				BTEqualStrategyNumber, F_OIDEQ,
				ObjectIdGetDatum(tmpid));
	scan = systable_beginscan(rel, SecuritySecidIndexId, true,
							  SnapshotNow, 1, key);
	/* Set up to copy the tuples except for inserting newid  */
	memset(values, 0, sizeof(values));
	memset(nulls, false, sizeof(nulls));
	memset(repls, false, sizeof(nulls));

	values[Anum_pg_security_datid - 1] = ObjectIdGetDatum(newid);
	repls[Anum_pg_security_datid - 1] = true;

	/* Insert entries within old database */
	while (HeapTupleIsValid(oldtup = systable_getnext(scan)))
	{
		newtup = heap_modify_tuple(oldtup, RelationGetDescr(rel),
								   values, nulls, repls);
		simple_heap_insert(rel, newtup);

		CatalogIndexInsert(ind, newtup);

		heap_freetuple(newtup);
	}

	systable_endscan(scan);

	CatalogCloseIndexes(ind);

	heap_close(rel, RowExclusiveLock);
}

void
securityOnDatabaseDrop(Oid datid)
{
	Relation		rel;
	SysScanDesc		scan;
	ScanKeyData		key[1];
	HeapTuple		tuple;

	rel = heap_open(SecurityRelationId, RowExclusiveLock);

	ScanKeyInit(&key[0],
				Anum_pg_security_datid,
				BTEqualStrategyNumber, F_OIDEQ,
				ObjectIdGetDatum(datid));

	scan = systable_beginscan(rel, SecuritySecidIndexId, true,
							  SnapshotNow, 1, key);

	while (HeapTupleIsValid(tuple = systable_getnext(scan)))
	{
		simple_heap_delete(rel, &tuple->t_self);
	}

	systable_endscan(scan);

	heap_close(rel, RowExclusiveLock);
}
