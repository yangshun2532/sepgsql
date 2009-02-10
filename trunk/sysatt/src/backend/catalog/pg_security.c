/*
 * src/backend/catalog/pg_security.c
 *    routines to support security label management
 *
 * Portions Copyright (c) 1996-2009, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 */
#include "postgres.h"

bool
securityTupleDescHasRowAcl(Relation rel)
{
	return false;
}

bool
securityTupleDescHasSecLabel(Relation rel)
{
	/*
	 * TODO: add sepgsqlXXXX() invocation here
	 */
	return true;
}

static char *
securityMetaSecurityLabel(void)
{
	/*
	 * TODO: add sepgsqlXXXX() invocation here
	 */
	return NULL;
}

typedef struct earlySecLabel
{
	struct earlySecLabel   *next;
	Oid			secid;
	char		seclabel[1];
} earlySecLabel;

static earlySecLabel *earlySecLabelList = NULL;

static Oid
earlyLookupSecurityId(const char *seclabel)
{
	earlySeclabel  *es;
	Oid				minsecid = SecurityRelationId;

	for (es = earlySecLabelList; es; es = es->next)
	{
		if (strcmp(seclabel, es->seclabel) == 0)
			return es->secid;
		if (es->secid < minsecid)
			minsecid = es->secid;
	}

	/* not found */
	es = MemoryContextAllocZero(TopMemoryContext,
								sizeof(*es) + strlen(seclabel));
	es->next = earlySeclabelList;
	es->secid = minsecid - 1;
	strcpy(es->seclabel, seclabel);
	earlySeclabelList = es;

	return es->secid;
}

static char *
earlyLookupSecurityLabel(Oid secid)
{
	earlySeclabel  *es;

	for (es = earlySecLabelList; es; es = es->next)
	{
		if (es->secid == secid)
			return pstrdup(es->seclabel);
	}

	return NULL;	/* not found */
}

void
securityPostBootstrapingMode(void)
{
	Relation			rel;
	CatalogIndexState	ind;
	HeapTuple			tuple;
	earlySeclabel	   *es;
	Oid					labelSid;
	Datum				values[Natts_pg_security];
	bool				nulls[Natts_pg_security];
	char			   *meta_label;

	if (!earlySecLabelList)
		return;	/* do nothing */

	StartTransactionCommand();

	rel = heap_open(SecurityRelationId, RowExclusiveLock);
	ind = CatalogOpenIndexes(rel);

	if (RelationGetDescr(rel)->tdhasseclabel &&
		(meta_label = securityMetaSecurityLabel()) != NULL)
		labelSid = earlyLookupSecurityId(meta_label);
	else
		labelSid = InvalidOid;

	for (es = earlySecLabelList; es; es = es->next)
	{
		memset(nulls, false, sizeof(nulls));

		values[Anum_pg_security_secused - 1]
			= BoolGetDatum(true);
		values[Anum_pg_security_seclabel - 1]
			= CStringGetTextDatum(es->seclabel);

		tuple = heap_form_tuple(RelationGetDescr(rel),
								values, nulls);
		HeapTupleSetOid(tuple, es->secid);
		if (HeapTupleHasSecLabel(tuple))
			HeapTupleSetSecLabel(tuple, labelSid);

		simple_heap_insert(rel, tuple);
		CatalogIndexInsert(ind, tuple);

		heap_freetuple(tuple);
	}

	CatalogCloseIndexes(ind);
	heap_close(rel, RowExclusiveLock);

	CommitTransactionCommand();
}

Oid
securityLookupSecurityId(const char *seclabel)
{
	Relation			rel;
	CatalogIndexState	ind;
	HeapTuple			tuple;
	Oid					labelOid;
	Oid					labelSid;
	Datum				values[Natts_pg_security];
	bool				nulls[Natts_pg_security];
	char			   *meta_label;

	if (IsBootstrapProcessingMode())
		return earlyLookupSecurityId(seclabel);

	/*
	 * lookup syscache at first
	 */
	tuple = SearchSysCache(SECURITYLABEL,
						   CStringGetTextDatum(seclabel),
						   0, 0, 0);
	if (HeapTupleIsValid(tuple))
	{
		labelOid = HeapTupleGetOid(tuple);
		ReleaseSysCache(tuple);
		return labelOid;
	}

	/*
	 * Not found, insert a new one into pg_security
	 */
	rel = heap_open(SecurityRelationId, RowExclusiveLock);

	ind = CatalogOpenIndexes(rel);

	if (RelationGetDescr(rel)->tdhasseclabel &&
		(meta_label = securityMetaSecurityLabel()) != NULL)
	{
		if (strcmp(seclabel, meta_label) == 0)
		{
			labelOid = labelSid = GetNewOid(rel);
		}
		else
		{
			labelOid = GetNewOid(rel);
			labelSid = securityLookupSecurityId(meta_label);
		}
	}
	else
	{
		labelOid = GetNewOid(rel);
		labelSid = InvalidOid;
	}

	memset(nulls, false, sizeof(nulls));
	values[Anum_pg_security_secused - 1]
		= BoolGetDatum(true);
	values[Anum_pg_security_seclabel - 1]
		= CStringGetTextDatum(seclabel);

	tuple = heap_form_tuple(RelationGetDescr(rel),
							values, nulls);

	if (HeapTupleHasSecLabel(tuple))
		HeapTupleSetSecLabel(tuple, labelSid);
	HeapTupleSetOid(tuple, labelOid);

	simple_heap_insert(rel, tuple);
	CatalogIndexInsert(ind, tuple);

	/*
	 * NOTE:
	 * We also have to insert a cache entry of new tuple of
	 * pg_security for temporary usage.
	 * If user tries to apply same security attribute twice
	 * or more within same command id, PGACE cannot decide
	 * whether it should be inserted, or not, because it
	 * cannot scan the prior one with SnapshotNow.
	 *
	 * A cache entry inserted will be invalidated on the
	 * next CommandIdIncrement().
	 * The purpose of InsertSysCache() here is to prevent
	 * duplicate insertion
	 */
	InsertSysCache(RelationGetRelid(rel), tuple);

	CatalogCloseIndexes(ind);

	heap_close(rel, RowExclusiveLock);

	return labelOid;
}

char *
securityLookupSecurityLabel(Oid secid)
{
	HeapTuple	tuple;
	Datum		labelTxt;
	char	   *label;
	bool		isnull;

	if (!OidIsValid(sid))
		return NULL;

	if (IsBootstrapProcessingMode())
		return earlyLookupSecurityLabel(secid);

	tuple = SearchSysCache(SECURITYOID,
						   ObjectIdGetDatum(secid),
						   0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		return NULL;

	labelTxt = SysCacheGetAttr(SECURITYOID, tuple,
							   Anum_pg_security_seclabel,
							   &isnull);
	Assert(!isnull);
	label = TextDatumGetCString(labelTxt);
	ReleaseSysCache(tuple);

	return label;
}

Oid
securityTransSecurityLabelIn(const char *seclabel)
{}

char *
securityTransSecurityLabelOut(Oid secid)
{}

Oid
securityTransRowAclIn(const Acl *acl)
{}

Acl *
securityTransRowAclOut(Oid secid)
{}

Datum
securityHeapGetSecurityAclSysattr(HeapTuple tuple)
{}

Datum
securityHeapGetSecurityLabelSysattr(HeapTuple tuple)
{}
