/*
 * src/backend/catalog/pg_security.c
 *    routines to support security label management
 *
 * Portions Copyright (c) 1996-2009, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 */
#include "postgres.h"

#include "access/heapam.h"
#include "access/xact.h"
#include "catalog/catalog.h"
#include "catalog/indexing.h"
#include "catalog/pg_security.h"
#include "miscadmin.h"
#include "security/sepgsql.h"
#include "utils/builtins.h"
#include "utils/memutils.h"
#include "utils/rel.h"
#include "utils/syscache.h"

bool
securityTupleDescHasSecLabel(Relation rel)
{
	return sepgsqlTupleDescHasSecLabel(rel);
}

static char *
securityMetaSecurityLabel(void)
{
	return sepgsqlMetaSecurityLabel();
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
	earlySecLabel  *es;
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
	es->next = earlySecLabelList;
	es->secid = minsecid - 1;
	strcpy(es->seclabel, seclabel);
	earlySecLabelList = es;

	return es->secid;
}

static char *
earlyLookupSecurityLabel(Oid secid)
{
	earlySecLabel  *es;

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
	earlySecLabel	   *es;
	Oid					labelSid;
	Datum				values[Natts_pg_security];
	bool				nulls[Natts_pg_security];
	char			   *meta_label;

	if (!earlySecLabelList)
		return;		/* do nothing */

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
	 * or more within same command id, we cannot decide
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

	if (!OidIsValid(secid))
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

/*
 * "security_label" system column related stuffs
 */
Oid
securityTransSecLabelIn(char *seclabel)
{
	char   *rawlabel = sepgsqlSecurityLabelTransIn(seclabel);

	return securityLookupSecurityId(rawlabel);
}

char *
securityTransSecLabelOut(Oid secid)
{
	char   *rawlabel = securityLookupSecurityLabel(secid);
	char   *seclabel;

	seclabel = sepgsqlSecurityLabelTransOut(rawlabel);
	if (!seclabel)
		seclabel = pstrdup("unlabeled");

	return seclabel;
}

Datum
securityHeapGetSecLabelSysattr(HeapTuple tuple)
{
	Oid		secid = HeapTupleGetSecLabel(tuple);

	return CStringGetTextDatum(securityTransSecLabelOut(secid));
}
