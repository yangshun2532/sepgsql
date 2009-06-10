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
	return sepgsqlMetaSecurityLabel(true);
}

typedef struct earlySecLabel
{
	struct earlySecLabel   *next;
	Oid			secid;
	char		seclabel[1];
} earlySecLabel;

static earlySecLabel *earlySecLabelList = NULL;

static Oid
earlyInputSecurityAttr(const char *seclabel)
{
	static Oid		dummySecid = SecurityRelationId;
	earlySecLabel  *es;

	for (es = earlySecLabelList; es; es = es->next)
	{
		if (strcmp(seclabel, es->seclabel) == 0)
			return es->secid;
	}

	/* not found */
	es = MemoryContextAlloc(TopMemoryContext,
							sizeof(*es) + strlen(seclabel));
	es->secid = --dummySecid;
	strcpy(es->seclabel, seclabel);

	es->next = earlySecLabelList;
	earlySecLabelList = es;

	return es->secid;
}

static char *
earlyOutputSecurityAttr(Oid secid)
{
	earlySecLabel  *es;

	for (es = earlySecLabelList; es; es = es->next)
	{
		if (es->secid == secid)
			return pstrdup(es->seclabel);
	}
	return NULL;	/* Not found */
}

void
securityPostBootstrapingMode(void)
{
	Relation			rel;
	CatalogIndexState	ind;
	HeapTuple			tuple;
	earlySecLabel	   *es;
	Oid					labelSid = InvalidOid;
	Datum				values[Natts_pg_security];
	bool				nulls[Natts_pg_security];
	char			   *meta_label;

	if (!earlySecLabelList)
		return;		/* do nothing */

	StartTransactionCommand();

	meta_label = securityMetaSecurityLabel();
	if (meta_label)
		labelSid = securityTransSecLabelIn(SecurityRelationId, meta_label);

	rel = heap_open(SecurityRelationId, RowExclusiveLock);
	ind = CatalogOpenIndexes(rel);

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

/*
 * InputSecurityAttr
 */
static Oid
InputSecurityAttr(Oid relid, const char *seclabel)
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
		return earlyInputSecurityAttr(seclabel);
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
			labelSid = securityTransSecLabelIn(SecurityRelationId, meta_label);
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

static char *
OutputSecurityAttr(Oid relid, Oid secid)
{
	HeapTuple	tuple;
	Datum		labelTxt;
	char	   *label;
	bool		isnull;

	if (IsBootstrapProcessingMode())
		return earlyOutputSecurityAttr(secid);

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
	char *seclabel = OutputSecurityAttr(relid, secid);

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
	char *seclabel = securityRawSecLabelOut(relid, secid);

	return sepgsqlTransSecLabelOut(seclabel);
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
