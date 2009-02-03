/*
 * src/backend/utils/sepgsql/label.c
 *    SE-PostgreSQL security label management
 *
 * Portions Copyright (c) 1996-2009, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 */
#include "postgres.h"

#include "access/xact.h"
#include "catalog/catalog.h"
#include "catalog/indexing.h"
#include "catalog/pg_database.h"
#include "catalog/pg_proc.h"
#include "catalog/pg_security.h"
#include "miscadmin.h"
#include "utils/builtins.h"
#include "utils/memutils.h"
#include "utils/sepgsql.h"
#include "utils/syscache.h"

/*
 * The following functions enables to manage security label of tuples.
 *
 * Security attribute has these features:
 * 1. It is imported/exported with text representation, like
 *    'system_u:object_r:sepgsql_table_t:s0'
 * 2. In generally, many tuples share a same security label.
 *    (They are grouped by security label in other word.)
 * 3. A object can have one security label at most.
 *    (It can have a state of unlabeled.)
 *
 * SE-PostgreSQL utilizes pg_security system catalog to store the text
 * representation of security label, and each tuple has its object id
 * ("oid") to identify own security label. We call it as security id
 * which enables to accociate with its text representation.
 * Please note that security id is purely internal representation, so
 * it does not have any guarantee a security id is associate with correct
 * security label outside of the system.
 *
 * It enables users to handle security label as if it stored as text data.
 * But it is translated into security id before it is stored in a tuple,
 * so it is not necessary any tuple to hold it as a string.
 * The security id is put on the padding field of HeapTupleHeader, with
 * sizeof(Oid) bytes length, as if "oid" doing here.
 *
 * Note: sepgsqlTupleDescHasSecLabel() can make a decision whether the
 * given relation can have a security label, or not. Currently, it is
 * limited to a few system catalog due to the row-level controls is
 * postponed.
 *
 * sepgsqlSidToSecurityLabel() returns a text representation for the
 * given security id, contrastingly, sepgsqlSecurityLabelToSid() returns
 * a security id for the given security label in text form. If the given
 * text form is not found on pg_security, it inserts a new entry automatically
 * and returns its security id.
 *
 * In the very early phase (invoked by initdb), pg_security system catalos is
 * not available yet. The earlySecurityLabelToSid() and earlySidToSecurityLabel()
 * is used to hold relationships between security id and text representation.
 * These relationships are stored at the end of bootstraping mode by
 * sepgsqlPostBootstrapingMode(). It write any cached relationships into
 * pg_security system catalog.
 */

/*
 * HeapTupleHasSecLabel
 * HeapTupleGetSecLabel
 * HeapTupleSetSecLabel
 *
 * These are workaround facilities to manage security attribute of
 * tuples. The current version assumes security identifier is assigned
 * to tuples within pg_database, pg_class, pg_attribute and pg_proc.
 * A specific column of these system columns are used to store it.
 */
bool
HeapTupleHasSecLabel(Oid relid, HeapTuple tuple)
{
	security_class_t tclass
		= sepgsqlTupleObjectClass(relid, tuple);

	if (tclass == SECCLASS_DB_DATABASE ||
		tclass == SECCLASS_DB_TABLE ||
		tclass == SECCLASS_DB_COLUMN ||
		tclass == SECCLASS_DB_PROCEDURE)
		return true;

	return false;
}

Oid
HeapTupleGetSecLabel(Oid relid, HeapTuple tuple)
{
	security_class_t tclass
		= sepgsqlTupleObjectClass(relid, tuple);

	switch (tclass)
	{
	case SECCLASS_DB_DATABASE:
		return ((Form_pg_database) GETSTRUCT(tuple))->datsecid;
	case SECCLASS_DB_TABLE:
		return ((Form_pg_class) GETSTRUCT(tuple))->relsecid;
	case SECCLASS_DB_COLUMN:
		return ((Form_pg_attribute) GETSTRUCT(tuple))->attsecid;
	case SECCLASS_DB_PROCEDURE:
		return ((Form_pg_proc) GETSTRUCT(tuple))->prosecid;
	}
	return InvalidOid;
}

void
HeapTupleSetSecLabel(Oid relid, HeapTuple tuple, Oid secid)
{
	security_class_t tclass
		= sepgsqlTupleObjectClass(relid, tuple);

	Assert(HeapTupleHasSecLabel(relid, tuple));

	switch (tclass)
	{
	case SECCLASS_DB_DATABASE:
		((Form_pg_database) GETSTRUCT(tuple))->datsecid = secid;
		break;
	case SECCLASS_DB_TABLE:
		((Form_pg_class) GETSTRUCT(tuple))->relsecid = secid;
		break;
	case SECCLASS_DB_COLUMN:
		((Form_pg_attribute) GETSTRUCT(tuple))->attsecid = secid;
		break;
	case SECCLASS_DB_PROCEDURE:
		((Form_pg_proc) GETSTRUCT(tuple))->prosecid = secid;
		break;
	}
}

/*
 * sepgsqlComputeMetaLabel()
 *   returns a security label to be assigned pg_security stuff
 */
static char *
sepgsqlComputeMetaLabel(void)
{
	char	   *tlabel, *mlabel;
	HeapTuple	tuple;

	tuple = SearchSysCache(RELOID,
						   ObjectIdGetDatum(SecurityRelationId),
						   0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "SELinux: cache lookup failed for relation %u",
			 SecurityRelationId);

	tlabel = sepgsqlLookupSecurityLabel(HeapTupleGetSecLabel(RelationRelationId, tuple));
	if (!tlabel || !sepgsqlCheckValidSecurityLabel(tlabel))
		tlabel = sepgsqlGetUnlabeledLabel();

	mlabel = sepgsqlComputeCreate(sepgsqlGetServerLabel(),
								  tlabel, SECCLASS_DB_TUPLE);
	ReleaseSysCache(tuple);

	return mlabel;
}

/*
 * struct earlySecLabel
 *   enables to contain a pair of security id/label in early phase
 */
typedef struct earlySecLabel
{
	Oid		sid;
	char	label[1];
} earlySecLabel;

static List *earlySecLabelList = NIL;

/*
 * earlySecurityLabelToSid()
 *   returns a security id for the given text form
 *   on bootstraping mode.
 */
static Oid
earlySecurityLabelToSid(security_context_t label)
{
	MemoryContext oldctx;
	ListCell *l;
	earlySecLabel *es;
	Oid minsid = SecurityRelationId;

	foreach (l, earlySecLabelList)
	{
		es = lfirst(l);

		if (strcmp(label, es->label) == 0)
			return es->sid;
		if (es->sid < minsid)
			minsid = es->sid;
	}
	/* not found, so make a new one */
	oldctx = MemoryContextSwitchTo(TopMemoryContext);
	es = palloc(sizeof(earlySecLabel) + strlen(label));
	es->sid = minsid - 1;
	strcpy(es->label, label);
	earlySecLabelList = lappend(earlySecLabelList, es);
	MemoryContextSwitchTo(oldctx);

	return es->sid;
}

/*
 * earlySidToSecurityLabel()
 *   returns a security label (or NULL) for the given
 *   security id on bootstraping mode.
 */
static char *
earlySidToSecurityLabel(Oid sid)
{
	ListCell *l;

	foreach (l, earlySecLabelList)
	{
		earlySecLabel *es = lfirst(l);

		if (es->sid == sid)
			return pstrdup(es->label);
	}

	return NULL;	/* not found */
}

/*
 * sepgsqlPostBootstrapingMode()
 *   is invoked at the end of bootstraping mode to flush
 *   all the security label used in "early" phase into
 *   pg_security system catalog.
 */
void
sepgsqlPostBootstrapingMode(void)
{
	Relation			rel;
	CatalogIndexState	ind;
	HeapTuple			tuple;
	char			   *metaLabel;
	Oid					metaSid;
	ListCell		   *l;
	Datum				value[Natts_pg_security];
	bool				isnull[Natts_pg_security];

	if (!sepgsqlIsEnabled())
		return;

	StartTransactionCommand();

	metaLabel = sepgsqlComputeMetaLabel();
	metaSid = earlySecurityLabelToSid(metaLabel);

	rel = heap_open(SecurityRelationId, RowExclusiveLock);
	ind = CatalogOpenIndexes(rel);

	foreach (l, earlySecLabelList)
	{
		earlySecLabel *es = lfirst(l);

		memset(isnull, 0, sizeof(isnull));
		value[Anum_pg_security_seclabel - 1]
			= CStringGetTextDatum(es->label);

		tuple = heap_form_tuple(RelationGetDescr(rel),
								value, isnull);

		HeapTupleSetOid(tuple, es->sid);
		if (HeapTupleHasSecLabel(RelationGetRelid(rel), tuple))
			HeapTupleSetSecLabel(RelationGetRelid(rel), tuple, metaSid);

		simple_heap_insert(rel, tuple);
		CatalogIndexInsert(ind, tuple);

		heap_freetuple(tuple);
	}
	CatalogCloseIndexes(ind);
	heap_close(rel, RowExclusiveLock);

	CommitTransactionCommand();
}

/*
 * sepgsqlLookupSecurityId()
 *   returns a security identifier for the given security
 *   label. If it is not found, a new entry is automatically
 *   inserted into pg_security system catalog, then it returns
 *   its object id.
 */
Oid
sepgsqlLookupSecurityId(char *raw_label)
{
	Relation 			rel;
	CatalogIndexState	ind;
	HeapTuple			tuple;
	Oid					labelOid;
	Oid					labelSid;
	char			   *metaLabel;
	Datum				value[Natts_pg_security];
	bool				isnull[Natts_pg_security];

	if (IsBootstrapProcessingMode())
		return earlySecurityLabelToSid(raw_label);

	/*
	 * (1) Try to lookup syscache
	 */
	tuple = SearchSysCache(SECURITYLABEL,
						   CStringGetTextDatum(raw_label),
						   0, 0, 0);
	if (HeapTupleIsValid(tuple))
	{
		Oid sid = HeapTupleGetOid(tuple);
		ReleaseSysCache(tuple);

		return sid;
	}

	/*
	 * (2) Not found, insert a new one into pg_security
	 */
	rel = heap_open(SecurityRelationId, RowExclusiveLock);
	ind = CatalogOpenIndexes(rel);

	metaLabel = sepgsqlComputeMetaLabel();

	if (!metaLabel)
	{
		labelSid = InvalidOid;
		labelOid = GetNewOid(rel);
	}
	else if (strcmp(raw_label, metaLabel) == 0)
	{
		labelOid = labelSid = GetNewOid(rel);
	}
	else
	{
		labelSid = sepgsqlLookupSecurityId(metaLabel);
		labelOid = GetNewOid(rel);
	}

	memset(isnull, 0, sizeof(isnull));
	value[Anum_pg_security_seclabel - 1]
		= CStringGetTextDatum(raw_label);
	tuple = heap_form_tuple(RelationGetDescr(rel),
							value, isnull);
	HeapTupleSetOid(tuple, labelOid);
	if (HeapTupleHasSecLabel(RelationGetRelid(rel), tuple))
		HeapTupleSetSecLabel(RelationGetRelid(rel), tuple, labelSid);

	simple_heap_insert(rel, tuple);
	CatalogIndexInsert(ind, tuple);

	/*
	 * NOTE:
	 * We also have to insert a cache entry of new tuple of
	 * pg_security for temporary usage.
	 * If user tries to apply same security attribute twice
	 * or more within same command id, it cannot decide
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

/*
 * sepgsqlSecurityLabelToSid()
 *   returns a security identifier for the given text form.
 *   It also enables to translate external representation
 *   like ("Secret", "Unclassified", ...) into raw format
 *   and checks its validation, not only looking up
 *   pg_security
 */
Oid
sepgsqlSecurityLabelToSid(char *label)
{
	char   *raw_label;

	if (!sepgsqlIsEnabled())
		return InvalidOid;

	raw_label = sepgsqlSecurityLabelTransIn(label);

	if (!sepgsqlCheckValidSecurityLabel(raw_label))
		ereport(ERROR,
				(errcode(ERRCODE_SELINUX_ERROR),
				 errmsg("SELinux: invalid security label: %s", raw_label)));

	return sepgsqlLookupSecurityId(raw_label);
}

/*
 * sepgsqlLookupSecurityLabel()
 *   returns a security label in text form for the given security id,
 *   or NULL, if not found on pg_security.
 */
char *
sepgsqlLookupSecurityLabel(Oid sid)
{
	HeapTuple	tuple;
	Datum		labelTxt;
	char	   *label;
	bool		isnull;

	if (IsBootstrapProcessingMode())
		return earlySidToSecurityLabel(sid);

	tuple = SearchSysCache(SECURITYOID,
						   ObjectIdGetDatum(sid),
						   0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		return NULL;

	labelTxt = SysCacheGetAttr(SECURITYOID, tuple,
							   Anum_pg_security_seclabel, &isnull);
	Assert(!isnull);

	label = TextDatumGetCString(labelTxt);
	ReleaseSysCache(tuple);

	return label;
}

/*
 * sepgsqlSidToSecurityLabel()
 *   returns a security label in text form for the given security id,
 *   which is translated into external representation.
 *   Please note that it returns an "unlabeled" security label when
 *   security id is not valid, or the text form got obsoluted.
 *   So, this function never returns NULL.
 */
char *
sepgsqlSidToSecurityLabel(Oid sid)
{
	char   *raw_label;

	if (!sepgsqlIsEnabled())
		return pstrdup("");

	raw_label = sepgsqlLookupSecurityLabel(sid);
	if (!raw_label || !sepgsqlCheckValidSecurityLabel(raw_label))
		raw_label = sepgsqlGetUnlabeledLabel();

	return sepgsqlSecurityLabelTransOut(raw_label);
}

/*
 * sepgsqlSecurityLabelTransIn()
 *   translate external security label into internal one
 */
security_context_t
sepgsqlSecurityLabelTransIn(security_context_t context)
{
	security_context_t raw_context, result;

	if (selinux_trans_to_raw_context(context, &raw_context) < 0)
		ereport(ERROR,
				(errcode(ERRCODE_SELINUX_ERROR),
				 errmsg("SELinux: could not translate external label: %s", context)));
	PG_TRY();
	{
		result = pstrdup(raw_context);
	}
	PG_CATCH();
	{
		freecon(raw_context);
		PG_RE_THROW();
	}
	PG_END_TRY();

	freecon(raw_context);

	return result;
}

/*
 * sepgsqlSecurityLabelTransOut()
 *   translate internal security label into external one
 */
security_context_t
sepgsqlSecurityLabelTransOut(security_context_t context)
{
	security_context_t trans_context, result;

	if (selinux_raw_to_trans_context(context, &trans_context) < 0)
		ereport(ERROR,
				(errcode(ERRCODE_SELINUX_ERROR),
				 errmsg("SELinux: could not translate internal label: %s", context)));
	PG_TRY();
	{
		result = pstrdup(trans_context);
	}
	PG_CATCH();
	{
		freecon(trans_context);
		PG_RE_THROW();
	}
	PG_END_TRY();

	freecon(trans_context);

	return result;
}

/*
 * sepgsqlCheckValidSecurityLabel()
 *   checks whether the given security context is a valid one, or not
 */
bool
sepgsqlCheckValidSecurityLabel(security_context_t context)
{
	if (security_check_context_raw(context) < 0)
		return false;

	return true;
}
