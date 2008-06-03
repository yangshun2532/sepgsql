/*
 * src/backend/security/pgaceCommon.c
 *   Common part of PostgreSQL Access Control Extension
 * Copyright 2007 KaiGai Kohei <kaigai@kaigai.gr.jp>
 */
#include "postgres.h"

#include "access/genam.h"
#include "access/hash.h"
#include "access/heapam.h"
#include "access/xact.h"
#include "catalog/catalog.h"
#include "catalog/indexing.h"
#include "catalog/pg_attribute.h"
#include "catalog/pg_largeobject.h"
#include "catalog/pg_security.h"
#include "catalog/pg_type.h"
#include "executor/executor.h"
#include "miscadmin.h"
#include "nodes/makefuncs.h"
#include "nodes/parsenodes.h"
#include "parser/parse_expr.h"
#include "security/pgace.h"
#include "utils/builtins.h"
#include "utils/fmgroids.h"
#include "utils/syscache.h"
#include "utils/tqual.h"
#include <unistd.h>
#include <sys/file.h>

/*****************************************************************************
 *   Extended SQL statements support
 *****************************************************************************/

/* CREATE TABLE with explicit CONTEXT */
List *pgaceRelationAttrList(CreateStmt *stmt)
{
	List *result = NIL;
	ListCell *l;
	DefElem *defel, *newel;

	if (stmt->pgaceItem) {
		defel = (DefElem *) stmt->pgaceItem;

		Assert(IsA(defel, DefElem));
		if (!pgaceIsGramSecurityItem(defel))
			elog(ERROR, "node is not a pgace security item");
		newel = makeDefElem(NULL, (Node *) copyObject(defel));
		result = lappend(result, newel);
	}

	foreach (l, stmt->tableElts) {
		ColumnDef *cdef = (ColumnDef *) lfirst(l);
		defel = (DefElem *) cdef->pgaceItem;

		if (defel) {
			Assert(IsA(defel, DefElem));
			if (!pgaceIsGramSecurityItem(defel))
				elog(ERROR, "node is not a pgace security item");
			newel = makeDefElem(pstrdup(cdef->colname),
								(Node *) copyObject(defel));
			result = lappend(result, newel);
		}
	}
	return result;
}

void pgaceCreateRelationCommon(Relation rel, HeapTuple tuple, List *pgace_attr_list) {
	ListCell *l;

	foreach (l, pgace_attr_list) {
		DefElem *defel = (DefElem *) lfirst(l);

		if (!defel->defname) {
			Assert(pgaceIsGramSecurityItem((DefElem *)defel->arg));
			pgaceGramCreateRelation(rel, tuple, (DefElem *)defel->arg);
			break;
		}
	}
}

void pgaceCreateAttributeCommon(Relation rel, HeapTuple tuple, List *pgace_attr_list) {
	Form_pg_attribute attr = (Form_pg_attribute) GETSTRUCT(tuple);
	ListCell *l;

	foreach (l, pgace_attr_list) {
		DefElem *defel = lfirst(l);

		if (!defel->defname)
			continue;	/* for table */
		if (!strcmp(defel->defname, NameStr(attr->attname))) {
			Assert(pgaceIsGramSecurityItem((DefElem *)defel->arg));
			pgaceGramCreateAttribute(rel, tuple, (DefElem *)defel->arg);
			break;
		}
	}
}

/* ALTER <tblname> [ALTER <colname>] CONTEXT = 'xxx' statement */
static void alterRelationCommon(Relation rel, DefElem *defel) {
	Relation pg_class;
	HeapTuple tuple;

	pg_class = heap_open(RelationRelationId, RowExclusiveLock);

	tuple = SearchSysCacheCopy(RELOID,
							   ObjectIdGetDatum(RelationGetRelid(rel)),
							   0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "cache lookup failed for relation '%s'", RelationGetRelationName(rel));
	pgaceGramAlterRelation(rel, tuple, defel);

	simple_heap_update(pg_class, &tuple->t_self, tuple);
	CatalogUpdateIndexes(pg_class, tuple);

	heap_freetuple(tuple);
	heap_close(pg_class, RowExclusiveLock);
}

static void alterAttributeCommon(Relation rel, char *colName, DefElem *defel) {
	Relation pg_attr;
	HeapTuple tuple;

	pg_attr = heap_open(AttributeRelationId, RowExclusiveLock);

	tuple = SearchSysCacheCopyAttName(RelationGetRelid(rel), colName);
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "cache lookup failed for attribute '%s' of relation '%s'", 
			 colName, RelationGetRelationName(rel));
	pgaceGramAlterAttribute(rel, tuple, defel);

	simple_heap_update(pg_attr, &tuple->t_self, tuple);
	CatalogUpdateIndexes(pg_attr, tuple);

	heap_freetuple(tuple);
	heap_close(pg_attr, RowExclusiveLock);
}

void pgaceAlterRelationCommon(Relation rel, AlterTableCmd *cmd) {
	DefElem *defel = (DefElem *) cmd->def;

	Assert(IsA(defel, DefElem));

	if (!pgaceIsGramSecurityItem(defel))
		elog(ERROR, "unsupported pgace security item");

	if (!cmd->name) {
		alterRelationCommon(rel, defel);
	} else {
		alterAttributeCommon(rel, cmd->name, defel);
	}
}

/*****************************************************************************
 *  security attribute management
 *****************************************************************************/

typedef struct earlySeclabel {
	struct earlySeclabel *next;
	Oid sid;
	char label[1];
} earlySeclabel;

static earlySeclabel *earlySeclabelList = NULL;

static Oid earlySecurityLabelToSid(char *label)
{
	earlySeclabel *es;
	Oid minsid = SecurityRelationId;

	for (es = earlySeclabelList; es != NULL; es = es->next)
	{
		if (!strcmp(label, es->label))
			return es->sid;
		if (es->sid < minsid)
			minsid = es->sid;
	}
	/* not found */
	es = malloc(sizeof(earlySeclabel) + strlen(label));
	es->next = earlySeclabelList;
	es->sid = minsid - 1;
	strcpy(es->label, label);
	earlySeclabelList = es;

	return es->sid;
}

static char *earlySidToSecurityLabel(Oid sid)
{
	earlySeclabel *es;

	for (es = earlySeclabelList; es != NULL; es = es->next)
	{
		if (es->sid == sid)
			return pstrdup(es->label);
	}
	/* not found */
	return NULL;
}

void pgacePostBootstrapingMode(void)
{
	Relation rel;
	CatalogIndexState ind;
	HeapTuple tuple;
	earlySeclabel *es, *_es;
	Oid meta_sid;
	Datum value;
	char isnull;

	StartTransactionCommand();

	meta_sid = earlySecurityLabelToSid(pgaceSecurityLabelOfLabel());

	rel = heap_open(SecurityRelationId, RowExclusiveLock);
	ind = CatalogOpenIndexes(rel);

	for (es = earlySeclabelList; es != NULL; es = _es)
	{
		_es = es->next;

		value = DirectFunctionCall1(textin, CStringGetDatum(es->label));
		isnull = ' ';
		tuple = heap_formtuple(RelationGetDescr(rel), &value, &isnull);

		HeapTupleSetOid(tuple, es->sid);
		HeapTupleSetSecurity(tuple, meta_sid);

		simple_heap_insert(rel, tuple);
		CatalogIndexInsert(ind, tuple);

		heap_freetuple(tuple);

		free(es);
	}
	CatalogCloseIndexes(ind);
	heap_close(rel, RowExclusiveLock);

	CommitTransactionCommand();
}

static Oid lookupSecurityIdCommon(char *label)
{
	Relation rel;
	HeapTuple tuple;
	SysScanDesc scan;
    ScanKeyData skey;
	Datum labelTxt;
	Oid labelOid;

	if (IsBootstrapProcessingMode())
		return earlySecurityLabelToSid(label);

	/* 1. lookup syscache */
	labelTxt = CStringGetTextDatum(label);
	tuple = SearchSysCache(SECURITYLABEL,
						   labelTxt, 0, 0, 0);
	if (HeapTupleIsValid(tuple)) {
		labelOid = HeapTupleGetOid(tuple);
		ReleaseSysCache(tuple);
		goto out;
	}

	/* 2. lookup pg_security with SnapshotSelf */
	rel = heap_open(SecurityRelationId, RowExclusiveLock);

	ScanKeyInit(&skey,
				Anum_pg_security_seclabel,
				BTEqualStrategyNumber, F_TEXTEQ,
				PointerGetDatum(labelTxt));
	scan = systable_beginscan(rel, SecuritySeclabelIndexId,
							  true, SnapshotSelf, 1, &skey);
	tuple = systable_getnext(scan);
	labelOid = HeapTupleIsValid(tuple)
		? HeapTupleGetOid(tuple) : InvalidOid;
	systable_endscan(scan);
out:
	return labelOid;
}

static char *lookupSecurityLabelCommon(Oid security_id)
{
	Relation rel;
	SysScanDesc scan;
    ScanKeyData skey;
    HeapTuple tuple;
    Datum labelTxt;
    char *label = NULL;
    bool isnull;

	if (IsBootstrapProcessingMode())
		return earlySidToSecurityLabel(security_id);

	/* 1. lookup system cache */
	tuple = SearchSysCache(SECURITYOID,
						   ObjectIdGetDatum(security_id),
						   0, 0, 0);
	if (HeapTupleIsValid(tuple))
	{
		labelTxt = SysCacheGetAttr(SECURITYOID,
								   tuple,
								   Anum_pg_security_seclabel,
								   &isnull);
		Assert(!isnull);
		label = TextDatumGetCString(labelTxt);
		ReleaseSysCache(tuple);
		return label;
	}

	/* 2. lookup pg_security with SnapshotSelf */
	rel = heap_open(SecurityRelationId, AccessShareLock);

	ScanKeyInit(&skey,
				ObjectIdAttributeNumber,
				BTEqualStrategyNumber, F_OIDEQ,
				ObjectIdGetDatum(security_id));
	scan = systable_beginscan(rel, SecurityOidIndexId,
							  true, SnapshotSelf, 1, &skey);
	tuple = systable_getnext(scan);
	if (HeapTupleIsValid(tuple)) {
		labelTxt = SysCacheGetAttr(SECURITYOID,
								   tuple,
								   Anum_pg_security_seclabel,
								   &isnull);
		Assert(!isnull);
		label = TextDatumGetCString(labelTxt);
	}
	systable_endscan(scan);
	heap_close(rel, AccessShareLock);

	return label;
}

Oid pgaceSecurityLabelToSid(char *label)
{
	Relation rel;
	CatalogIndexState ind;
	HeapTuple tuple;
	Oid labelOid, labelSid;
	Datum labelTxt;
	char isnull, *slabel;

	/* valid label checks */
	label = pgaceTranslateSecurityLabelIn(label);
	label = pgaceValidateSecurityLabel(label);

	labelOid = lookupSecurityIdCommon(label);
	if (labelOid == InvalidOid)
	{
		/* not found, insert a new one */
		rel = heap_open(SecurityRelationId, RowExclusiveLock);

		slabel = pgaceSecurityLabelOfLabel();

		if (!strcmp(label, slabel))
		{
			labelOid = labelSid = GetNewOid(rel);
		}
		else
		{
			labelSid = pgaceSecurityLabelToSid(slabel);
			labelOid = GetNewOid(rel);
		}
		ind = CatalogOpenIndexes(rel);

		labelTxt = CStringGetTextDatum(label);
		isnull = ' ';
		tuple = heap_formtuple(RelationGetDescr(rel),
							   &labelTxt, &isnull);
		HeapTupleSetSecurity(tuple, labelSid);
		HeapTupleSetOid(tuple, labelOid);

		simple_heap_insert(rel, tuple);
		CatalogIndexInsert(ind, tuple);

		CatalogCloseIndexes(ind);
		heap_close(rel, RowExclusiveLock);
	}
	return labelOid;
}

char *pgaceSidToSecurityLabel(Oid security_id)
{
	char *sec_label;

	if (security_id == InvalidOid)
		sec_label = pgaceValidateSecurityLabel(NULL);
	else
	{
		sec_label = lookupSecurityLabelCommon(security_id);
		if (!sec_label)
			elog(ERROR, "security id: %u is not a valid identifier", security_id);
	}
	sec_label = pgaceTranslateSecurityLabelOut(sec_label);
	Assert(sec_label != NULL);

	return sec_label;
}

char *pgaceLookupSecurityLabel(Oid security_id)
{
	char *sec_label;

	if (security_id == InvalidOid)
		sec_label = pgaceValidateSecurityLabel(NULL);
	else
	{
		sec_label = lookupSecurityLabelCommon(security_id);
		if (!sec_label)
			elog(ERROR, "security id: %u is not a valid identifier", security_id);
	}
	Assert(sec_label != NULL);

	return sec_label;
}

/*****************************************************************************
 *	 Set/Get security attribute of Large Object
 *****************************************************************************/
Datum
lo_get_security(PG_FUNCTION_ARGS)
{
	Oid loid = PG_GETARG_OID(0);
	Oid security_id = InvalidOid;
	Relation rel;
	ScanKeyData skey;
	SysScanDesc sd;
	HeapTuple tuple;
	bool found = false;

	ScanKeyInit(&skey,
				Anum_pg_largeobject_loid,
				BTEqualStrategyNumber, F_OIDEQ,
				ObjectIdGetDatum(loid));

	rel = heap_open(LargeObjectRelationId, AccessShareLock);

	sd = systable_beginscan(rel, LargeObjectLOidPNIndexId, true,
							SnapshotNow, 1, &skey);

	while ((tuple = systable_getnext(sd)) != NULL) {
		security_id = HeapTupleGetSecurity(tuple);
		pgaceLargeObjectGetSecurity(rel, tuple);
		found = true;
		break;
	}
	systable_endscan(sd);

	heap_close(rel, AccessShareLock);

	if (!found)
		elog(ERROR, "large object %u does not exist", loid);

	return CStringGetTextDatum(pgaceSidToSecurityLabel(security_id));
}

Datum
lo_set_security(PG_FUNCTION_ARGS)
{
	Oid loid = PG_GETARG_OID(0);
	Datum labelTxt = PG_GETARG_TEXT_P(1);
	Oid security_id;
	Relation rel;
	ScanKeyData skey;
	SysScanDesc sd;
	HeapTuple tuple, newtup;
	CatalogIndexState indstate;
	bool found = false;

	security_id = pgaceSecurityLabelToSid(TextDatumGetCString(labelTxt));

	ScanKeyInit(&skey,
				Anum_pg_largeobject_loid,
				BTEqualStrategyNumber, F_OIDEQ,
				ObjectIdGetDatum(loid));

	rel = heap_open(LargeObjectRelationId, RowExclusiveLock);

	indstate = CatalogOpenIndexes(rel);

	sd = systable_beginscan(rel, LargeObjectLOidPNIndexId, true,
							SnapshotNow, 1, &skey);

	while ((tuple = systable_getnext(sd)) != NULL) {
		newtup = heap_copytuple(tuple);
		HeapTupleSetSecurity(newtup, security_id);
		if (!found)
			pgaceLargeObjectSetSecurity(rel, tuple, newtup);
		simple_heap_update(rel, &newtup->t_self, newtup);
		CatalogUpdateIndexes(rel, newtup);
		found = true;
	}
	systable_endscan(sd);
	CatalogCloseIndexes(indstate);
	heap_close(rel, RowExclusiveLock);

	CommandCounterIncrement();

	if (!found)
		elog(ERROR, "large object %u does not exist.", loid);

	PG_RETURN_BOOL(true);
}

/******************************************************************
 * Extended functions stub
 ******************************************************************/

/*
 * In this section, you can put function stubs when your security
 * module is not activated.
 */
#ifndef HAVE_SELINUX
/*
 * SE-PostgreSQL adds three functions.
 * When it is disabled, call them causes an error.
 */
Datum sepgsql_getcon(PG_FUNCTION_ARGS)
{
	elog(ERROR, "%s is not implemented", __FUNCTION__);
	PG_RETURN_VOID();
}

Datum sepgsql_tuple_perms(PG_FUNCTION_ARGS)
{
	elog(ERROR, "%s is not implemented", __FUNCTION__);
	PG_RETURN_VOID();
}

Datum sepgsql_tuple_perms_abort(PG_FUNCTION_ARGS)
{
	elog(ERROR, "%s is not implemented", __FUNCTION__);
	PG_RETURN_VOID();
}
#endif  /* HAVE_SELINUX */


