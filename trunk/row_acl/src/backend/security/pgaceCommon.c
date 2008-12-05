
/*
 * src/backend/security/pgaceCommon.c
 *	  common framework of security modules
 *
 * Portions Copyright (c) 1996-2008, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
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
#include "libpq/be-fsstubs.h"
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
 *	 GUC Parameter Support
 *****************************************************************************/

/*
 * pgaceShowsFeatureIdentifier
 *
 * It is invoked when 'pgace_feature' is refered, and it has to return
 * an identifier of the guest.
 */
const char *
pgaceShowSecurityFeature(void)
{
	return pgaceSecurityFeatureIdentity();
}

/*****************************************************************************
 *	 Extended SQL statements support
 *****************************************************************************/

/*
 * PGACE enables to create a new table labed as explicitly specified security
 * attribute. It is implemented as an extension of SQL statement like:
 *   CREATE TABLE memo (
 *       id   integer primary key,
 *       msg  TEXT
 *   ) CONTEXT = 'system_u:object_r:sepgsql_secret_table_t';
 *
 * The specified security attribute is chained as a list of DefElem object,
 * at CreateStmt->pgaceItem for a table, ColumnDef->pgaceItem for a column.
 *
 * These items are generated at pgaceGramSecurityItem() hook invoked from
 * parser/gram.y. Then, pgaceRelationAttrList() pick them up and re-organize
 * as a list, to pass it as an argument of heap_create_with_catalog().
 *
 * When the list is not NIL, it means user specifies a security attribute
 * explicitly for a newly created table or column.
 * pgaceGramCreateRelation() and pgaceGramCreateAttribute() are invoked
 * just before inserting a new tuple into system catalog, and PGACE
 * framework invokes pgaceGramCreateRelation() and/or pgaceGramCreateAttribute()
 * hooks to give a chance the gurst to attach proper security attributes.
 */

List *
pgaceRelationAttrList(CreateStmt *stmt)
{
	List	   *result = NIL;
	ListCell   *l;
	DefElem    *defel, *newel;

	if (stmt->pgaceItem)
	{
		defel = (DefElem *) stmt->pgaceItem;

		Assert(IsA(defel, DefElem));

		if (!pgaceIsGramSecurityItem(defel))
			elog(ERROR, "node is not a pgace security item");
		newel = makeDefElem(NULL, (Node *) copyObject(defel));
		result = lappend(result, newel);
	}

	foreach(l, stmt->tableElts)
	{
		ColumnDef  *cdef = (ColumnDef *) lfirst(l);

		defel = (DefElem *) cdef->pgaceItem;

		if (defel)
		{
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

void
pgaceCreateRelationCommon(Relation rel, HeapTuple tuple, List *pgaceAttrList)
{
	ListCell   *l;

	foreach(l, pgaceAttrList)
	{
		DefElem    *defel = (DefElem *) lfirst(l);

		if (!defel->defname)
		{
			Assert(pgaceIsGramSecurityItem((DefElem *) defel->arg));
			pgaceGramCreateRelation(rel, tuple, (DefElem *) defel->arg);
			break;
		}
	}
}

void
pgaceCreateAttributeCommon(Relation rel, HeapTuple tuple,
						   List *pgaceAttrList)
{
	Form_pg_attribute attr = (Form_pg_attribute) GETSTRUCT(tuple);
	ListCell   *l;

	foreach(l, pgaceAttrList)
	{
		DefElem    *defel = lfirst(l);

		if (!defel->defname)
			continue;			/* for table */
		if (strcmp(defel->defname, NameStr(attr->attname)) == 0)
		{
			Assert(pgaceIsGramSecurityItem((DefElem *) defel->arg));
			pgaceGramCreateAttribute(rel, tuple, (DefElem *) defel->arg);
			break;
		}
	}
}

/*
 * pgaceAlterRelationCommon()
 *
 * This function is invoked when a user requires to change security attribute
 * of table/column with "ALTER TABLE" statement.
 *
 * When a user attempt to relabel a table, PGACE invokes alterRelationCommon()
 * and it gives the guest module a chance to set a new security attribute of
 * specified table.
 * When a user attempt to relabel a column, PGACE invokes alterAttributeCommon()
 * and it gives the guest module a chance to set a new security attribute of
 * specified column.
 */

static void
alterRelationCommon(Relation rel, DefElem *defel)
{
	Relation	pg_class;
	HeapTuple	tuple;

	pg_class = heap_open(RelationRelationId, RowExclusiveLock);

	tuple = SearchSysCacheCopy(RELOID,
							   ObjectIdGetDatum(RelationGetRelid(rel)),
							   0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "cache lookup failed for relation '%s'",
			 RelationGetRelationName(rel));
	pgaceGramAlterRelation(rel, tuple, defel);

	simple_heap_update(pg_class, &tuple->t_self, tuple);
	CatalogUpdateIndexes(pg_class, tuple);

	heap_freetuple(tuple);
	heap_close(pg_class, RowExclusiveLock);
}

static void
alterAttributeCommon(Relation rel, char *colName, DefElem *defel)
{
	Relation	pg_attr;
	HeapTuple	tuple;

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

void
pgaceAlterRelationCommon(Relation rel, AlterTableCmd *cmd)
{
	DefElem    *defel = (DefElem *) cmd->def;

	Assert(IsA(defel, DefElem));

	if (!pgaceIsGramSecurityItem(defel))
		ereport(ERROR,
				(errcode(ERRCODE_PGACE_ERROR),
				 errmsg("PGACE: unsupported security item")));

	if (!cmd->name)
	{
		alterRelationCommon(rel, defel);
	}
	else
	{
		alterAttributeCommon(rel, cmd->name, defel);
	}
}

/*****************************************************************************
 *	security attribute management
 *****************************************************************************/

/*
 * The following functions enables to manage security attribute of each tuple
 * (including ones within system catalog).
 *
 * Security attribute has these features:
 * 1. It is imported/exported with text representation, like
 *    'system_u:object_r:sepgsql_table_t:s0'
 * 2. In generally, many tuples share a same security attribute.
 *    (They are grouped by security attribute in other word.)
 * 3. A object can have one security attribute at most.
 *    (It can have a state of unlabeled.)
 *
 * PGACE utilizes a newly added system catalog of pg_security to store text
 * representation of security attribute efficiently. Any tuple has a object id
 * of a tuple within pg_security system catalog, we call it as a security id.
 *
 * Users can show security attribute as if it stored text data, but any tuple
 * has a security id which has a length of sizeof(Oid), without text data.
 * It is translated each other when it is exported/imported.
 *
 * pgaceSidToSecurityLabel() returns a text representation for a given security,
 * id, and pgaceSecurityLabelToSid() returns a security id for a give text
 * representation. (If a given text representation was not found on pg_security
 * system catalog, PGACE inserts a new entry automatically.)
 *
 * In the very early phase (invoked by initdb), pg_security system catalos is
 * not available yet. The earlySecurityLabelToSid() and earlySidToSecurityLabel()
 * is used to hold relationships between security id and text representation.
 * These relationships are stored at the end of bootstraping mode by
 * pgacePostBootstrapingMode(). It write any cached relationships into pg_security
 * system catalog.
 */

typedef struct earlySeclabel
{
	struct earlySeclabel *next;
	Oid			sid;
	char		label[1];
} earlySeclabel;

static earlySeclabel *earlySeclabelList = NULL;

static Oid
earlySecurityLabelToSid(char *label)
{
	earlySeclabel *es;
	Oid			minsid = SecurityRelationId;

	for (es = earlySeclabelList; es != NULL; es = es->next)
	{
		if (!strcmp(label, es->label))
			return es->sid;
		if (es->sid < minsid)
			minsid = es->sid;
	}
	/*
	 * not found
	 */
	es = malloc(sizeof(earlySeclabel) + strlen(label));
	es->next = earlySeclabelList;
	es->sid = minsid - 1;
	strcpy(es->label, label);
	earlySeclabelList = es;

	return es->sid;
}

static char *
earlySidToSecurityLabel(Oid sid)
{
	earlySeclabel *es;

	for (es = earlySeclabelList; es != NULL; es = es->next)
	{
		if (es->sid == sid)
			return pstrdup(es->label);
	}

	return NULL;	/* not found */
}

void
pgacePostBootstrapingMode(void)
{
	Relation	rel;
	CatalogIndexState ind;
	HeapTuple	tuple;
	earlySeclabel *es, *_es;
	Oid			meta_sid;
	Datum		value;
	bool		isnull;

	if (!earlySeclabelList)
		return;

	StartTransactionCommand();

	meta_sid = earlySecurityLabelToSid(pgaceSecurityLabelOfLabel());

	rel = heap_open(SecurityRelationId, RowExclusiveLock);
	ind = CatalogOpenIndexes(rel);

	for (es = earlySeclabelList; es != NULL; es = _es)
	{
		_es = es->next;

		value = DirectFunctionCall1(textin, CStringGetDatum(es->label));
		isnull = false;
		tuple = heap_form_tuple(RelationGetDescr(rel), &value, &isnull);

		HeapTupleSetOid(tuple, es->sid);
		if (HeapTupleHasSecurity(tuple))
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

/*
 * pgaceLookupSecurityId()
 *
 * The PGACE guest subsystem can use this interface to get a security id
 * for a given text representation.
 */
Oid
pgaceLookupSecurityId(char *raw_label)
{
	Oid			labelOid, labelSid;
	HeapTuple	tuple;

	if (!raw_label)
	{
		raw_label = pgaceUnlabeledSecurityLabel();
		if (!raw_label)
			return InvalidOid;
	}

	if (!pgaceCheckValidSecurityLabel(raw_label))
	{
		ereport(ERROR,
				(errcode(ERRCODE_PGACE_ERROR),
				 errmsg("%s: invalid security attribute", raw_label)));
	}

	if (IsBootstrapProcessingMode())
		return earlySecurityLabelToSid(raw_label);

	/*
	 * lookup syscache at first
	 */
	tuple = SearchSysCache(SECURITYLABEL,
						   CStringGetTextDatum(raw_label),
						   0, 0, 0);
	if (HeapTupleIsValid(tuple))
	{
		labelOid = HeapTupleGetOid(tuple);
		ReleaseSysCache(tuple);
	}
	else
	{
		/*
		 * not found, insert a new one into pg_security
		 */
		Relation	rel;
		CatalogIndexState ind;
		char	   *slabel;
		Datum		labelTxt;
		bool		isnull;

		rel = heap_open(SecurityRelationId, RowExclusiveLock);

		slabel = pgaceSecurityLabelOfLabel();

		if (!slabel)
		{
			labelSid = InvalidOid;
			labelOid = GetNewOid(rel);
		}
		else if (!strcmp(raw_label, slabel))
		{
			labelOid = labelSid = GetNewOid(rel);
		}
		else
		{
			labelSid = pgaceLookupSecurityId(slabel);
			labelOid = GetNewOid(rel);
		}

		ind = CatalogOpenIndexes(rel);

		labelTxt = CStringGetTextDatum(raw_label);
		isnull = false;
		tuple = heap_form_tuple(RelationGetDescr(rel),
								&labelTxt, &isnull);
		if (HeapTupleHasSecurity(tuple))
			HeapTupleSetSecurity(tuple, labelSid);
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
	}

	return labelOid;
}

Oid
pgaceSecurityLabelToSid(char *label)
{
	char *raw_label = pgaceTranslateSecurityLabelIn(label);

	return pgaceLookupSecurityId(raw_label);
}

/*
 * pgaceLookupSecurityLabel()
 *
 * The PGACE guest module can use this interface to get a text representation
 * in raw-format, without cosmetic translation.
 */
char *
pgaceLookupSecurityLabel(Oid security_id)
{
	HeapTuple	tuple;
	Datum		labelTxt;
	char	   *label, isnull;

	if (security_id == InvalidOid)
		goto unlabeled;

	if (IsBootstrapProcessingMode())
	{
		label = earlySidToSecurityLabel(security_id);
		if (!label)
			goto unlabeled;
		return label;
	}

	tuple = SearchSysCache(SECURITYOID,
						   ObjectIdGetDatum(security_id), 0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		goto unlabeled;

	labelTxt = SysCacheGetAttr(SECURITYOID,
							   tuple, Anum_pg_security_seclabel, &isnull);
	Assert(!isnull);
	label = TextDatumGetCString(labelTxt);
	ReleaseSysCache(tuple);

	if (pgaceCheckValidSecurityLabel(label))
		return label;

unlabeled:
	label = pgaceUnlabeledSecurityLabel();
	if (!label)
		return pstrdup("");

	return label;
}

char *
pgaceSidToSecurityLabel(Oid security_id)
{
	char *label = pgaceLookupSecurityLabel(security_id);

	return pgaceTranslateSecurityLabelOut(label);
}

/*****************************************************************************
 *	 Set/Get security attribute of Large Object
 *****************************************************************************/

/*
 * lo_get_security()
 *
 * This function returns a security attribute of large object
 * in TEXT representation.
 *
 * It assumes the first page means the whole of large object.
 * The guest of PGACE should pay effort to keep its consistency.
 */
Datum
lo_get_security(PG_FUNCTION_ARGS)
{
	Oid			loid = PG_GETARG_OID(0);
	Relation	rel;
	ScanKeyData skey;
	SysScanDesc scan;
	HeapTuple	tuple;
	Oid			security_id;

	rel = heap_open(LargeObjectRelationId, AccessShareLock);

	ScanKeyInit(&skey,
				Anum_pg_largeobject_loid,
				BTEqualStrategyNumber, F_OIDEQ,
				ObjectIdGetDatum(loid));

	scan = systable_beginscan(rel, LargeObjectLOidPNIndexId, true,
							  SnapshotNow, 1, &skey);
	tuple = systable_getnext(scan);
	if (!HeapTupleIsValid(tuple))
		ereport(ERROR,
				(errcode(ERRCODE_UNDEFINED_OBJECT),
				 errmsg("large object %u does not exist", loid)));
	pgaceLargeObjectGetSecurity(rel, tuple);
	security_id = HeapTupleGetSecurity(tuple);

	systable_endscan(scan);
	heap_close(rel, AccessShareLock);

	return CStringGetTextDatum(pgaceSidToSecurityLabel(security_id));
}

/*
 * lo_set_security()
 *
 * This function set a new security attribute of a large object.
 * It scans pg_largeobject system catalog with a given loid,
 * and invokes pgaceLargeObjectSetSecurity() for each page frame.
 */
Datum
lo_set_security(PG_FUNCTION_ARGS)
{
	Oid			loid = PG_GETARG_OID(0);
	Datum		labelTxt = PG_GETARG_DATUM(1);
	Relation	rel;
	ScanKeyData skey;
	SysScanDesc sd;
	HeapTuple	oldtup, newtup;
	CatalogIndexState indstate;
	Oid			security_id;
	List	   *okList = NIL;
	bool		found = false;

	security_id = pgaceSecurityLabelToSid(TextDatumGetCString(labelTxt));

	ScanKeyInit(&skey,
				Anum_pg_largeobject_loid,
				BTEqualStrategyNumber,
				F_OIDEQ, ObjectIdGetDatum(loid));

	rel = heap_open(LargeObjectRelationId, RowExclusiveLock);

	indstate = CatalogOpenIndexes(rel);

	sd = systable_beginscan(rel,
							LargeObjectLOidPNIndexId, true,
							SnapshotNow, 1, &skey);

	while ((oldtup = systable_getnext(sd)) != NULL)
	{
		ListCell *l;

		newtup = heap_copytuple(oldtup);
		HeapTupleSetSecurity(newtup, security_id);

		foreach (l, okList)
		{
			if (HeapTupleGetSecurity(oldtup) == lfirst_oid(l))
				goto skip;		/* already checked */
		}
		okList = lappend_oid(okList, HeapTupleGetSecurity(oldtup));

		pgaceLargeObjectSetSecurity(rel, newtup, oldtup);
	skip:
		simple_heap_update(rel, &newtup->t_self, newtup);
		CatalogUpdateIndexes(rel, newtup);
		found = true;
	}
	systable_endscan(sd);
	CatalogCloseIndexes(indstate);
	heap_close(rel, RowExclusiveLock);

	CommandCounterIncrement();

	if (!found)
		ereport(ERROR,
				(errcode(ERRCODE_UNDEFINED_OBJECT),
				 errmsg("large object %u does not exist", loid)));

	PG_RETURN_BOOL(true);
}

/******************************************************************
 * Function stubs related to security modules
 ******************************************************************/

/*
 * If the guest of PGACE added its specific functions, it has to put
 * function stubs on the following section, because the guest modules
 * are not compiled and linked when it is disabled.
 * It can cause a build problem in other environments.
 */
static Datum
unavailable_function(const char *fn_name, int error_code)
{
	ereport(ERROR,
			(errcode(error_code),
			 errmsg("%s is not available", fn_name)));
	PG_RETURN_VOID();
}

#ifndef HAVE_SELINUX

Datum
sepgsql_getcon(PG_FUNCTION_ARGS)
{
	return unavailable_function(__FUNCTION__,
								ERRCODE_SELINUX_ERROR);
}

Datum
sepgsql_getservcon(PG_FUNCTION_ARGS)
{
	return unavailable_function(__FUNCTION__,
								ERRCODE_SELINUX_ERROR);
}

Datum
sepgsql_get_user(PG_FUNCTION_ARGS)
{
	return unavailable_function(__FUNCTION__,
								ERRCODE_SELINUX_ERROR);
}

Datum
sepgsql_get_role(PG_FUNCTION_ARGS)
{
	return unavailable_function(__FUNCTION__,
								ERRCODE_SELINUX_ERROR);
}

Datum
sepgsql_get_type(PG_FUNCTION_ARGS)
{
	return unavailable_function(__FUNCTION__,
								ERRCODE_SELINUX_ERROR);
}

Datum
sepgsql_get_range(PG_FUNCTION_ARGS)
{
	return unavailable_function(__FUNCTION__,
								ERRCODE_SELINUX_ERROR);
}

Datum
sepgsql_set_user(PG_FUNCTION_ARGS)
{
	return unavailable_function(__FUNCTION__,
								ERRCODE_SELINUX_ERROR);
}

Datum
sepgsql_set_role(PG_FUNCTION_ARGS)
{
	return unavailable_function(__FUNCTION__,
								ERRCODE_SELINUX_ERROR);
}

Datum
sepgsql_set_type(PG_FUNCTION_ARGS)
{
	return unavailable_function(__FUNCTION__,
								ERRCODE_SELINUX_ERROR);
}

Datum
sepgsql_set_range(PG_FUNCTION_ARGS)
{
	return unavailable_function(__FUNCTION__,
								ERRCODE_SELINUX_ERROR);
}

#endif   /* HAVE_SELINUX */

#ifndef HAVE_ROW_ACL

Datum
rowacl_grant(PG_FUNCTION_ARGS)
{
	return unavailable_function(__FUNCTION__,
								ERRCODE_ROW_ACL_ERROR);
}

Datum
rowacl_revoke(PG_FUNCTION_ARGS)
{
	return unavailable_function(__FUNCTION__,
								ERRCODE_ROW_ACL_ERROR);
}

Datum
rowacl_revoke_cascade(PG_FUNCTION_ARGS)
{
	return unavailable_function(__FUNCTION__,
								ERRCODE_ROW_ACL_ERROR);
}

Datum
rowacl_table_default(PG_FUNCTION_ARGS)
{
	return unavailable_function(__FUNCTION__,
								ERRCODE_ROW_ACL_ERROR);
}

#endif	/* HAVE_ROW_ACL */
