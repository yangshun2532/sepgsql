
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
pgaceCreateRelationCommon(Relation rel, HeapTuple tuple, List *pgace_attr_list)
{
	ListCell   *l;

	foreach(l, pgace_attr_list)
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
						   List *pgace_attr_list)
{
	Form_pg_attribute attr = (Form_pg_attribute) GETSTRUCT(tuple);
	ListCell   *l;

	foreach(l, pgace_attr_list)
	{
		DefElem    *defel = lfirst(l);

		if (!defel->defname)
			continue;			/* for table */
		if (!strcmp(defel->defname, NameStr(attr->attname)))
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
	elog(ERROR, "security id: %u is not a valid identifier", sid);
	return NULL;				/* for compiler kindness */
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
	char		isnull;

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

Oid
pgaceSecurityLabelToSid(char *label)
{
	Oid			labelOid, labelSid;
	HeapTuple	tuple;

	/*
	 * valid label checks
	 */
	label = pgaceTranslateSecurityLabelIn(label);
	label = pgaceValidateSecurityLabel(label);

	if (IsBootstrapProcessingMode())
		return earlySecurityLabelToSid(label);

	/*
	 * lookup syscache at first
	 */
	tuple = SearchSysCache(SECURITYLABEL, CStringGetTextDatum(label), 0, 0, 0);
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
		char		isnull;

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
		tuple = heap_formtuple(RelationGetDescr(rel), &labelTxt, &isnull);
		HeapTupleSetSecurity(tuple, labelSid);
		HeapTupleSetOid(tuple, labelOid);

		simple_heap_insert(rel, tuple);
		CatalogIndexInsert(ind, tuple);

		InsertSysCache(RelationGetRelid(rel), tuple);

		CatalogCloseIndexes(ind);
		heap_close(rel, RowExclusiveLock);
	}

	return labelOid;
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
		return pgaceValidateSecurityLabel(NULL);

	if (IsBootstrapProcessingMode())
		return earlySidToSecurityLabel(security_id);

	tuple = SearchSysCache(SECURITYOID,
						   ObjectIdGetDatum(security_id), 0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "security id: %u is not a valid identifier", security_id);

	labelTxt = SysCacheGetAttr(SECURITYOID,
							   tuple, Anum_pg_security_seclabel, &isnull);
	Assert(!isnull);
	label = TextDatumGetCString(labelTxt);
	ReleaseSysCache(tuple);

	return label;
}

char *
pgaceSidToSecurityLabel(Oid security_id)
{
	char	   *label = pgaceLookupSecurityLabel(security_id);

	label = pgaceTranslateSecurityLabelOut(label);
	Assert(label != NULL);

	return label;
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
	Oid			security_id = InvalidOid;
	Relation	lorel, loidx;
	ScanKeyData skey;
	SysScanDesc sd;
	HeapTuple	tuple;
	bool		found = false;

	lorel = heap_open(LargeObjectRelationId, AccessShareLock);
	loidx = index_open(LargeObjectLOidPNIndexId, AccessShareLock);

	ScanKeyInit(&skey,
				Anum_pg_largeobject_loid,
				BTEqualStrategyNumber, F_OIDEQ, ObjectIdGetDatum(loid));

	sd = systable_beginscan_ordered(lorel, loidx, SnapshotNow, 1, &skey);
	tuple = systable_getnext_ordered(sd, ForwardScanDirection);
	if (HeapTupleIsValid(tuple))
	{
		pgaceLargeObjectGetSecurity(lorel, tuple);
		security_id = HeapTupleGetSecurity(tuple);
		found = true;
	}
	systable_endscan_ordered(sd);
	index_close(loidx, AccessShareLock);
	heap_close(lorel, AccessShareLock);

	if (!found)
		elog(ERROR, "large object %u does not exist", loid);

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
	HeapTuple	tuple, newtup;
	CatalogIndexState indstate;
	Datum		pgaceItem;
	Oid			security_id;
	bool		found = false;

	security_id = pgaceSecurityLabelToSid(TextDatumGetCString(labelTxt));

	ScanKeyInit(&skey,
				Anum_pg_largeobject_loid,
				BTEqualStrategyNumber, F_OIDEQ, ObjectIdGetDatum(loid));

	rel = heap_open(LargeObjectRelationId, RowExclusiveLock);

	indstate = CatalogOpenIndexes(rel);

	sd = systable_beginscan(rel, LargeObjectLOidPNIndexId,
							true, SnapshotNow, 1, &skey);

	while ((tuple = systable_getnext(sd)) != NULL)
	{
		pgaceLargeObjectSetSecurity(rel, tuple, security_id,
									!found, &pgaceItem);
		newtup = heap_copytuple(tuple);
		HeapTupleSetSecurity(newtup, security_id);

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
 * Function stubs related to security modules
 ******************************************************************/

/*
 * If the guest of PGACE added its specific functions, it has to put
 * function stubs on the following section, because the guest modules
 * are not compiled and linked when it is disabled.
 * It can cause a build problem in other environments.
 */

#ifndef HAVE_SELINUX

static Datum
sepgsql_is_disabled(const char *function)
{
	ereport(ERROR,
			(errcode(ERRCODE_SELINUX_ERROR),
			 errmsg("%s is not implemented", function)));
	PG_RETURN_VOID();
}

Datum
sepgsql_getcon(PG_FUNCTION_ARGS)
{
	return sepgsql_is_disabled(__FUNCTION__);
}

Datum
sepgsql_getservcon(PG_FUNCTION_ARGS)
{
	return sepgsql_is_disabled(__FUNCTION__);
}

Datum
sepgsql_get_user(PG_FUNCTION_ARGS)
{
	return sepgsql_is_disabled(__FUNCTION__);
}

Datum
sepgsql_get_role(PG_FUNCTION_ARGS)
{
	return sepgsql_is_disabled(__FUNCTION__);
}

Datum
sepgsql_get_type(PG_FUNCTION_ARGS)
{
	return sepgsql_is_disabled(__FUNCTION__);
}

Datum
sepgsql_get_range(PG_FUNCTION_ARGS)
{
	return sepgsql_is_disabled(__FUNCTION__);
}

Datum
sepgsql_set_user(PG_FUNCTION_ARGS)
{
	return sepgsql_is_disabled(__FUNCTION__);
}

Datum
sepgsql_set_role(PG_FUNCTION_ARGS)
{
	return sepgsql_is_disabled(__FUNCTION__);
}

Datum
sepgsql_set_type(PG_FUNCTION_ARGS)
{
	return sepgsql_is_disabled(__FUNCTION__);
}

Datum
sepgsql_set_range(PG_FUNCTION_ARGS)
{
	return sepgsql_is_disabled(__FUNCTION__);
}

#endif   /* HAVE_SELINUX */
