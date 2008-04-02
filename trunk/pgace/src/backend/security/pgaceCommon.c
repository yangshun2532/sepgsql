/*
 * src/backend/security/pgaceCommon.c
 *   Common part of PostgreSQL Access Control Extension
 * Copyright 2007 KaiGai Kohei <kaigai@kaigai.gr.jp>
 */
#include "postgres.h"

#include "access/genam.h"
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
 * Security attribute system column support
 *****************************************************************************/
#ifdef SECURITY_SYSATTR_NAME

bool pgaceIsSecuritySystemColumn(int attrno)
{
	return ((attrno == SecurityAttributeNumber) ? true : false);
}

void pgaceTransformSelectStmt(List *targetList) {
	ListCell *l;

	foreach (l, targetList) {
		TargetEntry *tle = lfirst(l);

		if (tle->resjunk)
			continue;
		if (!strcmp(tle->resname, SECURITY_SYSATTR_NAME)) {
			if (exprType((Node *) tle->expr) != SECLABELOID)
				elog(ERROR, "type mismatch in explicit labeling");
			tle->resjunk = true;
			break;
		}
	}
}

void pgaceTransformInsertStmt(List **p_icolumns, List **p_attrnos, List *targetList) {
	AttrNumber security_attrno = 0;
	ListCell *lc;

	foreach (lc, targetList) {
		TargetEntry *tle = (TargetEntry *) lfirst(lc);

		security_attrno++;
		if (strcmp(tle->resname, SECURITY_SYSATTR_NAME))
			continue;

		if (list_length(*p_icolumns) < list_length(targetList)) {
			List *__icolumns = NIL;
			List *__attrnos = NIL;
			ListCell *l1, *l2;
			int index = 0;

			forboth(l1, *p_icolumns, l2, *p_attrnos) {
				if (++index == security_attrno) {
					ResTarget *col = makeNode(ResTarget);
					col->name = pstrdup(SECURITY_SYSATTR_NAME);
					col->indirection = NIL;
					col->val = NULL;
					col->location = -1;

					__icolumns = lappend(__icolumns, col);
					__attrnos = lappend_int(__attrnos, SecurityAttributeNumber);
				}
				if (lfirst_int(l2) == SecurityAttributeNumber)
					return;
				__icolumns = lappend(__icolumns, lfirst(l1));
				__attrnos = lappend_int(__attrnos, lfirst_int(l2));
			}
			*p_icolumns = __icolumns;
			*p_attrnos = __attrnos;
		}
		break;
	}
}

void pgaceFetchSecurityAttribute(JunkFilter *junkfilter, TupleTableSlot *slot, Oid *tts_security)
{
	AttrNumber attno;
	Datum datum;
	bool isnull;

	attno = ExecFindJunkAttribute(junkfilter, SECURITY_SYSATTR_NAME);
	if (attno != InvalidAttrNumber) {
		datum = ExecGetJunkAttribute(slot, attno, &isnull);
		if (!isnull)
			*tts_security = DatumGetObjectId(datum);
	}
}
#else  /* SECURITY_SYSATTR_NAME */

bool pgaceIsSecuritySystemColumn(int attrno) {
	return false;
}

void pgaceTransformSelectStmt(List *targetList) {
	/* do nothing */
}

void pgaceTransformInsertStmt(List **p_icolumns,
							  List **p_attrnos,
							  List *targetList) {
	/* do nothing */
}

void pgaceFetchSecurityAttribute(JunkFilter *junkfilter,
								 TupleTableSlot *slot,
								 Oid *tts_security) {
	/* do nothing */
}
#endif /* SECURITY_SYSATTR_NAME */

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
 *   security_label type input/output handler
 *****************************************************************************/
static Oid early_security_label_to_sid(char *seclabel);
static char *early_sid_to_security_label(Oid sid);
#define EARLY_PG_SECURITY  "global/pg_security.bootstrap"

static bool pg_security_is_available() {
	/* -1 : early mode, 0: now in transfer, 1: available */
	static int pg_security_state = -1;
	char fname[MAXPGPATH];
	FILE *filp;

	if (pg_security_state > 0)
		return true;
	if (IsBootstrapProcessingMode() || pg_security_state==0)
		return false;
	/*
	 * if initial setting up was not done, the cache file is remaining.
	 * so we have to insert its contains into pg_selinux.
	 * we can make decision of whether it already done, or not, by looking
	 * the existance of 'EARLY_PG_SECURITY'.
	 */
	snprintf(fname, sizeof(fname), "%s/%s", DataDir, EARLY_PG_SECURITY);
	filp = fopen(fname, "rb");
	if (filp) {
		Relation rel;
		CatalogIndexState ind;
		HeapTuple tuple;
		char buffer[1024];
		Oid secoid, metaoid;
		Datum value;
		char  isnull;

		pg_security_state = 0;

		PG_TRY();
		{
			rel = heap_open(SecurityRelationId, RowExclusiveLock);
			ind = CatalogOpenIndexes(rel);
			while (fscanf(filp, "%u %s", &secoid, buffer) == 2) {
				metaoid = early_security_label_to_sid(pgaceSecurityLabelOfLabel(buffer));

				value = DirectFunctionCall1(textin, CStringGetDatum(buffer));
				isnull = ' ';
				tuple = heap_formtuple(RelationGetDescr(rel), &value, &isnull);

				HeapTupleSetOid(tuple, secoid);
				HeapTupleSetSecurity(tuple, metaoid);

				simple_heap_insert(rel, tuple);
				CatalogIndexInsert(ind, tuple);

				heap_freetuple(tuple);
			}
			CatalogCloseIndexes(ind);
			heap_close(rel, RowExclusiveLock);

			CommandCounterIncrement();
		}
		PG_CATCH();
		{
			fclose(filp);
			PG_RE_THROW();
		}
		PG_END_TRY();
		fclose(filp);
		if (unlink(fname) != 0)
			elog(ERROR, "PGACE: could not unlink '%s'", fname);
	}
	pg_security_state = 1;

	return true;
}

static Oid early_security_label_to_sid(char *seclabel)
{
	char fname[MAXPGPATH], buffer[1024];
	Oid sid, minsid = SecurityRelationId;
	FILE *filp;

	snprintf(fname, sizeof(fname), "%s/%s", DataDir, EARLY_PG_SECURITY);
	filp = fopen(fname, "a+b");
	if (!filp)
		ereport(ERROR,
				(errcode(ERRCODE_INTERNAL_ERROR),
				 errmsg("could not open '%s'", fname)));
	flock(fileno(filp), LOCK_EX);
	while (fscanf(filp, "%u %s", &sid, buffer) == 2) {
		if (!strcmp(seclabel, buffer)) {
			fclose(filp);
			return sid;
		}
		if (sid < minsid)
			minsid = sid;
	}
	sid = minsid - 1;
	fprintf(filp, "%u %s\n", sid, seclabel);
	fclose(filp);

	return sid;
}

static char *early_sid_to_security_label(Oid sid)
{
	char fname[MAXPGPATH], buffer[1024], *seclabel;
	FILE *filp;
	Oid __sid;

	snprintf(fname, sizeof(fname), "%s/%s", DataDir, EARLY_PG_SECURITY);
	filp = fopen(fname, "rb");
	if (!filp)
		goto not_found;

	flock(fileno(filp), LOCK_SH);
	while (fscanf(filp, "%u %s", &__sid, buffer) == 2) {
		if (sid == __sid) {
			fclose(filp);
			return pstrdup(buffer);
		}
	}
	fclose(filp);

not_found:
	seclabel = pgaceSecurityLabelCheckValid(NULL);
	elog(seclabel ? NOTICE : ERROR,
		 "PGACE: No text representation for sid = %u", sid);
	return seclabel;
}

static Oid get_security_label_oid(Relation rel, CatalogIndexState ind, char *new_label)
{
	/* rel has to be opened with RowExclusiveLock */
	char *mlabel_str, *__mlabel_str;
	Datum mlabel_text;
	HeapTuple tuple;
	Oid label_oid;

	mlabel_str = pgaceSecurityLabelOfLabel(new_label);
	__mlabel_str = pgaceSecurityLabelCheckValid(mlabel_str);
	if (mlabel_str != __mlabel_str)
		elog(NOTICE, "PGACE: '%s' is not a valid security label,"
					 " '%s' is applied instead.", mlabel_str, __mlabel_str);

	/* 1. lookup syscache */
	mlabel_text = DirectFunctionCall1(textin, CStringGetDatum(mlabel_str));
	tuple = SearchSysCache(SECURITYLABEL,
						   mlabel_text,
						   0, 0, 0);
	if (HeapTupleIsValid(tuple)) {
		label_oid = HeapTupleGetSecurity(tuple);
		ReleaseSysCache(tuple);
	} else {
		/* 2. lookup table on SnapshotSelf */
		SysScanDesc scan;
		ScanKeyData skey;

		ScanKeyInit(&skey,
					Anum_pg_security_seclabel,
					BTEqualStrategyNumber, F_TEXTEQ,
					PointerGetDatum(mlabel_text));
		scan = systable_beginscan(rel, SecuritySeclabelIndexId,
								  true, SnapshotSelf, 1, &skey);
		tuple = systable_getnext(scan);
		if (HeapTupleIsValid(tuple)) {
			label_oid = HeapTupleGetSecurity(tuple);
		} else {
			/* 3. insert a new tuple into pg_security */
			Datum value = PointerGetDatum(mlabel_text);
			char isnull = ' ';
			Oid meta_oid;

			tuple = heap_formtuple(RelationGetDescr(rel),
								   &value, &isnull);
			meta_oid = GetNewOid(rel);
			HeapTupleSetOid(tuple, meta_oid);
			HeapTupleSetSecurity(tuple, meta_oid);

			label_oid = simple_heap_insert(rel, tuple);
			Assert(label_oid == meta_oid);

			CatalogIndexInsert(ind, tuple);
		}
		systable_endscan(scan);
	}
	return label_oid;
}

static Oid security_label_to_sid(char *label_str)
{
	Datum label_text;
	Oid label_oid;
	HeapTuple tuple;

	if (!pg_security_is_available())
		return early_security_label_to_sid(label_str);

	/* 1. lookup system cache first */
	label_text = DirectFunctionCall1(textin, CStringGetDatum(label_str));
	tuple = SearchSysCache(SECURITYLABEL,
						   label_text,
						   0, 0, 0);
	if (HeapTupleIsValid(tuple)) {
		label_oid = HeapTupleGetOid(tuple);
		ReleaseSysCache(tuple);
	} else {
		/* 2. lookup within the current command ID */
		Relation rel;
		SysScanDesc scan;
		ScanKeyData skey;
		Oid meta_oid;

		rel = heap_open(SecurityRelationId, RowExclusiveLock);
		ScanKeyInit(&skey,
					Anum_pg_security_seclabel,
					BTEqualStrategyNumber, F_TEXTEQ,
					PointerGetDatum(label_text));
		scan = systable_beginscan(rel, SecuritySeclabelIndexId,
								  true, SnapshotSelf, 1, &skey);
		tuple = systable_getnext(scan);
		if (HeapTupleIsValid(tuple)) {
			label_oid = HeapTupleGetOid(tuple);
		} else {
			CatalogIndexState ind;
			Datum value = PointerGetDatum(label_text);
			char isnull = ' ';

			ind = CatalogOpenIndexes(rel);

			tuple = heap_formtuple(RelationGetDescr(rel),
								   &value, &isnull);
			meta_oid = get_security_label_oid(rel, ind, label_str);
			HeapTupleSetSecurity(tuple, meta_oid);

			label_oid = simple_heap_insert(rel, tuple);

			CatalogIndexInsert(ind, tuple);
			CatalogCloseIndexes(ind);
		}
		systable_endscan(scan);
		heap_close(rel, RowExclusiveLock);
	}
	return label_oid;
}

static char *sid_to_security_label(Oid sid)
{
	HeapTuple tuple;
	Datum tcon;
	char *seclabel;
	bool isnull, syscache = true;

	if (!pg_security_is_available())
		return early_sid_to_security_label(sid);

	tuple = SearchSysCache(SECURITYOID,
						   ObjectIdGetDatum(sid),
						   0, 0, 0);
	if (!HeapTupleIsValid(tuple)) {
		Relation rel;
		SysScanDesc scan;
		ScanKeyData skey;

		syscache = false;
		rel = heap_open(SecurityRelationId, AccessShareLock);
		ScanKeyInit(&skey,
					ObjectIdAttributeNumber,
					BTEqualStrategyNumber, F_OIDEQ,
					ObjectIdGetDatum(sid));
		scan = systable_beginscan(rel, SecurityOidIndexId,
								  true, SnapshotSelf, 1, &skey);
		tuple = systable_getnext(scan);
		if (HeapTupleIsValid(tuple))
			tuple = heap_copytuple(tuple);
		systable_endscan(scan);
		heap_close(rel, AccessShareLock);

		if (!HeapTupleIsValid(tuple)) {
			seclabel = pgaceSecurityLabelCheckValid(NULL);
			elog(seclabel ? NOTICE : ERROR,
				 "PGACE: No text representation for sid = %u", sid);
			return seclabel;
		}
	}
	tcon = SysCacheGetAttr(SECURITYOID,
						   tuple,
						   Anum_pg_security_seclabel,
						   &isnull);
	seclabel = DatumGetCString(DirectFunctionCall1(textout,
												   PointerGetDatum(tcon)));
	if (syscache)
		ReleaseSysCache(tuple);

	return seclabel;
}

/* security_label_in -- security_label input function */
Datum
security_label_in(PG_FUNCTION_ARGS)
{
	char *label = PG_GETARG_CSTRING(0);
	char *__label;

	label = pgaceSecurityLabelIn(label);
	__label = pgaceSecurityLabelCheckValid(label);
	if (label != __label)
		elog(ERROR, "PGACE: '%s' is not a valid security label", label);

	PG_RETURN_OID(security_label_to_sid(label));
}

/* security_label_out -- security_label output function */
Datum
security_label_out(PG_FUNCTION_ARGS)
{
	Oid sid = PG_GETARG_OID(0);
	char *label = sid_to_security_label(sid);
	char *__label = pgaceSecurityLabelCheckValid(label);
	if (label != __label)
		elog(NOTICE, "PGACE: '%s' is not a valid security label,"
					 " '%s' is applied instead.", label, __label);
	PG_RETURN_CSTRING(pgaceSecurityLabelOut(__label));
}

/* security_label_raw_in -- security_label input function in raw format */
Datum
security_label_raw_in(PG_FUNCTION_ARGS)
{
	char *label = PG_GETARG_CSTRING(0);
	char *__label;

	__label = pgaceSecurityLabelCheckValid(label);
	if (label != __label)
		elog(ERROR, "PGACE: '%s' is not a valid security label", label);

	PG_RETURN_OID(security_label_to_sid(label));
}

/* security_label_raw_out -- security_label output function in raw format */
Datum
security_label_raw_out(PG_FUNCTION_ARGS)
{
	Oid sid = PG_GETARG_OID(0);
	char *label = sid_to_security_label(sid);
	char *__label = pgaceSecurityLabelCheckValid(label);

	if (label != __label)
		elog(NOTICE, "PGACE: '%s' is not a valid security label,"
					 " '%s' is applied instead.", label, __label);
	PG_RETURN_CSTRING(__label);
}

/* text_to_security_label -- security_label cast function */
Datum
text_to_security_label(PG_FUNCTION_ARGS)
{
	text *t = PG_GETARG_TEXT_P(0);
	Datum seclabel;

	seclabel = DirectFunctionCall1(textout,
								   PointerGetDatum(t));
	return DirectFunctionCall1(security_label_in, seclabel);
}

/* security_label_to_text -- security_label cast function */
Datum
security_label_to_text(PG_FUNCTION_ARGS)
{
	Oid sid = PG_GETARG_OID(0);
	Datum seclabel;

	seclabel = DirectFunctionCall1(security_label_out,
								   ObjectIdGetDatum(sid));
	return DirectFunctionCall1(textin, seclabel);
}

/*****************************************************************************
 *	 Set/Get security attribute of Large Object
 *****************************************************************************/
Datum
lo_get_security(PG_FUNCTION_ARGS)
{
	Oid loid = PG_GETARG_OID(0);
	Oid lo_security = InvalidOid;
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
		lo_security = HeapTupleGetSecurity(tuple);
		pgaceLargeObjectGetSecurity(tuple);
		found = true;
		break;
	}
	systable_endscan(sd);

	heap_close(rel, AccessShareLock);

	if (!found)
		elog(ERROR, "large object %u does not exist", loid);

	PG_RETURN_OID(lo_security);
}

Datum
lo_set_security(PG_FUNCTION_ARGS)
{
	Oid loid = PG_GETARG_OID(0);
	Oid lo_security = PG_GETARG_OID(1);
	Relation rel;
	ScanKeyData skey;
	SysScanDesc sd;
	HeapTuple tuple, newtup;
	CatalogIndexState indstate;
	bool found = false;

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
		if (!found)
			pgaceLargeObjectSetSecurity(newtup, lo_security);
		HeapTupleSetSecurity(newtup, lo_security);
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
