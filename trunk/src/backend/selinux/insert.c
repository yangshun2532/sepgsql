/*
 * src/backend/selinux/insert.c
 *     Security Enhanced PostgreSQL implementation.
 *     This file provides proxy hook for INSERT statement.
 *
 *     Copyright (c) 2006 - 2007, KaiGai Kohei <kaigai@kaigai.gr.jp>
 */
#include "postgres.h"

#include "access/heapam.h"
#include "catalog/pg_attribute.h"
#include "catalog/pg_class.h"
#include "catalog/pg_database.h"
#include "catalog/pg_largeobject.h"
#include "catalog/pg_proc.h"
#include "catalog/pg_type.h"
#include "nodes/makefuncs.h"
#include "parser/parse_expr.h"
#include "sepgsql.h"
#include "storage/lock.h"
#include "utils/fmgroids.h"
#include "utils/syscache.h"
#include <selinux/flask.h>
#include <selinux/av_permissions.h>

static Expr *selinuxInsertTupleContext(Expr *esid, Oid relid, psid relselcon)
{
	FuncExpr *func;
	Const *cons;
	List *args;
	uint16 tclass;
	psid isid;

	/* 1st arg : security context of subject */
	cons = makeConst(PSIDOID, sizeof(psid),
					 ObjectIdGetDatum(selinuxGetClientPsid()),
					 false, true);
	args = list_make1(cons);

	/* 2nd arg : security context of object implicitly calculated */
	isid = selinuxComputeNewTupleContext(relid, relselcon, &tclass);
	cons = makeConst(PSIDOID, sizeof(psid),
					 ObjectIdGetDatum(isid),
					 false, true);
	args = lappend(args, cons);

	/* 3rd arg : security context of object explicitly specified */
	if (!esid) {
		cons = makeConst(PSIDOID, sizeof(psid),
						 ObjectIdGetDatum(isid),
						 false, true);
		args = lappend(args, cons);
	} else {
		if (exprType((Node *)esid) != PSIDOID)
			selerror("The type of security context (%u) is invalid", exprType((Node *)esid));
		Assert(exprType((Node *)esid) == PSIDOID);
		args = lappend(args, esid);
	}
	
	/* 4th arg : object class */
	cons = makeConst(INT4OID, sizeof(int32), Int32GetDatum(tclass), false, true);
	args = lappend(args, cons);

	func = makeFuncExpr(F_SELINUX_CHECK_CONTEXT_INSERT,
						PSIDOID, args, COERCE_DONTCARE);
	return (Expr *)func;
}

Query *selinuxProxyInsert(Query *query)
{
	RangeTblEntry *rte;
	HeapTuple tup;
	TargetEntry *tle;
	ListCell *tl;
	Form_pg_class pg_class;
	Form_pg_attribute pg_attr;
	psid relselcon;
	char *audit;
	int rc;
	bool security_context_checked = false;

	rte = (RangeTblEntry *)list_nth(query->rtable, query->resultRelation - 1);
	Assert(IsA(rte, RangeTblEntry));

	/* 1. check table:insert permission */
	tup = SearchSysCache(RELOID,
						 ObjectIdGetDatum(rte->relid),
						 0, 0, 0);
	if (!HeapTupleIsValid(tup))
		selerror("cache lookup failed for pg_class %u", rte->relid);
	
	pg_class = (Form_pg_class) GETSTRUCT(tup);
	rc = libselinux_avc_permission(selinuxGetClientPsid(),
								   pg_class->relselcon,
								   SECCLASS_TABLE,
								   TABLE__INSERT,
								   &audit);
	selinux_audit(rc, audit, NameStr(pg_class->relname));
	relselcon = pg_class->relselcon;
	ReleaseSysCache(tup);
	
	/* 2. check column:insert permission */
	foreach(tl, query->targetList) {
		tle = (TargetEntry *)lfirst(tl);
        tup = SearchSysCache(ATTNUM,
                             ObjectIdGetDatum(rte->relid),
                             Int16GetDatum(tle->resno),
                             0, 0);
        if (!HeapTupleIsValid(tup))
            selerror("cache lookup failed for pg_attribute (relid=%u, attnum=%d)",
                     rte->relid, tle->resno);

		pg_attr = (Form_pg_attribute) GETSTRUCT(tup);
		rc = libselinux_avc_permission(selinuxGetClientPsid(),
									   pg_attr->attselcon,
									   SECCLASS_COLUMN,
									   COLUMN__INSERT,
									   &audit);
		selinux_audit(rc, audit, NameStr(pg_attr->attname));

		if (selinuxAttributeIsPsid(pg_attr)) {
			/* check relabelfrom/relabelto condition */
			tle->expr = selinuxInsertTupleContext(tle->expr, rte->relid, relselcon);
			security_context_checked = true;
		}
		ReleaseSysCache(tup);
	}

	/* If targetList didn't contain security context,
	 * we should append security context. */
	if (!security_context_checked) {
		int index;
		Relation rel = relation_open(rte->relid, AccessShareLock);
		for (index=0; index < RelationGetNumberOfAttributes(rel); index++) {
			pg_attr = RelationGetDescr(rel)->attrs[index];
			if (selinuxAttributeIsPsid(pg_attr)) {
				Expr *e = selinuxInsertTupleContext(NULL, rte->relid, relselcon);
				tle = makeTargetEntry(e, index + 1,
									  pstrdup(NameStr(pg_attr->attname)),
									  false);
				query->targetList = lappend(query->targetList, tle);
				break;
			}
		}
		relation_close(rel, NoLock);
	}
	return query;
}

