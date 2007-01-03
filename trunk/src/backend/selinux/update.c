/*
 * src/backend/selinux/update.c
 *     Security Enhanced PostgreSQL implementation.
 *     This file provides proxy hook for UPDATE statement.
 *
 *     Copyright (c) 2006 - 2007, KaiGai Kohei <kaigai@kaigai.gr.jp>
 */
#include "postgres.h"

#include "catalog/pg_attribute.h"
#include "catalog/pg_class.h"
#include "catalog/pg_database.h"
#include "catalog/pg_largeobject.h"
#include "catalog/pg_proc.h"
#include "catalog/pg_type.h"
#include "nodes/makefuncs.h"
#include "nodes/pg_list.h"
#include "sepgsql.h"
#include "utils/fmgroids.h"
#include "utils/syscache.h"
#include <selinux/flask.h>
#include <selinux/av_permissions.h>

static void checkUpdateTarget(Query *query, RangeTblEntry *rte, int rindex, TargetEntry *tle)
{
	Oid relid = rte->relid;
	AttrNumber attnum = tle->resno;
	Form_pg_attribute attr;
	HeapTuple tuple;
	char *audit;
	int rc;

	tuple = SearchSysCache(ATTNUM,
						   ObjectIdGetDatum(relid),
						   Int16GetDatum(attnum),
						   0, 0);
	if (!HeapTupleIsValid(tuple))
		selerror("cache lookup failed for attribute %d of relation %u", relid, attnum);
	attr = (Form_pg_attribute) GETSTRUCT(tuple);

	/* 1. mark to check table:update */
	rte->access_vector |= TABLE__UPDATE;

	/* 2. checking column:update */
	rc = sepgsql_avc_permission(sepgsqlGetClientPsid(),
								attr->attselcon,
								SECCLASS_COLUMN,
								COLUMN__UPDATE,
								&audit);
	selinux_audit(rc, audit, NameStr(attr->attname));

	/* 2. checking column:select on expr */
	sepgsqlCheckExpr(query, tle->expr);

	/* 3. checking relabelfrom/relabelto, if necessary */
	if (sepgsqlAttributeIsPsid(attr)) {
		FuncExpr *func;
		List *args;
		uint16 tclass;

		switch (attr->attrelid) {
		case AttributeRelationId:
			tclass = SECCLASS_COLUMN;
			break;
		case RelationRelationId:
			tclass = SECCLASS_TABLE;
			break;
		case DatabaseRelationId:
			tclass = SECCLASS_DATABASE;
			break;
		case ProcedureRelationId:
			tclass = SECCLASS_PROCEDURE;
			break;
		case LargeObjectRelationId:
			tclass = SECCLASS_BLOB;
			break;
		default:
			tclass = SECCLASS_TUPLE;
			break;
		}

		/* 3.1. 1st arg : security context of sujbect */
		args = list_make1(makeConst(PSIDOID, sizeof(psid),
									ObjectIdGetDatum(sepgsqlGetClientPsid()),
									false, true));
		
		/* 3.2. 2nd arg : old security context */
		args = lappend(args, makeVar(rindex, attnum, attr->atttypid, attr->atttypmod, 0));
		
		/* 3.3. 3rd arg : new security context */
		args = lappend(args, tle->expr);
		
		/* 3.4. 4th arg : object class */
		args = lappend(args, makeConst(INT4OID, sizeof(int32),
									   Int32GetDatum(tclass),
									   false, true));

		/* selinux_check_context_update(ssid, osid, nsid, tclass) */
		func = makeFuncExpr(F_SELINUX_CHECK_CONTEXT_UPDATE,
							PSIDOID, args, COERCE_DONTCARE);
		tle->expr = (Expr *)func;
	}
	ReleaseSysCache(tuple);
}

Query *sepgsqlProxyUpdate(Query *query)
{
	RangeTblEntry *rte;
	ListCell *x;
	int rindex = query->resultRelation;

	/* 1. table:update checking on target relation */
	rte = list_nth(query->rtable, rindex - 1);
	rte->access_vector = TABLE__UPDATE;

	/* 2. column:update checking on target columns */
	foreach(x, query->targetList) {
		TargetEntry *tle = (TargetEntry *) lfirst(x);
		checkUpdateTarget(query, rte, rindex, tle);
	}

	/* 3. check where clause */
	sepgsqlCheckExpr(query, (Expr *)query->jointree->quals);

	/* 4. check returning clause, if necessary */
	sepgsqlCheckTargetList(query, query->returningList);

	/* 5. check any relations */
	rindex = 1;
	foreach (x, query->rtable) {
		rte = (RangeTblEntry *) lfirst(x);
		if (rte->rtekind == RTE_RELATION)
			sepgsqlCheckRteRelation(query, rte, rindex);
		rindex++;
	}

	return query;
}

