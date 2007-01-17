/*
 * src/backend/selinux/proxy.c
 *   SE-PostgreSQL implementation to check any query.
 * 
 * Copyright (c) 2006 - 2007, KaiGai Kohei <kaigai@kaigai.gr.jp>
 */
#include "postgres.h"

#include "access/heapam.h"
#include "catalog/pg_attribute.h"
#include "catalog/pg_class.h"
#include "catalog/pg_database.h"
#include "catalog/pg_inherits.h"
#include "catalog/pg_proc.h"
#include "catalog/pg_largeobject.h"
#include "nodes/parsenodes.h"
#include "sepgsql.h"
#include "utils/portal.h"
#include "utils/fmgroids.h"
#include "utils/syscache.h"

/* ---- local declaration of proxy functions ---- */
static void verifyRelationPerm(Oid relid, uint32 perms)
{
	HeapTuple tup;
	Form_pg_class pg_class;
	char *audit;
	int rc;

	tup = SearchSysCache(RELOID,
						 ObjectIdGetDatum(relid),
						 0, 0, 0);
	if (!HeapTupleIsValid(tup))
		selerror("cache lookup failed for relid=%u", relid);

	pg_class = ((Form_pg_class) GETSTRUCT(tup));
	rc = sepgsql_avc_permission(sepgsqlGetClientPsid(),
								pg_class->relselcon,
								SECCLASS_TABLE,
								perms, &audit);
	sepgsql_audit(rc, audit, NameStr(pg_class->relname));

	ReleaseSysCache(tup);
}

static void verifyColumnPerm(Oid relid, AttrNumber attnum, uint32 perms)
{
	HeapTuple tup;
	Form_pg_attribute attr;
	char *audit;
	int rc;

	tup = SearchSysCache(ATTNUM,
						 ObjectIdGetDatum(relid),
						 Int16GetDatum(attnum),
						 0, 0);
	if (!HeapTupleIsValid(tup))
		selerror("cache lookup failed (relid=%u, attnum=%d)", relid, attnum);
	attr = (Form_pg_attribute) GETSTRUCT(tup);

	rc = sepgsql_avc_permission(sepgsqlGetClientPsid(),
								attr->attselcon,
								SECCLASS_COLUMN,
								perms,
								&audit);
	sepgsql_audit(rc, audit, NameStr(attr->attname));

	ReleaseSysCache(tup);
}

static void verifyRteRelationInheritance(Query *query, Oid relid, uint32 perms)
{
	Relation inhrel;
	HeapScanDesc sdesc;
	ScanKeyData skey;

	inhrel = relation_open(InheritsRelationId, AccessShareLock);
	ScanKeyInit(&skey,
				Anum_pg_inherits_inhparent,
				BTEqualStrategyNumber, F_OIDEQ,
				ObjectIdGetDatum(relid));
	sdesc = heap_beginscan(inhrel, SnapshotNow, 1, &skey);
	while (true) {
		HeapTuple tup;
		Oid chdid;

		tup = heap_getnext(sdesc, ForwardScanDirection);
		if (!HeapTupleIsValid(tup))
			break;
		chdid = ((Form_pg_inherits) GETSTRUCT(tup))->inhrelid;
		verifyRelationPerm(chdid, perms);

		verifyRteRelationInheritance(query, relid, perms);
	}
	heap_endscan(sdesc);
    relation_close(inhrel, NoLock);
}

static void verifyRteRelation(Query *query, RangeTblEntry *rte)
{
	verifyRelationPerm(rte->relid, rte->access_vector);
	if (rte->inh)
		verifyRteRelationInheritance(query, rte->relid, rte->access_vector);
}

static void verifyRteFunction(Query *query, FuncExpr *func)
{
	Assert(IsA(func, FuncExpr));
	sepgsqlWalkExpr(query, true, (Expr *) func);
}

static void verifyRteValues(Query *query, List *valuesList)
{
	ListCell *l1, *l2;

	foreach(l1, valuesList) {
		List *sublist = (List *) lfirst(l1);
		foreach(l2, sublist)
			sepgsqlWalkExpr(query, true, (Expr *) lfirst(l2));
	}
}

static void verifyFromItem(Query *query, Node *n)
{
	if (IsA(n, RangeTblRef)) {
		RangeTblRef *rtr = (RangeTblRef *)n;
		RangeTblEntry *rte = list_nth(query->rtable, rtr->rtindex - 1);
		Assert(IsA(rte, RangeTblEntry));

		switch (rte->rtekind) {
		case RTE_RELATION:
			if (query->commandType == CMD_SELECT)
				rte->access_vector |= TABLE__SELECT;
			verifyRteRelation(query, rte);
			break;
		case RTE_SUBQUERY:
			sepgsqlSecureRewrite(rte->subquery);
			break;
		case RTE_FUNCTION:
			verifyRteFunction(query, (FuncExpr *) rte->funcexpr);
			break;
		case RTE_VALUES:
			verifyRteValues(query, rte->values_lists);
			break;
		case RTE_JOIN:
		case RTE_SPECIAL:
		default:
			selerror("rtekind = %d should not be found on fromList", rte->rtekind);
			break;
		}
	} else if (IsA(n, JoinExpr)) {
		JoinExpr *j = (JoinExpr *) n;
		verifyFromItem(query, j->larg);
		verifyFromItem(query, j->rarg);
	}
}

static void verifyFromList(Query *query)
{
	ListCell *l;

	foreach (l, query->jointree->fromlist)
		verifyFromItem(query, (Node *) lfirst(l));
	if (query->commandType != CMD_SELECT) {
		RangeTblEntry *rte = list_nth(query->rtable, query->resultRelation - 1);
		Assert(rte->rtekind == RTE_RELATION);
		verifyRteRelation(query, rte);
	}
}

/* selectProxy() -- check SELECT statement */
static void selectProxy(Query *query)
{
	ListCell *l;

	/* check column:select on the target column */
	foreach (l, query->targetList) {
		TargetEntry *te = (TargetEntry *) lfirst(l);
		Assert(IsA(te, TargetEntry));
		sepgsqlWalkExpr(query, true, te->expr);
	}

	/* check WHERE clause */
	sepgsqlWalkExpr(query, true, (Expr *)query->jointree->quals);

	/* FIXME: HAVING, GROUP BY, ... */

	/* permission mark on the fromList */
    verifyFromList(query);
}

/* updateProxy() -- check UPDATE statement */
static void updateProxy(Query *query)
{
	ListCell *l;
	RangeTblEntry *rte;

	/* check table:update on the target relation */
	rte = (RangeTblEntry *) list_nth(query->rtable, query->resultRelation - 1);
	Assert(IsA(rte, RangeTblEntry) && rte->rtekind == RTE_RELATION);
	rte->access_vector |= TABLE__UPDATE;

	/* check column:update on the target columns */
	foreach(l, query->targetList) {
		TargetEntry *te = (TargetEntry *) lfirst(l);
		verifyColumnPerm(rte->relid, te->resno, COLUMN__UPDATE);
		sepgsqlWalkExpr(query, true, te->expr);
	}

	/* check WHERE clause */
	sepgsqlWalkExpr(query, true, (Expr *)query->jointree->quals);

	/* check RETURNING clause */
	foreach(l, query->returningList) {
		TargetEntry *te = (TargetEntry *) lfirst(l);
		Assert(IsA(te, TargetEntry));
		sepgsqlWalkExpr(query, true, te->expr);
	}

    /* permission mark on the USING clause, and targetRelation */
    verifyFromList(query);
}

/* insertProxy() -- check INSERT statement */
static void insertProxy(Query *query)
{
	ListCell *l;
	RangeTblEntry *rte;

	/* 1. check table:insert on the target relation */
	rte = (RangeTblEntry *) list_nth(query->rtable, query->resultRelation - 1);
	Assert(IsA(rte, RangeTblEntry) && rte->rtekind == RTE_RELATION);
	rte->access_vector |= TABLE__INSERT;

	/* permission check on any column */
	foreach(l, query->targetList) {
		TargetEntry *te = (TargetEntry *) lfirst(l);
		verifyColumnPerm(rte->relid, te->resno, COLUMN__INSERT);
		sepgsqlWalkExpr(query, true, te->expr);
	}

	/* permission mark on RETURNING clause, if necessary. */
	foreach(l, query->returningList) {
		TargetEntry *te = (TargetEntry *) lfirst(l);
		Assert(IsA(te, TargetEntry));
		sepgsqlWalkExpr(query, true, te->expr);
	}

	/* check target relation's permission */
	verifyFromList(query);
}

/* deleteProxy() -- check DELETE statement */
static void deleteProxy(Query *query)
{
	RangeTblEntry *rte;
	ListCell *l;

	/* permission mark on the target relation */
	rte = (RangeTblEntry *) list_nth(query->rtable, query->resultRelation - 1);
	Assert(IsA(rte, RangeTblEntry) && rte->rtekind == RTE_RELATION);
	rte->access_vector |= TABLE__DELETE;

	/* permission mark on RETURNING clause, if necessary */
	foreach(l, query->returningList) {
		TargetEntry *te = (TargetEntry *) lfirst(l);
		Assert(IsA(te, TargetEntry));
		sepgsqlWalkExpr(query, false, te->expr);
	}
	/* permission mark on WHERE clause, if necessary */
	sepgsqlWalkExpr(query, false, (Expr *) query->jointree->quals);

	/* permission mark on the USING clause, and targetRelation */
	verifyFromList(query);
}

/* sepgsqlProxyPortal() -- abort current transaction,
 * if the queries try to execute are not allowed by security
 * policy.
 * @portal : the portal object of queries (read only)
 */
void sepgsqlProxyPortal(Portal portal)
{
	ListCell *query_item;

	foreach (query_item, portal->parseTrees) {
		ListCell *l;
		Query *query = (Query *) lfirst(query_item);

		/* clean up access_vector */
		foreach (l, query->rtable) {
			RangeTblEntry *rte = (RangeTblEntry *) lfirst(l);
			Assert(IsA(rte, RangeTblEntry));
			rte->access_vector = 0;
		}
		switch (query->commandType) {
		case CMD_SELECT:
			selectProxy(query);
			break;
		case CMD_UPDATE:
			updateProxy(query);
			break;
		case CMD_INSERT:
			insertProxy(query);
			break;
		case CMD_DELETE:
			deleteProxy(query);
			break;
		case CMD_UTILITY:
			/* do nothting */
			break;
		default:
			selnotice("Query->commandType = %u is not proxied", query->commandType);
			break;
		}
	}
}
