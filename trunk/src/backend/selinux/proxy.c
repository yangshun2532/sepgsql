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

static void sepgsqlProxyQuery(Query *query);

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
	sepgsqlWalkExpr(query, true, (Node *) func);
}

static void verifyRteValues(Query *query, List *valuesList)
{
	Assert(IsA(valuesList, List));
	sepgsqlWalkExpr(query, true, (Node *) valuesList);
}

static void verfityJoinTree(Query *query, Node *n)
{
	if (n == NULL)
		return;

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
			sepgsqlProxyQuery(rte->subquery);
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
	} else if (IsA(n, FromExpr)) {
		FromExpr *f = (FromExpr *)n;
		ListCell *l;

		foreach(l, f->fromlist)
			verfityJoinTree(query, (Node *) lfirst(l));
	} else if (IsA(n, JoinExpr)) {
		JoinExpr *j = (JoinExpr *)n;

		verfityJoinTree(query, j->larg);
		verfityJoinTree(query, j->rarg);
	} else {
		selerror("unrecognized node type (%d) in query->jointree", nodeTag(n));
	}
}

static void sepgsqlProxyQuery(Query *query)
{
	CmdType cmdType = query->commandType;
	RangeTblEntry *rte = NULL;
	ListCell *l;

	switch (cmdType) {
	case CMD_SELECT:
	case CMD_UPDATE:
	case CMD_INSERT:
	case CMD_DELETE:
		break;
	default:
		return;		/* do nothing */
		break;
	}

	/* cleanup rte->access_vector */
	foreach (l, query->rtable) {
		RangeTblEntry *rte = (RangeTblEntry *) lfirst(l);
		Assert(IsA(rte, RangeTblEntry));
		rte->access_vector = 0;
	}

	/* mark table:xxxx on the target Relation */
	if (query->commandType != CMD_SELECT) {
		rte = (RangeTblEntry *) list_nth(query->rtable, query->resultRelation - 1);
		Assert(IsA(rte, RangeTblEntry) && rte->rtekind == RTE_RELATION);
		switch (cmdType) {
		case CMD_UPDATE:
			rte->access_vector |= TABLE__UPDATE;
			break;
		case CMD_INSERT:
			rte->access_vector |= TABLE__INSERT;
			break;
		case CMD_DELETE:
			rte->access_vector |= TABLE__DELETE;
			break;
		default:
			selerror("could not handle this commandType (%d)", cmdType);
		}
	}

	/* check column:xxxx on the target column, except DELETE statement.
	 *
	 * ORDER BY/GROUP BY clause may use targetList,
	 * so we have to verify a junk column.
	 */
	if (cmdType != CMD_DELETE) {
		seldebug("verify targetList");
		foreach (l, query->targetList) {
			TargetEntry *te = (TargetEntry *) lfirst(l);
			Assert(IsA(te, TargetEntry));

			sepgsqlWalkExpr(query, true, (Node *) te->expr);
			if (cmdType == CMD_SELECT)
				continue;
			/* cmdType == CMD_UPDATE or CMD_INSERT */
			verifyColumnPerm(rte->relid, te->resno,
							 cmdType==CMD_UPDATE
							 ? COLUMN__UPDATE
							 : COLUMN__INSERT);
		}
	}

    /* permission check on WHERE/HAVING clause, if necessary */
	seldebug("verify WHERE clause");
    sepgsqlWalkExpr(query, true, query->jointree->quals);
	seldebug("verify HAVING clause");
	sepgsqlWalkExpr(query, true, query->havingQual);

	/* permission check on RETURNING clause, if necessary. */
	seldebug("verify RETURNING clause");
	foreach(l, query->returningList) {
		TargetEntry *te = (TargetEntry *) lfirst(l);
		Assert(IsA(te, TargetEntry));
		if (te->resjunk)
			continue;
		sepgsqlWalkExpr(query, true, (Node *) te->expr);
	}

	/* check ORDER BY clause */
	//sepgsqlWalkExpr(query, true, (Node *) query->sortClause);

	/* check GROUP BY/HAVING clause */
	//sepgsqlWalkExpr(query, true, (Node *) query->groupClause);

	/* check permission on the USING clause, and target Relation */
	seldebug("verify FROM/USING clause, and target Relation");
	verfityJoinTree(query, (Node *) query->jointree);
	if (cmdType == CMD_INSERT)
		verifyRteRelation(query, rte);
}

/* sepgsqlProxyPortal() -- abort current transaction,
 * if the queries try to execute are not allowed by security
 * policy.
 * @portal : the portal object of queries (read only)
 */
void sepgsqlProxyPortal(Portal portal)
{
	ListCell *query_item;

	foreach (query_item, portal->parseTrees)
		sepgsqlProxyQuery((Query *) lfirst(query_item));
}
