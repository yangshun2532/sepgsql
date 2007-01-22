/*
 * src/backend/selinux/rewrite.c
 *   SE-PostgreSQL Query rewriting implementation.
 *
 * Copyright (c) 2006 - 2007, KaiGai Kohei <kaigai@kaigai.gr.jp>
 */
#include "postgres.h"

#include "access/heapam.h"
#include "catalog/pg_attribute.h"
#include "catalog/pg_class.h"
#include "catalog/pg_database.h"
#include "catalog/pg_largeobject.h"
#include "catalog/pg_type.h"
#include "nodes/makefuncs.h"
#include "nodes/plannodes.h"
#include "parser/parse_expr.h"
#include "parser/parse_coerce.h"
#include "sepgsql.h"
#include "utils/portal.h"
#include "utils/fmgroids.h"
#include "utils/syscache.h"

static void secureRewriteRelation(Query *query, RangeTblEntry *rte, int rtindex, Node **quals)
{
	Relation rel;
	TupleDesc tdesc;
	AttrNumber attno;
	uint32 perms = 0;
	uint16 tclass;

	rel = relation_open(rte->relid, AccessShareLock);
	tdesc = RelationGetDescr(rel);

	switch (RelationGetRelid(rel)) {
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
	if (rte->access_vector & TABLE__SELECT)
		perms |= (tclass==SECCLASS_TUPLE) ? TUPLE__SELECT : COMMON_DATABASE__GETATTR;
	if (rte->access_vector & TABLE__UPDATE)
		perms |= (tclass==SECCLASS_TUPLE) ? TUPLE__UPDATE : COMMON_DATABASE__SETATTR;
	if (rte->access_vector & TABLE__INSERT)
		perms |= (tclass==SECCLASS_TUPLE) ? TUPLE__INSERT : COMMON_DATABASE__CREATE;
	if (rte->access_vector & TABLE__DELETE)
		perms |= (tclass==SECCLASS_TUPLE) ? TUPLE__DELETE : COMMON_DATABASE__DROP;
	if (!perms)
		goto skip;

	/* append sepgsql_permission(*.security_context, tclass, perms) */
	for (attno=0; attno < RelationGetNumberOfAttributes(rel); attno++) {
		Form_pg_attribute attr = tdesc->attrs[attno];
		if (sepgsqlAttributeIsPsid(attr)) {
			Var *v1;
			Const *c2, *c3;
			FuncExpr *func;

			if (attr->atttypid != PSIDOID)
				selerror("%s.%s must be PSID",
						 RelationGetRelationName(rel),
						 NameStr(attr->attname));
			/* 1st arg : security context of tuple */
			v1 = makeVar(rtindex, attr->attnum, attr->atttypid, attr->atttypmod, 0);
			/* 2nd arg : object class */
			c2 = makeConst(INT4OID, sizeof(int32),
						   Int32GetDatum(tclass),
						   false, true);
			/* 3rd arg : access vector */
			c3 = makeConst(INT4OID, sizeof(int32),
						   Int32GetDatum(perms),
						   false, true);

			func = makeFuncExpr(F_SEPGSQL_PERMISSION, BOOLOID,
								list_make3(v1, c2, c3), COERCE_DONTCARE);
			if (*quals == NULL) {
				*quals = (Node *) func;
			} else {
				*quals = (Node *) makeBoolExpr(AND_EXPR, list_make2(func, *quals));
			}
			seldebug("append sepgsql_permission(%s.%s, %d, 0x%08x)",
					 RelationGetRelationName(rel),
					 NameStr(attr->attname), tclass, perms);
		}
	}
skip:
	relation_close(rel, NoLock);
}

static void secureRewriteJoinTree(Query *query, Node *n, Node **quals)
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
			secureRewriteRelation(query, rte, rtr->rtindex, quals);
			break;
		case RTE_SUBQUERY:
			sepgsqlSecureRewrite(rte->subquery);
			break;
		case RTE_FUNCTION:
		case RTE_VALUES:
			/* do nothing here */
			break;
		default:
			selerror("rtekind = %d should not be found fromList", rte->rtekind);
			break;
		}
	} else if (IsA(n, FromExpr)) {
		FromExpr *f = (FromExpr *)n;
		ListCell *l;

		foreach(l, f->fromlist)
			secureRewriteJoinTree(query, (Node *) lfirst(l), quals);
	} else if (IsA(n, JoinExpr)) {
		JoinExpr *j = (JoinExpr *)n;

		secureRewriteJoinTree(query, j->larg, &j->quals);
		secureRewriteJoinTree(query, j->rarg, &j->quals);
	} else {
		selerror("unrecognized node type (%d) in query->jointree", nodeTag(n));
	}
}

static void secureRewriteSelect(Query *query)
{
	ListCell *l;

	/* permission mark on the target columns */
	foreach (l, query->targetList) {
		TargetEntry *te = lfirst(l);
		Assert(IsA(te, TargetEntry));
		sepgsqlWalkExpr(query, false, te->expr);
	}
	/* permission mark on the WHERE clause */
	sepgsqlWalkExpr(query, false, (Expr *) query->jointree->quals);

	/* FIXME: HAVING, ORDER BY, GROUP BY, LIMIT */

	/* permission mark on the fromList */
	secureRewriteJoinTree(query, (Node *)query->jointree, &query->jointree->quals);
}

static void secureRewriteUpdate(Query *query)
{
	RangeTblEntry *rte;
	ListCell *l;
	int rindex;

	/* permission mark on RETURNING clause, if necessary */
	foreach(l, query->returningList) {
		TargetEntry *te = (TargetEntry *) lfirst(l);
		Assert(IsA(te, TargetEntry));
		sepgsqlWalkExpr(query, false, te->expr);
	}

	/* permission mark on WHERE clause, if necessary */
	sepgsqlWalkExpr(query, false, (Expr *) query->jointree->quals);

	/* append sepgsql_permission() on the USING clause */
	secureRewriteJoinTree(query, (Node *)query->jointree, &query->jointree->quals);

	/* append sepgsql_permission() on the target Relation */
	rindex = query->resultRelation;
	rte = (RangeTblEntry *) list_nth(query->rtable, rindex - 1);
	Assert(IsA(rte, RangeTblEntry));
	rte->access_vector |= TABLE__UPDATE;
	secureRewriteRelation(query, rte, rindex, &query->jointree->quals);
}

static void secureRewriteInsert(Query *query)
{
	ListCell *l;

	/* permission mark on RETURNING clause, if necessary */
	foreach(l, query->returningList) {
		TargetEntry *te = (TargetEntry *) lfirst(l);
		Assert(IsA(te, TargetEntry));
		sepgsqlWalkExpr(query, false, te->expr);
	}

	/* append sepgsql_permission() on the USING clause */
	secureRewriteJoinTree(query, (Node *)query->jointree, &query->jointree->quals);
}

static void secureRewriteDelete(Query *query)
{
	ListCell *l;
	RangeTblEntry *rte;
	int rindex;

	/* permission mark on RETURNING clause, if necessary */
	foreach(l, query->returningList) {
		TargetEntry *te = (TargetEntry *) lfirst(l);
		Assert(IsA(te, TargetEntry));
		sepgsqlWalkExpr(query, false, te->expr);
	}
	/* permission mark on WHERE clause, if necessary */
	sepgsqlWalkExpr(query, false, (Expr *) query->jointree->quals);

	/* append sepgsql_permission() on the USING clause */
	secureRewriteJoinTree(query, (Node *)query->jointree, &query->jointree->quals);

	/* append sepgsql_permission() on the target Relation */
	rindex = query->resultRelation;
	rte = (RangeTblEntry *) list_nth(query->rtable, rindex - 1);
	Assert(IsA(rte, RangeTblEntry));
	rte->access_vector |= TABLE__DELETE;
	secureRewriteRelation(query, rte, rindex, &query->jointree->quals);
}

void sepgsqlSecureRewrite(Query *query)
{
	ListCell *l;

	switch (query->commandType) {
	case CMD_SELECT:
		secureRewriteSelect(query);
		break;
	case CMD_UPDATE:
		secureRewriteUpdate(query);
		break;
	case CMD_INSERT:
		secureRewriteInsert(query);
		break;
	case CMD_DELETE:
		secureRewriteDelete(query);
		break;
	default:
		/* do nothing */
		break;
	}

	/* clean-up any rte->access_vector */
	foreach (l, query->rtable) {
		RangeTblEntry *rte = (RangeTblEntry *) lfirst(l);
		rte->access_vector = 0;
	}
}
