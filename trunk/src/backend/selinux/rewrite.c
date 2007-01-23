/*
 * src/backend/selinux/rewrite.c
 *   SE-PostgreSQL Query rewriting implementation.
 *
 * Copyright (c) 2006 - 2007, KaiGai Kohei <kaigai@kaigai.gr.jp>
 */
#include "postgres.h"

#include "access/heapam.h"
#include "catalog/heap.h"
#include "catalog/pg_attribute.h"
#include "catalog/pg_class.h"
#include "catalog/pg_database.h"
#include "catalog/pg_largeobject.h"
#include "catalog/pg_type.h"
#include "nodes/makefuncs.h"
#include "nodes/plannodes.h"
#include "parser/parse_expr.h"
#include "parser/parse_coerce.h"
#include "parser/parse_relation.h"
#include "sepgsql.h"
#include "utils/portal.h"
#include "utils/fmgroids.h"
#include "utils/syscache.h"

static void secureRewriteQuery(Query *query);

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
			secureRewriteQuery(rte->subquery);
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

static void secureRewriteQuery(Query *query)
{
	CmdType cmdType = query->commandType;
	RangeTblEntry *rte = NULL;
	ListCell *l;

	if (cmdType != CMD_SELECT) {
		rte = list_nth(query->rtable, query->resultRelation - 1);
		Assert(IsA(rte, RangeTblEntry));
		Assert(rte->rtekind == RTE_RELATION);
		switch (cmdType) {
		case CMD_INSERT:
			rte->access_vector |= TABLE__INSERT;
			break;
		case CMD_UPDATE:
			rte->access_vector |= TABLE__UPDATE;
			break;
		case CMD_DELETE:
			rte->access_vector |= TABLE__DELETE;
			break;
		default:
			selerror("commandType = %d should not be found here", cmdType);
			break;
		}
	}

	/* permission mark on the target columns */
	if (cmdType != CMD_DELETE) {
		foreach (l, query->targetList) {
			TargetEntry *te = lfirst(l);
			Assert(IsA(te, TargetEntry));
			sepgsqlWalkExpr(query, false, (Node *) te->expr);
		}
	}

	/* permission mark on RETURNING clause, if necessary */
	sepgsqlWalkExpr(query, false, (Node *) query->returningList);

	/* permission mark on the WHERE/HAVING clause */
	sepgsqlWalkExpr(query, false, query->jointree->quals);
	sepgsqlWalkExpr(query, false, query->havingQual);

	/* permission mark on the ORDER BY clause */
	//sepgsqlWalkExpr(query, false, (Node *) query->sortClause);

	/* permission mark on the GROUP BY/HAVING clause */
	//sepgsqlWalkExpr(query, false, (Node *) query->groupClause);

	/* append sepgsql_permission() on the FROM clause/USING clause
	 * for SELECT/UPDATE/DELETE statement.
	 * The target Relation of INSERT is noe necessary to append it
	 */
	secureRewriteJoinTree(query, (Node *)query->jointree,
						  &query->jointree->quals);
}

static Query *convertTruncateToDelete(Relation rel)
{
	Query *query = makeNode(Query);
	RangeTblEntry *rte;
	RangeTblRef *rtr;

	rte = addRangeTableEntryForRelation(NULL, rel, NULL, false, false);
	rte->requiredPerms = ACL_DELETE;
	rtr = makeNode(RangeTblRef);
	rtr->rtindex = 1;

	query->commandType = CMD_DELETE;
	query->rtable = list_make1(rte);
	query->jointree = makeNode(FromExpr);
	query->jointree->fromlist = list_make1(rtr);
	query->jointree->quals = NULL;
	query->resultRelation = rtr->rtindex;
	query->hasSubLinks = false;
	query->hasAggs = false;

	secureRewriteQuery(query);

	return query;
}

static List *secureRewriteTruncate(Query *query)
{
	TruncateStmt *stmt = (TruncateStmt *) query->utilityStmt;
	Relation rel;
	Query *subqry;
	ListCell *l;
	List *subquery_list = NIL, *subquery_lids = NIL;

	/* resolve the relation names */
	foreach (l, stmt->relations) {
		RangeVar *rv = lfirst(l);

		rel = heap_openrv(rv, AccessShareLock);
		subqry = convertTruncateToDelete(rel);
		subquery_list = lappend(subquery_list, subqry);
		subquery_lids = lappend_oid(subquery_lids, RelationGetRelid(rel));
		heap_close(rel, NoLock);

		selnotice("virtual TRUNCATE %s", RelationGetRelationName(rel));
	}

	if (stmt->behavior == DROP_CASCADE) {
		subquery_lids = heap_truncate_find_FKs(subquery_lids);
		foreach (l, subquery_lids) {
			Oid relid = lfirst_oid(l);

			rel = heap_open(relid, AccessShareLock);
			subqry = convertTruncateToDelete(rel);
			subquery_list = lappend(subquery_list, subqry);
			heap_close(rel, NoLock);
		}
	}
	return subquery_list;
}

List *sepgsqlSecureRewrite(List *queryList)
{
	ListCell *l;
	List *result = NIL;

	foreach(l, queryList) {
		Query *query = (Query *) lfirst(l);
		List *new_list = NIL;

		switch (query->commandType) {
		case CMD_SELECT:
		case CMD_UPDATE:
		case CMD_INSERT:
		case CMD_DELETE:
			secureRewriteQuery(query);
			new_list = list_make1(query);
			break;
		case CMD_UTILITY:
			switch (nodeTag(query->utilityStmt)) {
			case T_TruncateStmt:
				new_list = secureRewriteTruncate(query);
				break;
			default:
				new_list = list_make1(query);
			}
			break;
		default:
			selerror("unknown command type (=%d) found", query->commandType);
			break;
		}
		result = list_concat(result, new_list);
	}
	return result;
}
