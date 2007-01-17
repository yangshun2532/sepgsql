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

static void secureRewriteFromItem(Query *query, Node *n, Node **quals)
{
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
		case RTE_JOIN:
			selerror("rtekind = RTE_JOIN should be found in fromList");
			break;
		case RTE_SPECIAL:
			selerror("rtekind = RTE_SPECIAL should be found in fromList");
			break;
		case RTE_FUNCTION:
			/* do nothing */
			break;
		case RTE_VALUES:
			/* do nothing */
			break;
		default:
			selerror("unknown rtekind = %d found", rte->rtekind);
			break;
		}
	} else if (IsA(n, JoinExpr)) {
		JoinExpr *j = (JoinExpr *) n;
		secureRewriteFromItem(query, j->larg, &j->quals);
		secureRewriteFromItem(query, j->rarg, &j->quals);
	}
}

static void secureRewriteFromList(Query *query)
{
	FromExpr *jtree = query->jointree;
	ListCell *l;

	foreach (l, jtree->fromlist)
		secureRewriteFromItem(query, (Node *) lfirst(l), &jtree->quals);
	if (query->commandType != CMD_SELECT) {
		RangeTblEntry *rte = list_nth(query->rtable, query->resultRelation - 1);
		Assert(rte->rtekind == RTE_RELATION);
		secureRewriteRelation(query, rte, query->resultRelation, &jtree->quals);
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
	secureRewriteFromList(query);
}

static void secureRewriteUpdate(Query *query)
{
	RangeTblEntry *rte;
	ListCell *l;

	/* permission mark on the target relation */
	rte = (RangeTblEntry *) list_nth(query->rtable, query->resultRelation - 1);
	Assert(IsA(rte, RangeTblEntry));
	rte->access_vector |= TABLE__UPDATE;

	/* permission mark on the targetList */

	/* permission mark on RETURNING clause, if necessary */
	foreach(l, query->returningList) {
		TargetEntry *te = (TargetEntry *) lfirst(l);
		Assert(IsA(te, TargetEntry));
		sepgsqlWalkExpr(query, false, te->expr);
	}

	/* permission mark on WHERE clause, if necessary */
	sepgsqlWalkExpr(query, false, (Expr *) query->jointree->quals);

	/* permission mark on the USING clause, and targetRelation */
    secureRewriteFromList(query);
}

#if 0
static void secureRewriteInsert(Query *query)
{
	Form_pg_class pg_class;
	Form_pg_attribute attr;
	HeapTuple rtup, atup;
	RangeTblEntry *rte;
	ListCell *l;
	int rindex;
	bool has_explicit_labeling = false;

	/* 2. call sepgsql_check_insert(), if necessary */
	rtup = SearchSysCache(RELOID,
						  ObjectIdGetDatum(rte->relid),
						  0, 0, 0);
	if (!HeapTupleIsValid(rtup))
		selerror("cache lookup failed (relid=%u)", rte->relid);
	pg_class = (Form_pg_class) GETSTRUCT(rtup);

	foreach (l, query->targetList) {
		TargetEntry *te = (TargetEntry *) lfirst(l);
		atup = SearchSysCache(ATTNUM,
							  ObjectIdGetDatum(rte->relid),
							  Int16GetDatum(te->resno),
							  0, 0);
		if (!HeapTupleIsValid(atup))
			selerror("cache lookup failed (relid=%u, attnum=%d)",
					 rte->relid, te->resno);
		attr = (Form_pg_attribute) GETSTRUCT(atup);
		if (sepgsqlAttributeIsPsid(attr)) {
			uint16 tclass = __get_tclass_by_relid(attr->attrelid);
			te->expr = call_sepgsql_check_insert(te->expr, pg_class->relselcon, tclass);
			has_explicit_labeling = true;
		}
		ReleaseSysCache(atup);

		sepgsqlWalkExpr(query, true, te->expr, rperms);
	}
	ReleaseSysCache(rtup);

	/* 3. add implicit labeling, if necessary */
	if (!has_explicit_labeling) {
		int i;
		Relation rel = relation_open(rte->relid, AccessShareLock);
		for (i=0; i < RelationGetNumberOfAttributes(rel); i++) {
			attr = RelationGetDescr(rel)->attrs[i];
			if (sepgsqlAttributeIsPsid(attr)) {
				TargetEntry *te;
				Const *cons;
				psid tupcon;

				tupcon = sepgsql_avc_createcon(sepgsqlGetClientPsid(),
											   pg_class->relselcon,
											   SECCLASS_TUPLE);
				cons = makeConst(PSIDOID, sizeof(psid),
								 ObjectIdGetDatum(tupcon),
								 false, true);
				te = makeTargetEntry((Expr *)cons, i + 1,
									 pstrdup(NameStr(attr->attname)),
									 false);
				query->targetList = lappend(query->targetList, te);
				goto out;
			}
		}
		seldebug("relation '%s' did not have '%s' column",
				 RelationGetRelationName(rel), TUPLE_SELCON);
	out:
		relation_close(rel, NoLock);
	}
}
#endif

static void secureRewriteDelete(Query *query)
{
	ListCell *l;
	RangeTblEntry *rte;

	/* permission mark on the target relation */
	rte = (RangeTblEntry *) list_nth(query->rtable, query->resultRelation - 1);
	Assert(IsA(rte, RangeTblEntry));
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
	secureRewriteFromList(query);
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
		/* no nothing */
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

/* sepgsqlExecuteQuery() -- add implicit labeling and relabel from/to
 * permission checking, when CREATE TABLE ... AS EXECUTE <prep>;
 * The arguments are copied object, so we can modify it to append
 * an additional conditions.
 */
void sepgsqlExecuteQuery(Query *query, Plan *plan)
{
#if 0
	ListCell *l;
	TargetEntry *te;
	psid tblcon, tupcon;

	Assert(query->commandType == CMD_SELECT);
	Assert(query->into != NULL);

	/* compute implicit labeling */
	tblcon = sepgsql_avc_createcon(sepgsqlGetClientPsid(),
								   sepgsqlGetDatabasePsid(),
								   SECCLASS_TABLE);
	tupcon = sepgsql_avc_createcon(sepgsqlGetClientPsid(),
								   tblcon,
								   SECCLASS_TUPLE);

	/* check explicit labeling */
	foreach(l, plan->targetlist) {
		bool has_explicit = false;
		te = (TargetEntry *) lfirst(l);

		if (!strcmp(te->resname, TUPLE_SELCON)) {
			te->expr = call_sepgsql_check_insert(te->expr, tblcon,
												 SECCLASS_TABLE);
			has_explicit = true;
		}

		if (!has_explicit) {
			/* add implicit labeling */
			AttrNumber resno = list_length(plan->targetlist) + 1;
			Const *con = makeConst(PSIDOID, sizeof(psid),
								   ObjectIdGetDatum(tupcon),
								   false, true);
			Expr *expr = call_sepgsql_check_insert((Expr *)con, tblcon,
												   SECCLASS_TABLE);
			te = makeTargetEntry(expr, resno, TUPLE_SELCON, false);
			plan->targetlist = lappend(plan->targetlist, te);
		}
	}
#endif
}
