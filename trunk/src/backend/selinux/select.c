/*
 * src/backend/selinux/select.c
 *     Security Enhanced PostgreSQL implementation.
 *     This file provides proxy hook for SELECT statement.
 *
 *     Copyright (c) 2006 - 2007, KaiGai Kohei <kaigai@kaigai.gr.jp>
 */
#include "postgres.h"

#include "access/heapam.h"
#include "catalog/catalog.h"
#include "catalog/pg_attribute.h"
#include "catalog/pg_class.h"
#include "catalog/pg_database.h"
#include "catalog/pg_inherits.h"
#include "catalog/pg_largeobject.h"
#include "catalog/pg_proc.h"
#include "catalog/pg_type.h"
#include "nodes/makefuncs.h"
#include "sepgsql.h"
#include "storage/lock.h"
#include "utils/fmgroids.h"
#include "utils/syscache.h"

#include <selinux/flask.h>
#include <selinux/av_permissions.h>

static void selinuxCheckFromItem(Query *query, Node *n);
static void selinuxCheckRteJoin(Query *query, JoinExpr *j);
static void selinuxCheckRteSubquery(Query *query, RangeTblEntry *rte);

Query *selinuxProxySelect(Query *query)
{
	ListCell *x;

	/* 1. permission checking on fromlist */
	foreach (x, query->targetList) {
		TargetEntry *tle = (TargetEntry *) lfirst(x);
		Assert(IsA(tle, TargetEntry));
		selinuxCheckExpr(query, tle->expr);
	}

	/* 2. permission checking on where clause */
	selinuxCheckExpr(query, (Expr *)query->jointree->quals);

	/* 3. permission checking on each column */
	foreach(x, query->jointree->fromlist)
		selinuxCheckFromItem(query, lfirst(x));

	return query;
}

static void selinuxCheckFromItem(Query *query, Node *n)
{
	if (IsA(n, JoinExpr)) {
		JoinExpr *j = (JoinExpr *)n;

		selinuxCheckRteJoin(query, j);
	} else if (IsA(n, RangeTblRef)) {
		RangeTblEntry *rte;
		int index = ((RangeTblRef *)n)->rtindex;
		
		rte = list_nth(query->rtable, index - 1);
		Assert(rte->type == T_RangeTblEntry);
		
		switch (rte->rtekind) {
		case RTE_RELATION:
			rte->access_vector = TABLE__SELECT;
			selinuxCheckRteRelation(query, rte, index);
			break;
		case RTE_SUBQUERY:
			selinuxCheckRteSubquery(query, rte);
			break;
		case RTE_FUNCTION:
			selnotice("RTE_FUNCTION in fromlist is not supported yet");
			break;
		default:
			selerror("unknown relkind (%u) in fromlist", rte->rtekind);
		}
	} else {
		selerror("unknown node (%u) in fromlist", n->type);
	}
}

/* selinuxCheckRteRelation() -- checks permission on Relation
 * and append an additional condition into where clause to
 * restrict its result set.
 * @query : the Quert structure of this statement.
 * @rte : RangeTblEntry which to be checked.
 * @index : index number of RangeTblEntry
 * @perm : access vector to evaluate
 */
static void selinuxCheckRteRelationInheritance(Oid relid, uint32 perm)
{
	Relation pg_inherits;
	HeapScanDesc sdesc;
	ScanKeyData skey;
	HeapTuple tuple;
	char *audit;
	int rc;

	pg_inherits = relation_open(InheritsRelationId, AccessShareLock);
	ScanKeyInit(&skey,
				Anum_pg_inherits_inhparent,
				BTEqualStrategyNumber, F_OIDEQ,
				ObjectIdGetDatum(relid));

	sdesc = heap_beginscan(pg_inherits, SnapshotNow, 1, &skey);
	while (true) {
		Form_pg_class pg_class;
		Oid chld_relid;

		tuple = heap_getnext(sdesc, ForwardScanDirection);
		if (!HeapTupleIsValid(tuple))
			break;

		chld_relid = ((Form_pg_inherits) GETSTRUCT(tuple))->inhrelid;

		tuple = SearchSysCache(RELOID,
							   ObjectIdGetDatum(chld_relid),
							   0, 0, 0);
		if (!HeapTupleIsValid(tuple))
			selerror("cache lookup failed for parent relation (oid=%u)", chld_relid);
		pg_class = ((Form_pg_class) GETSTRUCT(tuple));

		rc = sepgsql_avc_permission(selinuxGetClientPsid(),
									pg_class->relselcon,
									SECCLASS_TABLE,
									perm, &audit);
		selinux_audit(rc, audit, NameStr(pg_class->relname));
		ReleaseSysCache(tuple);

		selinuxCheckRteRelationInheritance(chld_relid, perm);
	}
	heap_endscan(sdesc);
	relation_close(pg_inherits, NoLock);
}

void selinuxCheckRteRelation(Query *query, RangeTblEntry *rte, int index)
{
	Relation rel;
	FuncExpr *func;
	Form_pg_attribute pg_attr;
	Form_pg_class pg_class;
	List *args = NIL;
	uint32 tperm = 0, perm = rte->access_vector;
	int cls, attno, rc;
	char *audit;
	
	Assert(rte->rtekind == RTE_RELATION);
	Assert(perm == (perm & (TABLE__SELECT | TABLE__UPDATE | TABLE__DELETE)));

	rel = relation_open(rte->relid, AccessShareLock);
	pg_class = RelationGetForm(rel);

	/* (1) check table permission of this relation and
	 * super relation if necessary
	 */
	seldebug("avc_permission(%u, %u, %d, %#08x)",
			 selinuxGetClientPsid(), pg_class->relselcon,
			 SECCLASS_TABLE, rte->access_vector);
	rc = sepgsql_avc_permission(selinuxGetClientPsid(),
								pg_class->relselcon,
								SECCLASS_TABLE,
								rte->access_vector,
								&audit);
	selinux_audit(rc, audit, NameStr(pg_class->relname));
	if (rte->inh)
		selinuxCheckRteRelationInheritance(rte->relid, rte->access_vector);

	/* (2) append a additional condition into where clause
	 * to narrow down the result set
	 */
	if (RelationGetRelid(rel) == AttributeRelationId
		|| RelationGetRelid(rel) == RelationRelationId
		|| RelationGetRelid(rel) == DatabaseRelationId
		|| RelationGetRelid(rel) == ProcedureRelationId
		|| RelationGetRelid(rel) == LargeObjectRelationId) {
		switch (RelationGetRelid(rel)) {
		case AttributeRelationId:
			attno = Anum_pg_attribute_attselcon - 1;
			cls = SECCLASS_COLUMN;
			break;
		case RelationRelationId:
			Assert(pg_class->relkind == RELKIND_RELATION);
			attno = Anum_pg_class_relselcon - 1;
			cls = SECCLASS_TABLE;
			break;
		case DatabaseRelationId:
			attno = Anum_pg_database_datselcon - 1;
			cls = SECCLASS_DATABASE;
			break;
		case ProcedureRelationId:
			attno = Anum_pg_proc_proselcon - 1;
			cls = SECCLASS_PROCEDURE;
			break;
		case LargeObjectRelationId:
			/* not supported yet */
		default:
			goto skip;
			break;
		}
		if ((rte->access_vector & TABLE__SELECT) != 0)
			tperm |= COMMON_DATABASE__GETATTR;
		if ((rte->access_vector & TABLE__UPDATE) != 0)
			tperm |= COMMON_DATABASE__SETATTR;
		if ((rte->access_vector & TABLE__DELETE) != 0)
			tperm |= COMMON_DATABASE__DROP;
	} else {
		for (attno=0; attno < RelationGetDescr(rel)->natts; attno++) {
			pg_attr = RelationGetDescr(rel)->attrs[attno];
			if (selinuxAttributeIsPsid(pg_attr)) {
				if (pg_attr->atttypid != PSIDOID)
					selerror("attispsid = true on not psid column (%s)",
							 NameStr(pg_attr->attname));
				break;
			}
		}
		if (attno >= RelationGetNumberOfAttributes(rel))
			goto skip;
		cls = SECCLASS_TUPLE;
		if ((perm & TABLE__SELECT) != 0)
			tperm |= TUPLE__SELECT;
		if ((perm & TABLE__UPDATE) != 0)
			tperm |= TUPLE__UPDATE;
		if ((perm & TABLE__DELETE) != 0)
			tperm |= TUPLE__DELETE;
	}
	/* 1st arg : security context of subject */
	args = lappend(args, makeConst(PSIDOID, sizeof(psid),
								   ObjectIdGetDatum(selinuxGetClientPsid()),
								   false, true));

	/* 2nd arg : security context of object */
	pg_attr = RelationGetDescr(rel)->attrs[attno];
	args = lappend(args, makeVar(index, pg_attr->attnum, pg_attr->atttypid,
								 pg_attr->atttypmod, 0));

	/* 3rd arg : object class */
	args = lappend(args, makeConst(INT4OID, sizeof(int32),
								   Int32GetDatum(cls), false, true));

	/* 4th arg : access vector */
	args = lappend(args, makeConst(INT4OID, sizeof(int32),
								   Int32GetDatum(tperm), false, true));

	func = makeFuncExpr(F_SELINUX_PERMISSION, BOOLOID, args, COERCE_DONTCARE);
	if (query->jointree->quals != NULL) {
		query->jointree->quals =
			(Node *)makeBoolExpr(AND_EXPR,
								 list_make2(func, query->jointree->quals));
	} else {
		query->jointree->quals = (Node *)func;
	}
	seldebug("append selinux_permission('%s', '%s.%s', %u, 0x%08x)",
			 sepgsql_psid_to_context(selinuxGetClientPsid()),
			 NameStr(pg_class->relname), NameStr(pg_attr->attname),
			 cls, perm);
skip:
	relation_close(rel, NoLock);
}

static void selinuxCheckRteJoin(Query *query, JoinExpr *j)
{
	seldebug("join left/right checking");
	selinuxCheckFromItem(query, j->larg);
	selinuxCheckFromItem(query, j->rarg);
}

static void selinuxCheckRteSubquery(Query *query, RangeTblEntry *rte)
{
	seldebug("subquery checking -- recursive");
	rte->subquery = selinuxProxy(rte->subquery);
}

/* -------- selinuxCheckExpr() related helper functions -------- */
static void selinuxCheckVar(Query *query, Var *v);
static void checkExprOpExpr(Query *query, OpExpr *x);
static void checkExprFuncExpr(Query *query, FuncExpr *func);
static void checkExprBoolExpr(Query *query, BoolExpr *be);
static void checkExprRelabelType(Query *query, RelabelType *rt);

/* selinuxCheckExpr() -- check SELECT permission for targetList
 * of SELECT ot returningList of UPDATE/INSERT/DELETE statement.
 */
void selinuxCheckTargetList(Query *query, List *targetList)
{
	ListCell *x;
	
	if (!targetList)
		return;

	foreach(x, targetList) {
		TargetEntry *tle = (TargetEntry *)lfirst(x);
		Assert(IsA(tle, TargetEntry));
		selinuxCheckExpr(query, tle->expr);
	}
}

/* selinuxCheckExpr() -- check SELECT permission for each Expr.
 * It should be called on the target of SELECT, where clause
 * and RETURN expansion.
 * @query : target query
 * @expr  : target expr object
 */
void selinuxCheckExpr(Query *query, Expr *expr)
{
	if (expr == NULL)
		return;

	switch (nodeTag(expr)) {
	case T_Const:
		/* do nothing */
		break;
	case T_Var:
		selinuxCheckVar(query, (Var *)expr);
		break;
	case T_FuncExpr:
		checkExprFuncExpr(query, (FuncExpr *)expr);
		break;
	case T_OpExpr:
		checkExprOpExpr(query, (OpExpr *)expr);
		break;
	case T_BoolExpr:
		checkExprBoolExpr(query, (BoolExpr *)expr);
		break;
	case T_RelabelType:
		checkExprRelabelType(query, (RelabelType *)expr);
		break;
	default:
		seldebug("now, we have no checking on the expr (tag = %u)", nodeTag(expr));
		break;
	}
}

static void selinuxCheckVar(Query *query, Var *v)
{
	RangeTblEntry *rte;
	char *audit;
	int rc;

	Assert(IsA(v, Var));

	rte = (RangeTblEntry *)list_nth(query->rtable, v->varno - 1);
	Assert(IsA(rte, RangeTblEntry));

	if (rte->rtekind == RTE_RELATION) {
		Form_pg_attribute attr;
		HeapTuple tuple;

		/* 1. mark table:select permission */
		/* NOTION: The actual permission checking is done later
		   by selinuxCheckRteRelation(). */
		rte->access_vector |= TABLE__SELECT;

		/* 2. check column:select permission */
		tuple = SearchSysCache(ATTNUM,
							   ObjectIdGetDatum(rte->relid),
							   Int16GetDatum(v->varattno),
							   0, 0);
		if (!HeapTupleIsValid(tuple))
			selerror("cache lookup failed for pg_attribute (relid=%u, attnum=%d)",
					 rte->relid, v->varattno);

		attr = (Form_pg_attribute) GETSTRUCT(tuple);
		seldebug("checking column:select on '%s'", NameStr(attr->attname));
		rc = sepgsql_avc_permission(selinuxGetClientPsid(),
									attr->attselcon,
									SECCLASS_COLUMN,
									COLUMN__SELECT,
									&audit);
		selinux_audit(rc, audit, NameStr(attr->attname));
		ReleaseSysCache(tuple);
	} else if (rte->rtekind == RTE_JOIN) {
		Var *join_var = list_nth(rte->joinaliasvars, v->varattno - 1);
		selinuxCheckVar(query, join_var);
	} else {
		seldebug("rtekind = %u is ignored", rte->rtekind);
	}
}

static void checkExprFuncExpr(Query *query, FuncExpr *func)
{
	psid new_psid;
	ListCell *l;
	HeapTuple tuple;
	Form_pg_proc pg_proc;
	uint32 perms;
	char *audit;
	int rc;

	Assert(IsA(func, FuncExpr));

	seldebug("checking FuncExpr(funcid=%u)", func->funcid);
	/* 1. check arguments */
	foreach(l, func->args)
		selinuxCheckExpr(query, (Expr *)lfirst(l));

	/* 2. obtain the context of procedure */
	tuple = SearchSysCache(PROCOID,
						   ObjectIdGetDatum(func->funcid),
						   0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		selerror("could not lookup the procedure (funcid=%u)", func->funcid);
	pg_proc = (Form_pg_proc) GETSTRUCT(tuple);

	/* 2. compute the context to execute procedure */
	new_psid = sepgsql_avc_createcon(selinuxGetClientPsid(),
									 pg_proc->proselcon,
									 SECCLASS_PROCEDURE);

	/* 3. check permission procedure:{execute entrypoint} */
	perms = PROCEDURE__EXECUTE;
	if (selinuxGetClientPsid() != new_psid)
		perms |= PROCEDURE__ENTRYPOINT;
	rc = sepgsql_avc_permission(selinuxGetClientPsid(),
								pg_proc->proselcon,
								SECCLASS_PROCEDURE,
								perms, &audit);
	selinux_audit(rc, audit, NameStr(pg_proc->proname));
	ReleaseSysCache(tuple);
}

static void checkExprOpExpr(Query *query, OpExpr *x)
{
	ListCell *l;

	seldebug("checking OpExpr(opno=%u)", x->opno);
	foreach(l, x->args)
		selinuxCheckExpr(query, (Expr *)lfirst(l));
}

static void checkExprBoolExpr(Query *query, BoolExpr *be)
{
	ListCell *l;

	Assert(IsA(be, BoolExpr));

	foreach(l, be->args)
		selinuxCheckExpr(query, lfirst(l));
}

static void checkExprRelabelType(Query *query, RelabelType *rt)
{
	Assert(IsA(rt, RelabelType));

	selinuxCheckExpr(query, rt->arg);
}
