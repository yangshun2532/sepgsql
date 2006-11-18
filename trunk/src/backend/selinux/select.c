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

	/* (1) permission check on fromlist */
	foreach(x, query->jointree->fromlist) {
		Node *n = lfirst(x);
		selinuxCheckFromItem(query, n);
	}

	/* (2) permission check on each column */
	foreach(x, query->targetList) {
		TargetEntry *tle = (TargetEntry *)lfirst(x);
		Assert(IsA(tle, TargetEntry));
		selinuxCheckExpr(query, tle->expr);
	}

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
			selinuxCheckRteRelation(query, rte, index, TABLE__SELECT);
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

		rc = libselinux_avc_permission(selinuxGetClientPsid(),
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

void selinuxCheckRteRelation(Query *query, RangeTblEntry *rte, int index, uint32 perm)
{
	Relation rel;
	FuncExpr *func;
	List *args;
	Var *var;
	Const *cons;
	Form_pg_attribute pg_attr;
	Form_pg_class pg_class;
	char *audit;
	int cls, attno, rc;
	
	Assert(rte->relkind == RTE_RELATION);
	Assert(perm==TABLE__SELECT || perm==TABLE__UPDATE || perm==TABLE__DELETE);

	rel = relation_open(rte->relid, AccessShareLock);
	pg_class = RelationGetForm(rel);

	/* (1) check table permission of this relation and
	 * super relation if necessary
	 */
	rc = libselinux_avc_permission(selinuxGetClientPsid(),
								   pg_class->relselcon,
								   SECCLASS_TABLE,
								   perm, &audit);
	selinux_audit(rc, audit, NameStr(pg_class->relname));
	if (rte->inh)
		selinuxCheckRteRelationInheritance(rte->relid, perm);

	/* (2) append a additional condition into where clause
	 * to narrow down the result set
	 */
	if (IsSystemClass(pg_class)) {
		switch (RelationGetRelid(rel)) {
		case AttributeRelationId:
			attno = Anum_pg_attribute_attselcon - 1;
			cls = SECCLASS_COLUMN;
			break;
		case RelationRelationId:
			if (pg_class->relkind != RELKIND_RELATION)
				goto skip;
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
		case LargeObjectRelationId: /* not supported yet */
		default:
			goto skip;
			break;
		}
		switch (perm) {
		case TABLE__SELECT:
			perm = COMMON_DATABASE__GETATTR;
			break;
		case TABLE__UPDATE:
			perm = COMMON_DATABASE__SETATTR;
			break;
		case TABLE__DELETE:
			perm = COMMON_DATABASE__DROP;
			break;
		}
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
		if (attno >= RelationGetDescr(rel)->natts)
			goto skip;
		cls = SECCLASS_TUPLE;
		switch (perm) {
		case TABLE__SELECT:
			perm = TUPLE__SELECT;
			break;
		case TABLE__UPDATE:
			perm = TUPLE__UPDATE;
			break;
		case TABLE__DELETE:
			perm = TUPLE__DELETE;
			break;
		}
	}
	/* 1st arg : security context of subject */
	cons = makeConst(PSIDOID, sizeof(psid),
					 ObjectIdGetDatum(selinuxGetClientPsid()),
					 false, true);
	args = list_make1(cons);

	/* 2nd arg : security context of object */
	pg_attr = RelationGetDescr(rel)->attrs[attno];
	var = makeVar(index, pg_attr->attnum, pg_attr->atttypid, pg_attr->atttypmod, 0);
	args = lappend(args, var);

	/* 3rd arg : object class */
	cons = makeConst(INT4OID, sizeof(int32), Int32GetDatum(cls), false, true);
	args = lappend(args, cons);

	/* 4th arg : access vector */
	cons = makeConst(INT4OID, sizeof(int32), Int32GetDatum(perm), false, true);
	args = lappend(args, cons);

	func = makeFuncExpr(F_SELINUX_PERMISSION, BOOLOID, args, COERCE_DONTCARE);
	if (query->jointree->quals != NULL) {
		query->jointree->quals =
			(Node *)makeBoolExpr(AND_EXPR,
								 list_make2(func, query->jointree->quals));
	} else {
		query->jointree->quals = (Node *)func;
	}
	seldebug("append selinux_permission('%s', '%s.%s', %u, 0x%08x)",
			 libselinux_psid_to_context(selinuxGetClientPsid()),
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
		Form_pg_class pg_class;
		Form_pg_attribute pg_attr;
		HeapTuple tup;
		
		/* 1. check table:select permission */
		tup = SearchSysCache(RELOID,
							 ObjectIdGetDatum(rte->relid),
							 0, 0, 0);
		if (!HeapTupleIsValid(tup))
			selerror("cache lookup failed for pg_class %u", rte->relid);

		pg_class = (Form_pg_class) GETSTRUCT(tup);
		seldebug("checking table:select on '%s'",
				 NameStr(pg_class->relname));
		rc = libselinux_avc_permission(selinuxGetClientPsid(),
									   pg_class->relselcon,
									   SECCLASS_TABLE,
									   TABLE__SELECT,
									   &audit);
		selinux_audit(rc, audit, NameStr(pg_class->relname));
		ReleaseSysCache(tup);

		/* 2. check column:select permission */
		tup = SearchSysCache(ATTNUM,
							 ObjectIdGetDatum(rte->relid),
							 Int16GetDatum(v->varattno),
							 0, 0);
		if (!HeapTupleIsValid(tup))
			selerror("cache lookup failed for pg_attribute (relid=%u, attnum=%d)",
					 rte->relid, v->varattno);

		pg_attr = (Form_pg_attribute) GETSTRUCT(tup);
		seldebug("checking column:select on '%s.%s'",
				 NameStr(pg_class->relname),
				 NameStr(pg_attr->attname));
		rc = libselinux_avc_permission(selinuxGetClientPsid(),
									   pg_attr->attselcon,
									   SECCLASS_COLUMN,
									   COLUMN__SELECT,
									   &audit);
		selinux_audit(rc, audit, NameStr(pg_attr->attname));
		ReleaseSysCache(tup);
	} else if (rte->rtekind == RTE_JOIN) {
		Var *join_var = list_nth(rte->joinaliasvars, v->varattno - 1);
		selinuxCheckVar(query, join_var);
	} else {
		seldebug("rtekind = %s is ignored", rte->rtekind);
	}
}
