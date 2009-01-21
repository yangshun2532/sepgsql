/*
 * src/backend/security/sepgsql/proxy.c
 *    Proxying the given Query trees via SE-PostgreSQL
 *
 * Portions Copyright (c) 1996-2009, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 */
#include "postgres.h"

#include "access/genam.h"
#include "access/heapam.h"
#include "access/sysattr.h"
#include "catalog/heap.h"
#include "catalog/indexing.h"
#include "catalog/namespace.h"
#include "catalog/pg_attribute.h"
#include "catalog/pg_class.h"
#include "catalog/pg_constraint.h"
#include "catalog/pg_database.h"
#include "catalog/pg_largeobject.h"
#include "catalog/pg_operator.h"
#include "catalog/pg_proc.h"
#include "catalog/pg_security.h"
#include "catalog/pg_trigger.h"
#include "catalog/pg_type.h"
#include "executor/executor.h"
#include "nodes/nodeFuncs.h"
#include "nodes/security.h"
#include "optimizer/clauses.h"
#include "optimizer/plancat.h"
#include "optimizer/prep.h"
#include "optimizer/tlist.h"
#include "parser/parsetree.h"
#include "security/pgace.h"
#include "storage/lock.h"
#include "utils/array.h"
#include "utils/fmgroids.h"
#include "utils/fmgrtab.h"
#include "utils/lsyscache.h"
#include "utils/syscache.h"
#include "utils/tqual.h"

/*
 * sepgsqlWalkerContext
 *
 * This structure holds a context during analyzing a given query.
 * selist is a list of SEvalItemXXX objects to enumerate appared
 * tables and columns. These are evaluated later, just before
 * executing query.
 * is_internal_use shows the current state whether the current
 * Node is chained with target list, or conditional clause.
 */
typedef struct sepgsqlWalkerContext
{
	struct sepgsqlWalkerContext *parent;
	Query  *query;	/* Query structure of current layer */
	List   *selist;	/* list of SEvalItemXXX */
	bool	is_internal_use;
} sepgsqlWalkerContext;

/*
 * addEvalRelation
 * addEvalRelationRTE
 *
 * These functions add a given relation into selist, if it is not
 * contained yet. In addition, addEvalRelationRTE also marks required 
 * permissions on rte->pgaceTuplePerms. It is delivered to Scan object
 * and we can use it on ExecScan hook to apply tuple-level access
 * controls.
 */
static List *
addEvalRelation(List *selist, Oid relid, bool inh, uint32 perms)
{
	SEvalItemRelation *ser;

	ListCell   *l;

	foreach(l, selist)
	{
		ser = (SEvalItemRelation *) lfirst(l);
		if (IsA(ser, SEvalItemRelation)
			&& ser->relid == relid
			&& ser->inh == inh)
		{
			ser->perms |= perms;
			return selist;
		}
	}
	/*
	 * not found
	 */
	ser = makeNode(SEvalItemRelation);
	ser->perms = perms;
	ser->relid = relid;
	ser->inh = inh;

	return lappend(selist, ser);
}

static List *
addEvalRelationRTE(List *selist, RangeTblEntry *rte, uint32 perms)
{
	rte->pgaceTuplePerms |= (perms & DB_TABLE__USE ? SEPGSQL_PERMS_USE : 0);
	rte->pgaceTuplePerms |=	(perms & DB_TABLE__SELECT ? SEPGSQL_PERMS_SELECT : 0);

	return addEvalRelation(selist, rte->relid, rte->inh, perms);
}

/*
 * addEvalAttribute
 * addEvalAttributeRTE
 *
 * These functions add a given attribute into selist, if it is not
 * contained yet. In addition, addEvalAttributeRTE also marks required 
 * permissions on rte->pgaceTuplePerms. It is delivered to Scan object
 * and we can use it on ExecScan hook to apply tuple-level access
 * controls.
 */
static List *
addEvalAttribute(List *selist, Oid relid, bool inh, AttrNumber attno, uint32 perms)
{
	SEvalItemAttribute *sea;

	ListCell   *l;

	foreach(l, selist)
	{
		sea = (SEvalItemAttribute *) lfirst(l);
		if (IsA(sea, SEvalItemAttribute)
			&& sea->relid == relid
			&& sea->inh == inh
			&& sea->attno == attno)
		{
			sea->perms |= perms;
			return selist;
		}
	}
	/*
	 * not found
	 */
	sea = makeNode(SEvalItemAttribute);
	sea->perms = perms;
	sea->relid = relid;
	sea->inh = inh;
	sea->attno = attno;

	return lappend(selist, sea);
}

static List *
addEvalAttributeRTE(List *selist, RangeTblEntry *rte, AttrNumber attno, uint32 perms)
{
	uint32		tbl_perms = 0;

	tbl_perms |= (perms & DB_COLUMN__USE ? DB_TABLE__USE : 0);
	tbl_perms |= (perms & DB_COLUMN__SELECT ? DB_TABLE__SELECT : 0);
	tbl_perms |= (perms & DB_COLUMN__INSERT ? DB_TABLE__INSERT : 0);
	tbl_perms |= (perms & DB_COLUMN__UPDATE ? DB_TABLE__UPDATE : 0);
	selist = addEvalRelationRTE(selist, rte, tbl_perms);

	/*
	 * Special care for pg_largeobject.data
	 */
	if ((perms & DB_COLUMN__SELECT) != 0 &&
		rte->relid == LargeObjectRelationId &&
		attno == Anum_pg_largeobject_data)
		rte->pgaceTuplePerms |= SEPGSQL_PERMS_READ;

	return addEvalAttribute(selist, rte->relid, rte->inh, attno, perms);
}

/*
 * addEvalForeignKeyConstraint
 *
 * This function add special case handling for PK/FK constraints.
 * invoke trigger function requires to access rights for all attribute
 *
 */
static List *
addEvalForeignKeyConstraint(List *selist, Form_pg_trigger trigger)
{
	HeapTuple contup;
	Datum attdat;
	ArrayType *attrs;
	int index;
	int16 *attnum;
	bool isnull;

	contup = SearchSysCache(CONSTROID,
							ObjectIdGetDatum(trigger->tgconstraint),
							0, 0, 0);
	if (!HeapTupleIsValid(contup))
		elog(ERROR, "SELinux: cache lookup failed for constraint %u",
			 trigger->tgconstrrelid);

	if (trigger->tgfoid == F_RI_FKEY_CHECK_INS ||
		trigger->tgfoid == F_RI_FKEY_CHECK_UPD)
		attdat = SysCacheGetAttr(CONSTROID, contup,
								 Anum_pg_constraint_conkey, &isnull);
	else
		attdat = SysCacheGetAttr(CONSTROID, contup,
								 Anum_pg_constraint_confkey, &isnull);
	if (isnull)
		elog(ERROR, "null PK/FK for constraint %u",
			 trigger->tgconstrrelid);
	attrs = DatumGetArrayTypeP(attdat);

	if (ARR_NDIM(attrs) != 1 ||
		ARR_HASNULL(attrs) ||
		ARR_ELEMTYPE(attrs) != INT2OID)
		elog(ERROR, "SELinux: unexpected constraint %u", trigger->tgconstrrelid);

	attnum = (int16 *) ARR_DATA_PTR(attrs);
	for (index = 0; index < ARR_DIMS(attrs)[0]; index++)
		selist = addEvalAttribute(selist, trigger->tgrelid, false,
								  attnum[index], DB_COLUMN__SELECT);

	ReleaseSysCache(contup);

	return selist;
}

/*
 * addEvalTriggerAccess
 *
 * This function adds needed items into selist, to execute a trigger
 * function. At least, it requires permission set to execute a function
 * configured as a trigger, to select a table and whole of columns
 * because whole of a tuple is delivered to trigger functions.
 */
static List *
addEvalTriggerAccess(List *selist, Oid relid, bool is_inh, int cmdType)
{
	Relation	rel;
	SysScanDesc scan;
	ScanKeyData skey;
	HeapTuple	tuple;

	rel = heap_open(TriggerRelationId, AccessShareLock);
	ScanKeyInit(&skey,
				Anum_pg_trigger_tgrelid,
				BTEqualStrategyNumber, F_OIDEQ, ObjectIdGetDatum(relid));
	scan = systable_beginscan(rel, TriggerRelidNameIndexId,
							  true, SnapshotNow, 1, &skey);
	while (HeapTupleIsValid((tuple = systable_getnext(scan))))
	{
		Form_pg_trigger trigForm = (Form_pg_trigger) GETSTRUCT(tuple);
		Form_pg_class relForm;
		HeapTuple reltup;

		/*
		 * Skip not-invoked triggers
		 */
		if (!trigForm->tgenabled)
			continue;
		if (cmdType == CMD_INSERT && !TRIGGER_FOR_INSERT(trigForm->tgtype))
			continue;
		if (cmdType == CMD_UPDATE && !TRIGGER_FOR_UPDATE(trigForm->tgtype))
			continue;
		if (cmdType == CMD_DELETE && !TRIGGER_FOR_DELETE(trigForm->tgtype))
			continue;

		/*
		 * per STATEMENT trigger cannot refer whole of a tuple
		 */
		if (!TRIGGER_FOR_ROW(trigForm->tgtype))
			continue;

		/*
		 * BEFORE-ROW-INSERT trigger cannot refer whole of a tuple
		 */
		if (TRIGGER_FOR_BEFORE(trigForm->tgtype) &&
			TRIGGER_FOR_INSERT(trigForm->tgtype))
			continue;

		reltup = SearchSysCache(RELOID,
								ObjectIdGetDatum(relid),
								0, 0, 0);
		relForm = (Form_pg_class) GETSTRUCT(reltup);

		selist = addEvalRelation(selist, relid, false, DB_TABLE__SELECT);

		if (RI_FKey_trigger_type(trigForm->tgfoid) != RI_TRIGGER_NONE)
			selist = addEvalForeignKeyConstraint(selist, trigForm);
		else
			selist = addEvalAttribute(selist, relid, false,
									  0, DB_COLUMN__SELECT);
		ReleaseSysCache(reltup);
	}
	systable_endscan(scan);
	heap_close(rel, AccessShareLock);

	if (is_inh)
	{
		List	   *child_list = find_inheritance_children(relid);
		ListCell   *l;

		foreach(l, child_list)
			selist = addEvalTriggerAccess(selist, lfirst_oid(l),
										  is_inh, cmdType);
	}

	return selist;
}

/*
 * sepgsqlExprWalker
 *
 * This function walks on the given expression tree to pick up
 * all the appeared tables and columns. Their identifiers are
 * chains on swc->selist to evaluate permissions on them later.
 *
 * walkVarHelper picks up an accessed column and its contained
 * table, and chains them on swc->selist.
 * When swc->is_internal_use is true, it means this reference
 * is checked as "use" permission because its contents are
 * consumed internally, and not to be returned to client directly.
 * Otherwise, "select" permission is applied.
 *
 * walkQueryHelper walks on Query structure.
 * The reason why we don't use query_tree_walker() is that
 * SE-PostgreSQL need to apply different permission between
 * targetList and havingQual, for example.
 */

static bool
sepgsqlExprWalker(Node *node, sepgsqlWalkerContext *swc);

static void
sepgsqlExprWalkerFlags(Node *node, sepgsqlWalkerContext *swc,
					   bool is_internal_use);

/*
 * wholeRefJoinWalker
 *
 * A corner case need to invoke this walker function.
 * When we use whole-row-reference on RTE_JOIN relation,
 * it should be extracted to whole-row-references on
 * sources relations.
 *
 * EXAMPLE:
 *   SELECT t4 FROM (t1 JOIN (t2 JOIN t3 USING (a)) USING (b)) AS t4;
 */
typedef struct
{
	Query *query;
	int rtindex;

	List *selist;
	uint32 perms;
} wholeRefJoinWalkerContext;

static bool
wholeRefJoinWalker(Node *node, wholeRefJoinWalkerContext *jwc)
{
	if (!node)
		return false;

	if (IsA(node, JoinExpr))
	{
		JoinExpr *j = (JoinExpr *) node;

		if (j->rtindex == jwc->rtindex)
		{
			int rtindex_backup = jwc->rtindex;
			bool rc;

			jwc->rtindex = 0;
			rc = expression_tree_walker(node, wholeRefJoinWalker, jwc);
			jwc->rtindex = rtindex_backup;

			return rc;
		}
	}
	else if (IsA(node, RangeTblRef) && jwc->rtindex == 0)
	{
		RangeTblRef *rtr = (RangeTblRef *) node;
		RangeTblEntry *rte = rt_fetch(rtr->rtindex,
									  jwc->query->rtable);
		if (rte->rtekind == RTE_RELATION)
		{
			jwc->selist = addEvalAttributeRTE(jwc->selist, rte, 0, jwc->perms);
		}
		else if (rte->rtekind == RTE_JOIN)
		{
			bool rc;

			jwc->rtindex = rtr->rtindex;
			rc = expression_tree_walker(node, wholeRefJoinWalker, jwc);
			jwc->rtindex = 0;	/* restore */

			return rc;
		}
	}
	return expression_tree_walker(node, wholeRefJoinWalker, jwc);
}

static void
walkVarHelper(Var *var, sepgsqlWalkerContext *swc)
{
	sepgsqlWalkerContext *cur = swc;
	Query		   *query;
	RangeTblEntry  *rte;
	int				lv;

	Assert(IsA(var, Var));

	for (lv = var->varlevelsup; lv > 0; lv--)
	{
		Assert(cur->parent != NULL);
		cur = cur->parent;
	}
	query = cur->query;

	rte = rt_fetch(var->varno, query->rtable);
	Assert(IsA(rte, RangeTblEntry));

	if (rte->rtekind == RTE_RELATION)
	{
		uint32 perms = swc->is_internal_use
			? DB_COLUMN__USE : DB_COLUMN__SELECT;

		swc->selist = addEvalAttributeRTE(swc->selist, rte,
										  var->varattno, perms);
	}
	else if (rte->rtekind == RTE_JOIN)
	{
		if (var->varattno == 0)
		{
			wholeRefJoinWalkerContext jwcData;

			jwcData.query = query;
			jwcData.rtindex = var->varno;
			jwcData.selist = swc->selist;
			jwcData.perms = swc->is_internal_use
				? DB_COLUMN__USE : DB_COLUMN__SELECT;

			wholeRefJoinWalker((Node *)query->jointree, &jwcData);
			swc->selist = jwcData.selist;
		}
		else
		{
			Node *node = list_nth(rte->joinaliasvars,
								  var->varattno - 1);
			sepgsqlExprWalker(node, swc);
		}
	}
}

static List *
walkQueryHelper(Query *query, sepgsqlWalkerContext *swc)
{
	sepgsqlWalkerContext swcData;
	RangeTblEntry *rte;

	memset(&swcData, 0, sizeof(swcData));
	swcData.parent = swc;
	swcData.selist = (!swc ? NIL : swc->selist);
	swcData.query = query;

	if (query->commandType != CMD_DELETE)
	{
		ListCell *l;

		foreach (l, query->targetList)
		{
			TargetEntry *tle = lfirst(l);
			bool is_security = false;

			Assert(IsA(tle, TargetEntry));

			if (tle->resjunk &&
				tle->resname &&
				strcmp(tle->resname, SecurityLabelAttributeName) == 0)
				is_security = true;

			if (tle->resjunk && !is_security)
			{
				sepgsqlExprWalkerFlags((Node *) tle->expr, &swcData, true);
				continue;
			}

			sepgsqlExprWalkerFlags((Node *) tle->expr, &swcData, false);

			if (query->commandType != CMD_SELECT)
			{
				AttrNumber attno = tle->resno;
				uint32 perms;

				if (is_security)
					attno = SecurityLabelAttributeNumber;

				if (query->commandType == CMD_UPDATE)
					perms = DB_COLUMN__UPDATE;
				else
					perms = DB_COLUMN__INSERT;

				rte = rt_fetch(query->resultRelation, query->rtable);
				Assert(IsA(rte, RangeTblEntry));

				swcData.selist
					= addEvalAttributeRTE(swcData.selist, rte, attno, perms);
			}
		}
	}
	else
	{
		/* no need to check column-level permission for DELETE */
		rte = rt_fetch(query->resultRelation, query->rtable);
		Assert(IsA(rte, RangeTblEntry));

		swcData.selist
			= addEvalRelationRTE(swcData.selist, rte, DB_TABLE__DELETE);
	}

	sepgsqlExprWalkerFlags((Node *) query->returningList, &swcData, false);
	sepgsqlExprWalkerFlags((Node *) query->jointree, &swcData, true);
	sepgsqlExprWalkerFlags((Node *) query->setOperations, &swcData, true);
	sepgsqlExprWalkerFlags((Node *) query->havingQual, &swcData, true);
	sepgsqlExprWalkerFlags((Node *) query->sortClause, &swcData, true);
	sepgsqlExprWalkerFlags((Node *) query->groupClause, &swcData, true);
	sepgsqlExprWalkerFlags((Node *) query->limitOffset, &swcData, true);
	sepgsqlExprWalkerFlags((Node *) query->limitCount, &swcData, true);
	sepgsqlExprWalkerFlags((Node *) query->cteList, &swcData, true);
	sepgsqlExprWalkerFlags((Node *) query->windowClause, &swcData, true);

	return swcData.selist;
}

static void
walkRangeTblRefHelper(RangeTblRef *rtr, sepgsqlWalkerContext *swc)
{
	Query *query = swc->query;
	RangeTblEntry *rte = rt_fetch(rtr->rtindex, query->rtable);

	Assert(IsA(rte, RangeTblEntry));

	switch (rte->rtekind)
	{
	case RTE_RELATION:
		if (rtr->rtindex != query->resultRelation)
			swc->selist = addEvalRelationRTE(swc->selist, rte,
											 DB_TABLE__SELECT);
		break;

	case RTE_SUBQUERY:
		swc->selist = walkQueryHelper(rte->subquery, swc);
		break;

	case RTE_FUNCTION:
		sepgsqlExprWalker(rte->funcexpr, swc);
		break;

	case RTE_VALUES:
		sepgsqlExprWalker((Node *) rte->values_lists, swc);
		break;

	default:
		/* do nothing */
		break;
	}
}

static void
walkSortGroupClauseHelper(SortGroupClause *sgc, sepgsqlWalkerContext *swc)
{
	Query *query = swc->query;
	TargetEntry *tle
		= get_sortgroupref_tle(sgc->tleSortGroupRef,
							   query->targetList);

	Assert(IsA(tle, TargetEntry));

	sepgsqlExprWalker((Node *) tle->expr, swc);
}

static bool
sepgsqlExprWalker(Node *node, sepgsqlWalkerContext *swc)
{
	if (node == NULL)
		return false;
	else if (IsA(node, Var))
		walkVarHelper((Var *) node, swc);
	else if (IsA(node, RangeTblRef))
		walkRangeTblRefHelper((RangeTblRef *) node, swc);
	else if (IsA(node, Query))
	{
		swc->selist
			= walkQueryHelper((Query *) node, swc);
	}
	else if (IsA(node, SortGroupClause))
	{
		walkSortGroupClauseHelper((SortGroupClause *) node, swc);

		return false;
	}
	return expression_tree_walker(node, sepgsqlExprWalker, (void *) swc);
}

static void
sepgsqlExprWalkerFlags(Node *node, sepgsqlWalkerContext *swc,
					   bool is_internal_use)
{
	bool		saved_is_internal_use = swc->is_internal_use;

	swc->is_internal_use = is_internal_use;
	sepgsqlExprWalker(node, swc);
	swc->is_internal_use = saved_is_internal_use;
}

/*
 * sepgsqlProxyQuery
 *
 * This function is invoked just after given queries are rewritten
 * via query-rewritter phase. It walks on given query trees to
 * picks up all appeared tables and columns, and to chains the list
 * of them on query->pgaceItem.
 * This list is used to evaluate permissions later, just before
 * the query execution.
 *
 * It do nothing for DDL queries, because these are processed in
 * sepgsqlProcessUtility() hook.
 */
List *
sepgsqlPostQueryRewrite(List *queryList)
{
	ListCell   *l;

	foreach (l, queryList)
	{
		Query  *query = (Query *) lfirst(l);

		Assert(IsA(query, Query));

		if (query->commandType == CMD_SELECT ||
			query->commandType == CMD_UPDATE ||
			query->commandType == CMD_INSERT ||
			query->commandType == CMD_DELETE)
		{
			query->pgaceItem
				= (Node *) walkQueryHelper(query, NULL);
		}
	}

	return queryList;
}

/*
 * verifyPgClassPerms
 *
 * It evaluates SEvalItemRelation object to access tables.
 */
static void
verifyPgClassPerms(Oid relid, bool inh, uint32 perms)
{
	Form_pg_class relForm;
	HeapTuple	tuple;

	/*
	 * prevent to modify pg_security directly
	 */
	if (relid == SecurityRelationId
		&& (perms & (DB_TABLE__UPDATE | DB_TABLE__INSERT | DB_TABLE__DELETE)))
		ereport(ERROR,
				(errcode(ERRCODE_SELINUX_ERROR),
				 errmsg("SELinux: user cannot modify pg_security directly")));

	/*
	 * check table:{required permissions}
	 */
	tuple = SearchSysCache(RELOID, ObjectIdGetDatum(relid), 0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "SELinux: cache lookup failed for relation: %u", relid);

	relForm = (Form_pg_class) GETSTRUCT(tuple);
	if (relForm->relkind == RELKIND_RELATION)
	{
		const char *audit_name = sepgsqlTupleName(RelationRelationId, tuple);
		sepgsqlClientHasPermission(HeapTupleGetSecLabel(tuple),
								   SECCLASS_DB_TABLE,
								   (access_vector_t) perms,
								   audit_name);
	}
	ReleaseSysCache(tuple);
}

/*
 * verifyPgAttributePerms
 *
 * It evaluates SEvalItemAttribute to access columns.
 */
static void
verifyPgAttributePerms(Oid relid, bool inh, AttrNumber attno, uint32 perms)
{
	Form_pg_class relForm;
	Form_pg_attribute attForm;
	HeapTuple reltup, atttup;
	const char *audit_name;

	reltup = SearchSysCache(RELOID,
							ObjectIdGetDatum(relid),
							0, 0, 0);
	if (!HeapTupleIsValid(reltup))
		elog(ERROR, "SELinux: cache lookup failed for relation: %u", relid);
	relForm = (Form_pg_class) GETSTRUCT(reltup);
	if (relForm->relkind != RELKIND_RELATION)
		goto out;

	if (attno == 0)
	{
		for (attno = 1; attno <= relForm->relnatts; attno++)
		{
			atttup = SearchSysCache(ATTNUM,
									ObjectIdGetDatum(relid),
									Int16GetDatum(attno),
									0, 0);
			if (!HeapTupleIsValid(atttup))
				continue;
			attForm = (Form_pg_attribute) GETSTRUCT(atttup);
			if (!attForm->attisdropped)
			{
				audit_name = sepgsqlTupleName(AttributeRelationId, atttup);
				sepgsqlClientHasPermission(HeapTupleGetSecLabel(atttup),
										   SECCLASS_DB_COLUMN,
										   perms,
										   audit_name);
			}
			ReleaseSysCache(atttup);
		}
	}
	else
	{
		atttup = SearchSysCache(ATTNUM,
								ObjectIdGetDatum(relid),
								Int16GetDatum(attno),
								0, 0);
		if (!HeapTupleIsValid(atttup))
			elog(ERROR, "SELinux: cache lookup failed for attribute %d of relation %u",
				 attno, relid);

		audit_name = sepgsqlTupleName(AttributeRelationId, atttup);
		sepgsqlClientHasPermission(HeapTupleGetSecLabel(atttup),
								   SECCLASS_DB_COLUMN,
								   perms,
								   audit_name);
		ReleaseSysCache(atttup);
	}
out:
	ReleaseSysCache(reltup);
}

/*
 * expandSEvalItemInheritance
 *
 * When a request to table/column is inheritable, we have to expand
 * the target to child relations, because accessing a column within
 * parent table also means accessing a column within child relation
 * in same time.
 *
 * For example, when t2 and t3 inherits t1, we have to check permission
 * on t2.x and t3.x for the request to t1.x.
 * It is impossible to be done before, because we have a chance to
 * change inheritance relationships between PREPARE and EXECUTE.
 * So, we have to check it in execution phase.
 */
static List *
expandRelationInheritance(List *selist, Oid relid, uint32 perms)
{
	List	   *inherits = find_all_inheritors(relid);
	ListCell   *l;

	foreach(l, inherits)
	{
		if (lfirst_oid(l) != relid)
			selist = addEvalRelation(selist, lfirst_oid(l), false, perms);
	}
	return selist;
}

static List *
expandAttributeInheritance(List *selist, Oid relid, char *attname,
						   uint32 perms)
{
	List	   *inherits = find_all_inheritors(relid);
	ListCell   *l;

	foreach(l, inherits)
	{
		Form_pg_attribute attForm;
		HeapTuple atttup;

		if (lfirst_oid(l) == relid)
			continue;

		atttup = SearchSysCacheAttName(lfirst_oid(l), attname);
		if (!HeapTupleIsValid(atttup))
			elog(ERROR, "SELinux: cache lookup failed for attribute %s of relation %u",
				 attname, lfirst_oid(l));

		attForm = (Form_pg_attribute) GETSTRUCT(atttup);
		selist = addEvalAttribute(selist, lfirst_oid(l), false,
								  attForm->attnum, perms);
		ReleaseSysCache(atttup);
	}

	return selist;
}

static List *
expandSEvalItemInheritance(List *selist)
{
	List	   *result = NIL;
	ListCell   *l;

	foreach(l, selist)
	{
		Node	   *node = lfirst(l);

		result = lappend(result, node);

		if (IsA(node, SEvalItemRelation))
		{
			SEvalItemRelation *ser = (SEvalItemRelation *) node;

			if (!ser->inh)
				continue;

			result = expandRelationInheritance(result, ser->relid, ser->perms);
		}
		else if (IsA(node, SEvalItemAttribute))
		{
			SEvalItemAttribute *sea = (SEvalItemAttribute *) node;

			if (!sea->inh)
				continue;

			if (sea->attno == 0)
			{
				HeapTuple reltup, atttup;
				Form_pg_class relForm;
				Form_pg_attribute attForm;
				AttrNumber attno;

				reltup = SearchSysCache(RELOID,
										ObjectIdGetDatum(sea->relid),
										0, 0, 0);
				if (!HeapTupleIsValid(reltup))
					elog(ERROR, "SELinux: cache lookup failed for relation: %u", sea->relid);
				relForm = (Form_pg_class) GETSTRUCT(reltup);

				for (attno = 1; attno <= relForm->relnatts; attno++)
				{
					atttup = SearchSysCache(ATTNUM,
											ObjectIdGetDatum(sea->relid),
											Int16GetDatum(attno),
											0, 0);
					if (!HeapTupleIsValid(atttup))
						continue;
					attForm = (Form_pg_attribute) GETSTRUCT(atttup);
					if (!attForm->attisdropped)
					{
						result =
							expandAttributeInheritance(result,
													   sea->relid,
													   NameStr(attForm->attname),
													   sea->perms);
					}
					ReleaseSysCache(atttup);
				}
				ReleaseSysCache(reltup);
			}
			else
			{
				char *attname = get_attname(sea->relid, sea->attno);

				if (!attname)
					elog(ERROR, "cache lookup failed for attribute %d of relation %u",
						 sea->attno, sea->relid);
				result = expandAttributeInheritance(result,
													sea->relid,
													attname,
													sea->perms);
			}
		}
		else
			elog(ERROR, "SELinux: unexpected node type (%u)", nodeTag(node));
	}
	return result;
}

/*
 * execVerifyQuery
 *
 * This function scans the given list, and invokes proper function
 * to evaluate it.
 */
static void
execVerifyQuery(List *selist)
{
	ListCell   *l;

	foreach(l, selist)
	{
		Node	   *node = lfirst(l);

		if (IsA(node, SEvalItemRelation))
		{
			SEvalItemRelation *ser
				= (SEvalItemRelation *) node;
			verifyPgClassPerms(ser->relid, ser->inh, ser->perms);
		}
		else if (IsA(node, SEvalItemAttribute))
		{
			SEvalItemAttribute *sea
				= (SEvalItemAttribute *) node;
			verifyPgAttributePerms(sea->relid, sea->inh, sea->attno, sea->perms);
		}
		else
			elog(ERROR, "SELinux: unexpected node type (%d)", nodeTag(node));
	}
}

/*
 * sepgsqlVerifyQuery
 *
 * This function is invoked at the head of ExecutorStart, to evaluate
 * permissions to access appeared object within the given query.
 * Query->pgaceItem is a list of SEvalItemXXXX objects generated in
 * previous phase, and it is copied to PlannedStmt->pgaceItem in the
 * optimizer.
 * sepgsqlVerifyQuery expand relations/columns and append permissions
 * to execute trigger functions, if necessary.
 */
void
sepgsqlExecutorStart(QueryDesc *queryDesc, int eflags)
{
	PlannedStmt *pstmt = queryDesc->plannedstmt;
	RangeTblEntry *rte;
	List	   *selist;
	ListCell   *l;

	/*
	 * EXPLAIN statement does not access any object.
	 */
	if (eflags & EXEC_FLAG_EXPLAIN_ONLY)
		return;
	if (!pstmt->pgaceItem)
		return;

	Assert(IsA(pstmt->pgaceItem, List));
	selist = copyObject(pstmt->pgaceItem);

	/*
	 * expand table inheritances
	 */
	selist = expandSEvalItemInheritance(selist);

	/*
	 * add checks for access via trigger function
	 */
	foreach(l, pstmt->resultRelations)
	{
		Index		rindex = lfirst_int(l);

		rte = rt_fetch(rindex, pstmt->rtable);
		Assert(IsA(rte, RangeTblEntry));

		selist = addEvalTriggerAccess(selist, rte->relid, rte->inh,
									  pstmt->commandType);
	}
	execVerifyQuery(selist);
}

/*
 * --------------------------------------------------------------
 * Process Utility hooks
 * --------------------------------------------------------------
 */

/*
 * checkTruncateStmt
 *
 * This function checks permissions of tuples within the given
 * tables before TRUNCATE them. Because its meanings are same
 * as unconditional DELETE logically, SE-PostgreSQL attempt to
 * apply same permission for them operation.
 * If there is a violated tuple at most, it stops to execute 
 * TRUNCATE and abort current trunsaction.
 */
static void
checkTruncateStmt(TruncateStmt *stmt)
{
	Relation	rel;
	HeapScanDesc scan;
	HeapTuple	tuple;
	List	   *relidList = NIL;
	ListCell   *l;

	foreach(l, stmt->relations)
	{
		RangeVar   *rv = lfirst(l);

		relidList = lappend_oid(relidList, RangeVarGetRelid(rv, false));
	}

	if (stmt->behavior == DROP_CASCADE)
	{
		relidList = list_concat(relidList, heap_truncate_find_FKs(relidList));
	}

	foreach(l, relidList)
	{
		Oid			relid = lfirst_oid(l);

		/*
		 * 1. db_table:{delete}
		 */
		tuple = SearchSysCache(RELOID, ObjectIdGetDatum(relid), 0, 0, 0);
		if (!HeapTupleIsValid(tuple))
			elog(ERROR, "SELinux: cache lookup failed for relation %u", relid);
		sepgsqlClientHasPermission(HeapTupleGetSecLabel(tuple),
								   SECCLASS_DB_TABLE,
								   DB_TABLE__DELETE,
								   sepgsqlTupleName(RelationRelationId, tuple));
		ReleaseSysCache(tuple);

		/*
		 * 2. db_tuple:{delete}
		 */
		rel = heap_open(relid, AccessShareLock);
		scan = heap_beginscan(rel, SnapshotNow, 0, NULL);

		while ((tuple = heap_getnext(scan, ForwardScanDirection)) != NULL)
		{
			sepgsqlCheckTuplePerms(rel, tuple, NULL,
								   SEPGSQL_PERMS_DELETE, true);
		}
		heap_endscan(scan);
		heap_close(rel, AccessShareLock);
	}
}

/*
 * sepgsqlProcessUtility
 *
 * This function is invoked from the head of ProcessUtility(), and
 * checks given DDL queries.
 * SE-PostgreSQL catch most of DDL actions on HeapTuple hooks, but
 * an exception is TRUNCATE statement.
 */
void
sepgsqlProcessUtility(Node *parsetree, ParamListInfo params, bool isTopLevel)
{
	switch (nodeTag(parsetree))
	{
		case T_TruncateStmt:
			checkTruncateStmt((TruncateStmt *) parsetree);
			break;

		case T_LoadStmt:
			sepgsqlCheckModuleInstallPerms(((LoadStmt *)parsetree)->filename);
			break;

		default:
			/* do nothing */
			break;
	}
}

/* ----------------------------------------------------------
 * COPY TO/COPY FROM statement hooks
 * ---------------------------------------------------------- */

/*
 * sepgsqlCopyTable
 *
 * This function checks permission on the target table and columns
 * of COPY statement. We don't place it at sepgsql/hooks.c because
 * it internally uses addEvalXXXX() interface statically declared.
 */
void
sepgsqlCopyTable(Relation rel, List *attNumList, bool isFrom)
{
	List	   *selist = NIL;
	ListCell   *l;

	/*
	 * on 'COPY FROM SELECT ...' cases, any checkings are done in select.c
	 */
	if (rel == NULL)
		return;

	/*
	 * no need to check non-table relation
	 */
	if (RelationGetForm(rel)->relkind != RELKIND_RELATION)
		return;

	selist = addEvalRelation(selist, RelationGetRelid(rel), false,
							 isFrom ? DB_TABLE__INSERT : DB_TABLE__SELECT);
	foreach(l, attNumList)
	{
		AttrNumber	attnum = lfirst_int(l);

		selist = addEvalAttribute(selist, RelationGetRelid(rel), false, attnum,
								  isFrom ? DB_COLUMN__INSERT : DB_COLUMN__SELECT);
	}

	/*
	 * check call trigger function
	 */
	if (isFrom)
		selist = addEvalTriggerAccess(selist, RelationGetRelid(rel),
									  false, CMD_INSERT);

	execVerifyQuery(selist);
}

/*
 * sepgsqlCopyFile
 *
 * This function check permission whether the client can
 * read from/write to the given file.
 */
void sepgsqlCopyFile(Relation rel, int fdesc, const char *filename, bool isFrom)
{
	security_context_t context;
	security_class_t tclass
		= sepgsqlFileObjectClass(fdesc, filename);

	if (fgetfilecon_raw(fdesc, &context) < 0)
		ereport(ERROR,
				(errcode(ERRCODE_SELINUX_ERROR),
				 errmsg("SELinux: could not get context of %s", filename)));
	PG_TRY();
	{
		sepgsqlComputePermission(sepgsqlGetClientContext(),
								 context,
								 tclass,
								 isFrom ? FILE__READ : FILE__WRITE,
								 filename);
	}
	PG_CATCH();
	{
		freecon(context);
		PG_RE_THROW();
	}
	PG_END_TRY();
	freecon(context);
}

/*
 * sepgsqlCopyToTuple
 *
 * This function check permission to read the given tuple.
 * If not allowed to read, it returns false to skip COPY TO
 * this tuple. In the result, any violated tuples are filtered
 * from the result of COPY TO, as if these are not exist.
 */
bool
sepgsqlCopyToTuple(Relation rel, List *attNumList, HeapTuple tuple)
{
	uint32		perms = SEPGSQL_PERMS_SELECT;

	/*
	 * for 'pg_largeobject'
	 */
	if (RelationGetRelid(rel) == LargeObjectRelationId)
	{
		ListCell   *l;

		foreach(l, attNumList)
		{
			AttrNumber	attnum = lfirst_int(l);

			if (attnum == Anum_pg_largeobject_data)
			{
				perms |= SEPGSQL_PERMS_READ;
				break;
			}
		}
	}
	return sepgsqlCheckTuplePerms(rel, tuple, NULL, perms, false);
}
