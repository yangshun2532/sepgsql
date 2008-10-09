/*
 * Row-level Database ACL support
 *
 * A small example of implementation on PGACE security framework
 */

#include "postgres.h"

#include "catalog/catalog.h"
#include "catalog/pg_class.h"
#include "catalog/pg_type.h"
#include "miscadmin.h"
#include "nodes/makefuncs.h"
#include "nodes/nodeFuncs.h"
#include "parser/parsetree.h"
#include "pgstat.h"
#include "security/pgace.h"
#include "storage/bufmgr.h"
#include "utils/acl.h"
#include "utils/array.h"
#include "utils/fmgroids.h"
#include "utils/syscache.h"

/*
 * static function declarations
 */
static void  proxySubQuery(Query *query);
static Acl  *rawAclTextToAclArray(char *raw_acl);
static char *rawAclTextFromAclArray(Acl *acl);

/******************************************************************
 * Global system setting
 ******************************************************************/

bool rowaclIsEnabled(void)
{
	/*
	 * TODO: This parameter should be controled via GUC
	 */
	return true;
}

/******************************************************************
 * Mark appeared Query/Sub-Query
 ******************************************************************/

static bool walkOnNodeTree(Node *node, Query *query)
{
	if (!node)
		return false;

	if (IsA(node, Query))
	{
		proxySubQuery((Query *) node);
	}
	else if (IsA(node, SortGroupClause))
	{
		/*
		 * expression_tree_walker() does not understand
		 * T_SortGroupClause node, so we have to avoid it
		 * walking on the node type.
		 */
		return false;
	}

	return expression_tree_walker(node, walkOnNodeTree, (void *) query);
}

static void walkOnJoinTree(Query *query, Node *node)
{
	if (!node)
		return;

	if (IsA(node, RangeTblRef))
	{
		RangeTblRef *rtr = (RangeTblRef *) node;
		RangeTblEntry *rte = rt_fetch(rtr->rtindex, query->rtable);

		if (rte->rtekind == RTE_RELATION &&
			rtr->rtindex != query->resultRelation)
		{
			rte->pgaceTuplePerms |= ACL_SELECT;
		}
		else if (rte->rtekind == RTE_SUBQUERY)
		{
			proxySubQuery(rte->subquery);
		}
	}
	else if (IsA(node, JoinExpr))
	{
		JoinExpr *join = (JoinExpr *) node;

		walkOnNodeTree(join->quals, query);
		walkOnJoinTree(query, join->larg);
		walkOnJoinTree(query, join->rarg);
	}
	else if (IsA(node, FromExpr))
	{
		FromExpr *from = (FromExpr *) node;
		ListCell *l;

		walkOnNodeTree(from->quals, query);
		foreach (l, from->fromlist)
			walkOnJoinTree(query, lfirst(l));
	}
	else
		elog(ERROR, "unexpected node type (%d) on fromlist", nodeTag(node));
}

static void proxySubQuery(Query *query)
{
	RangeTblEntry *rte;

	if (query->commandType == CMD_UPDATE)
	{
		rte = rt_fetch(query->resultRelation, query->rtable);
		rte->pgaceTuplePerms |= ACL_UPDATE;
		if (query->returningList)
			rte->pgaceTuplePerms |= ACL_SELECT;
	}
	else if (query->commandType == CMD_DELETE)
	{
		rte = rt_fetch(query->resultRelation, query->rtable);
		rte->pgaceTuplePerms |= ACL_DELETE;
		if (query->returningList)
			rte->pgaceTuplePerms |= ACL_SELECT;
	}
	walkOnJoinTree(query, (Node *) query->jointree);

	walkOnNodeTree((Node *) query->targetList, query);
	walkOnNodeTree((Node *) query->returningList, query);
	walkOnNodeTree((Node *) query->havingQual,  query);
	walkOnNodeTree((Node *) query->sortClause,  query);
	walkOnNodeTree((Node *) query->groupClause, query);
	walkOnNodeTree((Node *) query->cteList, query);
}

List *rowaclProxyQuery(List *queryList)
{
	ListCell *l;

	foreach (l, queryList)
	{
		Query *query = (Query *) lfirst(l);

		Assert(IsA(query, Query));

		if (query->commandType == CMD_SELECT ||
			query->commandType == CMD_UPDATE ||
			query->commandType == CMD_DELETE)
			proxySubQuery(query);
	}

	return queryList;
}

/******************************************************************
 * Row-level access controls
 ******************************************************************/


static bool under_integrity_checking = false;

static bool rowaclCheckPermission(Relation rel, HeapTuple tuple, AclMode perms)
{
	Oid sid = HeapTupleGetSecurity(tuple);
	Oid userId = GetUserId();
	Oid ownerId = RelationGetForm(rel)->relowner;
	char *raw_acl;
	Acl *acl;

	/* Superusers bypass all permission checking */
	if (superuser_arg(userId))
		return true;

	raw_acl = pgaceLookupSecurityLabel(sid);
	acl = rawAclTextToAclArray(raw_acl);

	/* no acl allows to access anything */
	if (!acl)
		return true;

	if (aclmask(acl, userId, ownerId, perms, ACLMASK_ANY))
		return true;

	return false;
}

bool rowaclExecScan(Scan *scan, Relation rel, TupleTableSlot *slot)
{
	HeapTuple tuple = ExecMaterializeSlot(slot);

	if (!scan->pgaceTuplePerms)
		return true;

	return rowaclCheckPermission(rel, tuple, scan->pgaceTuplePerms);
}

bool rowaclCopyToTuple(Relation rel, List *attNumList, HeapTuple tuple)
{
	return rowaclCheckPermission(rel, tuple, ACL_SELECT);
}

void rowaclBeginPerformCheckFK(Relation rel, bool is_primary, Datum *save_pgace)
{
	if (is_primary)
		return;
	*save_pgace = BoolGetDatum(under_integrity_checking);
	under_integrity_checking = true;
}

void rowaclEndPerformCheckFK(Relation rel, bool is_primary, Datum save_pgace)
{
	if (is_primary)
		return;

	under_integrity_checking = DatumGetBool(save_pgace);
}

/******************************************************************
 * Check appeared Query/Sub-Query
 ******************************************************************/

bool rowaclHeapTupleInsert(Relation rel, HeapTuple tuple,
						   bool is_internal, bool with_returning)
{
	if (HeapTupleGetSecurity(tuple) != InvalidOid)
	{
		/*
		 * Explicit ACL case
		 */
		if (RelationGetForm(rel)->relkind != RELKIND_RELATION)
			ereport(ERROR,
					(errcode(ERRCODE_ROW_ACL_ERROR),
					 errmsg("cannot set Row-level ACL to relation"
							" with relkind:%c", RelationGetForm(rel)->relkind)));

		if (is_internal && RelationGetRelid(rel) == RelationRelationId)
		{
			/*
			 * Default ACL via CREATE TABLE
			 */
			Form_pg_class class_form = (Form_pg_class) GETSTRUCT(tuple);

			if (class_form->relkind != RELKIND_RELATION)
				ereport(ERROR,
						(errcode(ERRCODE_ROW_ACL_ERROR),
						 errmsg("cannot set default ACL to relation"
								" with relkind:%c", class_form->relkind)));
			if (IsSystemClass(class_form))
				ereport(ERROR,
						(errcode(ERRCODE_ROW_ACL_ERROR),
						 errmsg("default ACL is unavailable for system catalog")));
			if (!pg_class_ownercheck(class_form->relowner, GetUserId()))
				ereport(ERROR,
						(errcode(ERRCODE_ROW_ACL_ERROR),
						 errmsg("Only owner or superuser can set default ACL")));
		}
		else if (IsSystemRelation(rel))
			ereport(ERROR,
					(errcode(ERRCODE_ROW_ACL_ERROR),
					 errmsg("Row-level ACL is unavailable for system catalog")));
		else if (!pg_class_ownercheck(RelationGetRelid(rel), GetUserId()))
			ereport(ERROR,
					(errcode(ERRCODE_ROW_ACL_ERROR),
					 errmsg("Only owner or superuser can set ACL")));
	}
	else if (!IsSystemRelation(rel))
	{
		/*
		 * Set default ACL
		 */
		Oid security_id;
		HeapTuple reltup
			= SearchSysCache(RELOID,
							 ObjectIdGetDatum(RelationGetRelid(rel)),
							 0, 0, 0);
		if (!HeapTupleIsValid(reltup))
			elog(ERROR, "cache lookup failed for relation %s",
				 RelationGetRelationName(rel));

		security_id = HeapTupleGetSecurity(reltup);
		HeapTupleSetSecurity(tuple, security_id);
		/*
		 * Note: Relation can have no default ACL (= InvalidOid).
		 * In this case, no ACLs are assigned to tuple.
		 */
		ReleaseSysCache(reltup);
	}

	return true;
}

static HeapTuple
getHeapTupleFromItemPointer(Relation rel, ItemPointer tid)
{
	/*
	 * obtain an old tuple
	 */
	Buffer      buffer;
	PageHeader  dp;
	ItemId      lp;
	HeapTupleData tuple;
	HeapTuple   oldtup;

	buffer = ReadBuffer(rel, ItemPointerGetBlockNumber(tid));
	LockBuffer(buffer, BUFFER_LOCK_SHARE);

	dp = (PageHeader) BufferGetPage(buffer);
	lp = PageGetItemId(dp, ItemPointerGetOffsetNumber(tid));

	Assert(ItemIdIsNormal(lp));

	tuple.t_data = (HeapTupleHeader) PageGetItem((Page) dp, lp);
	tuple.t_len = ItemIdGetLength(lp);
	tuple.t_self = *tid;
	tuple.t_tableOid = RelationGetRelid(rel);
	oldtup = heap_copytuple(&tuple);

	LockBuffer(buffer, BUFFER_LOCK_UNLOCK);
	ReleaseBuffer(buffer);

	return oldtup;
}

bool rowaclHeapTupleUpdate(Relation rel, ItemPointer otid, HeapTuple newtup,
						   bool is_internal, bool with_returning)
{
	HeapTuple oldtup = getHeapTupleFromItemPointer(rel, otid);

	if (HeapTupleGetSecurity(newtup) == InvalidOid)
	{
		/*
		 * Preserve Old ACL
		 */
		Oid security_id = HeapTupleGetSecurity(oldtup);

		HeapTupleSetSecurity(newtup, security_id);
	}
	else if (HeapTupleGetSecurity(newtup) != HeapTupleGetSecurity(oldtup))
	{
		if (is_internal && RelationGetRelid(rel) == RelationRelationId)
		{
			/*
			 * Default ACL via ALTER TABLE
			 */
			Form_pg_class class_form = (Form_pg_class) GETSTRUCT(newtup);

			if (class_form->relkind != RELKIND_RELATION)
				ereport(ERROR,
						(errcode(ERRCODE_ROW_ACL_ERROR),
						 errmsg("cannot set default ACL to relation"
								" with relkind:%c", class_form->relkind)));
			if (IsSystemClass(class_form))
				ereport(ERROR,
						(errcode(ERRCODE_ROW_ACL_ERROR),
						 errmsg("default ACL is unavailable for system catalog")));
			if (!pg_class_ownercheck(class_form->relowner, GetUserId()))
				ereport(ERROR,
						(errcode(ERRCODE_ROW_ACL_ERROR),
						 errmsg("Only owner or superuser can set default ACL")));
		}
		else if (IsSystemRelation(rel))
			ereport(ERROR,
					(errcode(ERRCODE_ROW_ACL_ERROR),
					 errmsg("Row-level ACL is unavailable for system catalog")));
		else if (!pg_class_ownercheck(RelationGetRelid(rel), GetUserId()))
			ereport(ERROR,
					(errcode(ERRCODE_ROW_ACL_ERROR),
					 errmsg("Only owner or superuser can set ACL")));
	}

	return true;
}

bool rowaclHeapTupleDelete(Relation rel, ItemPointer otid,
						   bool is_internal, bool with_returning)
{
	/*
	 * we don't need to do anything here.
	 */
	return true;
}

/******************************************************************
 * Default ACL support
 ******************************************************************/

DefElem *rowaclGramSecurityItem(char *defname, char *value)
{
	DefElem *node = NULL;

	if (strcmp(defname, "default_acl") == 0)
		node = makeDefElem(pstrdup(defname),
						   (Node *) makeString(value));
	return node;
}

bool rowaclIsGramSecurityItem(DefElem *defel)
{
	Assert(IsA(defel, DefElem));

	if (defel->defname &&
		strcmp(defel->defname, "default_acl") == 0)
		return true;

	return false;
}

void rowaclGramCreateRelation(Relation rel, HeapTuple tuple, DefElem *defel)
{
	if (defel)
	{
		Oid security_id = pgaceSecurityLabelToSid(strVal(defel->arg));

		HeapTupleSetSecurity(tuple, security_id);
	}
}

void rowaclGramAlterRelation(Relation rel, HeapTuple tuple, DefElem *defel)
{
	if (defel)
	{
		Oid security_id = pgaceSecurityLabelToSid(strVal(defel->arg));

		HeapTupleSetSecurity(tuple, security_id);
	}
}

/******************************************************************
 * Security Label interfaces
 ******************************************************************/

static Acl *rawAclTextToAclArray(char *raw_acl)
{
	Acl *acl = NULL;
	AclItem ai;
	int index;
	char *copy, *tok;

	if (!raw_acl || !strcmp(raw_acl, ROW_ACL_EMPTY_STRING))
		return NULL;

	index = 1;
	copy = pstrdup(raw_acl);
	for (tok = strtok(copy, ","); tok; tok = strtok(NULL, ","))
	{
		if (sscanf(tok, "%x:%x:%x",
				   &ai.ai_grantee,
				   &ai.ai_grantor,
				   &ai.ai_privs) != 3)
			continue;

		if (!acl)
			acl = construct_empty_array(ACLITEMOID);

		acl = array_set(acl, 1, &index,
						PointerGetDatum(&ai),
						false,
						-1,
						12,		/* typlen of aclitem */
						false,	/* typbyval of aclitem */
						'i');	/* typalign of aclitem */
		index++;
	}
	pfree(copy);

	check_acl(acl);

	return acl;
}

static char *rawAclTextFromAclArray(Acl *acl)
{
	AclItem *aip;
	AclMode mask = (ACL_SELECT | ACL_UPDATE | ACL_DELETE);
	char *raw_acl;
	int index, aclnum, ofs = 0;
	bool isnull;

	if (!acl)
		return pstrdup(ROW_ACL_EMPTY_STRING);

	aclnum = ArrayGetNItems(ARR_NDIM(acl), ARR_DIMS(acl));
	if (aclnum == 0)
		return pstrdup(ROW_ACL_EMPTY_STRING);

	check_acl(acl);

	raw_acl = palloc0(aclnum * 30);

	for (index = 1; index <= ARR_DIMS(acl)[0]; index++)
	{
		Datum tmp = array_ref(acl, 1, &index, -1,
							  12,		/* typlen of aclitem */
							  false,	/* typbyval of aclitem */
							  'i',		/* typalign of aclitem */
							  &isnull);
		aip = DatumGetAclItemP(tmp);

		if ((aip->ai_privs & mask) != aip->ai_privs)
			ereport(ERROR,
					(errcode(ERRCODE_ROW_ACL_ERROR),
					 errmsg("unsupported ACL: %04x", aip->ai_privs & ~mask)));

		ofs += sprintf(raw_acl + ofs,
					   "%s%x:%x:%x",
					   (ofs == 0 ? "" : ","),
					   aip->ai_grantee,
					   aip->ai_grantor,
					   aip->ai_privs);
	}

	return raw_acl;
}

char *rowaclTranslateSecurityLabelIn(char *acl_string)
{
	FmgrInfo finfo;
	Datum tmp;

	fmgr_info_cxt(F_ARRAY_IN, &finfo, CurrentMemoryContext);
	tmp = FunctionCall3(&finfo,
						CStringGetDatum(acl_string),
						ObjectIdGetDatum(ACLITEMOID),
						Int32GetDatum(-1));
	return rawAclTextFromAclArray(DatumGetAclP(tmp));
}

char *rowaclTranslateSecurityLabelOut(char *acl_string)
{
	FmgrInfo finfo;
	Datum tmp;
	Acl *acl;

	acl = rawAclTextToAclArray(acl_string);
	if (!acl)
		return pstrdup("{}");

	fmgr_info_cxt(F_ARRAY_OUT, &finfo, CurrentMemoryContext);
	tmp = FunctionCall3(&finfo,
						PointerGetDatum(acl),
						ObjectIdGetDatum(ACLITEMOID),
						Int32GetDatum(-1));
	return DatumGetCString(tmp);
}

bool rowaclCheckValidSecurityLabel(char *seclabel)
{
	int c, phase = 1;

	if (strcmp(seclabel, ROW_ACL_EMPTY_STRING) == 0)
		return true;

	while ((c = *seclabel++) != '\0')
	{
		switch (phase)
		{
		case 1:		/* authid of grantee */
			if (c == ':')
				phase = 2;
			else if (!isxdigit(c))
				return false;
			break;
		case 2:		/* authid of grantor */
			if (c == ':')
				phase = 3;
			else if (!isxdigit(c))
				return false;
			break;
		case 3:		/* privileges */
			if (c == ',')
				phase = 1;
			else if (!isxdigit(c))
				return false;
			break;
		}
	}
	if (phase != 3)
		return false;

	return true;
}

char *rowaclUnlabeledSecurityLabel(void)
{
	return pstrdup(ROW_ACL_EMPTY_STRING);
}
