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
#include "utils/lsyscache.h"
#include "utils/memutils.h"
#include "utils/syscache.h"

/*
 * static declarations
 */
static void  proxySubQuery(Query *query);
static Acl  *rawAclTextToAclArray(char *raw_acl);
static char *rawAclTextFromAclArray(Acl *acl);

#define ROW_ACL_ALL_PRIVS	(ACL_SELECT | ACL_UPDATE | ACL_DELETE)

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
 * Row-level ACL result cache
 ******************************************************************/

static MemoryContext RowAclMemCtx;

#define ROWACL_CACHE_SLOT_NUM		128
static List *rowAclCacheSlot[ROWACL_CACHE_SLOT_NUM];

static void rowAclCacheReset(void)
{
	int i;

	MemoryContextReset(RowAclMemCtx);

	for (i=0; i < ROWACL_CACHE_SLOT_NUM; i++)
		rowAclCacheSlot[i] = NIL;
}

typedef struct {
	Oid		relid;
	Oid		userId;
	Oid		securityId;
	AclMode	privs;
} rowAclCacheItem;

static int rowAclCacheHash(Oid relid, Oid userId, Oid securityId)
{
	Oid keys[3] = { relid, userId, securityId };

	return tag_hash(keys, sizeof(keys)) % ROWACL_CACHE_SLOT_NUM;
}

static void rowAclCacheInsert(Oid relid, Oid userId, Oid securityId, AclMode privs)
{
	MemoryContext oldctx;
	rowAclCacheItem *aci;
	int index = rowAclCacheHash(relid, userId, securityId);

	oldctx = MemoryContextSwitchTo(RowAclMemCtx);

	aci = palloc0(sizeof(rowAclCacheItem));
	aci->relid = relid;
	aci->userId = userId;
	aci->securityId = securityId;
	aci->privs = privs;

	rowAclCacheSlot[index] = lappend(rowAclCacheSlot[index], aci);

	MemoryContextSwitchTo(oldctx);
}

static bool rowAclCacheLookup(Oid relid, Oid userId, Oid securityId, AclMode *privs)
{
	ListCell *l;
	int index = rowAclCacheHash(relid, userId, securityId);

	foreach (l, rowAclCacheSlot[index])
	{
		rowAclCacheItem *aci = lfirst(l);

		if (aci->relid == relid &&
			aci->userId == userId &&
			aci->securityId == securityId)
		{
			*privs = aci->privs;
			return true;
		}
	}

	return false;
}

static void
rowaclRoleidCallback(Datum arg, int cacheid, ItemPointer tuplePtr)
{
	rowAclCacheReset();
}

void rowaclInitialize(bool is_bootstrap)
{
	RowAclMemCtx = AllocSetContextCreate(TopMemoryContext,
										 "Row-level ACL result cache",
										 ALLOCSET_DEFAULT_MINSIZE,
										 ALLOCSET_DEFAULT_INITSIZE,
										 ALLOCSET_DEFAULT_MAXSIZE);

	CacheRegisterSyscacheCallback(AUTHOID,
								  rowaclRoleidCallback, 0);

	rowAclCacheReset();
}

/******************************************************************
 * Row-level access controls
 ******************************************************************/

static Acl *rowaclDefaultAclArray(Oid relid)
{
	HeapTuple tuple;
	Form_pg_class classForm;
	Oid ownerId;
	Datum aclDatum;
	bool isnull;
	Acl *acl;
	AclItem *aidat;
	int i;

	/*
	 * Get owner Id
	 */
	tuple = SearchSysCache(RELOID,
						   ObjectIdGetDatum(relid),
						   0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		ereport(ERROR,
				(errcode(ERRCODE_ROW_ACL_ERROR),
				 errmsg("cache lookup failed for relation: %u", relid)));
	classForm = (Form_pg_class) GETSTRUCT(tuple);
	ownerId = classForm->relowner;

	aclDatum = SysCacheGetAttr(RELOID, tuple,
							   Anum_pg_class_relacl, &isnull);
	if (isnull)
	{
		acl = acldefault(classForm->relkind == RELKIND_SEQUENCE ?
						 ACL_OBJECT_SEQUENCE : ACL_OBJECT_RELATION,
						 ownerId);
	}
	else
	{
		acl = DatumGetAclPCopy(aclDatum);
	}

	ReleaseSysCache(tuple);

	/*
	 * Mask unsupported privileges
	 */
	aidat = ACL_DAT(acl);
	for (i = 0; i < ACL_NUM(acl); i++)
	{
		aidat[i].ai_privs &= ROW_ACL_ALL_PRIVS;
	}

	return acl;
}

struct rowaclUserInfoType {
	Oid userId;
	bool abort_on_error;
};
struct rowaclUserInfoType *rowaclUserInfo = NULL;

Datum rowaclBeginPerformCheckFK(Relation rel, bool is_primary, Oid save_userid)
{
	Datum save_pgace = PointerGetDatum(rowaclUserInfo);
	struct rowaclUserInfoType *uinfo
		= palloc0(sizeof(struct rowaclUserInfoType));
	uinfo->userId = (!rowaclUserInfo ? save_userid : rowaclUserInfo->userId);
	uinfo->abort_on_error = is_primary;

	rowaclUserInfo = uinfo;

	return save_pgace;
}

void rowaclEndPerformCheckFK(Relation rel, Datum save_pgace)
{
	rowaclUserInfo = (struct rowaclUserInfoType *) DatumGetPointer(save_pgace);
}

static bool rowaclCheckPermission(Relation rel, HeapTuple tuple, AclMode required)
{
	Oid relid = RelationGetRelid(rel);
	Oid ownerId = RelationGetForm(rel)->relowner;
	Oid userId = GetUserId();
	Oid securityId = HeapTupleGetSecurity(tuple);
	AclMode privs;

	Assert((required & ~ROW_ACL_ALL_PRIVS) == 0);

	if (rowaclUserInfo)
		userId = rowaclUserInfo->userId;

	/*
	 * ACL of pg_class means pre-configured default ACL
	 * It does not used to access control
	 */
	if (IsSystemRelation(rel))
		return true;

	if (!rowAclCacheLookup(relid, userId, securityId, &privs))
	{
		/* Superusers bypass all permission checking */
		if (superuser_arg(userId))
		{
			privs = ROW_ACL_ALL_PRIVS;
		}
		else
		{
			char *raw_acl = pgaceLookupSecurityLabel(securityId);
			Acl *acl = rawAclTextToAclArray(raw_acl);

			if (!acl)
				acl = rowaclDefaultAclArray(relid);

			privs = aclmask(acl, userId, ownerId, required, ACLMASK_ALL);
		}
		rowAclCacheInsert(relid, userId, securityId, privs);
	}

	if ((privs & required) == required)
		return true;

	if (rowaclUserInfo && rowaclUserInfo->abort_on_error)
		ereport(ERROR,
				(errcode(ERRCODE_ROW_ACL_ERROR),
				 errmsg("access violation in row-level acl")));

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
		HeapTuple reltup
			= SearchSysCache(RELOID,
							 ObjectIdGetDatum(RelationGetRelid(rel)),
							 0, 0, 0);
		if (!HeapTupleIsValid(reltup))
			elog(ERROR, "cache lookup failed for relation %s",
				 RelationGetRelationName(rel));

		HeapTupleSetSecurity(tuple, HeapTupleGetSecurity(reltup));

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
	AclMode mask = ROW_ACL_ALL_PRIVS;
	char *raw_acl;
	int i, aclnum, ofs = 0;

	if (!acl)
		return pstrdup(ROW_ACL_EMPTY_STRING);

	aclnum = ACL_NUM(acl);
	if (aclnum == 0)
		return pstrdup(ROW_ACL_EMPTY_STRING);

	check_acl(acl);

	raw_acl = palloc(aclnum * 30);	/* needed enough */

	aip = ACL_DAT(acl);
	for (i = 0; i < aclnum; i++)
	{
		if ((aip[i].ai_privs & mask) != aip[i].ai_privs)
			ereport(ERROR,
					(errcode(ERRCODE_ROW_ACL_ERROR),
					 errmsg("unsupported ACL: %04x", aip[i].ai_privs & ~mask)));

		ofs += sprintf(raw_acl + ofs,
					   "%s%x:%x:%x",
					   (ofs == 0 ? "" : ","),
					   aip[i].ai_grantee,
					   aip[i].ai_grantor,
					   aip[i].ai_privs);
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
		return pstrdup("");

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

/******************************************************************
 * SQL functions
 ******************************************************************/

/*
 * usage: rowacl_grant(tableoid, tuple_acl, 'username', 'select,update,delete')
 *        rowacl_revoke(tableoid, tuple_acl, 'username', 'select,update,delete');
 */
static Datum rowacl_grant_revoke(PG_FUNCTION_ARGS, bool grant, bool cascade)
{
	FmgrInfo fmgrInfo;
	char *tmp, *tok;
	Oid ownerId;
	Acl *acl;
	List *grantees = NIL;
	AclMode privileges = 0;

	/*
	 * Extract Acl array
	 */
	tmp = TextDatumGetCString(PG_GETARG_TEXT_P(1));
	if (tmp[0] == '\0')
	{
		/*
		 * Default ACL is same as table acl
		 */
		acl = rowaclDefaultAclArray(PG_GETARG_OID(0));
	}
	else
	{
		fmgr_info_cxt(F_ARRAY_IN, &fmgrInfo, CurrentMemoryContext);
		acl = DatumGetAclP(FunctionCall3(&fmgrInfo,
										 CStringGetDatum(tmp),
										 ObjectIdGetDatum(ACLITEMOID),
										 Int32GetDatum(-1)));
	}
	/*
	 * Extract usernames
	 */
	tmp = TextDatumGetCString(PG_GETARG_TEXT_P(2));
	for (tok = strtok(tmp, ","); tok; tok = strtok(NULL, ","))
	{
		if (strcasecmp(tok, "public") == 0)
		{
			grantees = lappend_oid(grantees, ACL_ID_PUBLIC);
		}
		else
		{
			Oid roleId = get_roleid(tok);

			if (roleId == InvalidOid)
				ereport(ERROR,
						(errcode(ERRCODE_ROW_ACL_ERROR),
						 errmsg("%s is not a valid identifier", tok)));

			grantees = lappend_oid(grantees, roleId);
		}
	}

	/*
	 * Extract permission names
	 */
	tmp = TextDatumGetCString(PG_GETARG_TEXT_P(3));
	for (tok = strtok(tmp, ","); tok; tok = strtok(NULL, ","))
	{
		if (strcasecmp(tok, "all") == 0)
			privileges |= (ACL_SELECT | ACL_UPDATE | ACL_DELETE);
		else if (strcasecmp(tok, "select") == 0)
			privileges |= ACL_SELECT;
		else if (strcasecmp(tok, "update") == 0)
            privileges |= ACL_UPDATE;
        else if (strcasecmp(tok, "delete") == 0)
            privileges |= ACL_DELETE;
        else
			ereport(ERROR,
					(errcode(ERRCODE_ROW_ACL_ERROR),
					 errmsg("%s is not a valid permission", tok)));
	}

	/*
	 * Merge ACL
	 */
	acl = merge_acl_with_grant(acl, grant, false, cascade,
							   grantees, privileges,
							   GetUserId(), ownerId);

	fmgr_info_cxt(F_ARRAY_OUT, &fmgrInfo, CurrentMemoryContext);
	tmp = DatumGetCString(FunctionCall3(&fmgrInfo,
										PointerGetDatum(acl),
										ObjectIdGetDatum(ACLITEMOID),
										Int32GetDatum(-1)));
	return CStringGetTextDatum(tmp);
}

Datum
rowacl_grant(PG_FUNCTION_ARGS)
{
	return rowacl_grant_revoke(fcinfo, true, false);
}

Datum
rowacl_revoke(PG_FUNCTION_ARGS)
{
	return rowacl_grant_revoke(fcinfo, false, false);
}

Datum
rowacl_revoke_cascade(PG_FUNCTION_ARGS)
{
	return rowacl_grant_revoke(fcinfo, false, true);
}
