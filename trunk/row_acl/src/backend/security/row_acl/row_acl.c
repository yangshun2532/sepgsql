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
#include "utils/inval.h"
#include "utils/lsyscache.h"
#include "utils/memutils.h"
#include "utils/syscache.h"

/*
 * static declarations
 */
static void  proxySubQuery(Query *query);
static void  rawAclTextToAclArray(const char *raw_acl, Acl **acl, Acl **defacl);
static char *rawAclTextFromAclArray(Acl *acl, Acl *defacl);
static void  aclArrayInput(const char *input, Acl **acl, Acl **defacl);
static char *aclArrayOutput(Acl *acl, Acl *defacl);

#define ROW_ACL_ALL_PRIVS	(ACL_SELECT | ACL_UPDATE | ACL_DELETE | ACL_REFERENCES)

/******************************************************************
 * Global system setting
 ******************************************************************/

bool rowacl_is_enabled_mode = true;

bool rowaclIsEnabled(void)
{
	return rowacl_is_enabled_mode;
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
	CacheRegisterSyscacheCallback(RELOID,
								  rowaclRoleidCallback, 0);

	rowAclCacheReset();
}

/******************************************************************
 * Row-level access controls
 ******************************************************************/

static Acl *rowaclDefaultAclArray(Oid ownerId)
{
	Acl *acl;
	AclItem *aip;

	/*
	 * All permissions to public in default
	 */

	acl = allocacl(1);
	aip = ACL_DAT(acl);
	aip->ai_grantee = ACL_ID_PUBLIC;
	aip->ai_grantor = ownerId;
	aip->ai_privs = ROW_ACL_ALL_PRIVS;

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
	{
		userId = rowaclUserInfo->userId;

		/*
		 * If ACL_SELECT is given within FK constraint checks,
		 * its privilege is replaced to ACL_REFERENCES.
		 */
		if (required & ACL_SELECT)
		{
			required &= ~ACL_SELECT;
			required |= ACL_REFERENCES;
		}
	}

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
			Acl *acl, *defacl;

			rawAclTextToAclArray(raw_acl, &acl, &defacl);
			if (!acl)
				acl = rowaclDefaultAclArray(ownerId);

			privs = aclmask(acl, userId, ownerId, ROW_ACL_ALL_PRIVS, ACLMASK_ALL);
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
	Acl *acl, *defacl;
	char *rawacl;

	if (HeapTupleGetSecurity(tuple) != InvalidOid)
	{
		if (RelationGetForm(rel)->relkind != RELKIND_RELATION)
			ereport(ERROR,
					(errcode(ERRCODE_ROW_ACL_ERROR),
					 errmsg("only general relation can have row-level ACL")));
		if (!is_internal &&
			!pg_class_ownercheck(RelationGetRelid(rel), GetUserId()))
			ereport(ERROR,
					(errcode(ERRCODE_ROW_ACL_ERROR),
					 errmsg("Only owner or superuser can set ACL")));
		/*
		 * validate ACL
		 */
		rawacl = pgaceLookupSecurityLabel(HeapTupleGetSecurity(tuple));
		rawAclTextToAclArray(rawacl, &acl, &defacl);
		if (defacl && RelationGetRelid(rel) != RelationRelationId)
				ereport(ERROR,
						(errcode(ERRCODE_ROW_ACL_ERROR),
						 errmsg("only pg_class can have default ACL")));
	}
	else if (!IsBootstrapProcessingMode())
	{
		HeapTuple reltup;
		Oid securityId;

		reltup = SearchSysCache(RELOID,
								ObjectIdGetDatum(RelationGetRelid(rel)),
								0, 0, 0);
		if (!HeapTupleIsValid(reltup))
			elog(ERROR, "cache lookup failed for relation %s",
				 RelationGetRelationName(rel));
		if (HeapTupleGetSecurity(reltup) != InvalidOid)
		{
			rawacl = pgaceLookupSecurityLabel(HeapTupleGetSecurity(reltup));
			rawAclTextToAclArray(rawacl, &acl, &defacl);

			if (defacl)
			{
				rawacl = rawAclTextFromAclArray(defacl, NULL);
				securityId = pgaceLookupSecurityId(rawacl);

				HeapTupleSetSecurity(tuple, securityId);
			}
		}
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
		Oid securityId = HeapTupleGetSecurity(oldtup);

		HeapTupleSetSecurity(newtup, securityId);
	}
	else if (HeapTupleGetSecurity(newtup) != HeapTupleGetSecurity(oldtup))
	{
		Acl *acl, *defacl;
		char *rawacl;

		if (!is_internal &&
			!pg_class_ownercheck(RelationGetRelid(rel), GetUserId()))
			ereport(ERROR,
					(errcode(ERRCODE_ROW_ACL_ERROR),
					 errmsg("Only owner or superuser can set ACL")));

		rawacl = pgaceLookupSecurityLabel(HeapTupleGetSecurity(newtup));
		rawAclTextToAclArray(rawacl, &acl, &defacl);

		if (defacl && RelationGetRelid(rel) != RelationRelationId)
			ereport(ERROR,
					(errcode(ERRCODE_ROW_ACL_ERROR),
					 errmsg("only pg_class can have default ACL")));
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
	Acl *acl, *defacl;
	char *defaclTxt;
	Oid securityId;

	if (!defel)
		return;

	aclArrayInput(strVal(defel->arg), &acl, &defacl);
	if (!acl || defacl)
		ereport(ERROR,
				(errcode(ERRCODE_ROW_ACL_ERROR),
				 errmsg("invalid default ACL : %s", strVal(defel->arg))));

	defaclTxt = rawAclTextFromAclArray(NULL, acl);
	securityId = pgaceLookupSecurityId(defaclTxt);

	HeapTupleSetSecurity(tuple, securityId);
}

void rowaclGramAlterRelation(Relation rel, HeapTuple tuple, DefElem *defel)
{
	Acl *acl, *defacl, *acl_old, *defacl_old;
	char *rawacl, *defaclTxt;
	Oid securityId;

	if (!defel)
		return;

	aclArrayInput(strVal(defel->arg), &acl, &defacl);
	if (!acl || defacl)
		ereport(ERROR,
				(errcode(ERRCODE_ROW_ACL_ERROR),
				 errmsg("invalid default ACL : %s", strVal(defel->arg))));

	/* lookup original one */
	rawacl = pgaceLookupSecurityLabel(HeapTupleGetSecurity(tuple));
	rawAclTextToAclArray(rawacl, &acl_old, &defacl_old);

	defaclTxt = rawAclTextFromAclArray(acl_old, acl);
	securityId = pgaceLookupSecurityId(defaclTxt);

	HeapTupleSetSecurity(tuple, securityId);
}

/******************************************************************
 * Security Label interfaces
 ******************************************************************/
static Acl *rawAclTokenToAclArray(char *rawacl)
{
	Acl *acl;
	AclItem *aip;
	char *tok, *sv;
	int aclnum = 0;

	aip = palloc(strlen(rawacl) * sizeof(AclItem) / 4);
	for (tok = strtok_r(rawacl, ",", &sv);
		 tok;
		 tok = strtok_r(NULL, ",", &sv))
	{
		if (sscanf(tok, "%x:%x:%x",
				   &aip[aclnum].ai_grantee,
				   &aip[aclnum].ai_grantor,
				   &aip[aclnum].ai_privs) != 3)
			continue;
		aclnum++;
	}
	acl = allocacl(aclnum);
	memcpy(ACL_DAT(acl), aip, aclnum * sizeof(AclItem));

	pfree(aip);

	check_acl(acl);

	return acl;
}

static char *rawAclTokenFromAclArray(Acl *acl)
{
	AclItem *aip = ACL_DAT(acl);
	char *rawacl = palloc0(ACL_NUM(acl) * 30 + 10);
	int i, ofs = 0;

	for (i = 0; i < ACL_NUM(acl); i++)
	{
		if ((aip[i].ai_privs & ROW_ACL_ALL_PRIVS) != aip[i].ai_privs)
			ereport(ERROR,
					(errcode(ERRCODE_ROW_ACL_ERROR),
					 errmsg("unsupported row-level ACL: %04x",
							aip[i].ai_privs & ~ROW_ACL_ALL_PRIVS)));

		ofs += sprintf(rawacl + ofs,
					   "%s%x:%x:%x",
					   (ofs == 0 ? "" : ","),
					   aip[i].ai_grantee,
					   aip[i].ai_grantor,
					   aip[i].ai_privs);
	}

	return rawacl;
}

static void rawAclTextToAclArray(const char *raw_acl, Acl **acl, Acl **defacl)
{
	char *copy, *tok, *sv;

	*acl = *defacl = NULL;

	copy = pstrdup(raw_acl);
	for (tok = strtok_r(copy, "/", &sv);
		 tok;
		 tok = strtok_r(NULL, "/", &sv))
	{
		if (strncmp(tok, "acl=", 4) == 0)
		{
			if (acl)
				*acl = rawAclTokenToAclArray(tok + 4);
		}
		else if (strncmp(tok, "default=", 8) == 0)
		{
			if (defacl)
				*defacl = rawAclTokenToAclArray(tok + 8);
		}
		else
			elog(WARNING, "invalid row-level acl token: %s", tok);
	}
	pfree(copy);
}

static char *rawAclTextFromAclArray(Acl *acl, Acl *defacl)
{
	char *aclTxt = NULL;
	char *defaclTxt = NULL;
	char *result;
	int ofs = 0, length = 0;

	if (acl)
	{
		aclTxt = rawAclTokenFromAclArray(acl);
		length += strlen(aclTxt) + 4;
	}
	if (defacl)
	{
		defaclTxt = rawAclTokenFromAclArray(defacl);
		length += strlen(defaclTxt) + 8;
	}

	result = palloc(length + 2);
	if (aclTxt)
	{
		ofs += sprintf(result + ofs, "%sacl=%s",
					   (ofs==0 ? "" : "/"), aclTxt);
		pfree(aclTxt);
	}
	if (defaclTxt)
	{
		ofs += sprintf(result + ofs, "%sdefault=%s",
					   (ofs==0 ? "" : "/"), defaclTxt);
		pfree(defaclTxt);
	}

	return result;
}

static void aclArrayInput(const char *input, Acl **acl, Acl **defacl)
{
	FmgrInfo finfo;
	char *copy, *tok, *sv;
	Datum tmp;

	copy = pstrdup(input);
	*acl = *defacl = NULL;
	for (tok = strtok_r(copy, " ", &sv);
		 tok;
		 tok = strtok_r(NULL, " ", &sv))
	{
		fmgr_info_cxt(F_ARRAY_IN, &finfo, CurrentMemoryContext);

		if (strncmp(tok, "default=", 8) == 0)
		{
			tmp = FunctionCall3(&finfo,
								CStringGetDatum(tok + 8),
								ObjectIdGetDatum(ACLITEMOID),
								Int32GetDatum(-1));
			*defacl = DatumGetAclP(tmp);
			if (ARR_NDIM(*defacl) == 0)
			{
				pfree(*defacl);
				*defacl = allocacl(0);
			}
			check_acl(*defacl);
		}
		else
		{
			tmp = FunctionCall3(&finfo,
                                CStringGetDatum(tok),
                                ObjectIdGetDatum(ACLITEMOID),
                                Int32GetDatum(-1));
			*acl = DatumGetAclP(tmp);
			if (ARR_NDIM(*acl) == 0)
			{
				pfree(*acl);
				*acl = allocacl(0);
			}
			check_acl(*acl);
		}
	}
}

static char *aclArrayOutput(Acl *acl, Acl *defacl)
{
	FmgrInfo finfo;
	char *aclTxt = NULL, *defaclTxt = NULL, *output;
	int ofs = 0, length = 0;

	if (acl)
	{
		fmgr_info_cxt(F_ARRAY_OUT, &finfo, CurrentMemoryContext);
		aclTxt = DatumGetCString(FunctionCall3(&finfo,
											   PointerGetDatum(acl),
											   ObjectIdGetDatum(ACLITEMOID),
											   Int32GetDatum(-1)));
		length += strlen(aclTxt);
	}

	if (defacl)
	{
		fmgr_info_cxt(F_ARRAY_OUT, &finfo, CurrentMemoryContext);
		defaclTxt = DatumGetCString(FunctionCall3(&finfo,
												  PointerGetDatum(defacl),
												  ObjectIdGetDatum(ACLITEMOID),
												  Int32GetDatum(-1)));
		length += strlen(defaclTxt) + 10;
	}

	output = palloc0(length + 2);
	if (aclTxt)
	{
		ofs += sprintf(output + ofs, "%s", aclTxt);
		pfree(aclTxt);
	}
	if (defaclTxt)
	{
		ofs += sprintf(output + ofs, "%sdefault=%s",
					   (ofs == 0 ? "" : " "), defaclTxt);
		pfree(defaclTxt);
	}
	return output;
}

char *rowaclTranslateSecurityLabelIn(char *acl_string)
{
	Acl *acl, *defacl;

	if (*acl_string == '\0')
		return acl_string;

	aclArrayInput(acl_string, &acl, &defacl);
	return rawAclTextFromAclArray(acl, defacl);
}

char *rowaclTranslateSecurityLabelOut(char *acl_string)
{

	Acl *acl, *defacl;

	rawAclTextToAclArray(acl_string, &acl, &defacl);
	return aclArrayOutput(acl, defacl);
}

bool rowaclCheckValidSecurityLabel(char *aclstring)
{
	char *copy, *tok, *sv, *ptr, *tok2, *sv2;
	AclItem ai;

	if (*aclstring == '\0')
		return true;

	copy = pstrdup(aclstring);
	for (tok = strtok_r(copy, "/", &sv);
		 tok;
		 tok = strtok_r(NULL, "/", &sv))
	{
		if (strncmp(tok, "acl=", 4) == 0)
			ptr = tok + 4;
		else if (strncmp(tok, "default=", 8) == 0)
			ptr = tok + 8;
		else
			return false;

		for (tok2 = strtok_r(ptr, ",", &sv2);
			 tok2;
			 tok2 = strtok_r(NULL, "/", &sv2))
		{
			if (sscanf(ptr, "%x:%x:%x",
					   &ai.ai_grantee,
					   &ai.ai_grantor,
					   &ai.ai_privs) != 3)
				return false;
		}
	}

	return true;
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
	char *input, *tok, *sv;
	HeapTuple tuple;
	Acl *acl, *defacl;
	Oid ownerId;
	List *grantees = NIL;
	AclMode privileges = 0;

	/*
	 * Get owner Id;
	 */
	tuple = SearchSysCache(RELOID,
						   PG_GETARG_DATUM(0), 0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "cache lookup failed for relation %u",
			 PG_GETARG_OID(0));

	ownerId = ((Form_pg_class) GETSTRUCT(tuple))->relowner;
	ReleaseSysCache(tuple);

	/*
	 * Extract Acl array
	 */
	input = TextDatumGetCString(PG_GETARG_TEXT_P(1));
	aclArrayInput(input, &acl, &defacl);
	if (!acl)
		acl = rowaclDefaultAclArray(ownerId);

	/*
	 * Extract usernames
	 */
	input = TextDatumGetCString(PG_GETARG_TEXT_P(2));
	for (tok = strtok_r(input, ",", &sv);
		 tok;
		 tok = strtok_r(NULL, ",", &sv))
	{
		if (strcasecmp(tok, "public") == 0)
			grantees = lappend_oid(grantees, ACL_ID_PUBLIC);
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
	input = TextDatumGetCString(PG_GETARG_TEXT_P(3));
	for (tok = strtok_r(input, ",", &sv);
		 tok;
		 tok = strtok_r(NULL, ",", &sv))
	{
		if (strcasecmp(tok, "all") == 0)
			privileges |= ROW_ACL_ALL_PRIVS;
		else if (strcasecmp(tok, "select") == 0)
			privileges |= ACL_SELECT;
		else if (strcasecmp(tok, "update") == 0)
            privileges |= ACL_UPDATE;
        else if (strcasecmp(tok, "delete") == 0)
            privileges |= ACL_DELETE;
		else if (strcasecmp(tok, "references") == 0)
			privileges |= ACL_REFERENCES;
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

	return CStringGetTextDatum(aclArrayOutput(acl, defacl));
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
