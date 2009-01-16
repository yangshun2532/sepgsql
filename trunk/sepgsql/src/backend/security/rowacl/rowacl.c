/*
 * src/backend/rowacl/rowacl.c
 *   Row-level Database ACLs support
 *
 * Portions Copyright (c) 1996-2009, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 */
#include "postgres.h"

#include "access/reloptions.h"
#include "catalog/namespace.h"
#include "catalog/pg_type.h"
#include "commands/defrem.h"
#include "miscadmin.h"
#include "nodes/nodeFuncs.h"
#include "parser/parsetree.h"
#include "security/pgace.h"
#include "storage/bufmgr.h"
#include "utils/builtins.h"
#include "utils/fmgroids.h"
#include "utils/guc.h"
#include "utils/inval.h"
#include "utils/lsyscache.h"
#include "utils/memutils.h"
#include "utils/syscache.h"

#define ROWACL_ALL_PRIVS	(ACL_SELECT | ACL_UPDATE | ACL_DELETE | ACL_REFERENCES)

static void walkOnQueryTree(Query *query);

/******************************************************************
 * Mark appeared Query/Sub-Query
 ******************************************************************/

static bool walkOnNodeTree(Node *node, Query *query)
{
	if (!node)
		return false;

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
			walkOnQueryTree(rte->subquery);
		}
	}
	else if (IsA(node, Query))
	{
		walkOnQueryTree((Query *) node);
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

static void walkOnQueryTree(Query *query)
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
	query_tree_walker(query,
					  walkOnNodeTree,
					  (void *) query, 0);
}

List *rowaclPostQueryRewrite(List *queryList)
{
	ListCell *l;

	foreach (l, queryList)
	{
		Query *query = (Query *) lfirst(l);

		Assert(IsA(query, Query));

		if (query->commandType == CMD_SELECT ||
			query->commandType == CMD_UPDATE ||
			query->commandType == CMD_DELETE)
			walkOnQueryTree(query);
	}

	return queryList;
}

/******************************************************************
 * Cache boost row-level ACLs checks
 ******************************************************************/

static MemoryContext RowAclMemCtx;

#define ROWACL_CACHE_SLOT_NUM       128
static List *rowaclCacheSlot[ROWACL_CACHE_SLOT_NUM];

static void rowaclCacheReset(void)
{
	int i;

	MemoryContextReset(RowAclMemCtx);

	for (i=0; i < ROWACL_CACHE_SLOT_NUM; i++)
		rowaclCacheSlot[i] = NIL;
}

typedef struct {
	Oid		relid;
	Oid		userid;
	Oid		aclid;
	AclMode	privs;
} rowaclCacheItem;

static int rowaclCacheHash(Oid relid, Oid userid, Oid aclid)
{
	Oid keys[3] = { relid, userid, aclid };

	return tag_hash(keys, sizeof(keys)) % ROWACL_CACHE_SLOT_NUM;
}

static void rowaclCacheInsert(Oid relid, Oid userid, Oid aclid, AclMode privs)
{
    MemoryContext oldctx;
    rowaclCacheItem *aci;
    int index = rowaclCacheHash(relid, userid, aclid);

	oldctx = MemoryContextSwitchTo(RowAclMemCtx);

	aci = palloc0(sizeof(rowaclCacheItem));
	aci->relid = relid;
	aci->userid = userid;
	aci->aclid = aclid;
	aci->privs = privs;

	rowaclCacheSlot[index] = lappend(rowaclCacheSlot[index], aci);

	MemoryContextSwitchTo(oldctx);
}

static bool rowaclCacheLookup(Oid relid, Oid userid, Oid aclid, AclMode *privs)
{
	ListCell *l;
	int index = rowaclCacheHash(relid, userid, aclid);

	foreach (l, rowaclCacheSlot[index])
	{
		rowaclCacheItem *aci = lfirst(l);

		if (aci->relid == relid &&
			aci->userid == userid &&
			aci->aclid == aclid)
		{
			*privs = aci->privs;
			return true;
		}
	}

	return false;
}

static void
rowaclSyscacheCallback(Datum arg, int cacheid, ItemPointer tuplePtr)
{
	rowaclCacheReset();
}

void rowaclInitialize(bool is_bootstrap)
{
	RowAclMemCtx = AllocSetContextCreate(TopMemoryContext,
										 "Row-level ACL result cache",
										 ALLOCSET_DEFAULT_MINSIZE,
										 ALLOCSET_DEFAULT_INITSIZE,
										 ALLOCSET_DEFAULT_MAXSIZE);

	CacheRegisterSyscacheCallback(AUTHOID,
								  rowaclSyscacheCallback, 0);
	CacheRegisterSyscacheCallback(RELOID,
								  rowaclSyscacheCallback, 0);
	rowaclCacheReset();
}

/******************************************************************
 * Row-level access controls
 ******************************************************************/

struct rowaclUserInfoType {
	Oid userid;
	bool abort_on_error;
};
struct rowaclUserInfoType *rowaclUserInfo = NULL;

Datum rowaclBeginPerformCheckFK(Relation rel, bool is_primary, Oid save_userid)
{
	Datum save_pgace = PointerGetDatum(rowaclUserInfo);
	struct rowaclUserInfoType *uinfo
		= palloc0(sizeof(struct rowaclUserInfoType));
	uinfo->userid = save_userid;
	uinfo->abort_on_error = is_primary;

	rowaclUserInfo = uinfo;

	return save_pgace;
}

void rowaclEndPerformCheckFK(Relation rel, Datum save_pgace)
{
	rowaclUserInfo = (struct rowaclUserInfoType *) DatumGetPointer(save_pgace);
}

static bool
rowaclCheckPermission(Relation rel, HeapTuple tuple, AclMode required)
{
    Oid relid = RelationGetRelid(rel);
    Oid ownerid = RelationGetForm(rel)->relowner;
    Oid userid = GetUserId();
    Oid aclid = HeapTupleGetRowAcl(tuple);
	AclMode privs;

	if (rowaclUserInfo)
	{
		userid = rowaclUserInfo->userid;

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

	if (!rowaclCacheLookup(relid, userid, aclid, &privs))
	{
		/* Superusers/Owner bypass all permission checking */
		if (superuser_arg(userid) || userid == ownerid)
		{
			privs = ROWACL_ALL_PRIVS;
		}
		else
		{
			Acl *acl = rowaclSidToSecurityAcl(aclid, ownerid);

			privs = aclmask(acl, userid, ownerid, ROWACL_ALL_PRIVS, ACLMASK_ALL);
		}
		rowaclCacheInsert(relid, userid, aclid, privs);
	}

	if ((privs & required) == required)
		return true;

	if (rowaclUserInfo && rowaclUserInfo->abort_on_error)
		ereport(ERROR,
				(errcode(ERRCODE_ROWACL_ERROR),
				 errmsg("access violation in row-level acl")));

    return false;
}

bool rowaclExecScan(Scan *scan, Relation rel, TupleTableSlot *slot)
{
	AclMode required = scan->pgaceTuplePerms & ROWACL_ALL_PRIVS;
	HeapTuple tuple;

	if (required==0 || !RelationGetRowLevelAcl(rel))
		return true;

	tuple = ExecMaterializeSlot(slot);

	return rowaclCheckPermission(rel, tuple, required);
}

bool rowaclCopyToTuple(Relation rel, List *attNumList, HeapTuple tuple)
{
	if (!RelationGetRowLevelAcl(rel))
		return true;

	return rowaclCheckPermission(rel, tuple, ACL_SELECT);
}

/******************************************************************
 * Check ownership of tuples
 ******************************************************************/
bool rowaclHeapTupleInsert(Relation rel, HeapTuple tuple,
						   bool is_internal, bool with_returning)
{
	if (!HeapTupleHasRowAcl(tuple))
		return true;

	if (OidIsValid(HeapTupleGetRowAcl(tuple)))
	{
		if (RelationGetForm(rel)->relkind != RELKIND_RELATION)
			ereport(ERROR,
					(errcode(ERRCODE_ROWACL_ERROR),
					 errmsg("only general relation can have row-level ACL")));
		if (!is_internal &&
			!pg_class_ownercheck(RelationGetRelid(rel), GetUserId()))
			ereport(ERROR,
					(errcode(ERRCODE_ROWACL_ERROR),
					 errmsg("Only owner or superuser can set ACL")));
	}
	else
	{
		char *default_row_acl = RelationGetDefaultRowAcl(rel);

		if (default_row_acl)
		{
			FmgrInfo finfo;
			Datum aclDat;
			Oid sid;

			fmgr_info(F_ARRAY_IN, &finfo);
			aclDat = FunctionCall3(&finfo,
								   CStringGetDatum(default_row_acl),
								   ObjectIdGetDatum(ACLITEMOID),
								   Int32GetDatum(-1));
			sid = rowaclSecurityAclToSid(DatumGetAclP(aclDat));
			HeapTupleSetRowAcl(tuple, sid);
		}
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

	if (!HeapTupleHasRowAcl(newtup))
		return true;

	if (!OidIsValid(HeapTupleGetRowAcl(newtup)))
	{
		/* preserve old ACL */
		HeapTupleSetRowAcl(newtup, HeapTupleGetRowAcl(oldtup));
	}
	else if (HeapTupleGetRowAcl(newtup) != HeapTupleGetRowAcl(oldtup))
	{
		if (!is_internal &&
			!pg_class_ownercheck(RelationGetRelid(rel), GetUserId()))
			ereport(ERROR,
					(errcode(ERRCODE_ROWACL_ERROR),
					 errmsg("Only owner or superuser can set ACL")));
	}
	return true;
}

bool rowaclHeapTupleDelete(Relation rel, ItemPointer otid,
						   bool is_internal, bool with_returning)
{
	/*
	 * Do nothing here
	 */
	return true;
}

/******************************************************************
 * Relation Options
 ******************************************************************/
void
rawaclValidateDefaultRowAclRelopt(const char *value)
{
	FmgrInfo finfo;
	Datum acldat;

	/*
	 * If given default row-acl in reloptions is not valid,
	 * aclitemin can raise an error.
	 */
	fmgr_info(F_ARRAY_IN, &finfo);
	acldat = FunctionCall3(&finfo,
						   CStringGetDatum(value),
						   ObjectIdGetDatum(ACLITEMOID),
						   Int32GetDatum(-1));
	pfree(DatumGetAclP(acldat));
}

/******************************************************************
 * Row-level ACLs management
 ******************************************************************/

bool rowaclTupleDescHasRowAcl(Relation rel, List *relopts)
{
	ListCell *l;

	if (rel)
		return RelationGetRowLevelAcl(rel);

	/* SELECT INTO cases */
	foreach (l, relopts)
	{
		DefElem *def = (DefElem *) lfirst(l);

		if (pg_strcasecmp(def->defname, "row_level_acl") == 0)
			return defGetBoolean(def);
	}

	return false;
}

static Acl *
rowaclDefaultAclArray(Oid ownerId)
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
	aip->ai_privs = ROWACL_ALL_PRIVS;

	return acl;
}

static bool
rowaclCheckValidSecurityAcl(const char *raw_acl)
{
	char *copy, *tok, *sv = NULL;
	AclItem ai;

	if (strncmp(raw_acl, "acl:", 4) != 0)
		return false;

	copy = pstrdup(raw_acl + 4);
	for (tok = strtok_r(copy, ",", &sv);
		 tok;
		 tok = strtok_r(NULL, ",", &sv))
	{
		if (sscanf(tok, "%x=%x/%x",
				   &ai.ai_grantee,
				   &ai.ai_privs,
				   &ai.ai_grantor) != 3)
			return false;
	}

	return true;
}

static Acl *
rawAclTextToAclArray(const char *raw_acl)
{
	Acl *acl;
	AclItem *aip;
	char *copy, *tok, *sv = NULL;
	int num = 0;

	Assert(strncmp(raw_acl, "acl:", 4) == 0);

	copy = pstrdup(raw_acl + 4);
	aip = palloc(strlen(copy) * sizeof(AclItem) / 4);
	for (tok = strtok_r(copy, ",", &sv);
		 tok;
		 tok = strtok_r(NULL, ",", &sv))
	{
		if (sscanf(tok, "%x=%x/%x",
				   &aip[num].ai_grantee,
				   &aip[num].ai_privs,
				   &aip[num].ai_grantor) != 3)
			continue;
		num++;
	}

	acl = allocacl(num);
	memcpy(ACL_DAT(acl), aip, num * sizeof(AclItem));

	pfree(aip);
	pfree(copy);

	check_acl(acl);

	return acl;
}

static char *
rawAclTextFromAclArray(Acl *acl)
{
	AclItem *aip = ACL_DAT(acl);
	char *raw_acl = palloc0(ACL_NUM(acl) * 30 + 10); /* enough length */
	int i, ofs;

	ofs = sprintf(raw_acl, "acl:");

	for (i = 0; i < ACL_NUM(acl); i++)
	{
		if ((aip[i].ai_privs & ROWACL_ALL_PRIVS) != aip[i].ai_privs)
			ereport(ERROR,
					(errcode(ERRCODE_ROWACL_ERROR),
					 errmsg("unsupported privileges in row_acl: %04x",
							aip[i].ai_privs & ~ROWACL_ALL_PRIVS)));

		ofs += sprintf(raw_acl + ofs,
					   "%s%x=%x/%x",
					   (i == 0 ? "" : ","),
					   aip[i].ai_grantee,
					   aip[i].ai_privs,
					   aip[i].ai_grantor);
	}

	return raw_acl;
}

Acl *rowaclSidToSecurityAcl(Oid sid, Oid ownerId)
{
	char *raw_acl
		= pgaceLookupSecurityLabel(sid);

	if (!raw_acl || !rowaclCheckValidSecurityAcl(raw_acl))
		return rowaclDefaultAclArray(ownerId);

	return rawAclTextToAclArray(raw_acl);
}

Oid rowaclSecurityAclToSid(Acl *acl)
{
	char *raw_acl
		= rawAclTextFromAclArray(acl);

	return pgaceLookupSecurityId(raw_acl);
}

Datum rowaclHeapGetSecurityAclSysattr(HeapTuple tuple)
{
	HeapTuple rtup;
	Oid		rowaclSid = InvalidOid;
	Oid		relowner;
	char	relkind;
	Datum	reloptions;
	bool	isnull;

	rtup = SearchSysCache(RELOID,
						  ObjectIdGetDatum(tuple->t_tableOid),
						  0, 0, 0);
	if (!HeapTupleIsValid(rtup))
		elog(ERROR, "cache lookup failed for relation %u", tuple->t_tableOid);

	relowner = ((Form_pg_class) GETSTRUCT(rtup))->relowner;
	relkind = ((Form_pg_class) GETSTRUCT(rtup))->relkind;
	reloptions = SysCacheGetAttr(RELOID, rtup,
								 Anum_pg_class_reloptions,
								 &isnull);
	if (!isnull)
	{
		StdRdOptions *RdOpts
			= (StdRdOptions *) heap_reloptions(relkind, reloptions, false);

		if (RdOpts && RdOpts->row_level_acl)
			rowaclSid = HeapTupleGetRowAcl(tuple);
	}

	ReleaseSysCache(rtup);

	return PointerGetDatum(rowaclSidToSecurityAcl(rowaclSid, relowner));
}

/******************************************************************
 * SQL functions
 ******************************************************************/

static Datum rowacl_grant_revoke(PG_FUNCTION_ARGS, bool grant, bool cascade)
{
	char *input, *tok, *sv = NULL;
	HeapTuple tuple;
	Acl *acl;
	Oid ownerid;
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

	ownerid = ((Form_pg_class) GETSTRUCT(tuple))->relowner;
	ReleaseSysCache(tuple);

    /*
     * Extract Acl array
     */
	acl = PG_GETARG_ACL_P(1);

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
			Oid roleid = get_roleid(tok);

			if (roleid == InvalidOid)
				ereport(ERROR,
						(errcode(ERRCODE_ROWACL_ERROR),
						 errmsg("%s is not a valid identifier", tok)));

			grantees = lappend_oid(grantees, roleid);
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
			privileges |= ROWACL_ALL_PRIVS;
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
					(errcode(ERRCODE_ROWACL_ERROR),
					 errmsg("%s is not a valid permission", tok)));
	}

	/*
	 * Merge ACL
	 */
	acl = merge_acl_with_grant(acl, grant, false, cascade,
							   grantees, privileges,
							   GetUserId(), ownerid);

	PG_RETURN_ACL_P(acl);
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
