/*
 * src/backend/rowacl/rowacl.c
 *   Row-level Database ACLs support
 *
 * Portions Copyright (c) 1996-2009, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 */
#include "postgres.h"

#include "catalog/pg_authid.h"
#include "catalog/pg_class.h"
#include "catalog/pg_security.h"
#include "catalog/pg_type.h"
#include "commands/defrem.h"
#include "miscadmin.h"
#include "nodes/nodeFuncs.h"
#include "parser/parsetree.h"
#include "security/rowacl.h"
#include "utils/fmgroids.h"
#include "utils/hsearch.h"
#include "utils/inval.h"
#include "utils/memutils.h"
#include "utils/rel.h"
#include "utils/syscache.h"


/******************************************************************
 * Mark appeared Query/Sub-Query
 ******************************************************************/

static void walkOnQueryTree(Query *query);

static bool
walkOnNodeTree(Node *node, Query *query)
{
	if (!node)
		return false;

	if (IsA(node, RangeTblRef))
	{
		RangeTblRef	   *rtr = (RangeTblRef *) node;
		RangeTblEntry  *rte = rt_fetch(rtr->rtindex, query->rtable);

		if (rte->rtekind == RTE_RELATION &&
			rtr->rtindex != query->resultRelation)
		{
			rte->tuplePerms |= ACL_SELECT;
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

	return expression_tree_walker(node, walkOnNodeTree, (void *) query);
}

static void
walkOnQueryTree(Query *query)
{
	RangeTblEntry *rte;

	if (query->commandType == CMD_UPDATE)
	{
		rte = rt_fetch(query->resultRelation, query->rtable);
		rte->tuplePerms |= ACL_UPDATE;
		if (query->returningList)
			rte->tuplePerms |= ACL_SELECT;
	}
	else if (query->commandType == CMD_DELETE)
	{
		rte = rt_fetch(query->resultRelation, query->rtable);
		rte->tuplePerms |= ACL_DELETE;
		if (query->returningList)
			rte->tuplePerms |= ACL_SELECT;
	}
	query_tree_walker(query, walkOnNodeTree, (void *) query, 0);
}

void
rowaclPostQueryRewrite(List *queryList)
{
	ListCell *l;

	foreach (l, queryList)
	{
		Query *query = (Query *) lfirst(l);

		Assert(IsA(query, Query));

		if (query->commandType == CMD_SELECT ||
			query->commandType == CMD_UPDATE ||
			query->commandType == CMD_INSERT ||
			query->commandType == CMD_DELETE)
			walkOnQueryTree(query);
	}
}

/******************************************************************
 * Cache boost row-level ACLs checks
 ******************************************************************/

static MemoryContext RowAclMemCtx;

#define ROWACL_CACHE_SLOT_NUM       128
static List *rowaclCacheSlot[ROWACL_CACHE_SLOT_NUM];

static void
rowaclCacheReset(void)
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

static int
rowaclCacheHash(Oid relid, Oid userid, Oid aclid)
{
	Oid keys[3] = { relid, userid, aclid };

	return tag_hash(keys, sizeof(keys)) % ROWACL_CACHE_SLOT_NUM;
}

static void
rowaclCacheInsert(Oid relid, Oid userid, Oid aclid, AclMode privs)
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

static bool
rowaclCacheLookup(Oid relid, Oid userid, Oid aclid, AclMode *privs)
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

void
rowaclInitialize(void)
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

static bool
rowaclCheckPermission(Relation rel, HeapTuple tuple,
					  AclMode required, bool abort)
{
	Oid relid = RelationGetRelid(rel);
	Oid ownerid = RelationGetForm(rel)->relowner;
	Oid userid = GetUserId();
	Oid aclid = HeapTupleGetRowAcl(tuple);
	AclMode privs;

	if (!rowaclCacheLookup(relid, userid, aclid, &privs))
	{
		/* Superusers/Owner bypass all permission checking */
		if (pg_class_ownercheck(RelationGetRelid(rel), userid))
			privs = ACL_ALL_RIGHTS_TUPLE;
		else
		{
			Acl	   *acl = securityTransRowAclOut(aclid, ownerid);

			privs = aclmask(acl, userid, ownerid,
							ACL_ALL_RIGHTS_TUPLE, ACLMASK_ALL);
		}
		rowaclCacheInsert(relid, userid, aclid, privs);
	}

	if ((privs & required) == required)
		return true;

	if (abort)
		ereport(ERROR,
				(errcode(ERRCODE_ROWACL_ERROR),
				 errmsg("access violation on Row-level ACLs")));

	return false;
}

bool
rowaclExecScan(Relation rel, HeapTuple tuple, AclMode required, bool abort)
{
	Assert((required & ACL_ALL_RIGHTS_TUPLE) == required);

	if (!required || !RelationGetRowLevelAcl(rel))
		return true;

	return rowaclCheckPermission(rel, tuple, required, abort);
}

bool
rowaclCopyToTuple(Relation rel, List *attNumList, HeapTuple tuple)
{
	if (!RelationGetRowLevelAcl(rel))
		return true;

	return rowaclCheckPermission(rel, tuple, ACL_SELECT, false);
}

/******************************************************************
 * Relation options
 ******************************************************************/

static char *
extractDefaultRowAcl(const char *defacl, Oid relowner)
{
	char   *result;
	int		i, len, ofs;

	for (i=0, len=1; defacl[i] != '\0'; i++)
	{
		if (defacl[i] == '%')
			len += NAMEDATALEN;
		else
			len++;
	}

	result = palloc0(len);
	for (i=0, ofs=0; defacl[i] != '\0'; i++)
	{
		if (defacl[i] == '%')
		{
			Form_pg_authid	authForm;
			HeapTuple		utup;
			int				code = defacl[++i];

			if (code == 'u')
			{
				utup = SearchSysCache(AUTHOID,
									  ObjectIdGetDatum(GetUserId()),
									  0, 0, 0);
				if (!HeapTupleIsValid(utup))
					elog(ERROR, "cache lookup failed for user: %u", GetUserId());

				authForm = (Form_pg_authid) GETSTRUCT(utup);
				strcpy(result + ofs, NameStr(authForm->rolname));
				ofs += strlen(NameStr(authForm->rolname));
				ReleaseSysCache(utup);
			}
			else if (code == 'o')
			{
				utup = SearchSysCache(AUTHOID,
									  ObjectIdGetDatum(relowner),
									  0, 0, 0);
				if (!HeapTupleIsValid(utup))
					elog(ERROR, "cache lookup failed for user: %u", relowner);

				authForm = (Form_pg_authid) GETSTRUCT(utup);
				strcpy(result + ofs, NameStr(authForm->rolname));
				ofs += strlen(NameStr(authForm->rolname));
				ReleaseSysCache(utup);
			}
			else
			{
				ereport(ERROR,
						(errcode(ERRCODE_ROWACL_ERROR),
						 errmsg("invalid replacement character '%c'", code)));
			}
		}
		else
			result[ofs++] = defacl[i];
	}

	return result;
}

void
rowaclValidateDefaultRowAclRelopt(char *value)
{
	FmgrInfo	finfo;
	Datum		acldat;
	char	   *defacl = extractDefaultRowAcl(value, GetUserId());

	/*
	 * If given default row-acl in reloptions is not valid,
	 * aclitemin can raise an error.
	 */
	fmgr_info(F_ARRAY_IN, &finfo);
	acldat = FunctionCall3(&finfo,
						   CStringGetDatum(defacl),
						   ObjectIdGetDatum(ACLITEMOID),
						   Int32GetDatum(-1));
	pfree(DatumGetAclP(acldat));
	pfree(defacl);
}

/*
 * rowaclTupleDescHasRowAcl()
 *   returns availability of Row-level ACLs in the given relation.
 */
bool
rowaclTupleDescHasRowAcl(Relation rel)
{
	return RelationGetRowLevelAcl(rel);
}

/*
 * rowaclInterpretRowAclOption()
 *   returns availability of Row-level ACLs in newly generated
 *   relation via SELECT INTO statement. Because its Relation
 *   structure is not available when we need to make a decision
 *   whether TupleDesc->tdhasrowacl is true, or false.
 */
bool
rowaclInterpretRowAclOption(List *relopts)
{
	ListCell   *l;

	foreach (l, relopts)
	{
		DefElem	   *def = (DefElem *) lfirst(l);

		if (pg_strcasecmp(def->defname, "row_level_acl") == 0)
			return defGetBoolean(def);
	}

	return false;
}

/******************************************************************
 * Hooks for heap_(insert|update|delete)
 ******************************************************************/
bool
rowaclHeapTupleInsert(Relation rel, HeapTuple newtup, bool internal)
{
	if (!HeapTupleHasRowAcl(newtup))
		return true;

	if (OidIsValid(HeapTupleGetRowAcl(newtup)))
	{
		if (RelationGetForm(rel)->relkind != RELKIND_RELATION)
			ereport(ERROR,
					(errcode(ERRCODE_ROWACL_ERROR),
					 errmsg("Only normal relation can have Row-level ACLs")));
		if (!internal &&
			!pg_class_ownercheck(RelationGetRelid(rel), GetUserId()))
			ereport(ERROR,
					(errcode(ERRCODE_ROWACL_ERROR),
					 errmsg("Only owner or superuser can set ACLs")));
	}
	else
	{
		char   *defacl = RelationGetDefaultRowAcl(rel);

		if (defacl)
		{
			FmgrInfo	finfo;
			Datum		aclDat;
			Oid			secid;
			Oid			relowner = RelationGetForm(rel)->relowner;

			defacl = extractDefaultRowAcl(defacl, relowner);
			fmgr_info(F_ARRAY_IN, &finfo);
			aclDat = FunctionCall3(&finfo,
								   CStringGetDatum(defacl),
								   ObjectIdGetDatum(ACLITEMOID),
								   Int32GetDatum(-1));
			secid = securityTransRowAclIn(DatumGetAclP(aclDat));
			HeapTupleSetRowAcl(newtup, secid);
		}
		/*
		 * When no default ACLs are not configured but row_level_acl
		 * on the relation is activated, we keep it as InvalidOid.
		 * If no ACLs are set, it is dealt as default one which allows
		 * public to do anything.
		 */
	}

	return true;
}

bool
rowaclHeapTupleUpdate(Relation rel, HeapTuple oldtup, HeapTuple newtup, bool internal)
{
	if (!HeapTupleHasRowAcl(newtup))
		return true;

	if (!OidIsValid(HeapTupleGetRowAcl(newtup)))
	{
		/* preserve old one */
		HeapTupleSetRowAcl(newtup, HeapTupleGetRowAcl(oldtup));
	}
	else if (HeapTupleGetRowAcl(newtup) != HeapTupleGetRowAcl(oldtup))
	{
		if (!internal &&
			!pg_class_ownercheck(RelationGetRelid(rel), GetUserId()))
			ereport(ERROR,
					(errcode(ERRCODE_ROWACL_ERROR),
					 errmsg("Only owner or superuser can set ACLs")));
	}
	return true;
}

bool
rowaclHeapTupleDelete(Relation rel, HeapTuple oldtup, bool internal)
{
	/*
	 * No need to do anything here
	 */
	return true;
}
