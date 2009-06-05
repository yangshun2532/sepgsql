/*
 * src/backend/rowacl/rowacl.c
 *   Row-level Database ACLs support
 *
 * Portions Copyright (c) 1996-2009, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 */
#include "postgres.h"

#include "access/heapam.h"
#include "catalog/pg_authid.h"
#include "catalog/pg_class.h"
#include "catalog/pg_security.h"
#include "catalog/pg_type.h"
#include "commands/defrem.h"
#include "miscadmin.h"
#include "nodes/nodeFuncs.h"
#include "parser/parsetree.h"
#include "security/rowacl.h"
#include "utils/builtins.h"
#include "utils/fmgroids.h"
#include "utils/hsearch.h"
#include "utils/inval.h"
#include "utils/memutils.h"
#include "utils/rel.h"
#include "utils/syscache.h"

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
bool
rowaclExecScan(Relation rel, HeapTuple tuple, uint32 required, bool abort)
{
	Oid		relid;
	Oid		ownerid;
	Oid		userid;
	Oid		aclid;
	AclMode	privs;

	if (!RelationGetRowLevelAcl(rel) || !required)
		return true;

	relid = RelationGetRelid(rel);
	ownerid = RelationGetForm(rel)->relowner;
	userid = GetUserId();
	aclid = HeapTupleGetRowAcl(tuple);

	if (!rowaclCacheLookup(relid, userid, aclid, &privs))
	{
		/* Superusers/Owner bypass all permission checking */
		if (pg_class_ownercheck(RelationGetRelid(rel), userid))
			privs = ACL_ALL_RIGHTS_TUPLE;
		else
		{
			Acl	   *acl = securityTransRowAclOut(relid, aclid, ownerid);

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
				 errmsg("Access violation at Row-level ACLs")));

	return false;
}

uint32
rowaclSetupTuplePerms(RangeTblEntry *rte)
{
	AclMode		mask = (ACL_SELECT | ACL_UPDATE | ACL_DELETE);
	Relation	relation;

	if (rte->rtekind != RTE_RELATION)
		return 0;

	/*
	 * we need not lock the relation since it was already locked.
	 * If the row_level_acl reloption is disabled, we don't need
	 * to apply row-level acls on the relation.
	 */
	relation = heap_open(rte->relid, NoLock);

	if (!RelationGetRowLevelAcl(relation))
		mask = 0;

	heap_close(relation, NoLock);

	return rte->requiredPerms & mask;
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
rowaclReloptDefaultRowAcl(char *value)
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
			Oid			relid = RelationGetRelid(rel);
			Oid			ownid = RelationGetForm(rel)->relowner;

			defacl = extractDefaultRowAcl(defacl, ownid);
			fmgr_info(F_ARRAY_IN, &finfo);
			aclDat = FunctionCall3(&finfo,
								   CStringGetDatum(defacl),
								   ObjectIdGetDatum(ACLITEMOID),
								   Int32GetDatum(-1));
			secid = securityTransRowAclIn(relid, DatumGetAclP(aclDat));
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

/******************************************************************
 * Row-Acl input/output handler
 ******************************************************************/
char *
rowaclTransRowAclIn(Acl *acl)
{
	AclItem	   *aip = ACL_DAT(acl);
	char	   *secacl = palloc0(ACL_NUM(acl) * 30 + 10);
	int			i, ofs = 0;

	for (i=0; i < ACL_NUM(acl); i++)
	{
		if ((aip[i].ai_privs & ACL_ALL_RIGHTS_TUPLE) != aip[i].ai_privs)
			ereport(ERROR,
					(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
					 errmsg("unsupported row level privileges: %04x",
							aip[i].ai_privs & ~ACL_ALL_RIGHTS_TUPLE)));
		ofs += sprintf(secacl + ofs, "%s%x=%x/%x",
					   (i == 0 ? "" : ","),
					   aip[i].ai_grantee,
					   aip[i].ai_privs,
					   aip[i].ai_grantor);
	}

	return secacl;
}

Acl *
rowaclTransRowAclOut(char *secacl)
{
	Acl		   *acl = NULL;
	AclItem	   *aip;
	char	   *copy, *tok, *sv = NULL;
	int			index = 0;

	if (!secacl)
		return NULL;	/* fallback to default acl */

	aip = palloc(strlen(secacl) * sizeof(AclItem) / 4);
	copy = pstrdup(secacl);

	for (tok = strtok_r(copy, ",", &sv);
		 tok;
		 tok = strtok_r(NULL, ",", &sv))
	{
		if (sscanf(tok, "%x=%x/%x",
				   &aip[index].ai_grantee,
				   &aip[index].ai_privs,
				   &aip[index].ai_grantor) != 3)
			goto out;
		index++;
	}

	if (index > 0)
	{
		acl = allocacl(index);
		memcpy(ACL_DAT(acl), aip, index * sizeof(AclItem));
	}
out:
	pfree(aip);
	pfree(copy);

	return acl;
}

Datum
rowacl_acl_to_internal(PG_FUNCTION_ARGS)
{
	Acl	   *acl = PG_GETARG_ACL_P(0);
	char   *secacl = rowaclTransRowAclIn(acl);

	PG_RETURN_TEXT_P(CStringGetTextDatum(secacl));
}

Datum
rowacl_internal_to_acl(PG_FUNCTION_ARGS)
{
	char   *secacl = TextDatumGetCString(PG_GETARG_TEXT_P(0));
	Acl	   *acl = rowaclTransRowAclOut(secacl);

	if (!acl)
		PG_RETURN_NULL();

	PG_RETURN_ACL_P(acl);
}
