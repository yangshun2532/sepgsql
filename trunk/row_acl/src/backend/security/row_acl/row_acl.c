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
#include "pgstat.h"
#include "security/pgace.h"
#include "storage/bufmgr.h"
#include "utils/acl.h"
#include "utils/array.h"
#include "utils/fmgroids.h"
#include "utils/syscache.h"

bool rowaclIsEnabled(void)
{
	return true;
}

/******************************************************************
 * Row-level access controls
 ******************************************************************/
List *rowaclProxyQuery(List *queryList)
{
	return queryList;
}

bool rowaclExecScan(Scan *scan, Relation rel, TupleTableSlot *slot)
{
	return true;
}

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
			Form_pg_class class_form = (Form_pg_class) tuple;

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
			Form_pg_class class_form = (Form_pg_class) newtup;

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

bool rowaclCopyToTuple(Relation rel, List *attNumList, HeapTuple tuple)
{
	return true;
}

void rowaclBeginPerformCheckFK(Relation rel, bool rel_is_primary, Datum *save_pgace)
{

}

void rowaclEndPerformCheckFK(Relation rel, bool rel_is_primary, Datum save_pgace)
{

}

/******************************************************************
 * Default ACL support
 ******************************************************************/

DefElem *rowaclGramSecurityItem(char *defname, char *value)
{
	return NULL;
}

bool rowaclIsGramSecurityItem(DefElem *defel)
{
	return false;
}

void rowaclGramCreateRelation(Relation rel, HeapTuple tuple, DefElem *defel)
{}

void rowaclGramAlterRelation(Relation rel, HeapTuple tuple, DefElem *defel)
{}

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
