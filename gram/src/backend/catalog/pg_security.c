/*
 * src/backend/catalog/pg_security.c
 *    routines to support security label management
 *
 * Portions Copyright (c) 1996-2009, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 */
#include "postgres.h"

#include "access/genam.h"
#include "access/heapam.h"
#include "access/xact.h"
#include "catalog/catalog.h"
#include "catalog/indexing.h"
#include "catalog/pg_security.h"
#include "catalog/pg_shsecurity.h"
#include "miscadmin.h"
#include "security/sepgsql.h"
#include "utils/builtins.h"
#include "utils/fmgroids.h"
#include "utils/memutils.h"
#include "utils/rel.h"
#include "utils/syscache.h"
#include "utils/tqual.h"

bool
securityTupleDescHasRowAcl(Relation rel)
{
	/*
	 * TODO: check "row_level_acl" reloption here
	 */
	return false;
}

bool
securityTupleDescHasSecLabel(Relation rel)
{
	return sepgsqlTupleDescHasSecLabel(rel);
}

static char *
securityMetaSecurityLabel(bool shared)
{
	/*
	 * It returns the security label of tuples within
	 * pg_security system catalog
	 */
	return NULL;
}

/*
 * security attribute management at the initdb phase.
 */
typedef struct earlySecAttr
{
	struct earlySecAttr	   *next;
	Oid		relid;
	Oid		secid;
	char	seckind;
	char	secattr[1];
} earlySecAttr;

static earlySecAttr *earlySecAttrList = NULL;

static Oid
earlyInputSecurityAttr(Oid relid, char seckind, const char *secattr)
{
	static Oid		dummySecid = SharedSecurityRelationId;
	earlySecAttr   *es;

	for (es = earlySecAttrList; es; es = es->next)
	{
		if (es->relid == relid &&
			es->seckind == seckind &&
			strcmp(es->secattr, secattr) == 0)
			return es->secid;
	}
	/* Not found */
	es = MemoryContextAlloc(TopMemoryContext,
							sizeof(*es) + strlen(secattr));
	es->relid = relid;
	es->secid = --dummySecid;
	es->seckind = seckind;
	strcpy(es->secattr, secattr);

	es->next = earlySecAttrList;
	earlySecAttrList = es;

	return es->secid;
}

static char *
earlyOutputSecurityAttr(Oid relid, char seckind, Oid secid)
{
	earlySecAttr   *es;

	for (es = earlySecAttrList; es; es = es->next)
	{
		if (es->relid == relid &&
			es->seckind == seckind &&
			es->secid == secid)
			return pstrdup(es->secattr);
	}
	return NULL;	/* Not found */
}

void
securityPostBootstrapingMode(void)
{
	Relation			lorel, shrel;
	CatalogIndexState	loind, shind;
	earlySecAttr	   *es;
	char			   *meta_label;
	Oid					meta_lo_secid = InvalidOid;
	Oid					meta_sh_secid = InvalidOid;

	if (!earlySecAttrList)
		return;		/* do nothing */

	StartTransactionCommand();

	/* security_label on the pg_security */
	meta_label = securityMetaSecurityLabel(false);
	if (meta_label)
		meta_lo_secid = securityTransSecLabelIn(SecurityRelationId, meta_label);

	/* security_label on the pg_shsecurity */
	meta_label = securityMetaSecurityLabel(true);
	if (meta_label)
		meta_sh_secid = securityTransSecLabelIn(SharedSecurityRelationId, meta_label);

	lorel = heap_open(SecurityRelationId, RowExclusiveLock);
	loind = CatalogOpenIndexes(lorel);

	shrel = heap_open(SharedSecurityRelationId, RowExclusiveLock);
	shind = CatalogOpenIndexes(shrel);

	for (es = earlySecAttrList; es; es = es->next)
	{
		HeapTuple	tuple;

		if (!IsSharedRelation(es->relid))
		{
			Datum	values[Natts_pg_security];
			bool	nulls[Natts_pg_security];

			memset(nulls, false, sizeof(nulls));
			values[Anum_pg_security_relid - 1] = ObjectIdGetDatum(es->relid);
			values[Anum_pg_security_seckind - 1] = CharGetDatum(es->seckind);
			values[Anum_pg_security_secattr - 1] = CStringGetTextDatum(es->secattr);

			tuple = heap_form_tuple(RelationGetDescr(lorel), values, nulls);
			HeapTupleSetOid(tuple, es->secid);
			if (HeapTupleHasSecLabel(tuple))
				HeapTupleSetSecLabel(tuple, meta_lo_secid);

			simple_heap_insert(lorel, tuple);
			CatalogIndexInsert(loind, tuple);
		}
		else
		{
			Datum	values[Natts_pg_shsecurity];
			bool	nulls[Natts_pg_shsecurity];

			memset(nulls, false, sizeof(nulls));
			values[Anum_pg_shsecurity_relid - 1] = ObjectIdGetDatum(es->relid);
			values[Anum_pg_shsecurity_seckind - 1] = CharGetDatum(es->seckind);
			values[Anum_pg_shsecurity_secattr - 1] = CStringGetTextDatum(es->secattr);

			tuple = heap_form_tuple(RelationGetDescr(shrel), values, nulls);
			HeapTupleSetOid(tuple, es->secid);
			if (HeapTupleHasSecLabel(tuple))
				HeapTupleSetSecLabel(tuple, meta_sh_secid);

			simple_heap_insert(shrel, tuple);
			CatalogIndexInsert(shind, tuple);
		}

		heap_freetuple(tuple);
	}

	CatalogCloseIndexes(shind);
	heap_close(shrel, RowExclusiveLock);

	CatalogCloseIndexes(loind);
	heap_close(lorel, RowExclusiveLock);

	CommitTransactionCommand();
}

/*
 * InputSecurityAttr
 */
static Oid
InputSecurityAttr(Oid relid, char seckind, const char *secattr)
{
	Relation		rel;
	CatalogIndexState	ind;
	HeapTuple		tuple;
	int				cacheId;
	Oid				sec_relid;
	Oid				sec_oid;
	char		   *meta_label;
	Oid				meta_secid = InvalidOid;
	bool			shared = IsSharedRelation(relid);
	Datum			values[Natts_pg_security];
	bool			nulls[Natts_pg_security];

	if (IsBootstrapProcessingMode())
		return earlyInputSecurityAttr(relid, seckind, secattr);

	/*
	 * Lookup the syscache first
	 */
	cacheId = (!shared ? SECURITYATTR : SHSECURITYATTR);
	tuple = SearchSysCache(cacheId,
						   ObjectIdGetDatum(relid),
						   CharGetDatum(seckind),
						   CStringGetTextDatum(secattr),
						   0);
	if (HeapTupleIsValid(tuple))
	{
		sec_oid = HeapTupleGetOid(tuple);

		ReleaseSysCache(tuple);

		return sec_oid;
	}

	/*
	 * Insert a new tuple, if not found
	 */
	sec_relid = (!shared ? SecurityRelationId
						 : SharedSecurityRelationId);
	rel = heap_open(sec_relid, RowExclusiveLock);
	ind = CatalogOpenIndexes(rel);

	sec_oid = GetNewOid(rel);

	/*
	 * set up security context of itself
	 */
	meta_label = securityMetaSecurityLabel(shared);
	if (meta_label != NULL)
	{
		/*
		 * NOTE: when the meta_label refers itself, no need to
		 * assign sec_oid anymore. This check is necessary to
		 * avoid infinite invocations.
		 */
		if (sec_relid == relid &&
			seckind == SECKIND_SECURITY_LABEL &&
			strcmp(meta_label, secattr) == 0)
			meta_secid = sec_oid;
		else
			meta_secid = securityTransSecLabelIn(sec_relid, meta_label);
	}

	memset(nulls, false, sizeof(nulls));
	values[Anum_pg_security_relid - 1] = ObjectIdGetDatum(relid);
	values[Anum_pg_security_seckind - 1] = CharGetDatum(seckind);
	values[Anum_pg_security_secattr - 1] = CStringGetTextDatum(secattr);

	tuple = heap_form_tuple(RelationGetDescr(rel), values, nulls);

	HeapTupleSetOid(tuple, sec_oid);
	if (HeapTupleHasSecLabel(tuple))
		HeapTupleSetSecLabel(tuple, meta_secid);

	simple_heap_insert(rel, tuple);

	CatalogIndexInsert(ind, tuple);

	/*
	 * NOTE:
	 * We also need to insert the new tuple into the system cache
	 * for temporary usage.
	 * When user tries to apply same security attribute twice or
	 * more within a single command id, it cannot determine whether
	 * the given security attribute is already inserted, or not.
	 *
	 * The cache entry shall be invalidated on the next
	 * CommandIdIncrement(). The purpose of InsertSysCache() is
	 * to prevent duplicate insertion (and undesirable error).
	 */
	InsertSysCache(RelationGetRelid(rel), tuple);

	CatalogCloseIndexes(ind);

	heap_close(rel, RowExclusiveLock);

	return sec_oid;
}

static char *
OutputSecurityAttr(Oid relid, char seckind, Oid secid)
{
	bool		shared = IsSharedRelation(relid);
	int			cacheId = (!shared ? SECURITYSECID : SHSECURITYSECID);
	HeapTuple	tuple;
	Datum		datum;
	bool		isnull;
	char	   *result;

	if (IsBootstrapProcessingMode())
		return earlyOutputSecurityAttr(relid, seckind, secid);

	tuple = SearchSysCache(cacheId,
						   ObjectIdGetDatum(secid),
						   0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		return NULL;

	/* Integrity checks */
	datum = SysCacheGetAttr(cacheId, tuple,
							Anum_pg_security_relid,
							&isnull);
	if (isnull || DatumGetObjectId(datum) != relid)
		goto error;

	datum = SysCacheGetAttr(cacheId, tuple,
							Anum_pg_security_seckind,
							&isnull);
	if (isnull || DatumGetChar(datum) != seckind)
		goto error;

	/* Fetch security attribute */
	datum = SysCacheGetAttr(cacheId, tuple,
							Anum_pg_security_secattr,
							&isnull);
	if (isnull)
		goto error;

	result = TextDatumGetCString(datum);

	ReleaseSysCache(tuple);

	return result;

error:
	ReleaseSysCache(tuple);
	return NULL;
}

/*
 * input/output handler
 */
Oid
securityRawSecLabelIn(Oid relid, char *seclabel)
{
	seclabel = sepgsqlRawSecLabelIn(seclabel);

	return InputSecurityAttr(relid, SECKIND_SECURITY_LABEL, seclabel);
}

char *
securityRawSecLabelOut(Oid relid, Oid secid)
{
	char *seclabel = OutputSecurityAttr(relid, SECKIND_SECURITY_LABEL, secid);

	return sepgsqlRawSecLabelOut(seclabel);
}

Oid
securityTransSecLabelIn(Oid relid, char *seclabel)
{
	seclabel = sepgsqlTransSecLabelIn(seclabel);

	return securityRawSecLabelIn(relid, seclabel);
}

char *
securityTransSecLabelOut(Oid relid, Oid secid)
{
	char *seclabel = securityRawSecLabelOut(relid, secid);

	return sepgsqlTransSecLabelOut(seclabel);
}

Oid
securityTransRowAclIn(Oid relid, Acl *acl)
{
	char   *secacl = NULL;

	return InputSecurityAttr(relid, SECKIND_SECURITY_ACL, secacl);
}

Acl *
securityTransRowAclOut(Oid relid, Oid secid, Oid ownid)
{
	char   *secacl = OutputSecurityAttr(relid, SECKIND_SECURITY_ACL, secid);
	Acl	   *acl = NULL;

	if (!acl)
		acl = acldefault(ACL_OBJECT_TUPLE, ownid);

	return acl;
}

/*
 * Output handler for system columns
 */
Datum
securityHeapGetRowAclSysattr(HeapTuple tuple)
{
	HeapTuple	reltup;
	Oid			secid = HeapTupleGetRowAcl(tuple);
	Oid			ownid;
	Acl		   *acl;

	reltup = SearchSysCache(RELOID,
							ObjectIdGetDatum(tuple->t_tableOid),
							0, 0, 0);
	if (!HeapTupleIsValid(reltup))
		elog(ERROR, "cache lookup failed for relation: %u", tuple->t_tableOid);

	ownid = ((Form_pg_class) GETSTRUCT(reltup))->relowner;

	ReleaseSysCache(reltup);

	acl = securityTransRowAclOut(tuple->t_tableOid, secid, ownid);

	return PointerGetDatum(acl);
}

Datum
securityHeapGetSecLabelSysattr(HeapTuple tuple)
{
	Oid		secid = HeapTupleGetSecLabel(tuple);
	char   *seclabel;

	seclabel = securityTransSecLabelOut(tuple->t_tableOid, secid);
	if (!seclabel)
		seclabel = pstrdup("unlabeled");

	return CStringGetTextDatum(seclabel);
}
