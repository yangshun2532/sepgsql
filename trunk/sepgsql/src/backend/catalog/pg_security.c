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
#include "access/sysattr.h"
#include "access/xact.h"
#include "catalog/catalog.h"
#include "catalog/indexing.h"
#include "catalog/pg_proc.h"
#include "catalog/pg_security.h"
#include "catalog/pg_shsecurity.h"
#include "catalog/pg_type.h"
#include "executor/spi.h"
#include "miscadmin.h"
#include "security/rowacl.h"
#include "security/sepgsql.h"
#include "utils/builtins.h"
#include "utils/fmgroids.h"
#include "utils/memutils.h"
#include "utils/rel.h"
#include "utils/lsyscache.h"
#include "utils/syscache.h"
#include "utils/tqual.h"

bool
securityTupleDescHasRowAcl(Relation rel)
{
	return RelationGetRowLevelAcl(rel);
}

bool
securityTupleDescHasSecLabel(Relation rel)
{
	return sepgsqlTupleDescHasSecLabel(rel);
}

static char *
securityMetaSecurityLabel(bool shared)
{
	return sepgsqlMetaSecurityLabel(shared);
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
	char   *secacl = rowaclTransRowAclIn(acl);

	return InputSecurityAttr(relid, SECKIND_SECURITY_ACL, secacl);
}

Acl *
securityTransRowAclOut(Oid relid, Oid secid, Oid ownid)
{
	char   *secacl = OutputSecurityAttr(relid, SECKIND_SECURITY_ACL, secid);
	Acl	   *acl = rowaclTransRowAclOut(secacl);

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

/*
 * securityReclaimOnDropTable
 *   drop orphan entries within pg_security on drop table
 */
void
securityReclaimOnDropTable(Oid relid)
{
	Oid				srelId;
	Oid				sindId;
	Relation		srel;
	SysScanDesc		sscan;
	ScanKeyData		key[1];
	HeapTuple		tuple;

	if (!IsSharedRelation(relid))
	{
		srelId = SecurityRelationId;
		sindId = SecuritySecattrIndexId;
	}
	else
	{
		srelId = SharedSecurityRelationId;
		sindId = SharedSecuritySecattrIndexId;
	}

	/*
	 * reclaim all the entries with pg_security.relid == relid
	 */
	ScanKeyInit(&key[0],
				Anum_pg_security_relid,
				BTEqualStrategyNumber, F_OIDEQ,
				ObjectIdGetDatum(relid));

	srel = heap_open(srelId, RowExclusiveLock);
	sscan = systable_beginscan(srel, sindId, true,
							   SnapshotNow, 1, key);
	while (HeapTupleIsValid(tuple = systable_getnext(sscan)))
	{
		Datum	datum;
		bool	isnull;

		datum = heap_getattr(tuple,
							 Anum_pg_security_secattr,
							 RelationGetDescr(srel),
							 &isnull);
		Assert(!isnull);

		elog(NOTICE, "%s: \"%s\" is reclaimed",
			 __FUNCTION__, TextDatumGetCString(datum));

		simple_heap_delete(srel, &tuple->t_self);
	}

	systable_endscan(sscan);

	heap_close(srel, RowExclusiveLock);
}

/*
 * security_quote_relation
 *   returns palloc'de identifier with explicit namespace
 */
static char *
security_quote_relation(Oid relid)
{
	Oid		nspoid = get_rel_namespace(relid);
	char   *nspname;
	char   *relname;

	nspname = get_namespace_name(nspoid);
	relname = get_rel_name(relid);

	return quote_qualified_identifier(nspname, relname);
}

/*
 * security_reclaim_table
 *   reclaims orphan entries associated to a certain table
 */
static int
security_reclaim_table(Oid relid, char seckind)
{
	StringInfoData	query;
	SPIPlanPtr		plan;
	Oid				types[2];
	Datum			values[2];
	int				index;
	Oid				sec_relid;
	Oid				proc_oid;
	char		   *relname_full;
	char		   *attname_relid;
	char		   *attname_seckind;
	char		   *attname_oid;
	char		   *attname_secattr;
	char		   *sec_proname;
	char		   *sec_nspname;
	Form_pg_proc	proForm;
	HeapTuple		protup;

	/*
	 * LOCK the target table
	 */
	initStringInfo(&query);
	relname_full = security_quote_relation(relid);
	appendStringInfo(&query, "LOCK %s IN SHARE MODE", relname_full);
	if (SPI_execute(query.data, false, 0) != SPI_OK_UTILITY)
		elog(ERROR, "SPI_execute failed on %s", query.data);

	/*
	 * DELETE orphan entries
	 */
	initStringInfo(&query);

	sec_relid = (!IsSharedRelation(relid)
				 ? SecurityRelationId : SharedSecurityRelationId);
	attname_relid = get_attname(sec_relid, Anum_pg_security_relid);
	attname_seckind = get_attname(sec_relid, Anum_pg_security_seckind);
	attname_oid = get_attname(sec_relid, ObjectIdAttributeNumber);
	attname_secattr = get_attname(sec_relid, Anum_pg_security_secattr);

	appendStringInfo(&query,
					 "DELETE FROM %s WHERE %s = $1 AND %s = $2 AND %s NOT IN ",
					 security_quote_relation(sec_relid),
					 quote_identifier(attname_relid),
					 quote_identifier(attname_seckind),
					 quote_identifier(attname_oid));
	switch (seckind)
	{
	case SECKIND_SECURITY_LABEL:
		proc_oid = F_SECURITY_LABEL_TO_SECID;
		break;
	case SECKIND_SECURITY_ACL:
		proc_oid = F_SECURITY_ACL_TO_SECID;
		break;
	default:
		elog(ERROR, "unexpected seckind: %c", seckind);
		proc_oid = InvalidOid;	/* to compiler silent */
		break;
	}

	protup = SearchSysCache(PROCOID,
							ObjectIdGetDatum(proc_oid),
							0, 0, 0);
	if (!HeapTupleIsValid(protup))
		elog(ERROR, "cache lookup failed for procedure: %u", proc_oid);
	proForm = (Form_pg_proc) GETSTRUCT(protup);
	sec_proname = NameStr(proForm->proname);
	sec_nspname = get_namespace_name(proForm->pronamespace);

	appendStringInfo(&query,
					 "(SELECT %s.%s(%s) FROM ONLY %s) "
					 "RETURNING %s,%s",
					 quote_identifier(sec_nspname),
					 quote_identifier(sec_proname),
					 quote_identifier(get_rel_name(relid)),
					 relname_full,
					 quote_identifier(attname_oid),
					 quote_identifier(attname_secattr));
	ReleaseSysCache(protup);

	/*
	 * Setup and execute query
	 */
	types[0] = OIDOID;
	types[1] = CHAROID;
	plan = SPI_prepare(query.data, 2, types);
	if (!plan)
		elog(ERROR, "SPI_prepare failed on %s", query.data);

	values[0] = ObjectIdGetDatum(relid);
	values[1] = CharGetDatum(seckind);
	if (SPI_execute_plan(plan, values, NULL, false, 0) != SPI_OK_DELETE_RETURNING)
		elog(ERROR, "SPI_execute_plan failed on %s", query.data);

	for (index = 0; index < SPI_processed; index++)
	{
		char   *recl_secid;
		char   *recl_secattr;

		recl_secid = SPI_getvalue(SPI_tuptable->vals[index],
								  SPI_tuptable->tupdesc, 1);
		recl_secattr = SPI_getvalue(SPI_tuptable->vals[index],
									SPI_tuptable->tupdesc, 2);
		ereport(NOTICE,
				(errmsg("secattr=\"%s\", secid=%s on %s was reclaimed",
						recl_secattr, recl_secid, security_quote_relation(relid))));
	}

	SPI_freetuptable(SPI_tuptable);

	return SPI_processed;
}

static int
security_reclaim_all_tables(char seckind)
{
	StringInfoData	query;
	char	   *attname;
	int			index;
	Datum		datum;
	bool		isnull;
	int			count = 0;
	List	   *relidList = NIL;
	ListCell   *l;

	initStringInfo(&query);

	attname = get_attname(SecurityRelationId, Anum_pg_security_relid);
	appendStringInfo(&query,
					 "SELECT DISTINCT %s FROM %s",
					 quote_identifier(attname),
					 security_quote_relation(SecurityRelationId));

	appendStringInfo(&query, " UNION ");

	attname = get_attname(SharedSecurityRelationId, Anum_pg_shsecurity_relid);
	appendStringInfo(&query,
					 "SELECT DISTINCT %s FROM %s",
					 quote_identifier(attname),
					 security_quote_relation(SharedSecurityRelationId));

	if (SPI_execute(query.data, true, 0) != SPI_OK_SELECT)
		elog(ERROR, "SPI_execute failed on %s", query.data);

	for (index = 0; index < SPI_processed; index++)
	{
		datum = SPI_getbinval(SPI_tuptable->vals[index],
							  SPI_tuptable->tupdesc, 1, &isnull);
		if (isnull)
			continue;
		relidList = lappend_oid(relidList, DatumGetObjectId(datum));
	}
	SPI_freetuptable(SPI_tuptable);

	foreach (l, relidList)
		count += security_reclaim_table(lfirst_oid(l), seckind);

	return count;
}

static int
security_reclaim(Oid relid, char seckind)
{
	bool		sepgsql_saved;
	int			count;

	if (!superuser())
		ereport(ERROR,
				(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
				 errmsg("must be superuser to reclaim security attributes")));
	/*
	 * Disable SE-PostgreSQL temporary
	 */
	sepgsql_saved = sepgsqlSetExceptionMode(true);

	PG_TRY();
	{
		if (SPI_connect() != SPI_OK_CONNECT)
			elog(ERROR, "SPI_connect failed");

		if (OidIsValid(relid))
			count = security_reclaim_table(relid, seckind);
		else
			count = security_reclaim_all_tables(seckind);

		if (SPI_finish() != SPI_OK_FINISH)
			elog(ERROR, "SPI_finish failed");
	}
	PG_CATCH();
	{
		sepgsqlSetExceptionMode(sepgsql_saved);
		PG_RE_THROW();
	}
	PG_END_TRY();

	sepgsqlSetExceptionMode(sepgsql_saved);

	return count;
}

Datum
security_reclaim_acl(PG_FUNCTION_ARGS)
{
	PG_RETURN_INT32(security_reclaim(InvalidOid, SECKIND_SECURITY_ACL));
}

Datum
security_reclaim_table_acl(PG_FUNCTION_ARGS)
{
	PG_RETURN_INT32(security_reclaim(PG_GETARG_OID(0), SECKIND_SECURITY_ACL));
}

Datum
security_reclaim_label(PG_FUNCTION_ARGS)
{
	PG_RETURN_INT32(security_reclaim(InvalidOid, SECKIND_SECURITY_LABEL));
}

Datum
security_reclaim_table_label(PG_FUNCTION_ARGS)
{
	PG_RETURN_INT32(security_reclaim(PG_GETARG_OID(0), SECKIND_SECURITY_LABEL));
}

Datum
security_acl_to_secid(PG_FUNCTION_ARGS)
{
	HeapTupleHeader	tuphdr = PG_GETARG_HEAPTUPLEHEADER(0);

	PG_RETURN_OID(HeapTupleHeaderGetRowAcl(tuphdr));
}

Datum
security_label_to_secid(PG_FUNCTION_ARGS)
{
	HeapTupleHeader tuphdr = PG_GETARG_HEAPTUPLEHEADER(0);

	PG_RETURN_OID(HeapTupleHeaderGetSecLabel(tuphdr));
}
