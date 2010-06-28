/*
 * label.c
 *
 * It provides security label support in SELinux
 *
 * Author: KaiGai Kohei <kaigai@ak.jp.nec.com>
 *
 * Copyright (c) 2007 - 2010, NEC Corporation
 * Copyright (c) 2006 - 2007, KaiGai Kohei <kaigai@kaigai.gr.jp>
 */
#include "postgres.h"

#include "access/heapam.h"
#include "access/genam.h"
#include "catalog/catalog.h"
#include "catalog/indexing.h"
#include "catalog/pg_description.h"
#include "catalog/pg_shdescription.h"
#include "libpq/libpq-be.h"
#include "miscadmin.h"
#include "utils/builtins.h"
#include "utils/fmgroids.h"
#include "utils/rel.h"
#include "utils/tqual.h"

#include "sepgsql.h"

static security_context_t	client_label = NULL;

/*
 * sepgsql_get_client_label
 *
 * It returns security label of the client.
 */
char *
sepgsql_get_client_label(void)
{
	if (!client_label)
	{
		int		old_mode;

		/*
		 * Get peer's security context
		 */
		if (getpeercon_raw(MyProcPort->sock, &client_label) < 0)
			ereport(FATAL,
					(errcode(ERRCODE_INTERNAL_ERROR),
					 errmsg("SELinux: unable to get security label of the peer")));
		/*
		 * Set the working mode to DEFAULT from INTERNAL
		 */
		old_mode = sepgsql_set_mode(SEPGSQL_MODE_DEFAULT);
		Assert(old_mode == SEPGSQL_MODE_INTERNAL);
	}
	return client_label;
}

/*
 * sepgsql_set_client_label
 *
 * It allows to set a new security label of the client. It also returns
 * the older label, so the caller has to restore it correctly.
 */
char *
sepgsql_set_client_label(char *new_label)
{
	char   *old_label = client_label;

	client_label = new_label;

	return old_label;
}

/*
 * sepgsql_get_unlabeled_label
 *
 * It returns system's "unlabeled" security label.
 */
char *
sepgsql_get_unlabeled_label(void)
{
	security_context_t	unlabeled;
	char   *result;

	if (security_get_initial_context_raw("unlabeled", &unlabeled) < 0)
		ereport(ERROR,
				(errcode(ERRCODE_INTERNAL_ERROR),
				 errmsg("SELinux: unable to get initial security context")));

	PG_TRY();
	{
		result = pstrdup(unlabeled);
	}
	PG_CATCH();
	{
		freecon(unlabeled);
		PG_RE_THROW();
	}
	PG_END_TRY();

	freecon(unlabeled);

	return result;
}

/*
 * sepgsql_get_local_label
 *
 * It returns a security label of the specified local database object,
 * or NULL if unlabeled.
 */
static char *
sepgsql_get_local_label(Oid classOid, Oid objOid, int32 subId)
{
	Relation		rel;
	SysScanDesc		scan;
	ScanKeyData		skey[3];
	HeapTuple		tuple;
	char		   *seclabel = NULL;

    /* Use the index to search for a matching old tuple */
    ScanKeyInit(&skey[0],
                Anum_pg_description_objoid,
                BTEqualStrategyNumber, F_OIDEQ,
                ObjectIdGetDatum(objOid));
    ScanKeyInit(&skey[1],
                Anum_pg_description_classoid,
                BTEqualStrategyNumber, F_OIDEQ,
                ObjectIdGetDatum(classOid));
    ScanKeyInit(&skey[2],
                Anum_pg_description_objsubid,
                BTEqualStrategyNumber, F_INT4EQ,
                Int32GetDatum(subId));

	rel = heap_open(DescriptionRelationId, AccessShareLock);

	scan = systable_beginscan(rel, DescriptionObjIndexId, true,
							  SnapshotNow, 3, skey);

	tuple = systable_getnext(scan);
	if (HeapTupleIsValid(tuple))
	{
		Datum		value;
		bool		isnull;

		value = heap_getattr(tuple, Anum_pg_description_description,
							 RelationGetDescr(rel), &isnull);
		if (!isnull)
			seclabel = TextDatumGetCString(value);
	}
    systable_endscan(scan);

    heap_close(rel, AccessShareLock);

    return seclabel;
}

/*
 * sepgsql_get_shared_label
 *
 * It returns a security label of the specified shared database object,
 * or NULL if unlabeled.
 */
static char *
sepgsql_get_shared_label(Oid classOid, Oid objOid)
{
	Relation		rel;
	SysScanDesc		scan;
	ScanKeyData		skey[2];
	HeapTuple		tuple;
	char		   *seclabel = NULL;

	/* Use the index to search for a matching old tuple */
	ScanKeyInit(&skey[0],
				Anum_pg_description_objoid,
				BTEqualStrategyNumber, F_OIDEQ,
				ObjectIdGetDatum(objOid));
	ScanKeyInit(&skey[1],
				Anum_pg_description_classoid,
				BTEqualStrategyNumber, F_OIDEQ,
				ObjectIdGetDatum(classOid));

	rel = heap_open(SharedDescriptionRelationId, AccessShareLock);

	scan = systable_beginscan(rel, SharedDescriptionObjIndexId, true,
							  SnapshotNow, 2, skey);

	tuple = systable_getnext(scan);
	if (HeapTupleIsValid(tuple))
	{
		Datum		value;
		bool		isnull;

		value = heap_getattr(tuple, Anum_pg_shdescription_description,
							 RelationGetDescr(rel), &isnull);
		if (!isnull)
			seclabel = TextDatumGetCString(value);
	}
	systable_endscan(scan);

	heap_close(rel, AccessShareLock);

	return seclabel;
}

/*
 * sepgsql_get_label
 *
 * It returns a security context of the specified database object.
 * If unlabeled or incorrectly labeled, the system "unlabeled" label
 * shall be returned.
 */
char *
sepgsql_get_label(Oid relOid, Oid objOid, int32 subId)
{
	char   *tcontext;

	if (IsSharedRelation(relOid))
		tcontext = sepgsql_get_shared_label(relOid, objOid);
	else
		tcontext = sepgsql_get_local_label(relOid, objOid, subId);

	if (!tcontext || security_check_context(tcontext) < 0)
		tcontext = sepgsql_get_unlabeled_label();

	return tcontext;
}

/*
 * TEXT sepgsql_getcon(VOID)
 *
 * It returns the security label of the client.
 */
Datum
sepgsql_getcon(PG_FUNCTION_ARGS)
{
	char   *client_label;

	if (!sepgsql_is_enabled())
		ereport(ERROR,
				(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
				 errmsg("SELinux: now disabled")));

	client_label = sepgsql_get_client_label();

	PG_RETURN_POINTER(cstring_to_text(client_label));
}

/*
 * TEXT sepgsql_mcstrans_in(TEXT)
 *
 * It translate the given qualified MLS/MCS range into raw format
 * when mcstrans daemon is working.
 */
Datum
sepgsql_mcstrans_in(PG_FUNCTION_ARGS)
{
	text   *label = PG_GETARG_TEXT_P(0);
	char   *raw_label;
	char   *result;

	if (!sepgsql_is_enabled())
		ereport(ERROR,
				(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
				 errmsg("SELinux: now disabled")));

	if (selinux_trans_to_raw_context(text_to_cstring(label),
									 &raw_label) < 0)
		ereport(ERROR,
				(errcode(ERRCODE_INTERNAL_ERROR),
				 errmsg("SELinux: internal error on mcstrans")));

	PG_TRY();
	{
		result = pstrdup(raw_label);
	}
	PG_CATCH();
	{
		freecon(raw_label);
		PG_RE_THROW();
	}
	PG_END_TRY();
	freecon(raw_label);

	PG_RETURN_POINTER(cstring_to_text(result));
}

/*
 * TEXT sepgsql_mcstrans_out(TEXT)
 *
 * It translate the given raw MLS/MCS range into qualified format
 * when mcstrans daemon is working.
 */
Datum
sepgsql_mcstrans_out(PG_FUNCTION_ARGS)
{
	text   *label = PG_GETARG_TEXT_P(0);
	char   *qual_label;
	char   *result;

	if (!sepgsql_is_enabled())
		ereport(ERROR,
				(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
				 errmsg("SELinux: now disabled")));

	if (selinux_raw_to_trans_context(text_to_cstring(label),
									 &qual_label) < 0)
		ereport(ERROR,
				(errcode(ERRCODE_INTERNAL_ERROR),
				 errmsg("SELinux: internal error on mcstrans")));

	PG_TRY();
	{
		result = pstrdup(qual_label);
	}
	PG_CATCH();
	{
		freecon(qual_label);
		PG_RE_THROW();
	}
	PG_END_TRY();
	freecon(qual_label);

	PG_RETURN_POINTER(cstring_to_text(result));
}
