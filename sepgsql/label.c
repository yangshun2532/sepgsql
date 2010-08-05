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
#include "catalog/dependency.h"
#include "catalog/indexing.h"
#include "catalog/pg_description.h"
#include "catalog/pg_shdescription.h"
#include "commands/dbcommands.h"
#include "commands/seclabel.h"
#include "libpq/libpq-be.h"
#include "miscadmin.h"
#include "utils/builtins.h"
#include "utils/fmgroids.h"
#include "utils/lsyscache.h"
#include "utils/rel.h"
#include "utils/tqual.h"

#include "sepgsql.h"

#include <selinux/label.h>

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
 * sepgsql_get_label
 *
 * It returns a security context of the specified database object.
 * If unlabeled or incorrectly labeled, the system "unlabeled" label
 * shall be returned.
 */
char *
sepgsql_get_label(Oid relOid, Oid objOid, int32 subId)
{
	ObjectAddress	object = {
		.classId		= relOid,
		.objectId		= objOid,
		.objectSubId	= subId,
	};
	char   *tcontext = GetSecurityLabel(&object, SEPGSQL_LABEL_TAG);

	if (!tcontext || security_check_context(tcontext) < 0)
		tcontext = sepgsql_get_unlabeled_label();

	return tcontext;
}

/*
 * TEXT sepgsql_getcon(VOID)
 *
 * It returns the security label of the client.
 */
PG_FUNCTION_INFO_V1(sepgsql_getcon);
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
PG_FUNCTION_INFO_V1(sepgsql_mcstrans_in);
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
PG_FUNCTION_INFO_V1(sepgsql_mcstrans_out);
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

/*
 * BOOL sepgsql_initial_labeling(BOOL, TEXT)
 *
 * It assignes default security context on all the database objects
 * within the current database. If the 1st argument is true, it also
 * tries tp relabel shared database object. The 2nd argument is path
 * to the specfile; can be NULL for default.
 *
 * Note that this function is only available in permissive mode.
 */
static void
exec_initial_relation_labeling(struct selabel_handle *sehnd)
{
	Form_pg_class		relForm;
	Form_pg_attribute	attForm;
	Relation			pg_class;
	Relation			pg_attribute;
	SysScanDesc			relscan;
	SysScanDesc			attscan;
	ScanKeyData			key;
	HeapTuple			reltup;
	HeapTuple			atttup;
	ObjectAddress		object;
	security_context_t	context;
	char			   *database_name = get_database_name(MyDatabaseId);
	char			   *namespace_name;
	char				name_buf[NAMEDATALEN * 4 + 10];
	Oid					relationId;
	int					tclass;
	int					offset;

	pg_class = heap_open(RelationRelationId, AccessShareLock);

	pg_attribute = heap_open(AttributeRelationId, AccessShareLock);

	relscan = systable_beginscan(pg_class, InvalidOid, false,
								 SnapshotNow, 0, NULL);
	while (HeapTupleIsValid(reltup = systable_getnext(relscan)))
	{
		relForm = (Form_pg_class) GETSTRUCT(reltup);
		relationId = HeapTupleGetOid(reltup);

		/*
		 * These relkind don't have individual security labels
		 */
		switch (relForm->relkind)
		{
			case RELKIND_RELATION:
				tclass = SELABEL_DB_TABLE;
				break;
			case RELKIND_SEQUENCE:
				tclass = SELABEL_DB_SEQUENCE;
				break;
			case RELKIND_VIEW:
				tclass = SELABEL_DB_VIEW;
				break;
			default:
				/* other relation don't have individual security labels */
				continue;
		}
		namespace_name = get_namespace_name(relForm->relnamespace);

		offset = snprintf(name_buf, sizeof(name_buf), "%s.%s.%s",
						  database_name, namespace_name,
						  NameStr(relForm->relname));
		pfree(namespace_name);

		if (selabel_lookup_raw(sehnd, &context, name_buf, tclass) == 0)
		{
			PG_TRY();
			{
				object.classId = RelationRelationId;
				object.objectId = relationId;
				object.objectSubId = 0;

				SetSecurityLabel(&object, SEPGSQL_LABEL_TAG, context);
			}
			PG_CATCH();
			{
				freecon(context);
				PG_RE_THROW();
			}
			PG_END_TRY();
			freecon(context);
		}

		/*
		 * Only attributes within regular table have individual
		 * security labels
		 */
		if (relForm->relkind != RELKIND_RELATION)
			continue;

		ScanKeyInit(&key,
					Anum_pg_attribute_attrelid,
					BTEqualStrategyNumber, F_OIDEQ,
					ObjectIdGetDatum(HeapTupleGetOid(reltup)));

		attscan = systable_beginscan(pg_attribute,
									 AttributeRelidNumIndexId, true,
									 SnapshotNow, 1, &key);
		while (HeapTupleIsValid(atttup = systable_getnext(attscan)))
		{
			attForm = (Form_pg_attribute) GETSTRUCT(atttup);

			snprintf(name_buf + offset, sizeof(name_buf) - offset,
					 ".%s", NameStr(attForm->attname));

			if (selabel_lookup_raw(sehnd, &context, name_buf,
								   SELABEL_DB_COLUMN) == 0)
			{
				PG_TRY();
				{
					object.classId = RelationRelationId;
					object.objectId = relationId;
					object.objectSubId = attForm->attnum;

					SetSecurityLabel(&object, SEPGSQL_LABEL_TAG, context);
				}
				PG_CATCH();
				{
					freecon(context);
					PG_RE_THROW();
				}
				PG_END_TRY();
				freecon(context);
			}
		}
		systable_endscan(attscan);
	}
	systable_endscan(relscan);

	heap_close(pg_attribute, NoLock);

	heap_close(pg_class, NoLock);
}

PG_FUNCTION_INFO_V1(sepgsql_initial_labeling);
Datum
sepgsql_initial_labeling(PG_FUNCTION_ARGS)
{
	bool					with_shared	= PG_GETARG_BOOL(0);
	struct selabel_handle  *sehnd;
	struct selinux_opt		seopts = {
		.type = SELABEL_OPT_UNUSED,
		.value = NULL
	};

	if (!sepgsql_is_enabled())
		ereport(ERROR,
				(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
				 errmsg("SELinux: now disabled")));
	if (sepgsql_get_enforce())
		ereport(ERROR,
				(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
				 errmsg("unavailable to run in enforcing mode")));
	/*
	 * open selabel facilities
	 */
	if (!PG_ARGISNULL(1))
	{
		seopts.type = SELABEL_OPT_PATH;
		seopts.value = TextDatumGetCString(PG_GETARG_DATUM(1));
	}
	sehnd = selabel_open(SELABEL_CTX_DB, &seopts, 1);
	if (!sehnd)
		ereport(ERROR,
				(errcode(ERRCODE_INTERNAL_ERROR),
				 errmsg("SELinux internal error")));
	PG_TRY();
	{
		exec_initial_relation_labeling(sehnd);
	}
	PG_CATCH();
	{
		selabel_close(sehnd);
		PG_RE_THROW();
	}
	PG_END_TRY();	

	selabel_close(sehnd);

	PG_RETURN_BOOL(true);
}
