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

	if (!tcontext ||
		security_check_context_raw((security_context_t)tcontext) < 0)
		tcontext = sepgsql_get_unlabeled_label();

	return tcontext;
}

/*
 * sepgsql_relation_relabel
 *
 * It checks privileges to relabel on the specified object.
 */
static void
sepgsql_relation_relabel(const ObjectAddress *object, const char *seclabel)
{
	Oid			relOid = object->objectId;
	AttrNumber	attnum = object->objectSubId;
	uint16_t	tclass;
	char	   *tcontext;
	char	   *audit_name;
	char		audit_name_buf[NAMEDATALEN * 2 + 10];

	Assert(object->classId == RelationRelationId);

	/*
	 * Is it an appropriate object class?
	 */
	switch (get_rel_relkind(relOid))
	{
		case RELKIND_RELATION:
			if (attnum != InvalidAttrNumber)
			{
				tclass = SEPG_CLASS_DB_COLUMN;
				snprintf(audit_name_buf, sizeof(audit_name_buf), "%s.%s",
						 get_rel_name(relOid),
						 get_attname(relOid, attnum));
				audit_name = audit_name_buf;
				break;
			}
			tclass = SEPG_CLASS_DB_TABLE;
			audit_name = get_rel_name(relOid);
			break;

		case RELKIND_SEQUENCE:
			if (attnum != InvalidAttrNumber)
				ereport(ERROR,
						(errcode(ERRCODE_WRONG_OBJECT_TYPE),
						 errmsg("cannot assign security label on attributes "
								"of relations, except for regular tables.")));
			tclass = SEPG_CLASS_DB_SEQUENCE;
			audit_name = get_rel_name(relOid);
			break;

		default:
			if (attnum != InvalidAttrNumber)
				ereport(ERROR,
						(errcode(ERRCODE_WRONG_OBJECT_TYPE),
						 errmsg("cannot assign security label on attributes "
								"of relations, except for regular tables.")));
			tclass = SEPG_CLASS_DB_TUPLE;
			audit_name = get_rel_name(relOid);
			break;
	}

	if (!seclabel)
	{
		/*
		 * check db_xxx:{setattr} permission
		 */
		tcontext = sepgsql_get_label(RelationRelationId, relOid, attnum);

		sepgsql_compute_perms(sepgsql_get_client_label(),
							  tcontext,
							  tclass,
							  SEPG_DB_TABLE__SETATTR,
							  audit_name,
							  true);
	}
	else
	{
		/*
		 * check db_xxx:{setattr relabelfrom} permission
		 */
		tcontext = sepgsql_get_label(RelationRelationId, relOid, attnum);

		sepgsql_compute_perms(sepgsql_get_client_label(),
							  tcontext,
							  tclass,
							  SEPG_DB_TABLE__SETATTR |
							  SEPG_DB_TABLE__RELABELFROM,
							  audit_name,
							  true);
		/*
		 * check db_xxx:{relabelto} permission
		 */
		sepgsql_compute_perms(sepgsql_get_client_label(),
							  seclabel,
							  tclass,
							  SEPG_DB_TABLE__RELABELTO,
							  audit_name,
							  true);
	}
}

/*
 * sepgsql_object_relabel
 *
 * An entrypoint of SECURITY LABEL statement
 */
void
sepgsql_object_relabel(const ObjectAddress *object, const char *seclabel)
{
	/*
	 * validate format of the supplied security label,
	 * if it is security context of selinux.
	 */
	if (seclabel &&
		security_check_context_raw((security_context_t) seclabel) < 0)
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_SECLABEL),
				 errmsg("invalid security label: \"%s\"", seclabel)));
	/*
	 * Do actual permission checks for each object classes
	 */
	switch (object->classId)
	{
		case RelationRelationId:
			sepgsql_relation_relabel(object, seclabel);
			break;

		default:
			elog(ERROR, "unsupported object type: %u", object->classId);
			break;
	}
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
 * exec_relation_restorecon
 *
 * A helper function of sepgsql_restorecon
 */
static void
exec_relation_restorecon(struct selabel_handle *sehnd)
{
	Form_pg_class		relform;
	Form_pg_attribute	attform;
	Relation			relheap;
	Relation			attheap;
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

	relheap = heap_open(RelationRelationId, AccessShareLock);

	attheap = heap_open(AttributeRelationId, AccessShareLock);

	relscan = systable_beginscan(relheap, InvalidOid, false,
								 SnapshotNow, 0, NULL);
	while (HeapTupleIsValid(reltup = systable_getnext(relscan)))
	{
		relform = (Form_pg_class) GETSTRUCT(reltup);
		relationId = HeapTupleGetOid(reltup);

		switch (relform->relkind)
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
				/*
				 * This kind of relation does not have individual
				 * security label, so we skip this entry.
				 */
				continue;
		}
		/*
		 * Set up fully-qualified relation name
		 */
		namespace_name = get_namespace_name(relform->relnamespace);
		offset = snprintf(name_buf, sizeof(name_buf), "%s.%s.%s",
						  database_name, namespace_name,
						  NameStr(relform->relname));
		pfree(namespace_name);

		if (selabel_lookup_raw(sehnd, &context, name_buf, tclass) == 0)
		{
			PG_TRY();
			{
				object.classId = RelationRelationId;
				object.objectId = relationId;
				object.objectSubId = 0;

				/*
				 * check permission to relabel the relation
				 */
				sepgsql_object_relabel(&object, context);
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
		else if (errno == ENOENT)
			ereport(WARNING,
					(errmsg("no valid initial label for %s, skipped",
							name_buf)));
		else
			ereport(ERROR,
					(errcode(ERRCODE_INTERNAL_ERROR),
					 errmsg("libselinux internal error")));

		/*
         * only pg_attribute entries of regular tables have
         * individual security labels.
         */
		if (relform->relkind != RELKIND_RELATION)
			continue;

		ScanKeyInit(&key,
					Anum_pg_attribute_attrelid,
					BTEqualStrategyNumber, F_OIDEQ,
					ObjectIdGetDatum(relationId));

		attscan = systable_beginscan(attheap,
									 AttributeRelidNumIndexId, true,
									 SnapshotNow, 1, &key);
		while (HeapTupleIsValid(atttup = systable_getnext(attscan)))
		{
			attform = (Form_pg_attribute) GETSTRUCT(atttup);

			snprintf(name_buf + offset, sizeof(name_buf) - offset,
					 ".%s", NameStr(attform->attname));

			if (selabel_lookup_raw(sehnd, &context, name_buf,
								   SELABEL_DB_COLUMN) == 0)
			{
				PG_TRY();
				{
					object.classId = RelationRelationId;
					object.objectId = relationId;
					object.objectSubId = attform->attnum;

					/*
					 * permission check to relabel the column
					 */
					sepgsql_object_relabel(&object, context);
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

	heap_close(attheap, NoLock);

	heap_close(relheap, NoLock);
}

/*
 * BOOL sepgsql_restorecon(BOOL with_shared, TEXT specfile)
 *
 * This function tries to assign initial security labels on all the object
 * within current database, according to the system setting.
 * It is typically invoked just after initdb by initdb.sepgsql script to
 * initialize security label of the system object.
 *
 * If @with_shared is true, it also tries to label shared database object,
 * such as pg_database and so on.
 * If @specfile is not NULL, it uses explicitly specified specfile, instead
 * of the system default.
 */
PG_FUNCTION_INFO_V1(sepgsql_restorecon);
Datum
sepgsql_restorecon(PG_FUNCTION_ARGS)
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
	/*
	 * check DAC permission
	 */
	if (!superuser())
		ereport(ERROR,
				(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
				 errmsg("must be superuser to restore initial contexts")));

	/*
	 * open selabel_lookup(3) stuff
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
		if (with_shared)
			/* do nothing right now */ ;

		exec_relation_restorecon(sehnd);
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
