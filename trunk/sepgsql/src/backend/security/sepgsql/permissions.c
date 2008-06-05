/*
 * src/backend/security/sepgsql/permissions.c
 *   applies SE-PostgreSQL permission checks
 *
 * Portions Copyright (c) 1996-2008, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 */
#include "postgres.h"

#include "catalog/pg_attribute.h"
#include "catalog/pg_authid.h"
#include "catalog/pg_class.h"
#include "catalog/pg_database.h"
#include "catalog/pg_language.h"
#include "catalog/pg_largeobject.h"
#include "catalog/pg_proc.h"
#include "catalog/pg_security.h"
#include "catalog/pg_trigger.h"
#include "catalog/pg_type.h"
#include "miscadmin.h"
#include "security/pgace.h"
#include "utils/syscache.h"

static access_vector_t sepgsql_perms_to_common_perms(uint32 perms) {
	access_vector_t result = 0;

	result |= (perms & SEPGSQL_PERMS_USE         ? COMMON_DATABASE__GETATTR : 0);
	result |= (perms & SEPGSQL_PERMS_SELECT	     ? COMMON_DATABASE__GETATTR : 0);
	result |= (perms & SEPGSQL_PERMS_UPDATE	     ? COMMON_DATABASE__SETATTR : 0);
	result |= (perms & SEPGSQL_PERMS_INSERT	     ? COMMON_DATABASE__CREATE  : 0);
    result |= (perms & SEPGSQL_PERMS_DELETE	     ? COMMON_DATABASE__DROP    : 0);
	result |= (perms & SEPGSQL_PERMS_RELABELFROM ? COMMON_DATABASE__RELABELFROM : 0);
	result |= (perms & SEPGSQL_PERMS_RELABELTO   ? COMMON_DATABASE__RELABELTO : 0);

	return result;
}

static access_vector_t sepgsql_perms_to_tuple_perms(uint32 perms) {
	access_vector_t result = 0;

	result |= (perms & SEPGSQL_PERMS_USE         ? DB_TUPLE__USE    : 0);
	result |= (perms & SEPGSQL_PERMS_SELECT      ? DB_TUPLE__SELECT : 0);
	result |= (perms & SEPGSQL_PERMS_UPDATE      ? DB_TUPLE__UPDATE : 0);
	result |= (perms & SEPGSQL_PERMS_INSERT      ? DB_TUPLE__INSERT : 0);
	result |= (perms & SEPGSQL_PERMS_DELETE	     ? DB_TUPLE__DELETE : 0);
	result |= (perms & SEPGSQL_PERMS_RELABELFROM ? DB_TUPLE__RELABELFROM : 0);
	result |= (perms & SEPGSQL_PERMS_RELABELTO   ? DB_TUPLE__RELABELTO : 0);

	return result;
}

const char *sepgsqlTupleName(Oid relid, HeapTuple tuple)
{
	static char buffer[NAMEDATALEN * 3];

	switch (relid)
	{
	case AttributeRelationId: {
		Form_pg_attribute attForm
			= (Form_pg_attribute) GETSTRUCT(tuple);

		if (!IsBootstrapProcessingMode())
		{
			HeapTuple exttup
				= SearchSysCache(RELOID,
								 ObjectIdGetDatum(attForm->attrelid),
								 0, 0, 0);
			if (HeapTupleIsValid(exttup))
			{
				snprintf(buffer, sizeof(buffer), "%s.%s",
						 NameStr(((Form_pg_class) GETSTRUCT(exttup))->relname),
						 NameStr(((Form_pg_attribute) GETSTRUCT(tuple))->attname));
				ReleaseSysCache(exttup);
				break;
			}
		}
		snprintf(buffer, sizeof(buffer), "%s",
				 NameStr(((Form_pg_attribute) GETSTRUCT(tuple))->attname));
		break;
	}
	case AuthIdRelationId:
		snprintf(buffer, sizeof(buffer), "%s",
				 NameStr(((Form_pg_authid) GETSTRUCT(tuple))->rolname));
		break;

	case RelationRelationId:
		snprintf(buffer, sizeof(buffer), "%s",
				 NameStr(((Form_pg_class) GETSTRUCT(tuple))->relname));
		break;

	case DatabaseRelationId:
		snprintf(buffer, sizeof(buffer), "%s",
				 NameStr(((Form_pg_database) GETSTRUCT(tuple))->datname));
		break;

	case LargeObjectRelationId:
		snprintf(buffer, sizeof(buffer), "loid:%u",
				 ((Form_pg_largeobject) GETSTRUCT(tuple))->loid);
		break;

	case ProcedureRelationId:
		snprintf(buffer, sizeof(buffer), "%s",
				 NameStr(((Form_pg_proc) GETSTRUCT(tuple))->proname));
		break;

	case TriggerRelationId:
		snprintf(buffer, sizeof(buffer), "%s",
				 NameStr(((Form_pg_trigger) GETSTRUCT(tuple))->tgname));
		break;

	case TypeRelationId:
		snprintf(buffer, sizeof(buffer), "pg_type::%s",
				 NameStr(((Form_pg_type) GETSTRUCT(tuple))->typname));
		break;
	default:
		/* this tuple has no name */
		return NULL;
	}
	return buffer;
}

static void check_pg_attribute(HeapTuple tuple, HeapTuple oldtup,
							   access_vector_t *p_perms, security_class_t *p_tclass)
{
	Form_pg_attribute attForm, oldForm;
	HeapTuple reltup;

	attForm = (Form_pg_attribute) GETSTRUCT(tuple);
	switch (attForm->attrelid) {
    case TypeRelationId:
    case ProcedureRelationId:
    case AttributeRelationId:
    case RelationRelationId:
		/* those are pure relation */
		break;
	default:
		reltup = SearchSysCache(RELOID,
								ObjectIdGetDatum(attForm->attrelid),
								0, 0, 0);
		if (!HeapTupleIsValid(reltup))
			elog(ERROR, "SELinux: cache lookup failed for relation %u", attForm->attrelid);
		if (RELKIND_RELATION != ((Form_pg_class) GETSTRUCT(reltup))->relkind)
		{
			*p_tclass = SECCLASS_DB_TUPLE;
			*p_perms = sepgsql_perms_to_tuple_perms(*p_perms);
			ReleaseSysCache(reltup);
			return;
		}
		ReleaseSysCache(reltup);
		break;
	}
	*p_tclass = SECCLASS_DB_COLUMN;
	*p_perms = sepgsql_perms_to_common_perms(*p_perms);
	if (HeapTupleIsValid(oldtup))
	{
		oldForm = (Form_pg_attribute) GETSTRUCT(oldtup);

		if (oldForm->attisdropped != true && attForm->attisdropped == true)
			*p_perms |= DB_COLUMN__DROP;
	}
}

static void check_pg_largeobject(HeapTuple tuple, HeapTuple oldtup,
								 access_vector_t *p_perms, security_class_t *p_tclass)
{
	access_vector_t perms;

	/*
	 * NOTE: INSERT tuples into pg_largeobject has a possibility to create
	 * a new largeobject, if the given loid is not exist on the current
	 * pg_largeobject. Ditto for DELETE statement, it also has a possibility
	 * to drop a largeobject, if it removes all tuples within a large object.
	 *
	 * db_blob:{create} and db_blob:{drop} should be evaluated for 
	 * creation/deletion of largeobject, but we have to check pg_largeobject
	 * with SnapshotSelf whether there is one or more tuple having same loid,
	 * or not, on each tuple insertion or deletion.
	 *
	 * So, we assume any INSERT means db_blob:{create}, any DELETE means
	 * db_blob:{drop}.
	 */
	perms = sepgsql_perms_to_common_perms(*p_perms);
	perms |= (*p_perms & SEPGSQL_PERMS_INSERT ? DB_BLOB__WRITE : 0);
	perms |= (*p_perms & SEPGSQL_PERMS_DELETE ? DB_BLOB__WRITE : 0);
	perms |= (*p_perms & SEPGSQL_PERMS_READ   ? DB_BLOB__READ  : 0);
	perms |= (*p_perms & SEPGSQL_PERMS_WRITE  ? DB_BLOB__WRITE : 0);

	// TODO: add DB_BLOB__CREATE | DB_BLOB__DROP for SEPGSQL_PERMS_UPDATE,
	//       if loid is changed

	*p_tclass = SECCLASS_DB_BLOB;
	*p_perms = perms;
}

static void check_pg_proc(HeapTuple tuple, HeapTuple oldtup,
						  access_vector_t *p_perms, security_class_t *p_tclass)
{
	access_vector_t perms = sepgsql_perms_to_common_perms(*p_perms);
	Form_pg_proc procForm = (Form_pg_proc) GETSTRUCT(tuple);

	if (procForm->prolang == ClanguageId) {
		Datum oldbin, newbin;
		bool isnull, verify = false;

		newbin = SysCacheGetAttr(PROCOID, tuple,
								 Anum_pg_proc_probin, &isnull);
		if (!isnull) {
			if (perms & DB_PROCEDURE__CREATE) {
				verify = true;
			} else if (HeapTupleIsValid(oldtup)) {
				oldbin = SysCacheGetAttr(PROCOID, oldtup,
										 Anum_pg_proc_probin, &isnull);
				if (isnull || DatumGetBool(DirectFunctionCall2(textne, oldbin, newbin)))
					verify = true;
			}

			if (verify) {
				char *file_name;
				security_context_t file_context;

				/* <client type> <-- database:module_install --> <database type> */
				sepgsqlAvcPermission(sepgsqlGetClientContext(),
									 sepgsqlGetDatabaseContext(),
									 SECCLASS_DB_DATABASE,
									 DB_DATABASE__INSTALL_MODULE,
									 NULL);

				/* <client type> <-- database:module_install --> <file type> */
				file_name = DatumGetCString(DirectFunctionCall1(textout, newbin));
				file_name = expand_dynamic_library_name(file_name);
				if (getfilecon_raw(file_name, &file_context) < 0)
					ereport(ERROR,
							(errcode(ERRCODE_SELINUX_ERROR),
							 errmsg("SELinux: could not get context of %s", file_name)));
				PG_TRY();
				{
					sepgsqlAvcPermission(sepgsqlGetClientContext(),
										 file_context,
										 SECCLASS_DB_DATABASE,
										 DB_DATABASE__INSTALL_MODULE,
										 file_name);
				}
				PG_CATCH();
				{
					freecon(file_context);
					PG_RE_THROW();
				}
				PG_END_TRY();
				freecon(file_context);
			}
		}
	}
	*p_perms = perms;
	*p_tclass = SECCLASS_DB_PROCEDURE;
}

static void check_pg_relation(HeapTuple tuple, HeapTuple oldtup,
							  access_vector_t *p_perms, security_class_t *p_tclass)
{
	Form_pg_class classForm = (Form_pg_class) GETSTRUCT(tuple);
	if (classForm->relkind == RELKIND_RELATION)
	{
		*p_tclass = SECCLASS_DB_TABLE;
		*p_perms = sepgsql_perms_to_common_perms(*p_perms);
	} else {
		*p_tclass = SECCLASS_DB_TUPLE;
		*p_perms = sepgsql_perms_to_tuple_perms(*p_perms);
	}
}

bool sepgsqlCheckTuplePerms(Relation rel, HeapTuple tuple, HeapTuple oldtup, uint32 perms, bool abort)
{
	security_class_t tclass;
	bool rc = true;

	Assert(tuple != NULL);

	switch (RelationGetRelid(rel))
	{
		case DatabaseRelationId:		/* pg_datbase */
			perms = sepgsql_perms_to_common_perms(perms);
			tclass = SECCLASS_DB_DATABASE;
			break;

		case RelationRelationId:		/* pg_class */
			check_pg_relation(tuple, oldtup, &perms, &tclass);
			break;

		case AttributeRelationId:		/* pg_attribute */
			check_pg_attribute(tuple, oldtup, &perms, &tclass);
			break;

		case ProcedureRelationId:		/* pg_proc */
			check_pg_proc(tuple, oldtup, &perms, &tclass);
			break;

		case LargeObjectRelationId:		/* pg_largeobject */
			check_pg_largeobject(tuple, oldtup, &perms, &tclass);
			break;

		default:
			perms = sepgsql_perms_to_tuple_perms(perms);
			tclass = SECCLASS_DB_TUPLE;
			break;
	}

	if (perms)
	{
		security_context_t tcontext
			= pgaceLookupSecurityLabel(HeapTupleGetSecurity(tuple));

		if (abort) {
			sepgsqlAvcPermission(sepgsqlGetClientContext(),
								 tcontext, tclass, perms,
								 sepgsqlTupleName(RelationGetRelid(rel), tuple));
		}
		else
		{
			rc = sepgsqlAvcPermissionNoAbort(sepgsqlGetClientContext(),
											 tcontext, tclass, perms,
											 sepgsqlTupleName(RelationGetRelid(rel), tuple));
		}
		pfree(tcontext);
	}
	return rc;
}

security_context_t sepgsqlGetDefaultContext(Relation rel, HeapTuple tuple)
{
	security_context_t tcontext;
	security_class_t tclass = 0;

	/* special cases */
	switch (RelationGetRelid(rel))
	{
	case DatabaseRelationId:
		tclass = SECCLASS_DB_DATABASE;
		tcontext = sepgsqlGetClientContext();
		break;

	case RelationRelationId: {
		Form_pg_class clsForm = (Form_pg_class) GETSTRUCT(tuple);

		if (clsForm->relkind == RELKIND_RELATION)
		{
			tclass = SECCLASS_DB_TABLE;
			tcontext = sepgsqlGetDatabaseContext();
		}
		break;
	}
	case AttributeRelationId: {
		Form_pg_attribute attForm = (Form_pg_attribute) GETSTRUCT(tuple);
		HeapTuple reltup;

		switch (attForm->attrelid)
		{
		case TypeRelationId:
		case ProcedureRelationId:
		case AttributeRelationId:
		case RelationRelationId:
			/* we cannot touch these relations at very early phase in bootstrap */
			if (IsBootstrapProcessingMode())
			{
				tclass = SECCLASS_DB_COLUMN;
				tcontext = sepgsqlAvcCreateCon(sepgsqlGetClientContext(),
											   sepgsqlGetDatabaseContext(),
											   SECCLASS_DB_TABLE);
				break;
			}
		default:
			reltup = SearchSysCache(RELOID,
									ObjectIdGetDatum(attForm->attrelid),
									0, 0, 0);
			if (!HeapTupleIsValid(reltup))
				elog(ERROR, "SELinux: cache lookup failed for relation %u", attForm->attrelid);
			tclass = (RELKIND_RELATION == ((Form_pg_class) GETSTRUCT(reltup))->relkind)
				? SECCLASS_DB_COLUMN : SECCLASS_DB_TUPLE;
			tcontext = pgaceLookupSecurityLabel(HeapTupleGetSecurity(reltup));
			ReleaseSysCache(reltup);
		}
		break;
	}
	case ProcedureRelationId:
		tclass = SECCLASS_DB_PROCEDURE;
		tcontext = sepgsqlGetDatabaseContext();
		break;

	case LargeObjectRelationId:
		/*
		 * NOTE: a desirable behavior when a new tuple insertion is
		 * inheris the security context of previous pages.
		 * However, it need to lookup pg_largeobject with SnapshotSelf
		 * for each insertion.
		 *
		 * If you insert tuples via lowrite(), it inherits correctly.
		 * Fundamentally, we don't use INSERT a tuple directlly.
		 */
		tclass = SECCLASS_DB_BLOB;
		tcontext = sepgsqlGetDatabaseContext();
		break;

	case TypeRelationId:
		if (IsBootstrapProcessingMode())
		{
			/* we cannot touch system cache in very early phase */
			tclass = SECCLASS_DB_TUPLE;
			tcontext = sepgsqlAvcCreateCon(sepgsqlGetClientContext(),
										   sepgsqlGetDatabaseContext(),
										   SECCLASS_DB_TABLE);
		}
		break;
	}
	/* normal or user defined relation */
	if (tclass == 0)
	{
		HeapTuple reltup;

		reltup = SearchSysCache(RELOID,
								ObjectIdGetDatum(RelationGetRelid(rel)),
								0, 0, 0);
		if (!HeapTupleIsValid(reltup))
			elog(ERROR, "SELinux: cache lookup failed for relation %u", RelationGetRelid(rel));
		tclass = SECCLASS_DB_TUPLE;
		tcontext = pgaceLookupSecurityLabel(HeapTupleGetSecurity(reltup));
		ReleaseSysCache(reltup);
	}
	return sepgsqlAvcCreateCon(sepgsqlGetClientContext(),
							   tcontext, tclass);
}
