/*
 * src/backend/security/sepgsql/bridge.c
 *
 * New style security hooks for SE-PostgreSQL
 *
 * Portions Copyright (c) 1996-2009, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 */
#include "postgres.h"

#include "access/sysattr.h"
#include "catalog/indexing.h"
#include "catalog/pg_authid.h"
#include "catalog/pg_cast.h"
#include "catalog/pg_conversion.h"
#include "catalog/pg_database.h"
#include "catalog/pg_foreign_data_wrapper.h"
#include "catalog/pg_foreign_server.h"
#include "catalog/pg_language.h"
#include "catalog/pg_namespace.h"
#include "catalog/pg_operator.h"
#include "catalog/pg_opclass.h"
#include "catalog/pg_opfamily.h"
#include "catalog/pg_proc.h"
#include "catalog/pg_rewrite.h"
#include "catalog/pg_security.h"
#include "catalog/pg_tablespace.h"
#include "catalog/pg_ts_parser.h"
#include "catalog/pg_ts_dict.h"
#include "catalog/pg_ts_template.h"
#include "catalog/pg_ts_config.h"
#include "catalog/pg_type.h"
#include "catalog/pg_user_mapping.h"
#include "commands/dbcommands.h"
#include "miscadmin.h"
#include "security/sepgsql.h"
#include "utils/builtins.h"
#include "utils/fmgroids.h"
#include "utils/lsyscache.h"
#include "utils/syscache.h"
#include "utils/tqual.h"

/* ------------------------------------------------------------ *
 * Common Helper Routines
 * ------------------------------------------------------------ */



/* ------------------------------------------------------------ *
 *
 * Pg_database related security hooks
 *
 * ------------------------------------------------------------ */
static bool
sepgsql_database_common(Oid datOid, uint32 required, bool abort)
{
	HeapTuple		tuple;
	sepgsql_sid_t	sid;
	uint16			tclass;
	const char	   *auname;
	bool			rc;

	tuple = SearchSysCache(DATABASEOID,
						   ObjectIdGetDatum(datOid),
						   0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "cache lookup failed for database: %u", datOid);

	auname = NameStr(((Form_pg_database) GETSTRUCT(tuple))->datname);

	sid = sepgsqlGetTupleSecid(DatabaseRelationId, tuple, &tclass);

	rc = sepgsqlClientHasPerms(sid, tclass, required, auname, abort);

	ReleaseSysCache(tuple);

	return rc;
}

Oid
sepgsql_database_create(const char *datName, DefElem *newLabel)
{
	sepgsql_sid_t	sid;

	if (!sepgsqlIsEnabled())
		return InvalidOid;

	if (!newLabel)
		sid = sepgsqlGetDefaultDatabaseSecid();
	else
	{
		sid.relid = DatabaseRelationId;
		sid.secid = securityTransSecLabelIn(sid.relid,
											strVal(newLabel->arg));
	}

	sepgsqlClientHasPerms(sid, SEPG_CLASS_DB_DATABASE,
						  SEPG_DB_DATABASE__CREATE,
						  datName, true);
	return sid.secid;
}

void
sepgsql_database_alter(Oid datOid)
{
	if (!sepgsqlIsEnabled())
		return;

	sepgsql_database_common(datOid, SEPG_DB_DATABASE__SETATTR, true);
}

void
sepgsql_database_drop(Oid datOid)
{
	if (!sepgsqlIsEnabled())
		return;

	sepgsql_database_common(datOid, SEPG_DB_DATABASE__DROP, true);
}

Oid
sepgsql_database_relabel(Oid datOid, DefElem *newLabel)
{
	sepgsql_sid_t	sid;

	if (!sepgsqlIsEnabled())
	{
		if (newLabel)
			ereport(ERROR,
					(errcode(ERRCODE_SELINUX_ERROR),
					 errmsg("SELinux is disabled now")));

		return InvalidOid;
	}
	sid.relid = DatabaseRelationId;
	sid.secid = securityTransSecLabelIn(sid.relid, strVal(newLabel->arg));

	/* db_database:{setattr relabelfrom} to older seclabel */
	sepgsql_database_common(datOid,
							SEPG_DB_DATABASE__SETATTR |
							SEPG_DB_DATABASE__RELABELFROM, true);

	/* db_database:{relabelto} to newer seclabel */
	sepgsqlClientHasPerms(sid,
						  SEPG_CLASS_DB_DATABASE,
						  SEPG_DB_DATABASE__RELABELTO,
						  get_database_name(datOid), true);

	return sid.secid;
}

void
sepgsql_database_grant(Oid datOid)
{
	if (!sepgsqlIsEnabled())
		return;

	sepgsql_database_common(datOid, SEPG_DB_DATABASE__SETATTR, true);
}

void
sepgsql_database_access(Oid datOid)
{
	if (!sepgsqlIsEnabled())
		return;

	sepgsql_database_common(datOid, SEPG_DB_DATABASE__ACCESS, true);
}

bool
sepgsql_database_superuser(Oid datOid)
{
	if (!sepgsqlIsEnabled())
		return true;

	return sepgsql_database_common(datOid, SEPG_DB_DATABASE__SUPERUSER, false);
}

void
sepgsql_database_load_module(Oid datOid, const char *filename)
{
	HeapTuple			tuple;
	security_context_t	filecon;
	security_context_t	datcon;

	if (!sepgsqlIsEnabled())
		return;
	/*
	 * It assumes preloaded libraries are secure,
	 * because it can be set up using guc variable
	 * not any SQL statements.
	 */
	if (GetProcessingMode() == InitProcessing)
		return;

	/* Get database context */
	tuple = SearchSysCache(DATABASEOID,
						   ObjectIdGetDatum(datOid),
						   0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "cache lookup failed for database: %u", datOid);

	datcon = securityRawSecLabelOut(DatabaseRelationId,
									HeapTupleGetSecid(tuple));
	ReleaseSysCache(tuple);

	/* Get library context */
	if (getfilecon_raw(filename, &filecon) < 0)
		ereport(ERROR,
				(errcode_for_file_access(),
				 errmsg("could not access file \"%s\": %m", filename)));
	PG_TRY();
	{
		sepgsqlComputePerms(datcon,
							filecon,
							SEPG_CLASS_DB_DATABASE,
							SEPG_DB_DATABASE__LOAD_MODULE,
							filename, true);
	}
	PG_CATCH();
	{
		freecon(filecon);
		PG_RE_THROW();
	}
	PG_END_TRY();
	freecon(filecon);
}

/* ------------------------------------------------------------ *
 *
 * Pg_namespace related security hooks
 *
 * ------------------------------------------------------------ */
static bool
sepgsql_schema_common(Oid nspOid, uint32 required, bool abort)
{
	HeapTuple		tuple;
	sepgsql_sid_t	sid;
	uint16			tclass;
	const char	   *auname;
	bool			rc;

	tuple = SearchSysCache(NAMESPACEOID,
						   ObjectIdGetDatum(nspOid),
						   0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "cache lookup failed for namespace: %u", nspOid);

	sid = sepgsqlGetTupleSecid(NamespaceRelationId, tuple, &tclass);

	auname = NameStr(((Form_pg_namespace) GETSTRUCT(tuple))->nspname);

	rc = sepgsqlClientHasPerms(sid, tclass, required, auname, abort);

	ReleaseSysCache(tuple);

	return rc;
}

Oid
sepgsql_schema_create(const char *nspName, bool isTemp, DefElem *newLabel)
{
	sepgsql_sid_t	sid;

	if (!sepgsqlIsEnabled())
		return InvalidOid;

	if (!newLabel)
		sid = sepgsqlGetDefaultSchemaSecid(MyDatabaseId);
	else
	{
		sid.relid = NamespaceRelationId;
		sid.secid = securityTransSecLabelIn(sid.relid, strVal(newLabel->arg));
	}

	sepgsqlClientHasPerms(sid,
						  SEPG_CLASS_DB_SCHEMA,
						  SEPG_DB_SCHEMA__CREATE,
						  nspName, true);
	return sid.secid;
}

void
sepgsql_schema_alter(Oid nspOid)
{
	if (!sepgsqlIsEnabled())
		return;

	sepgsql_schema_common(nspOid, SEPG_DB_SCHEMA__SETATTR, true);
}

void
sepgsql_schema_drop(Oid nspOid)
{
	if (!sepgsqlIsEnabled())
		return;

	sepgsql_schema_common(nspOid, SEPG_DB_SCHEMA__DROP, true);
}

Oid
sepgsql_schema_relabel(Oid nspOid, DefElem *newLabel)
{
	sepgsql_sid_t	sid;

	if (!sepgsqlIsEnabled())
	{
		if (newLabel)
			ereport(ERROR,
					(errcode(ERRCODE_SELINUX_ERROR),
					 errmsg("SELinux is disabled now")));
		return InvalidOid;
	}
	sid.relid = NamespaceRelationId;
	sid.secid = securityTransSecLabelIn(sid.relid, strVal(newLabel->arg));

	/* db_schema:{setattr relabelfrom} for older seclabel */
    sepgsql_schema_common(nspOid,
						  SEPG_DB_SCHEMA__SETATTR |
						  SEPG_DB_SCHEMA__RELABELFROM, true);

    /* db_schema:{relabelto} for newer seclabel */
	sepgsqlClientHasPerms(sid,
						  SEPG_CLASS_DB_SCHEMA,
						  SEPG_DB_SCHEMA__RELABELTO,
						  get_namespace_name(nspOid), true);

	return sid.secid;
}

void
sepgsql_schema_grant(Oid nspOid)
{
	if (!sepgsqlIsEnabled())
		return;

	sepgsql_schema_common(nspOid, SEPG_DB_SCHEMA__SETATTR, true);
}

bool
sepgsql_schema_search(Oid nspOid, bool abort)
{
	if (!sepgsqlIsEnabled())
		return true;

	return sepgsql_schema_common(nspOid, SEPG_DB_SCHEMA__SEARCH, abort);
}

/* ------------------------------------------------------------ *
 *
 * Pg_class and Pg_attribute related security hooks
 *
 * ------------------------------------------------------------ */


/* ------------------------------------------------------------ *
 *
 * Pg_proc related security hooks
 *
 * ------------------------------------------------------------ */
static bool
sepgsql_proc_common(Oid procOid, uint32 required, bool abort)
{
	sepgsql_sid_t	sid;
	HeapTuple		tuple;
	uint16			tclass;
	const char	   *auname;
	bool			rc;

	tuple = SearchSysCache(PROCOID,
						   ObjectIdGetDatum(procOid),
						   0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "cache lookup failed for procedure: %u", procOid);

	auname = NameStr(((Form_pg_proc) GETSTRUCT(tuple))->proname);
	sid = sepgsqlGetTupleSecid(ProcedureRelationId, tuple, &tclass);

	rc = sepgsqlClientHasPerms(sid, tclass, required, auname, abort);

	ReleaseSysCache(tuple);

	return rc;
}

/* workaround */
#if 0
void
sepgsqlCheckProcedureInstall(Oid procOid)
{
	if (sepgsqlIsEnabled() && OidIsValid(procOid))
		sepgsql_proc_common(procOid, SEPG_DB_PROCEDURE__INSTALL, true);
}
#endif

Oid
sepgsql_proc_create(const char *procName, Oid procOid,
					Oid nspOid, Oid langOid, DefElem *newLabel)
{
	sepgsql_sid_t	sid;
	HeapTuple		tuple;
	uint32			required;
	bool			trusted;

	if (!sepgsqlIsEnabled())
		return InvalidOid;

	if (!OidIsValid(procOid))
	{
		/* create a new function */
		required = SEPG_DB_PROCEDURE__CREATE;
		if (!newLabel)
			sid = sepgsqlGetDefaultProcedureSecid(nspOid);
		else
		{
			sid.relid = ProcedureRelationId;
			sid.secid = securityTransSecLabelIn(sid.relid, strVal(newLabel->arg));
		}
	}
	else if (!newLabel)
	{
		/* replace an existing function, without any label */
		required = SEPG_DB_PROCEDURE__SETATTR;
		sid = sepgsqlGetSysobjSecid(ProcedureRelationId, procOid, 0, NULL);
	}
	else
	{
		/* replace an existing function, with relabeling */
		sepgsql_proc_common(procOid,
							SEPG_DB_PROCEDURE__SETATTR |
							SEPG_DB_PROCEDURE__RELABELFROM, true);

		required = SEPG_DB_PROCEDURE__RELABELTO;
		sid.relid = ProcedureRelationId;
		sid.secid = securityTransSecLabelIn(sid.relid, strVal(newLabel->arg));
	}

	/* Procedural language is trusted? */
	tuple = SearchSysCache(LANGOID,
						   ObjectIdGetDatum(langOid),
						   0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "cache lookup failed for procedural langugage: %u", langOid);

	trusted = ((Form_pg_language) GETSTRUCT(tuple))->lanpltrusted;
	if (!trusted)
		required |= SEPG_DB_PROCEDURE__UNTRUSTED;

	ReleaseSysCache(tuple);

	/* check it */
	sepgsqlClientHasPerms(sid, SEPG_CLASS_DB_PROCEDURE,
						  required, procName, true);

	return sid.secid;
}

void
sepgsql_proc_alter(Oid procOid, const char *newName, Oid newNsp)
{
	if (!sepgsqlIsEnabled())
		return;

	sepgsql_proc_common(procOid, SEPG_DB_PROCEDURE__SETATTR, true);
	if (newName || OidIsValid(newNsp))
	{
		HeapTuple	tuple;
		Oid			oldNsp;

		tuple = SearchSysCache(PROCOID,
							   ObjectIdGetDatum(procOid),
							   0, 0, 0);
		if (!HeapTupleIsValid(tuple))
			elog(ERROR, "cache lookup failed for function %u", procOid);

		oldNsp = ((Form_pg_proc) GETSTRUCT(tuple))->pronamespace;

		ReleaseSysCache(tuple);

		if (!OidIsValid(newNsp))
		{
			sepgsql_schema_common(oldNsp,
								  SEPG_DB_SCHEMA__ADD_NAME |
								  SEPG_DB_SCHEMA__REMOVE_NAME, true);
		}
		else
		{
			sepgsql_schema_common(oldNsp, SEPG_DB_SCHEMA__REMOVE_NAME, true);
			sepgsql_schema_common(newNsp, SEPG_DB_SCHEMA__ADD_NAME, true);
		}
	}
}

void
sepgsql_proc_drop(Oid procOid)
{
	if (!sepgsqlIsEnabled())
		return;

	sepgsql_proc_common(procOid, SEPG_DB_PROCEDURE__DROP, true);
}

void
sepgsql_proc_grant(Oid procOid)
{
	if (!sepgsqlIsEnabled())
		return;

	sepgsql_proc_common(procOid, SEPG_DB_PROCEDURE__SETATTR, true);
}

Oid
sepgsql_proc_relabel(Oid procOid, DefElem *newLabel)
{
	sepgsql_sid_t	sid;

	if (!sepgsqlIsEnabled())
	{
		if (newLabel)
			ereport(ERROR,
					(errcode(ERRCODE_SELINUX_ERROR),
					 errmsg("SELinux is disabled now")));
		return InvalidOid;
	}

	sid.relid = ProcedureRelationId;
	sid.secid = securityTransSecLabelIn(sid.relid, strVal(newLabel->arg));

	/* db_procedure:{setattr relabelfrom} for older seclabel */
	sepgsql_proc_common(procOid,
						SEPG_DB_PROCEDURE__SETATTR |
						SEPG_DB_PROCEDURE__RELABELFROM, true);
	/* db_procedure:{relabelto} for newer seclabel */
	sepgsqlClientHasPerms(sid,
						  SEPG_CLASS_DB_PROCEDURE,
						  SEPG_DB_PROCEDURE__RELABELTO,
						  get_func_name(procOid), true);
	return sid.secid;
}

void
sepgsql_proc_execute(Oid procOid)
{
	if (!sepgsqlIsEnabled())
		return;

	sepgsql_proc_common(procOid, SEPG_DB_PROCEDURE__EXECUTE, true);
}

bool
sepgsql_proc_hint_inlined(HeapTuple protup)
{
	security_context_t	newcon;
	sepgsql_sid_t		sid;

	if (!sepgsqlIsEnabled())
		return true;

	if (!sepgsql_proc_common(HeapTupleGetOid(protup),
							 SEPG_DB_PROCEDURE__EXECUTE, false))
		return false;
	/*
	 * If the security context of client is unchange
	 * before or after invocation of the functions,
	 * it is not a trusted procedure, so it can be
	 * inlined due to performance purpose.
	 */
	sid = sepgsqlGetTupleSecid(ProcedureRelationId, protup, NULL);

	newcon = sepgsqlClientCreateLabel(sid, SEPG_CLASS_PROCESS);

	if (strcmp(sepgsqlGetClientLabel(), newcon) == 0)
		return true;

	return false;
}

/*
 * sepgsqlCheckProcedureEntrypoint
 *   checks whether the given function call causes domain transition,
 *   or not. If it needs a domain transition, it injects a wrapper
 *   function to invoke it under new domain.
 */
struct TrustedProcedureCache
{
	FmgrInfo	flinfo;
	char		newcon[1];
};

static Datum
sepgsqlTrustedProcedure(PG_FUNCTION_ARGS)
{
	struct TrustedProcedureCache *tcache;
	security_context_t	save_context;
	FmgrInfo		   *save_flinfo;
	Datum				result;

	tcache = fcinfo->flinfo->fn_extra;
	Assert(tcache != NULL);

	save_context = sepgsqlSwitchClient(tcache->newcon);
	save_flinfo = fcinfo->flinfo;
	fcinfo->flinfo = &tcache->flinfo;

	PG_TRY();
	{
		result = FunctionCallInvoke(fcinfo);
	}
	PG_CATCH();
	{
		sepgsqlSwitchClient(save_context);
		fcinfo->flinfo = save_flinfo;
		PG_RE_THROW();
	}
	PG_END_TRY();
	sepgsqlSwitchClient(save_context);
	fcinfo->flinfo = save_flinfo;

	return result;
}

void
sepgsql_proc_entrypoint(FmgrInfo *flinfo, HeapTuple protup)
{
	struct TrustedProcedureCache   *tcache;
	security_context_t	newcon;
	sepgsql_sid_t		proSid;

	if (!sepgsqlIsEnabled())
		return;

	proSid = sepgsqlGetTupleSecid(ProcedureRelationId,
								  protup, NULL);

	newcon = sepgsqlClientCreateLabel(proSid, SEPG_CLASS_PROCESS);

	/* Do nothing, if it is not a trusted procedure */
	if (strcmp(newcon, sepgsqlGetClientLabel()) == 0)
		return;

	/* check db_procedure:{entrypoint} */
	sepgsqlClientHasPerms(proSid,
						  SEPG_CLASS_DB_PROCEDURE,
						  SEPG_DB_PROCEDURE__ENTRYPOINT,
						  NULL, true);

	/* check process:{transition} */
	sepgsqlComputePerms(sepgsqlGetClientLabel(),
						newcon,
						SEPG_CLASS_PROCESS,
						SEPG_PROCESS__TRANSITION,
						NULL, true);

	/* setup trusted procedure */
	tcache = MemoryContextAllocZero(flinfo->fn_mcxt,
							sizeof(*tcache) + strlen(newcon));
	memcpy(&tcache->flinfo, flinfo, sizeof(*flinfo));
	strcpy(tcache->newcon, newcon);
	flinfo->fn_addr = sepgsqlTrustedProcedure;
	flinfo->fn_extra = tcache;
}

/* ------------------------------------------------------------ *
 *
 * Pg_cast related security hooks
 *
 * ------------------------------------------------------------ */
Oid
sepgsql_cast_create(Oid sourceTypOid, Oid targetTypOid, Oid funcOid)
{
	sepgsql_sid_t	sid;
	char			audit_buffer[2*NAMEDATALEN+10];

	if (!sepgsqlIsEnabled())
		return InvalidOid;

	sid = sepgsqlGetDefaultTupleSecid(CastRelationId);

	snprintf(audit_buffer, sizeof(audit_buffer), "%s::%s",
			 format_type_be(sourceTypOid), format_type_be(targetTypOid));

	sepgsqlClientHasPerms(sid, SEPG_CLASS_DB_TUPLE,
						  SEPG_DB_TUPLE__INSERT,
						  audit_buffer, true);

	if (OidIsValid(funcOid))
		sepgsql_proc_common(funcOid, SEPG_DB_PROCEDURE__INSTALL, true);

	return sid.secid;
}

void
sepgsql_cast_drop(Oid castOid)
{
	Form_pg_cast	castForm;
	Relation		rel;
	HeapTuple		tuple;
	ScanKeyData		skey;
	SysScanDesc		scan;
	sepgsql_sid_t	sid;
	uint16			tclass;
	char			audit_buffer[2*NAMEDATALEN+10];

	if (!sepgsqlIsEnabled())
		return;

	rel = heap_open(CastRelationId, AccessShareLock);

	ScanKeyInit(&skey,
				ObjectIdAttributeNumber,
				BTEqualStrategyNumber, F_OIDEQ,
				ObjectIdGetDatum(castOid));

	scan = systable_beginscan(rel, CastOidIndexId, true,
							  SnapshotNow, 1, &skey);
	tuple = systable_getnext(scan);
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "could not find tuple for cast: %u", castOid);

	castForm = (Form_pg_cast) GETSTRUCT(tuple);

	snprintf(audit_buffer, sizeof(audit_buffer), "%s::%s",
			 format_type_be(castForm->castsource),
			 format_type_be(castForm->casttarget));

	sid = sepgsqlGetTupleSecid(CastRelationId, tuple, &tclass);
	sepgsqlClientHasPerms(sid, tclass,
						  SEPG_DB_TUPLE__DELETE,
						  audit_buffer, true);

	systable_endscan(scan);

	heap_close(rel, AccessShareLock);
}

/* ------------------------------------------------------------ *
 *
 * Pg_conversion related security hooks
 *
 * ------------------------------------------------------------ */
Oid
sepgsql_conversion_create(const char *convName, Oid nspOid, Oid procOid)
{
	sepgsql_sid_t	sid;

	if (!sepgsqlIsEnabled())
		return InvalidOid;

	sid = sepgsqlGetDefaultTupleSecid(ConversionRelationId);
	sepgsqlClientHasPerms(sid, SEPG_CLASS_DB_TUPLE,
						  SEPG_DB_TUPLE__INSERT,
						  convName, true);

	/* db_schema:{add_name} */
	sepgsql_schema_common(nspOid, SEPG_DB_SCHEMA__ADD_NAME, true);

	/* db_procedure:{install} */
	sepgsql_proc_common(procOid, SEPG_DB_PROCEDURE__INSTALL, true);

	return sid.secid;
}

void
sepgsql_conversion_alter(Oid convOid, const char *newName)
{
	Form_pg_conversion	convForm;
	HeapTuple		tuple;
	sepgsql_sid_t	sid;
	uint16			tclass;

	if (!sepgsqlIsEnabled())
		return;

	tuple = SearchSysCache(CONVOID,
						   ObjectIdGetDatum(convOid),
						   0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "cache lookup failed for conversion %u", convOid);
	convForm = (Form_pg_conversion) GETSTRUCT(tuple);

	sid = sepgsqlGetTupleSecid(ConversionRelationId, tuple, &tclass);
	sepgsqlClientHasPerms(sid, tclass,
						  SEPG_DB_TUPLE__UPDATE,
						  NameStr(convForm->conname), true);
	if (newName)
	{
		Oid	nspOid = convForm->connamespace;

		sepgsql_schema_common(nspOid,
							  SEPG_DB_SCHEMA__ADD_NAME |
							  SEPG_DB_SCHEMA__REMOVE_NAME, true);
	}
	ReleaseSysCache(tuple);
}

void
sepgsql_conversion_drop(Oid convOid)
{
	Form_pg_conversion	convForm;
	HeapTuple		tuple;
	sepgsql_sid_t	sid;
	uint16			tclass;

	if (!sepgsqlIsEnabled())
		return;

	tuple = SearchSysCache(CONVOID,
						   ObjectIdGetDatum(convOid),
						   0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "cache lookup failed for conversion %u", convOid);
	convForm = (Form_pg_conversion) GETSTRUCT(tuple);

	sid = sepgsqlGetTupleSecid(ConversionRelationId, tuple, &tclass);
	sepgsqlClientHasPerms(sid, tclass,
						  SEPG_DB_TUPLE__UPDATE,
						  NameStr(convForm->conname), true);

	/* db_schema:{remove_name} */
	sepgsql_schema_common(convForm->connamespace,
						  SEPG_DB_SCHEMA__REMOVE_NAME, true);

	ReleaseSysCache(tuple);
}

/* ------------------------------------------------------------ *
 *
 * Pg_foreign_data_wrapper related security hooks
 *
 * ------------------------------------------------------------ */
static bool
sepgsql_fdw_common(Oid fdwOid, uint32 required, bool abort)
{
	Form_pg_foreign_data_wrapper	fdwForm;
	HeapTuple		tuple;
	sepgsql_sid_t	sid;
	uint16			tclass;
	bool			rc;

	tuple = SearchSysCache(FOREIGNDATAWRAPPEROID,
						   ObjectIdGetDatum(fdwOid),
						   0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "cache lookup failed for FDW: %u", fdwOid);
	fdwForm = (Form_pg_foreign_data_wrapper) GETSTRUCT(tuple);

	sid = sepgsqlGetTupleSecid(ForeignDataWrapperRelationId, tuple, &tclass);
	rc = sepgsqlClientHasPerms(sid, tclass, required,
							   NameStr(fdwForm->fdwname), abort);
	ReleaseSysCache(tuple);

	return rc;
}

Oid
sepgsql_fdw_create(const char *fdwName, Oid fdwValidator)
{
	sepgsql_sid_t	sid;

	if (!sepgsqlIsEnabled())
		return InvalidOid;

	sid = sepgsqlGetDefaultTupleSecid(ForeignDataWrapperRelationId);
	sepgsqlClientHasPerms(sid, SEPG_CLASS_DB_TUPLE,
						  SEPG_DB_TUPLE__INSERT,
						  fdwName, true);

	/* db_procedure:{install} */
	if (OidIsValid(fdwValidator))
		sepgsql_proc_common(fdwValidator, SEPG_DB_PROCEDURE__INSTALL, true);

	return sid.secid;
}

void
sepgsql_fdw_alter(Oid fdwOid, Oid newValidator)
{
	sepgsql_fdw_common(fdwOid, SEPG_DB_TUPLE__UPDATE, true);

	/* db_procedure:{install} */
	if (OidIsValid(newValidator))
		sepgsql_proc_common(newValidator, SEPG_DB_PROCEDURE__INSTALL, true);
}

void
sepgsql_fdw_drop(Oid fdwOid)
{
	sepgsql_fdw_common(fdwOid, SEPG_DB_TUPLE__DELETE, true);
}

void
sepgsql_fdw_grant(Oid fdwOid)
{
	sepgsql_fdw_common(fdwOid, SEPG_DB_TUPLE__UPDATE, true);
}

/* ------------------------------------------------------------ *
 *
 * Pg_foreign_server related security hooks
 *
 * ------------------------------------------------------------ */
static bool
sepgsql_foreign_server_common(Oid fsrvOid, uint32 required, bool abort)
{
	Form_pg_foreign_server	fsrvForm;
	HeapTuple		tuple;
	sepgsql_sid_t	sid;
	uint16			tclass;
	bool			rc;

	tuple = SearchSysCache(FOREIGNSERVEROID,
						   ObjectIdGetDatum(fsrvOid),
						   0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "cache lookup failed for foreign server %u", fsrvOid);
	fsrvForm = (Form_pg_foreign_server) GETSTRUCT(tuple);

	sid = sepgsqlGetTupleSecid(ForeignServerRelationId, tuple, &tclass);
    rc = sepgsqlClientHasPerms(sid, tclass, required,
							   NameStr(fsrvForm->srvname), abort);
	ReleaseSysCache(tuple);

	return rc;
}

Oid
sepgsql_foreign_server_create(const char *fsrvName)
{
	sepgsql_sid_t	sid;

	if (!sepgsqlIsEnabled())
		return InvalidOid;

	sid = sepgsqlGetDefaultTupleSecid(ForeignServerRelationId);
	sepgsqlClientHasPerms(sid, SEPG_CLASS_DB_TUPLE,
						  SEPG_DB_TUPLE__INSERT,
						  fsrvName, true);

	return sid.secid;
}

void
sepgsql_foreign_server_alter(Oid fsrvOid)
{
	if (!sepgsqlIsEnabled())
		return;

	sepgsql_foreign_server_common(fsrvOid, SEPG_DB_TUPLE__UPDATE, true);
}

void
sepgsql_foreign_server_drop(Oid fsrvOid)
{
	if (!sepgsqlIsEnabled())
		return;

	sepgsql_foreign_server_common(fsrvOid, SEPG_DB_TUPLE__DELETE, true);
}

void
sepgsql_foreign_server_grant(Oid fsrvOid)
{
	if (!sepgsqlIsEnabled())
		return;

	sepgsql_foreign_server_common(fsrvOid, SEPG_DB_TUPLE__UPDATE, true);
}

/* ------------------------------------------------------------ *
 *
 * Pg_language related security hooks
 *
 * ------------------------------------------------------------ */
static bool
sepgsql_language_common(Oid langOid, uint32 required, bool abort)
{
	Form_pg_language	langForm;
	HeapTuple		tuple;
	sepgsql_sid_t	sid;
	uint16			tclass;
	bool			rc;

	tuple = SearchSysCache(LANGOID,
						   ObjectIdGetDatum(langOid),
						   0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "cache lookup failed for language %u", langOid);
	langForm = (Form_pg_language) GETSTRUCT(tuple);

	sid = sepgsqlGetTupleSecid(LanguageRelationId, tuple, &tclass);
	rc = sepgsqlClientHasPerms(sid, tclass, required,
							   NameStr(langForm->lanname), abort);

	ReleaseSysCache(tuple);

	return rc;
}

Oid
sepgsql_language_create(const char *langName, Oid handlerOid, Oid validatorOid)
{
	sepgsql_sid_t	sid;

	sid = sepgsqlGetDefaultTupleSecid(LanguageRelationId);
	sepgsqlClientHasPerms(sid, SEPG_CLASS_DB_TUPLE,
						  SEPG_DB_TUPLE__INSERT, langName, true);

	/* db_procedure:{install} */
	if (OidIsValid(handlerOid))
		sepgsql_proc_common(handlerOid, SEPG_DB_PROCEDURE__INSTALL, true);
	if (OidIsValid(validatorOid))
		sepgsql_proc_common(validatorOid, SEPG_DB_PROCEDURE__INSTALL, true);

	return sid.secid;
}

void
sepgsql_language_alter(Oid langOid)
{
	if (!sepgsqlIsEnabled())
		return;

	sepgsql_language_common(langOid, SEPG_DB_TUPLE__UPDATE, true);
}

void
sepgsql_language_drop(Oid langOid)
{
	if (!sepgsqlIsEnabled())
		return;

	sepgsql_language_common(langOid, SEPG_DB_TUPLE__DELETE, true);
}

void
sepgsql_language_grant(Oid langOid)
{
	if (!sepgsqlIsEnabled())
		return;

	sepgsql_language_common(langOid, SEPG_DB_TUPLE__UPDATE, true);
}

/* ------------------------------------------------------------ *
 *
 * Pg_opclass related security hooks
 *
 * ------------------------------------------------------------ */
Oid
sepgsql_opclass_create(const char *opcName, Oid nspOid)
{
	sepgsql_sid_t	sid;

	if (!sepgsqlIsEnabled())
		return InvalidOid;

	sid = sepgsqlGetDefaultTupleSecid(OperatorClassRelationId);
	sepgsqlClientHasPerms(sid, SEPG_CLASS_DB_TUPLE,
						  SEPG_DB_TUPLE__INSERT,
						  opcName, true);

	/* db_schema:{add_name} */
	sepgsql_schema_common(nspOid, SEPG_DB_SCHEMA__ADD_NAME, true);

	return sid.secid;
}

void
sepgsql_opclass_alter(Oid opcOid, const char *newName)
{
	Form_pg_opclass	opcForm;
	HeapTuple		tuple;
	sepgsql_sid_t	sid;
	uint16			tclass;

	if (!sepgsqlIsEnabled())
		return;

	tuple = SearchSysCache(CLAOID,
						   ObjectIdGetDatum(opcOid),
						   0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "cache lookup failed for opclass %u", opcOid);
	opcForm = (Form_pg_opclass) GETSTRUCT(tuple);

	sid = sepgsqlGetTupleSecid(OperatorClassRelationId, tuple, &tclass);
	sepgsqlClientHasPerms(sid, tclass,
						  SEPG_DB_TUPLE__UPDATE,
						  NameStr(opcForm->opcname), true);

	/* db_schema:{add_name remove_name} */
	if (newName)
	{
		sepgsql_schema_common(opcForm->opcnamespace,
							  SEPG_DB_SCHEMA__ADD_NAME |
							  SEPG_DB_SCHEMA__REMOVE_NAME, true);
	}
	ReleaseSysCache(tuple);
}

void
sepgsql_opclass_drop(Oid opcOid)
{
	Form_pg_opclass	opcForm;
	HeapTuple		tuple;
	sepgsql_sid_t	sid;
	uint16			tclass;

	if (!sepgsqlIsEnabled())
		return;

	tuple = SearchSysCache(CLAOID,
						   ObjectIdGetDatum(opcOid),
						   0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "cache lookup failed for opclass %u", opcOid);
	opcForm = (Form_pg_opclass) GETSTRUCT(tuple);

	sid = sepgsqlGetTupleSecid(OperatorClassRelationId, tuple, &tclass);
	sepgsqlClientHasPerms(sid, tclass,
						  SEPG_DB_TUPLE__UPDATE,
						  NameStr(opcForm->opcname), true);

	/* db_schema:{remove_name} */
	sepgsql_schema_common(opcForm->opcnamespace,
						  SEPG_DB_SCHEMA__REMOVE_NAME, true);

	ReleaseSysCache(tuple);
}

/* ------------------------------------------------------------ *
 *
 * Pg_opfamily related security hooks
 *
 * ------------------------------------------------------------ */
Oid
sepgsql_opfamily_create(const char *opfName, Oid nspOid)
{
	sepgsql_sid_t	sid;

	if (!sepgsqlIsEnabled())
		return InvalidOid;

	sid = sepgsqlGetDefaultTupleSecid(OperatorFamilyRelationId);
	sepgsqlClientHasPerms(sid, SEPG_CLASS_DB_TUPLE,
						  SEPG_DB_TUPLE__INSERT,
						  opfName, true);

	/* db_schema:{add_name} */
	sepgsql_schema_common(nspOid, SEPG_DB_SCHEMA__ADD_NAME, true);

	return sid.secid;
}

void
sepgsql_opfamily_alter(Oid opfOid, const char *newName)
{
	Form_pg_opfamily	opfForm;
	HeapTuple		tuple;
	sepgsql_sid_t	sid;
	uint16			tclass;

	if (!sepgsqlIsEnabled())
		return;

	tuple = SearchSysCache(OPFAMILYOID,
						   ObjectIdGetDatum(opfOid),
						   0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "cache lookup failed for operator family: %u", opfOid);
	opfForm = (Form_pg_opfamily) GETSTRUCT(tuple);

	sid = sepgsqlGetTupleSecid(OperatorFamilyRelationId, tuple, &tclass);
	sepgsqlClientHasPerms(sid, tclass,
						  SEPG_DB_TUPLE__UPDATE,
						  NameStr(opfForm->opfname), true);
	if (newName)
	{
		sepgsql_schema_common(opfForm->opfnamespace,
							  SEPG_DB_SCHEMA__ADD_NAME |
							  SEPG_DB_SCHEMA__REMOVE_NAME, true);
	}
	ReleaseSysCache(tuple);
}

void
sepgsql_opfamily_drop(Oid opfOid)
{
	Form_pg_opfamily	opfForm;
    HeapTuple			tuple;
    sepgsql_sid_t		sid;
    uint16				tclass;

	if (!sepgsqlIsEnabled())
		return;

	tuple = SearchSysCache(OPFAMILYOID,
						   ObjectIdGetDatum(opfOid),
						   0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "cache lookup failed for operator family: %u", opfOid);
	opfForm = (Form_pg_opfamily) GETSTRUCT(tuple);

	sid = sepgsqlGetTupleSecid(OperatorFamilyRelationId, tuple, &tclass);
	sepgsqlClientHasPerms(sid, tclass,
						  SEPG_DB_TUPLE__DELETE,
						  NameStr(opfForm->opfname), true);

	/* db_schema:{remove_name} */
	sepgsql_schema_common(opfForm->opfnamespace,
						  SEPG_DB_SCHEMA__REMOVE_NAME, true);

    ReleaseSysCache(tuple);
}

void
sepgsql_opfamily_add_operator(Oid opfOid, Oid operOid)
{
	if (!sepgsqlIsEnabled())
		return;

	/* currently, do nothing here */
}

void
sepgsql_opfamily_add_procedure(Oid opfOid, Oid procOid)
{
	if (!sepgsqlIsEnabled())
		return;

	/*
	 * Note that db_tuple:{setattr} is already checked at the
	 * earlier phase, so db_procedure:{install} is only needed.
	 */
	if (OidIsValid(procOid))
		sepgsql_proc_common(procOid, SEPG_DB_PROCEDURE__INSTALL, true);
}

/* ------------------------------------------------------------ *
 *
 * Pg_operator related security hooks
 *
 * ------------------------------------------------------------ */
static bool
sepgsql_operator_common(Oid oprOid, uint32 required, bool abort)
{
	Form_pg_operator	oprForm;
	HeapTuple			tuple;
	sepgsql_sid_t		sid;
	uint16				tclass;
	bool				rc;

	tuple = SearchSysCache(OPEROID,
						   ObjectIdGetDatum(oprOid),
						   0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "cache lookup failed for operator: %u", oprOid);
	oprForm = (Form_pg_operator) GETSTRUCT(tuple);

	sid = sepgsqlGetTupleSecid(OperatorRelationId, tuple, &tclass);
	rc = sepgsqlClientHasPerms(sid, tclass,
							   SEPG_DB_TUPLE__DELETE,
							   NameStr(oprForm->oprname), abort);

	ReleaseSysCache(tuple);

	return rc;
}

Oid
sepgsql_operator_create(const char *oprName, Oid oprOid, Oid nspOid,
						Oid codeFn, Oid restFn, Oid joinFn)
{
	HeapTuple		tuple;
	sepgsql_sid_t	sid;
	uint32			required;

	if (!sepgsqlIsEnabled())
		return InvalidOid;

	if (!OidIsValid(oprOid))
	{
		sid = sepgsqlGetDefaultTupleSecid(OperatorRelationId);
		required = SEPG_DB_TUPLE__INSERT;
	}
	else
	{
		tuple = SearchSysCache(OPEROID,
							   ObjectIdGetDatum(oprOid),
							   0, 0, 0);
        if (!HeapTupleIsValid(tuple))
            elog(ERROR, "cache lookup failed for operator %u", oprOid);

		sid = sepgsqlGetTupleSecid(OperatorRelationId, tuple, NULL);

		ReleaseSysCache(tuple);

		required = SEPG_DB_TUPLE__UPDATE;
	}

	sepgsqlClientHasPerms(sid, SEPG_CLASS_DB_TUPLE,
						  required, oprName, true);

	/* db_schema:{add_name} checks */
	if (!OidIsValid(oprOid))
		sepgsql_schema_common(nspOid, SEPG_DB_SCHEMA__ADD_NAME, true);

	/* db_procedure:{install} checks */
	if (OidIsValid(codeFn))
		sepgsql_proc_common(codeFn, SEPG_DB_PROCEDURE__INSTALL, true);
	if (OidIsValid(restFn))
		sepgsql_proc_common(restFn, SEPG_DB_PROCEDURE__INSTALL, true);
	if (OidIsValid(joinFn))
		sepgsql_proc_common(joinFn, SEPG_DB_PROCEDURE__INSTALL, true);

	return sid.secid;
}

void
sepgsql_operator_alter(Oid oprOid)
{
	if (!sepgsqlIsEnabled())
		return;

	sepgsql_operator_common(oprOid, SEPG_DB_TUPLE__UPDATE, true);
}

void
sepgsql_operator_drop(Oid oprOid)
{
	if (!sepgsqlIsEnabled())
		return;

	sepgsql_operator_common(oprOid, SEPG_DB_TUPLE__DELETE, true);
}

/* ------------------------------------------------------------ *
 *
 * Pg_trigger related security hooks
 *
 * ------------------------------------------------------------ */
void
sepgsql_trigger_create(Oid relOid, const char *trigName, Oid procOid)
{
	/* db_table:{setattr} */
	// sepgsql_relation_common(relOid, SEPG_DB_TABLE__SETATTR, true);

	/* db_procedure:{install} */
	sepgsql_proc_common(procOid, SEPG_DB_PROCEDURE__INSTALL, true);
}

void
sepgsql_trigger_alter(Oid relOid, const char *trigName)
{
	/* db_table:{setattr} */
	// sepgsql_relation_common(relOid, SEPG_DB_TABLE__SETATTR, true);
}

void
sepgsql_trigger_drop(Oid relOid, const char *trigName)
{
	/* db_table:{setattr} */
	// sepgsql_relation_common(relOid, SEPG_DB_TABLE__SETATTR, true);
}

/* ------------------------------------------------------------ *
 *
 * Pg_type related security hooks
 *
 * ------------------------------------------------------------ */
Oid
sepgsql_type_create(const char *typName, Oid typOid, Oid nspOid,
					Oid inputProc, Oid outputProc, Oid recvProc, Oid sendProc,
					Oid modinProc, Oid modoutProc, Oid analyzeProc)
{
	sepgsql_sid_t	sid;
	uint32			required;

	if (!sepgsqlIsEnabled())
		return InvalidOid;

	if (!OidIsValid(typOid))
	{
		sid = sepgsqlGetDefaultTupleSecid(TypeRelationId);
		required = SEPG_DB_TUPLE__INSERT;
	}
	else
	{
		sid = sepgsqlGetSysobjSecid(TypeRelationId, typOid, 0, NULL);
		required = SEPG_DB_TUPLE__UPDATE;
	}
	sepgsqlClientHasPerms(sid, SEPG_CLASS_DB_TUPLE,
						  required, typName, true);
	/* db_schema:{add_name} */
	sepgsql_schema_common(nspOid, SEPG_DB_SCHEMA__ADD_NAME, true);

	/* db_procedure:{install} */
	if (OidIsValid(inputProc))
		sepgsql_proc_common(inputProc, SEPG_DB_PROCEDURE__INSTALL, true);
	if (OidIsValid(outputProc))
		sepgsql_proc_common(outputProc, SEPG_DB_PROCEDURE__INSTALL, true);
	if (OidIsValid(recvProc))
		sepgsql_proc_common(recvProc, SEPG_DB_PROCEDURE__INSTALL, true);
	if (OidIsValid(sendProc))
		sepgsql_proc_common(sendProc, SEPG_DB_PROCEDURE__INSTALL, true);
	if (OidIsValid(modinProc))
		sepgsql_proc_common(modinProc, SEPG_DB_PROCEDURE__INSTALL, true);
	if (OidIsValid(modoutProc))
		sepgsql_proc_common(modoutProc, SEPG_DB_PROCEDURE__INSTALL, true);
	if (OidIsValid(analyzeProc))
		sepgsql_proc_common(analyzeProc, SEPG_DB_PROCEDURE__INSTALL, true);

	return sid.secid;
}

void
sepgsql_type_alter(Oid typOid, const char *newName, Oid newNsp)
{
	Form_pg_type	typForm;
	HeapTuple		tuple;
	sepgsql_sid_t	sid;
	uint16			tclass;

	if (!sepgsqlIsEnabled())
		return;

	tuple = SearchSysCache(TYPEOID,
						   ObjectIdGetDatum(typOid),
						   0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "cache lookup failed for type: %u", typOid);
	typForm = (Form_pg_type) GETSTRUCT(tuple);

	sid = sepgsqlGetTupleSecid(TypeRelationId, tuple, &tclass);
	sepgsqlClientHasPerms(sid, tclass,
						  SEPG_DB_TUPLE__UPDATE,
						  NameStr(typForm->typname), true);

	if (newName || OidIsValid(newNsp))
	{
		Oid oldNsp = typForm->typnamespace;

		if (!OidIsValid(newNsp))
		{
			sepgsql_schema_common(oldNsp,
								  SEPG_DB_SCHEMA__ADD_NAME |
								  SEPG_DB_SCHEMA__REMOVE_NAME, true);
		}
		else
		{
			sepgsql_schema_common(oldNsp, SEPG_DB_SCHEMA__REMOVE_NAME, true);
			sepgsql_schema_common(newNsp, SEPG_DB_SCHEMA__ADD_NAME, true);
		}
	}
	ReleaseSysCache(tuple);
}

void
sepgsql_type_drop(Oid typOid)
{
	Form_pg_type	typForm;
	HeapTuple		tuple;
	sepgsql_sid_t	sid;
	uint16			tclass;

	if (!sepgsqlIsEnabled())
		return;

	tuple = SearchSysCache(TYPEOID,
						   ObjectIdGetDatum(typOid),
						   0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "cache lookup failed for type: %u", typOid);
	typForm = (Form_pg_type) GETSTRUCT(tuple);

	if (typForm->typtype == TYPTYPE_COMPOSITE ||
		(typForm->typtype == TYPTYPE_BASE && OidIsValid(typForm->typarray)))
	{
		/*
		 * No need to check for composite type and implicitly
		 * declared array type here.
		 */
		ReleaseSysCache(tuple);
		return;
	}

	sid = sepgsqlGetTupleSecid(TypeRelationId, tuple, &tclass);
	sepgsqlClientHasPerms(sid, tclass,
						  SEPG_DB_TUPLE__DELETE,
						  NameStr(typForm->typname), true);

	/* db_schema:{remove_name} */
	sepgsql_schema_common(typForm->typnamespace,
						  SEPG_DB_SCHEMA__REMOVE_NAME, true);

	ReleaseSysCache(tuple);
}




/* ------------------------------------------------------------ *
 *
 * Misc system object related security hooks
 *
 * ------------------------------------------------------------ */

void
sepgsql_sysobj_drop(const ObjectAddress *object)
{
	if (!sepgsqlIsEnabled())
		return;

	switch (object->classId)
	{
	case RelationRelationId:
		if (object->objectSubId == 0)
			/* sepgsql_relation_drop */;
		else
			/* sepgsql_attribute_drop */;
		break;

	case ProcedureRelationId:
		sepgsql_proc_drop(object->objectId);
		break;

	case TypeRelationId:
		sepgsql_type_drop(object->objectId);
		break;

	case CastRelationId:
		sepgsql_cast_drop(object->objectId);
		break;

	case ConversionRelationId:
		sepgsql_conversion_drop(object->objectId);
		break;

	case LanguageRelationId:
		sepgsql_language_drop(object->objectId);
		break;

	case OperatorRelationId:
		sepgsql_operator_drop(object->objectId);
		break;

	case OperatorClassRelationId:
		sepgsql_opclass_drop(object->objectId);
		break;

	case OperatorFamilyRelationId:
		sepgsql_opfamily_drop(object->objectId);
		break;

	case RewriteRelationId:
		break;

	case NamespaceRelationId:
		sepgsql_schema_drop(object->objectId);
		break;

	case TSParserRelationId:
		break;

	case TSDictionaryRelationId:
		break;

	case TSTemplateRelationId:
		break;

	case TSConfigRelationId:
		break;

	case AuthIdRelationId:
		break;

	case DatabaseRelationId:
		break;

	case TableSpaceRelationId:
		break;

	case ForeignDataWrapperRelationId:
		sepgsql_fdw_drop(object->objectId);
		break;

	case ForeignServerRelationId:
		sepgsql_foreign_server_drop(object->objectId);
		break;

	case UserMappingRelationId:
		break;

	default:
		/* do nothing */
		break;
	}
}
