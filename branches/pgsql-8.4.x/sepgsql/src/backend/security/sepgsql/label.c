/*
 * src/backend/security/sepgsql/label.c
 *    SE-PostgreSQL security label management
 *
 * Portions Copyright (c) 1996-2009, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 */
#include "postgres.h"

#include "access/sysattr.h"
#include "access/xact.h"
#include "catalog/catalog.h"
#include "catalog/pg_constraint.h"
#include "catalog/heap.h"
#include "catalog/indexing.h"
#include "catalog/namespace.h"
#include "catalog/pg_aggregate.h"
#include "catalog/pg_amop.h"
#include "catalog/pg_amproc.h"
#include "catalog/pg_attrdef.h"
#include "catalog/pg_attribute.h"
#include "catalog/pg_auth_members.h"
#include "catalog/pg_authid.h"
#include "catalog/pg_cast.h"
#include "catalog/pg_class.h"
#include "catalog/pg_conversion.h"
#include "catalog/pg_database.h"
#include "catalog/pg_description.h"
#include "catalog/pg_enum.h"
#include "catalog/pg_foreign_data_wrapper.h"
#include "catalog/pg_foreign_server.h"
#include "catalog/pg_inherits.h"
#include "catalog/pg_language.h"
#include "catalog/pg_largeobject.h"
#include "catalog/pg_namespace.h"
#include "catalog/pg_opclass.h"
#include "catalog/pg_operator.h"
#include "catalog/pg_opfamily.h"
#include "catalog/pg_proc.h"
#include "catalog/pg_rewrite.h"
#include "catalog/pg_security.h"
#include "catalog/pg_shdescription.h"
#include "catalog/pg_statistic.h"
#include "catalog/pg_tablespace.h"
#include "catalog/pg_trigger.h"
#include "catalog/pg_ts_config.h"
#include "catalog/pg_ts_config_map.h"
#include "catalog/pg_ts_dict.h"
#include "catalog/pg_ts_parser.h"
#include "catalog/pg_ts_template.h"
#include "catalog/pg_type.h"
#include "catalog/pg_user_mapping.h"
#include "miscadmin.h"
#include "nodes/makefuncs.h"
#include "security/sepgsql.h"
#include "storage/fd.h"
#include "utils/fmgroids.h"
#include "utils/lsyscache.h"
#include "utils/syscache.h"
#include "utils/tqual.h"

/* GUC: to turn on/off row level controls in SE-PostgreSQL */
bool sepostgresql_row_level;

/* GUC parameter to turn on/off mcstrans */
bool sepostgresql_use_mcstrans;

/*
 * sepgsqlTupleDescHasSecid
 *
 *   returns a hint whether we should allocate a field to store
 *   security label on the given relation, or not.
 */
bool
sepgsqlTupleDescHasSecid(Oid relid, char relkind)
{
	if (!sepgsqlIsEnabled())
		return false;

	if (!OidIsValid(relid))
		return sepostgresql_row_level;	/* Target of SELECT INTO */

	/* These system catalogs always have its secid */
	if (relid == DatabaseRelationId  ||
		relid == NamespaceRelationId ||
		relid == RelationRelationId  ||
		relid == AttributeRelationId ||
		relid == ProcedureRelationId)
		return true;

	/* These system catalogs are an external attributes */
	if (relid == AggregateRelationId				||
		relid == AccessMethodOperatorRelationId		||
		relid == AccessMethodProcedureRelationId	||
		relid == AttrDefaultRelationId				||
		relid == AuthMemRelationId					||
		relid == ConstraintRelationId				||
		relid == DescriptionRelationId				||
		relid == EnumRelationId						||
		relid == IndexRelationId					||
		relid == InheritsRelationId					||
		relid == RewriteRelationId					||
		relid == SecurityRelationId					||
		relid == SharedDescriptionRelationId		||
		relid == StatisticRelationId				||
		relid == TriggerRelationId)
		return false;

	return sepostgresql_row_level;
}

/*
 * sepgsqlGetDefaultDatabaseSecid
 *   It returns the default security label of a database object.
 */
sepgsql_sid_t
sepgsqlGetDefaultDatabaseSecid(void)
{
	security_context_t	seclabel;
	sepgsql_sid_t		sid;
	char		filename[MAXPGPATH];
	char		buffer[1024], *policy_type, *tmp;
	FILE	   *filp;

	/*
	 * NOTE: when the security policy provide a configuration to
	 * specify the default security context of database object,
	 * we apply is as a default one.
	 * If the configuration is unavailable, we compute the
	 * default security context without any parent object.
	 */
	if (selinux_getpolicytype(&policy_type) < 0)
		goto fallback;

	snprintf(filename, sizeof(filename),
			 "%s%s/contexts/sepgsql_context", selinux_path(), policy_type);
	filp = AllocateFile(filename, PG_BINARY_R);
	if (!filp)
		goto fallback;

	while (fgets(buffer, sizeof(buffer), filp) != NULL)
	{
		tmp = strchr(buffer, '#');
		if (tmp)
			*tmp = '\0';

		seclabel = strtok(buffer, " \t\n\r");
		if (!seclabel)
			continue;

		/* An entry found */
		FreeFile(filp);

		sid.relid = DatabaseRelationId;
		sid.secid = securityTransSecLabelIn(sid.relid, seclabel);

		return sid;
	}
	FreeFile(filp);

fallback:
	seclabel = sepgsqlComputeCreate(sepgsqlGetClientLabel(),
									sepgsqlGetClientLabel(),
									SEPG_CLASS_DB_DATABASE);
	sid.relid = DatabaseRelationId;
	sid.secid = securityTransSecLabelIn(sid.relid, seclabel);

	return sid;
}

static sepgsql_sid_t
defaultSecidWithDatabase(Oid relid, Oid datoid, uint16 tclass)
{
	HeapTuple		tuple;
	sepgsql_sid_t	datsid;

	if (IsBootstrapProcessingMode())
	{
		static sepgsql_sid_t cached = { InvalidOid, InvalidOid };

		if (!SidIsValid(cached))
			cached = sepgsqlGetDefaultDatabaseSecid();
		datsid = cached;
	}
	else
	{
		tuple = SearchSysCache(DATABASEOID,
							   ObjectIdGetDatum(datoid),
							   0, 0, 0);
		if (!HeapTupleIsValid(tuple))
			elog(ERROR, "cache lookup failed for database: %u", datoid);
		datsid.relid = DatabaseRelationId;
		datsid.secid = HeapTupleGetSecid(tuple);
		ReleaseSysCache(tuple);
	}

	return sepgsqlClientCreateSecid(datsid, tclass, relid);
}

sepgsql_sid_t
sepgsqlGetDefaultSchemaSecid(Oid database_oid)
{
	return defaultSecidWithDatabase(NamespaceRelationId,
									database_oid,
									SEPG_CLASS_DB_SCHEMA);
}

static sepgsql_sid_t
defaultSecidWithSchema(Oid relid, Oid nspoid, uint16 tclass)
{
	HeapTuple		tuple;
	sepgsql_sid_t	nspsid;

	if (IsBootstrapProcessingMode())
	{
		static sepgsql_sid_t cached = { InvalidOid, InvalidOid };

		if (!SidIsValid(cached))
			cached = sepgsqlGetDefaultSchemaSecid(MyDatabaseId);

		nspsid = sepgsqlGetDefaultSchemaSecid(MyDatabaseId);
	}
	else
	{
		tuple = SearchSysCache(NAMESPACEOID,
							   ObjectIdGetDatum(nspoid),
							   0, 0, 0);
		if (!HeapTupleIsValid(tuple))
			elog(ERROR, "cache lookup failed for namespace: %u", nspoid);
		nspsid.relid = NamespaceRelationId;
		nspsid.secid = HeapTupleGetSecid(tuple);
		ReleaseSysCache(tuple);
	}

	return sepgsqlClientCreateSecid(nspsid, tclass, relid);
}

sepgsql_sid_t
sepgsqlGetDefaultTableSecid(Oid namespace_oid)
{
	return defaultSecidWithSchema(RelationRelationId,
								  namespace_oid,
								  SEPG_CLASS_DB_TABLE);
}

sepgsql_sid_t
sepgsqlGetDefaultSequenceSecid(Oid namespace_oid)
{
	return defaultSecidWithSchema(RelationRelationId,
								  namespace_oid,
								  SEPG_CLASS_DB_SEQUENCE);
}

sepgsql_sid_t
sepgsqlGetDefaultViewSecid(Oid namespace_oid)
{
	return defaultSecidWithSchema(RelationRelationId,
								  namespace_oid,
								  SEPG_CLASS_DB_VIEW);
}

sepgsql_sid_t
sepgsqlGetDefaultProcedureSecid(Oid namespace_oid)
{
	return defaultSecidWithSchema(ProcedureRelationId,
								  namespace_oid,
								  SEPG_CLASS_DB_PROCEDURE);
}

static sepgsql_sid_t
defaultSecidWithTable(Oid relid, Oid tbloid, security_class_t tclass)
{
	HeapTuple		tuple;
	sepgsql_sid_t	relsid;

	if (IsBootstrapProcessingMode()
		&& (tbloid == TypeRelationId ||
			tbloid == ProcedureRelationId ||
			tbloid == AttributeRelationId ||
			tbloid == RelationRelationId))
	{
		static sepgsql_sid_t cached = { InvalidOid, InvalidOid };

		if (!SidIsValid(cached))
			cached = sepgsqlGetDefaultTableSecid(PG_CATALOG_NAMESPACE);

		relsid = cached;
	}
	else
	{
		tuple = SearchSysCache(RELOID,
							   ObjectIdGetDatum(tbloid),
							   0, 0, 0);
		if (!HeapTupleIsValid(tuple))
			elog(ERROR, "cache lookup failed for relation: %u", tbloid);
		relsid.relid = RelationRelationId;
		relsid.secid = HeapTupleGetSecid(tuple);
		ReleaseSysCache(tuple);
	}

	return sepgsqlClientCreateSecid(relsid, tclass, relid);
}

sepgsql_sid_t
sepgsqlGetDefaultColumnSecid(Oid table_oid)
{
	return defaultSecidWithTable(AttributeRelationId,
								 table_oid,
								 SEPG_CLASS_DB_COLUMN);
}

sepgsql_sid_t
sepgsqlGetDefaultTupleSecid(Oid table_oid)
{
	return defaultSecidWithTable(table_oid,
								 table_oid,
								 SEPG_CLASS_DB_TUPLE);
}

sepgsql_sid_t
sepgsqlGetDefaultBlobSecid(Oid database_oid)
{
	return defaultSecidWithDatabase(LargeObjectRelationId,
									MyDatabaseId,
									SEPG_CLASS_DB_BLOB);
}

void
sepgsqlSetDefaultSecid(Relation rel, HeapTuple tuple)
{
	sepgsql_sid_t	newSid;
	Oid		relOid = RelationGetRelid(rel);
	Oid		nspOid, tblOid;
	char	relkind;

	if (!sepgsqlIsEnabled())
		return;

	if (!HeapTupleHasSecid(tuple))
		return;

	/* initialize */
	newSid.relid = relOid;
	newSid.secid = InvalidOid;

	switch (relOid)
	{
	case DatabaseRelationId:
		newSid = sepgsqlGetDefaultDatabaseSecid();
		break;

	case NamespaceRelationId:
		newSid = sepgsqlGetDefaultSchemaSecid(MyDatabaseId);
		break;

	case RelationRelationId:
		nspOid = ((Form_pg_class) GETSTRUCT(tuple))->relnamespace;
		relkind = ((Form_pg_class) GETSTRUCT(tuple))->relkind;

		switch (relkind)
		{
		case RELKIND_RELATION:
			newSid = sepgsqlGetDefaultTableSecid(nspOid);
			break;

		case RELKIND_SEQUENCE:
			newSid = sepgsqlGetDefaultSequenceSecid(nspOid);
			break;

		case RELKIND_VIEW:
			newSid = sepgsqlGetDefaultViewSecid(nspOid);
			break;

		case RELKIND_INDEX:
			/* no individual security context */
			break;

		default:
			newSid = sepgsqlGetDefaultTupleSecid(nspOid);
			break;
		}

	case ProcedureRelationId:
		nspOid = ((Form_pg_proc) GETSTRUCT(tuple))->pronamespace;
		newSid = sepgsqlGetDefaultProcedureSecid(nspOid);
		break;

	case AttributeRelationId:
		tblOid = ((Form_pg_attribute) GETSTRUCT(tuple))->attrelid;

		/* special handling for initdb phase */
		if (tblOid == TypeRelationId ||
			tblOid == ProcedureRelationId ||
			tblOid == AttributeRelationId ||
			tblOid == RelationRelationId)
			newSid = sepgsqlGetDefaultColumnSecid(tblOid);

		relkind = get_rel_relkind(tblOid);
		if (relkind == RELKIND_RELATION ||
			relkind == RELKIND_TOASTVALUE)
			newSid = sepgsqlGetDefaultColumnSecid(tblOid);

		/* otherwise, it does not have individual security context */
		break;

	case LargeObjectRelationId:
		newSid = sepgsqlGetDefaultBlobSecid(MyDatabaseId);
		break;

	default:
		newSid = sepgsqlGetDefaultTupleSecid(relOid);
		break;
	}

	HeapTupleSetSecid(tuple, newSid.secid);
}

/*
 * sepgsqlGetSysobjSecid
 *
 * It returns a pair of relid/secid for the given OID.
 */
static sepgsql_sid_t
getSysobjSecidDirect(Oid classOid, Oid indexOid, Oid objectId, uint16 *tclass)
{
	sepgsql_sid_t	sid;
	Relation		rel;
	HeapTuple		tup;
	ScanKeyData		skey;
	SysScanDesc		scan;

	rel = heap_open(CastRelationId, AccessShareLock);

	ScanKeyInit(&skey,
				ObjectIdAttributeNumber,
				BTEqualStrategyNumber, F_OIDEQ,
				ObjectIdGetDatum(objectId));

	scan = systable_beginscan(rel, CastOidIndexId, true,
							  SnapshotNow, 1, &skey);
	tup = systable_getnext(scan);

	if (!HeapTupleIsValid(tup))
		elog(ERROR, "system object lookup failed for oid %u on relation %u",
			 objectId, classOid);

	sid = sepgsqlGetTupleSecid(classOid, tup, tclass);

	systable_endscan(scan);

	heap_close(rel, AccessShareLock);

	return sid;
}

sepgsql_sid_t
sepgsqlGetSysobjSecid(Oid classOid, Oid objectId, int32 objsubId, uint16 *tclass)
{
	sepgsql_sid_t	sid;
	HeapTuple		tup;

	switch (classOid)
	{
	case AccessMethodRelationId:
		tup = SearchSysCache(AMOID,
							 ObjectIdGetDatum(objectId),
							 0, 0, 0);
		if (!HeapTupleIsValid(tup))
			elog(ERROR, "cache lookup failed for access method: %u", objectId);
		break;

	case AccessMethodOperatorRelationId:
		return getSysobjSecidDirect(AccessMethodOperatorRelationId,
									AccessMethodOperatorOidIndexId,
									objectId, tclass);

	case AccessMethodProcedureRelationId:
		return getSysobjSecidDirect(AccessMethodProcedureRelationId,
									AccessMethodProcedureOidIndexId,
									objectId, tclass);

	case AuthIdRelationId:
		tup = SearchSysCache(AUTHOID,
							 ObjectIdGetDatum(objectId),
							 0, 0, 0);
		if (!HeapTupleIsValid(tup))
			elog(ERROR, "cache lookup failed for role: %u", objectId);
		break;

	case CastRelationId:
		return getSysobjSecidDirect(CastRelationId,
									CastOidIndexId,
									objectId, tclass);

	case ConstraintRelationId:
		tup = SearchSysCache(CONSTROID,
							 ObjectIdGetDatum(objectId),
							 0, 0, 0);
		if (!HeapTupleIsValid(tup))
			elog(ERROR, "cache lookup failed for constraint: %u", objectId);
		break;

	case ConversionRelationId:
		tup = SearchSysCache(CONVOID,
							 ObjectIdGetDatum(objectId),
							 0, 0, 0);
		if (!HeapTupleIsValid(tup))
			elog(ERROR, "cache lookup failed for conversion: %u", objectId);
		break;

	case DatabaseRelationId:
		tup = SearchSysCache(DATABASEOID,
							 ObjectIdGetDatum(objectId),
							 0, 0, 0);
		if (!HeapTupleIsValid(tup))
			elog(ERROR, "cache lookup failed for database: %u", objectId);
		break;

	case ForeignDataWrapperRelationId:
		tup = SearchSysCache(FOREIGNDATAWRAPPEROID,
							 ObjectIdGetDatum(objectId),
							 0, 0, 0);
		if (!HeapTupleIsValid(tup))
			elog(ERROR, "cache lookup failed for FDW: %u", objectId);
		break;

	case ForeignServerRelationId:
		tup = SearchSysCache(FOREIGNSERVEROID,
							 ObjectIdGetDatum(objectId),
							 0, 0, 0);
		if (!HeapTupleIsValid(tup))
			elog(ERROR, "cache lookup failed for foreign server: %u", objectId);
		break;

	case LanguageRelationId:
		tup = SearchSysCache(LANGOID,
							 ObjectIdGetDatum(objectId),
							 0, 0, 0);
		break;

	case LargeObjectRelationId:
		/* to be replaced by LargeObjectMetaRelationId! */
		{
			Relation		rel;
			ScanKeyData		skey;
			SysScanDesc		scan;

			rel = heap_open(LargeObjectRelationId, AccessShareLock);

			ScanKeyInit(&skey,
						Anum_pg_largeobject_loid,
						BTEqualStrategyNumber, F_OIDEQ,
						ObjectIdGetDatum(objectId));

			scan = systable_beginscan(rel, LargeObjectLOidPNIndexId,
									  true, SnapshotNow, 1, &skey);

			tup = systable_getnext(scan);

			if (!HeapTupleIsValid(tup))
				elog(ERROR, "largeobject %u lookup failed", objectId);

			sid = sepgsqlGetTupleSecid(classOid, tup, tclass);
			systable_endscan(scan);

			heap_close(rel, AccessShareLock);
		}
		return sid;

	case RelationRelationId:
		if (objsubId != 0)
		{
			classOid = AttributeRelationId;
			tup = SearchSysCache(ATTNUM,
								 ObjectIdGetDatum(objectId),
								 Int16GetDatum(objsubId),
								 0, 0);
			if (!HeapTupleIsValid(tup))
				elog(ERROR, "cache lookup failed for attribute %d of relation %u",
					 objsubId, objectId);
		}
		else
		{
			classOid = RelationRelationId;
			tup = SearchSysCache(RELOID,
								 ObjectIdGetDatum(objectId),
								 0, 0, 0);
			if (!HeapTupleIsValid(tup))
				elog(ERROR, "cache lookup failed for relation %u", objectId);
		}
		break;

	case NamespaceRelationId:
		tup = SearchSysCache(NAMESPACEOID,
							 ObjectIdGetDatum(objectId),
							 0, 0, 0);
		if (!HeapTupleIsValid(tup))
			elog(ERROR, "cache lookup failed for schema %u", objectId);
		break;

	case OperatorClassRelationId:
		tup = SearchSysCache(CLAOID,
							 ObjectIdGetDatum(objectId),
							 0, 0, 0);
		if (!HeapTupleIsValid(tup))
			elog(ERROR, "cache lookup failed for opclass %u", objectId);
		break;

	case OperatorFamilyRelationId:
		tup = SearchSysCache(OPFAMILYOID,
							 ObjectIdGetDatum(objectId),
							 0, 0, 0);
		if (!HeapTupleIsValid(tup))
			elog(ERROR, "cache lookup failed for opfamily %u", objectId);
		break;

	case OperatorRelationId:
		tup = SearchSysCache(OPEROID,
							 ObjectIdGetDatum(objectId),
							 0, 0, 0);
		if (!HeapTupleIsValid(tup))
			elog(ERROR, "cache lookup failed for operator %u", objectId);
		break;

	case ProcedureRelationId:
		tup = SearchSysCache(PROCOID,
							 ObjectIdGetDatum(objectId),
							 0, 0, 0);
		if (!HeapTupleIsValid(tup))
			elog(ERROR, "cache lookup failed for procedure %u", objectId);
		break;

	case RewriteRelationId:
		return getSysobjSecidDirect(RewriteRelationId,
									RewriteOidIndexId,
									objectId, tclass);

	case TableSpaceRelationId:
		return getSysobjSecidDirect(TableSpaceRelationId,
									TablespaceOidIndexId,
									objectId, tclass);

	case TriggerRelationId:
		return getSysobjSecidDirect(TriggerRelationId,
									TriggerOidIndexId,
									objectId, tclass);

	case TSConfigRelationId:
		tup = SearchSysCache(TSCONFIGOID,
							 ObjectIdGetDatum(objectId),
							 0, 0, 0);
		if (!HeapTupleIsValid(tup))
			elog(ERROR, "cache lookup failed for text search configuration %u", objectId);
		break;

	case TSDictionaryRelationId:
		tup = SearchSysCache(TSDICTOID,
							 ObjectIdGetDatum(objectId),
							 0, 0, 0);
		if (!HeapTupleIsValid(tup))
			elog(ERROR, "cache lookup failed for text search dictionary %u", objectId);
		break;

	case TSParserRelationId:
		tup = SearchSysCache(TSPARSEROID,
							 ObjectIdGetDatum(objectId),
							 0, 0, 0);
		if (!HeapTupleIsValid(tup))
			elog(ERROR, "cache lookup failed for text search parser %u", objectId);
		break;

	case TSTemplateRelationId:
		tup = SearchSysCache(TSTEMPLATEOID,
							 ObjectIdGetDatum(objectId),
							 0, 0, 0);
		if (!HeapTupleIsValid(tup))
			elog(ERROR, "cache lookup failed for text search template %u", objectId);
		break;

	case TypeRelationId:
		tup = SearchSysCache(TYPEOID,
							 ObjectIdGetDatum(objectId),
							 0, 0, 0);
		if (!HeapTupleIsValid(tup))
			elog(ERROR, "cache lookup failed for type %u", objectId);
		break;

	case UserMappingRelationId:
		tup = SearchSysCache(USERMAPPINGOID,
							 ObjectIdGetDatum(objectId),
							 0, 0, 0);
		if (!HeapTupleIsValid(tup))
			elog(ERROR, "cache lookup failed for user mapping %u", objectId);
		break;

	default:
		elog(ERROR, "unexpected class OID: %u", classOid);
		tup = NULL;	/* for compiler quiet */
		break;
	}

	Assert(HeapTupleIsValid(tup));

	sid = sepgsqlGetTupleSecid(classOid, tup, tclass);

	ReleaseSysCache(tup);

	return sid;
}

/*
 * sepgsqlGetTupleSecid
 *
 * It returns a pair of relid/secid for the given HeapTuple.
 * A few system catalogs is handled as an attribute of other
 * system objects.
 * E.g) pg_attrdef is an attribute of a certain pg_attribute
 */
sepgsql_sid_t
sepgsqlGetTupleSecid(Oid tableOid, HeapTuple tuple, uint16 *tclass)
{
	sepgsql_sid_t	sid;
	HeapTuple		exttup;
	Oid				extid;
	Oid				extcls;
	AttrNumber		extsub;
	char			relkind;

	/* initialize (unlabeled security context) */
	sid.relid = tableOid;
	sid.secid = InvalidOid;
	if (tclass)
		*tclass = SEPG_CLASS_DB_TUPLE;

	switch (tableOid)
	{
	case AggregateRelationId:
		extid = ((Form_pg_aggregate) GETSTRUCT(tuple))->aggfnoid;
		exttup = SearchSysCache(PROCOID,
								ObjectIdGetDatum(extid),
								0, 0, 0);
		if (HeapTupleIsValid(exttup))
		{
			sid = sepgsqlGetTupleSecid(ProcedureRelationId,
									   exttup, tclass);
			ReleaseSysCache(exttup);
		}
		break;

	case AccessMethodOperatorRelationId:
		extid = ((Form_pg_amop) GETSTRUCT(tuple))->amopfamily;
		exttup = SearchSysCache(OPFAMILYOID,
								ObjectIdGetDatum(extid),
								0, 0, 0);
		if (HeapTupleIsValid(exttup))
		{
			sid = sepgsqlGetTupleSecid(OperatorFamilyRelationId,
									   exttup, tclass);
			ReleaseSysCache(exttup);
		}
		break;

	case AccessMethodProcedureRelationId:
		extid = ((Form_pg_amproc) GETSTRUCT(tuple))->amprocfamily;
		exttup = SearchSysCache(OPFAMILYOID,
								ObjectIdGetDatum(extid),
								0, 0, 0);
		if (HeapTupleIsValid(exttup))
		{
			sid = sepgsqlGetTupleSecid(OperatorFamilyRelationId,
									   exttup, tclass);
			ReleaseSysCache(exttup);
		}
		break;

	case AttrDefaultRelationId:
		extid = ((Form_pg_attrdef) GETSTRUCT(tuple))->adrelid;
		extsub = ((Form_pg_attrdef) GETSTRUCT(tuple))->adnum;
		exttup = SearchSysCache(ATTNUM,
								ObjectIdGetDatum(extid),
								Int16GetDatum(extsub),
								0, 0);
		if (HeapTupleIsValid(exttup))
		{
			sid = sepgsqlGetTupleSecid(AttributeRelationId,
									   exttup, tclass);
			ReleaseSysCache(exttup);
		}
		break;

	case AttributeRelationId:
		extid = ((Form_pg_attribute) GETSTRUCT(tuple))->attrelid;
		exttup = SearchSysCache(RELOID,
								ObjectIdGetDatum(extid),
								0, 0, 0);
		if (HeapTupleIsValid(exttup))
		{
			relkind = ((Form_pg_class) GETSTRUCT(exttup))->relkind;

			if (relkind == RELKIND_RELATION ||
				relkind == RELKIND_TOASTVALUE)
				sid.secid = HeapTupleGetSecid(tuple);
			else
				sid = sepgsqlGetTupleSecid(RelationRelationId,
										   exttup, tclass);
			ReleaseSysCache(exttup);
		}
		break;

	case AuthMemRelationId:
		extid = ((Form_pg_auth_members) GETSTRUCT(tuple))->roleid;
		exttup = SearchSysCache(AUTHOID,
								ObjectIdGetDatum(extid),
								0, 0, 0);
		if (HeapTupleIsValid(exttup))
		{
			sid = sepgsqlGetTupleSecid(AuthIdRelationId,
									   exttup, tclass);
			ReleaseSysCache(exttup);
		}
		break;

	case ConstraintRelationId:
		/* CHECK constraint is an attribute of the relation */
		extid = ((Form_pg_constraint) GETSTRUCT(tuple))->conrelid;
		if (OidIsValid(extid))
		{
			exttup = SearchSysCache(RELOID,
									ObjectIdGetDatum(extid),
									0, 0, 0);
			if (HeapTupleIsValid(exttup))
			{
				sid = sepgsqlGetTupleSecid(RelationRelationId,
										   exttup, tclass);
				ReleaseSysCache(exttup);
			}
			break;
		}
		/* DOMAIN constraint is an attribute of the domain type */
		extid = ((Form_pg_constraint) GETSTRUCT(tuple))->contypid;
		if (OidIsValid(extid))
		{
			sid.relid = TypeRelationId;
			exttup = SearchSysCache(TYPEOID,
									ObjectIdGetDatum(extid),
									0, 0, 0);
			if (HeapTupleIsValid(exttup))
			{
				sid = sepgsqlGetTupleSecid(TypeRelationId,
										   exttup, tclass);
				ReleaseSysCache(exttup);
			}
			break;
		}
		/* Database's context for global assertion */
		exttup = SearchSysCache(DATABASEOID,
								ObjectIdGetDatum(MyDatabaseId),
								0, 0, 0);
		if (HeapTupleIsValid(exttup))
		{
			sid = sepgsqlGetTupleSecid(DatabaseRelationId,
									   exttup, tclass);
			ReleaseSysCache(exttup);
		}
		break;

	case DatabaseRelationId:
		sid.secid = HeapTupleGetSecid(tuple);
		if (tclass)
			*tclass = SEPG_CLASS_DB_DATABASE;
		break;

	case DescriptionRelationId:
		/* recursive call */
		extid = ((Form_pg_description) GETSTRUCT(tuple))->objoid;
		extcls = ((Form_pg_description) GETSTRUCT(tuple))->classoid;
		return sepgsqlGetSysobjSecid(extcls, extid, 0, tclass);

	case EnumRelationId:
		extid = ((Form_pg_enum) GETSTRUCT(tuple))->enumtypid;
		exttup = SearchSysCache(TYPEOID,
								ObjectIdGetDatum(extid),
								0, 0, 0);
		if (HeapTupleIsValid(exttup))
		{
			sid = sepgsqlGetTupleSecid(TypeRelationId,
									   exttup, tclass);
			ReleaseSysCache(exttup);
		}
		break;

	case IndexRelationId:
		extid = ((Form_pg_index) GETSTRUCT(tuple))->indrelid;
		exttup = SearchSysCache(RELOID,
								ObjectIdGetDatum(extid),
								0, 0, 0);
		if (HeapTupleIsValid(exttup))
		{
			sid = sepgsqlGetTupleSecid(RelationRelationId,
									   exttup, tclass);
			ReleaseSysCache(exttup);
		}
		break;

	case InheritsRelationId:
		extid = ((Form_pg_inherits) GETSTRUCT(tuple))->inhrelid;
		exttup = SearchSysCache(RELOID,
								ObjectIdGetDatum(extid),
								0, 0, 0);
		if (HeapTupleIsValid(exttup))
		{
			sid = sepgsqlGetTupleSecid(RelationRelationId,
									   exttup, tclass);
			ReleaseSysCache(exttup);
		}
		break;

	case LargeObjectRelationId:
		sid.secid = HeapTupleGetSecid(tuple);
		if (tclass)
			*tclass = SEPG_CLASS_DB_BLOB;
		break;

	case NamespaceRelationId:
		sid.secid = HeapTupleGetSecid(tuple);
		if (tclass)
			*tclass = SEPG_CLASS_DB_SCHEMA;
		break;

	case ProcedureRelationId:
		sid.secid = HeapTupleGetSecid(tuple);
		if (tclass)
			*tclass = SEPG_CLASS_DB_PROCEDURE;
		break;

	case RelationRelationId:
		relkind = ((Form_pg_class) GETSTRUCT(tuple))->relkind;

		switch (relkind)
		{
		case RELKIND_INDEX:
			extid = HeapTupleGetOid(tuple);
			exttup = SearchSysCache(INDEXRELID,
									ObjectIdGetDatum(extid),
									0, 0, 0);
			if (HeapTupleIsValid(exttup))
			{
				sid = sepgsqlGetTupleSecid(IndexRelationId,
										   exttup, tclass);
				ReleaseSysCache(exttup);
			}
			break;

		case RELKIND_RELATION:
			sid.secid = HeapTupleGetSecid(tuple);
			if (tclass)
				*tclass = SEPG_CLASS_DB_TABLE;
			break;

		case RELKIND_SEQUENCE:
			sid.secid = HeapTupleGetSecid(tuple);
			if (tclass)
				*tclass = SEPG_CLASS_DB_SEQUENCE;
			break;
		case RELKIND_VIEW:
			sid.secid = HeapTupleGetSecid(tuple);
			if (tclass)
				*tclass = SEPG_CLASS_DB_VIEW;
			break;
		default:	/* RELKIND_TOASTVALUE, RELKIND_COMPOSITE */
			sid.secid = HeapTupleGetSecid(tuple);
			break;
		}
		break;

	case RewriteRelationId:
		extid = ((Form_pg_rewrite) GETSTRUCT(tuple))->ev_class;
		exttup = SearchSysCache(RELOID,
								ObjectIdGetDatum(extid),
								0, 0, 0);
		if (HeapTupleIsValid(exttup))
		{
			sid = sepgsqlGetTupleSecid(RelationRelationId,
									   exttup, tclass);
			ReleaseSysCache(exttup);
		}
		break;

	case SharedDescriptionRelationId:
		/* recursive invocation */
		extid = ((Form_pg_shdescription) GETSTRUCT(tuple))->objoid;
		extcls = ((Form_pg_shdescription) GETSTRUCT(tuple))->classoid;
		return sepgsqlGetSysobjSecid(extcls, extid, 0, tclass);

	case StatisticRelationId:
		extid = ((Form_pg_statistic) GETSTRUCT(tuple))->starelid;
		extsub = ((Form_pg_statistic) GETSTRUCT(tuple))->staattnum;
		exttup = SearchSysCache(ATTNUM,
								ObjectIdGetDatum(extid),
								Int16GetDatum(extsub),
								0, 0);
		if (HeapTupleIsValid(exttup))
		{
			sid = sepgsqlGetTupleSecid(AttributeRelationId,
									   exttup, tclass);
			ReleaseSysCache(exttup);
		}
		break;

	case TriggerRelationId:
		extid = ((Form_pg_trigger) GETSTRUCT(tuple))->tgrelid;
		exttup = SearchSysCache(RELOID,
								ObjectIdGetDatum(extid),
								0, 0, 0);
		if (HeapTupleIsValid(exttup))
		{
			sid = sepgsqlGetTupleSecid(RelationRelationId,
									   exttup, tclass);
			ReleaseSysCache(exttup);
		}
		break;

	case TSConfigMapRelationId:
		extid = ((Form_pg_ts_config_map) GETSTRUCT(tuple))->mapcfg;
		exttup = SearchSysCache(TSCONFIGOID,
								ObjectIdGetDatum(extid),
								0, 0, 0);
		if (HeapTupleIsValid(exttup))
		{
			sid = sepgsqlGetTupleSecid(TSConfigRelationId,
									   exttup, tclass);
			ReleaseSysCache(exttup);
		}
		break;

	default:
		/* No external lookups (normal case) */
		sid.secid = HeapTupleGetSecid(tuple);
		break;
	}

	return sid;
}

/*
 * sepgsqlRawSecLabelIn
 *   correctness checks for the given security context
 */
char *
sepgsqlRawSecLabelIn(char *seclabel)
{
	if (!sepgsqlIsEnabled())
		return seclabel;

	if (!seclabel || security_check_context_raw(seclabel) < 0)
		ereport(ERROR,
				(errcode(ERRCODE_SELINUX_ERROR),
				 errmsg("Invalid security context: \"%s\"", seclabel)));

	return seclabel;
}

/*
 * sepgsqlRawSecLabelOut
 *   correctness checks for the given security context,
 *   and replace it if invalid security context
 */
char *
sepgsqlRawSecLabelOut(char *seclabel)
{
	if (!sepgsqlIsEnabled())
		return seclabel;

	if (!seclabel || security_check_context_raw(seclabel) < 0)
	{
		security_context_t	unlabeledcon;

		if (security_get_initial_context_raw("unlabeled",
											 &unlabeledcon) < 0)
			ereport(ERROR,
					(errcode(ERRCODE_SELINUX_ERROR),
					 errmsg("Unabled to get unlabeled security context")));
		PG_TRY();
		{
			seclabel = pstrdup(unlabeledcon);
		}
		PG_CATCH();
		{
			freecon(unlabeledcon);
			PG_RE_THROW();
		}
		PG_END_TRY();
		freecon(unlabeledcon);
	}
	return seclabel;
}

/*
 * sepgsqlTransSecLabelIn
 * sepgsqlTransSecLabelOut
 *   translation between human-readable and raw format
 */
char *
sepgsqlTransSecLabelIn(char *seclabel)
{
	security_context_t	rawlabel;
	security_context_t	result;

	if (!sepgsqlIsEnabled() ||
		!sepostgresql_use_mcstrans)
		return seclabel;

	if (selinux_trans_to_raw_context(seclabel, &rawlabel) < 0)
		ereport(ERROR,
				(errcode(ERRCODE_SELINUX_ERROR),
				 errmsg("SELinux: failed to translate \"%s\"", seclabel)));
	PG_TRY();
	{
		result = pstrdup(rawlabel);
	}
	PG_CATCH();
	{
		freecon(rawlabel);
		PG_RE_THROW();
	}
	PG_END_TRY();
	freecon(rawlabel);

	return result;
}

char *
sepgsqlTransSecLabelOut(char *seclabel)
{
	security_context_t	translabel;
	security_context_t	result;

	if (!sepgsqlIsEnabled() ||
		!sepostgresql_use_mcstrans)
		return seclabel;

	if (selinux_raw_to_trans_context(seclabel, &translabel) < 0)
		ereport(ERROR,
				(errcode(ERRCODE_SELINUX_ERROR),
				 errmsg("SELinux: failed to translate \"%s\"", seclabel)));
	PG_TRY();
	{
		result = pstrdup(translabel);
	}
	PG_CATCH();
	{
		freecon(translabel);
		PG_RE_THROW();
	}
	PG_END_TRY();
	freecon(translabel);

	return result;
}

char *
sepgsqlSysattSecLabelOut(Oid relid, HeapTuple tuple)
{
	sepgsql_sid_t	sid;

	sid = sepgsqlGetTupleSecid(relid, tuple, NULL);

	return securityTransSecLabelOut(sid.relid, sid.secid);
}
