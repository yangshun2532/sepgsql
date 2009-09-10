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

sepgsql_sid_t
sepgsqlGetDefaultSchemaTempSecid(Oid database_oid)
{
	return defaultSecidWithDatabase(NamespaceRelationId,
									database_oid,
									SEPG_CLASS_DB_SCHEMA_TEMP);
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
	Oid				relOid = RelationGetRelid(rel);
	Oid				nspOid, tblOid;
	sepgsql_sid_t	newSid;

	if (!sepgsqlIsEnabled())
		return;

	if (!HeapTupleHasSecid(tuple))
		return;

	switch (sepgsqlTupleObjectClass(relOid, tuple))
	{
	case SEPG_CLASS_DB_DATABASE:
		newSid = sepgsqlGetDefaultDatabaseSecid();
		break;
	case SEPG_CLASS_DB_SCHEMA:
		newSid = sepgsqlGetDefaultSchemaSecid(MyDatabaseId);
		break;
	case SEPG_CLASS_DB_SCHEMA_TEMP:
		newSid = sepgsqlGetDefaultSchemaTempSecid(MyDatabaseId);
		break;
	case SEPG_CLASS_DB_TABLE:
		nspOid = ((Form_pg_class) GETSTRUCT(tuple))->relnamespace;
		newSid = sepgsqlGetDefaultTableSecid(nspOid);
		break;
	case SEPG_CLASS_DB_SEQUENCE:
		nspOid = ((Form_pg_class) GETSTRUCT(tuple))->relnamespace;
		newSid = sepgsqlGetDefaultSequenceSecid(nspOid);
		break;
	case SEPG_CLASS_DB_PROCEDURE:
		nspOid = ((Form_pg_proc) GETSTRUCT(tuple))->pronamespace;
		newSid = sepgsqlGetDefaultProcedureSecid(nspOid);
		break;
	case SEPG_CLASS_DB_COLUMN:
		tblOid = ((Form_pg_attribute) GETSTRUCT(tuple))->attrelid;
		newSid = sepgsqlGetDefaultColumnSecid(tblOid);
		break;
	case SEPG_CLASS_DB_BLOB:
		newSid = sepgsqlGetDefaultBlobSecid(MyDatabaseId);
		break;
	default:
		newSid = sepgsqlGetDefaultTupleSecid(relOid);
		break;
	}

	Assert(newSid.relid == relOid);
	HeapTupleSetSecid(tuple, newSid.secid);
}

/*
 * sepgsqlCreateTableColumn
 *   It returns an array of security identifier for the new table
 *   and columns to be assigned. The corresponding security labels
 *   are already checked for db_table/db_sequence/db_column:{create}
 *   permission.
 *   In the default labeling rule, a column inherits the security
 *   label of its table, but we cannot refer it using system caches,
 *   because the command counter is not incremented under the
 *   heap_create_with_catalog(). Thus, we need to compute and check
 *   them prior to the actual creation of table and columns.
 */
Oid *
sepgsqlCreateTableColumns(CreateStmt *stmt,
						  const char *relname, Oid namespace_oid,
						  TupleDesc tupdesc, char relkind)
{
	sepgsql_sid_t	relsid;
	Oid			   *secLabels = NULL;
	int				index;

	if (!sepgsqlIsEnabled())
		return NULL;

	/*
	 * In the current version, we don't assign any certain security
	 * labels on relations except for tables/sequences.
	 */
	if (relkind != RELKIND_RELATION && relkind != RELKIND_SEQUENCE)
		return NULL;

	/*
	 * The secLabels array stores security identifiers to be assigned
	 * on the new table and columns.
	 * 
	 * secLabels[0] is security identifier of the table.
	 * secLabels[attnum - FirstLowInvalidHeapAttributeNumber]
	 *   is security identifier of columns.
	 */
	secLabels = palloc0(sizeof(Oid) * (tupdesc->natts
							- FirstLowInvalidHeapAttributeNumber));

	/*
	 * SELinux checks db_table/db_sequence:{create}
	 */
	switch (relkind)
	{
	case RELKIND_RELATION:
		if (!stmt || !stmt->secLabel)
			relsid = sepgsqlGetDefaultTableSecid(namespace_oid);
		else
		{
			relsid.relid = RelationRelationId;
			relsid.secid = securityTransSecLabelIn(relsid.relid,
								strVal(((DefElem *)stmt->secLabel)->arg));
		}
		sepgsqlClientHasPerms(relsid,
							  SEPG_CLASS_DB_TABLE,
							  SEPG_DB_TABLE__CREATE,
							  relname, true);
		break;

	case RELKIND_SEQUENCE:
		if (!stmt || !stmt->secLabel)
			relsid = sepgsqlGetDefaultSequenceSecid(namespace_oid);
		else
		{
			relsid.relid = RelationRelationId;
			relsid.secid = securityTransSecLabelIn(relsid.relid,
								strVal(((DefElem *)stmt->secLabel)->arg));
		}
		sepgsqlClientHasPerms(relsid,
							  SEPG_CLASS_DB_SEQUENCE,
							  SEPG_DB_SEQUENCE__CREATE,
							  relname, true);
		break;

	default:
		if (stmt && stmt->secLabel)
			ereport(ERROR,
					(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
					 errmsg("Unable to set security label on \"%s\"", relname)));
		relsid = sepgsqlGetDefaultTupleSecid(RelationRelationId);
		break;
	}
	/* table's security identifier to be assigned on */
	secLabels[0] = relsid.secid;

	/*
	 * SELinux checks db_column:{create}
	 */
	for (index = FirstLowInvalidHeapAttributeNumber + 1;
		 index < tupdesc->natts;
		 index++)
	{
		Form_pg_attribute	attr;
		sepgsql_sid_t	attsid = { InvalidOid, InvalidOid };
		char			attname[NAMEDATALEN * 2 + 3];

		/* skip unnecessary attributes */
		if (index < 0 && (relkind == RELKIND_VIEW ||
						  relkind == RELKIND_COMPOSITE_TYPE))
			continue;
		if (index == ObjectIdAttributeNumber && !tupdesc->tdhasoid)
			continue;

		if (index < 0)
			attr = SystemAttributeDefinition(index, tupdesc->tdhasoid);
		else
			attr = tupdesc->attrs[index];

		/* Is there any given security label? */
		if (stmt)
		{
			ListCell   *l;

			foreach (l, stmt->tableElts)
			{
				ColumnDef  *colDef = lfirst(l);

				if (colDef->secLabel &&
					strcmp(colDef->colname, NameStr(attr->attname)) == 0)
				{
					attsid.relid = AttributeRelationId;
					attsid.secid = securityTransSecLabelIn(attsid.relid,
									strVal(((DefElem *)colDef->secLabel)->arg));
					break;
				}
			}
		}

		switch (relkind)
		{
		case RELKIND_RELATION:
			/* compute default column's label if necessary */
			if (!SidIsValid(attsid))
				attsid = sepgsqlClientCreateSecid(relsid,
												  SEPG_CLASS_DB_COLUMN,
												  AttributeRelationId);

			sprintf(attname, "%s.%s", relname, NameStr(attr->attname));
			sepgsqlClientHasPerms(attsid,
								  SEPG_CLASS_DB_COLUMN,
								  SEPG_DB_COLUMN__CREATE,
								  attname, true);
			break;

		default:
			if (SidIsValid(attsid))
				ereport(ERROR,
						(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
						 errmsg("Unable to set security label on \"%s.%s\"",
								relname, NameStr(attr->attname))));
			attsid = sepgsqlGetDefaultTupleSecid(AttributeRelationId);
			break;
		}
		/* column's security identifier to be assigend on */
		secLabels[index - FirstLowInvalidHeapAttributeNumber] = attsid.secid;
	}
	return secLabels;
}

/*
 * sepgsqlCopyTableColumns
 *   It returns an array of security identifier of table and columns
 *   to be copied on make_new_heap(). It actually create a new temporary
 *   relation and insert all the tuples within original one into the
 *   temporary one, but swap_relation_files() swaps their file nodes.
 *   Thus, there are no changes from the viewpoint of users.
 *   SE-PostgreSQL also does not check and change anything. It simply
 *   copies security identifier of the source relation to the destination
 *   relation.
 */
Oid *
sepgsqlCopyTableColumns(Relation source)
{
	HeapTuple	tuple;
	Oid		   *secLabels;
	Oid			relid = RelationGetRelid(source);
	int			index;

	if (!sepgsqlIsEnabled())
		return PointerGetDatum(NULL);

	/* see the comment at sepgsqlCreateTableColumn*/
	secLabels = palloc0(sizeof(Oid) * (RelationGetDescr(source)->natts
							- FirstLowInvalidHeapAttributeNumber));

	/* copy table's security identifier */
	tuple = SearchSysCache(RELOID,
						   ObjectIdGetDatum(relid),
						   0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "cache lookup failed for relation \"%s\"",
			 RelationGetRelationName(source));

	secLabels[0] = HeapTupleGetSecid(tuple);

	ReleaseSysCache(tuple);

	/* copy column's security identifier */
	for (index = FirstLowInvalidHeapAttributeNumber + 1;
		 index < RelationGetDescr(source)->natts;
		 index++)
	{
		Form_pg_attribute	attr;

		if (index < 0)
			attr = SystemAttributeDefinition(index, true);
		else
			attr = RelationGetDescr(source)->attrs[index];

		tuple = SearchSysCache(ATTNUM,
							   ObjectIdGetDatum(relid),
							   Int16GetDatum(attr->attnum),
							   0, 0);
		if (!HeapTupleIsValid(tuple))
			continue;

		secLabels[index - FirstLowInvalidHeapAttributeNumber]
			= HeapTupleGetSecid(tuple);

		ReleaseSysCache(tuple);
	}

	return secLabels;
}

/*
 * sepgsqlGetSysobjContext
 *
 * It returns a pair of relid/secid for the given OID.
 */
static sepgsql_sid_t
getSysobjContextDirect(Oid classOid, Oid indexOid, Oid objectId, uint16 *tclass)
{
	sepgsql_sid_t	sid = { InvalidOid, InvalidOid };
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

	if (HeapTupleIsValid(tup))
		sid = sepgsqlGetTupleContext(classOid, tup, tclass);

	systable_endscan(scan);

	heap_close(rel, AccessShareLock);

	return sid;
}

sepgsql_sid_t
sepgsqlGetSysobjContext(Oid classOid, Oid objectId, int32 objsubId, uint16 *tclass)
{
	sepgsql_sid_t	sid = { InvalidOid, InvalidOid };
	HeapTuple		tup = NULL;

	switch (classOid)
	{
	case AccessMethodRelationId:
		tup = SearchSysCache(AMOID,
							 ObjectIdGetDatum(objectId),
							 0, 0, 0);
		break;

	case AccessMethodOperatorRelationId:
		return getSysobjContextDirect(AccessMethodOperatorRelationId,
									  AccessMethodOperatorOidIndexId,
									  objectId, tclass);

	case AccessMethodProcedureRelationId:
		return getSysobjContextDirect(AccessMethodProcedureRelationId,
									  AccessMethodProcedureOidIndexId,
									  objectId, tclass);

	case AuthIdRelationId:
		tup = SearchSysCache(AUTHOID,
							 ObjectIdGetDatum(objectId),
							 0, 0, 0);
		break;

	case CastRelationId:
		return getSysobjContextDirect(CastRelationId,
									  CastOidIndexId,
									  objectId, tclass);

	case ConstraintRelationId:
		tup = SearchSysCache(CONSTROID,
							 ObjectIdGetDatum(objectId),
							 0, 0, 0);
		break;

	case ConversionRelationId:
		tup = SearchSysCache(CONVOID,
							 ObjectIdGetDatum(objectId),
							 0, 0, 0);
		break;

	case DatabaseRelationId:
		tup = SearchSysCache(DATABASEOID,
							 ObjectIdGetDatum(objectId),
							 0, 0, 0);
		break;

	case ForeignDataWrapperRelationId:
		tup = SearchSysCache(FOREIGNDATAWRAPPEROID,
							 ObjectIdGetDatum(objectId),
							 0, 0, 0);
		break;

	case ForeignServerRelationId:
		tup = SearchSysCache(FOREIGNSERVEROID,
							 ObjectIdGetDatum(objectId),
							 0, 0, 0);
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

			if (HeapTupleIsValid(tup))
				sid = sepgsqlGetTupleContext(classOid, tup, tclass);

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
		}
		else
		{
			classOid = RelationRelationId;
			tup = SearchSysCache(RELOID,
								 ObjectIdGetDatum(objectId),
								 0, 0, 0);
		}
		break;

	case NamespaceRelationId:
		tup = SearchSysCache(NAMESPACEOID,
							 ObjectIdGetDatum(objectId),
							 0, 0, 0);
		break;

	case OperatorClassRelationId:
		tup = SearchSysCache(CLAOID,
							 ObjectIdGetDatum(objectId),
							 0, 0, 0);
		break;

	case OperatorFamilyRelationId:
		tup = SearchSysCache(OPFAMILYOID,
							 ObjectIdGetDatum(objectId),
							 0, 0, 0);
		break;

	case OperatorRelationId:
		tup = SearchSysCache(OPEROID,
							 ObjectIdGetDatum(objectId),
							 0, 0, 0);
		break;

	case ProcedureRelationId:
		tup = SearchSysCache(PROCOID,
							 ObjectIdGetDatum(objectId),
							 0, 0, 0);
		break;

	case RewriteRelationId:
		return getSysobjContextDirect(RewriteRelationId,
									  RewriteOidIndexId,
									  objectId, tclass);

	case TableSpaceRelationId:
		return getSysobjContextDirect(TableSpaceRelationId,
									  TablespaceOidIndexId,
									  objectId, tclass);

	case TriggerRelationId:
		return getSysobjContextDirect(TriggerRelationId,
									  TriggerOidIndexId,
									  objectId, tclass);

	case TSConfigRelationId:
		tup = SearchSysCache(TSCONFIGOID,
							 ObjectIdGetDatum(objectId),
							 0, 0, 0);
		break;

	case TSDictionaryRelationId:
		tup = SearchSysCache(TSDICTOID,
							 ObjectIdGetDatum(objectId),
							 0, 0, 0);
		break;

	case TSParserRelationId:
		tup = SearchSysCache(TSPARSEROID,
							 ObjectIdGetDatum(objectId),
							 0, 0, 0);
		break;

	case TSTemplateRelationId:
		tup = SearchSysCache(TSTEMPLATEOID,
							 ObjectIdGetDatum(objectId),
							 0, 0, 0);
		break;

	case TypeRelationId:
		tup = SearchSysCache(TYPEOID,
							 ObjectIdGetDatum(objectId),
							 0, 0, 0);
		break;

	case UserMappingRelationId:
		tup = SearchSysCache(USERMAPPINGOID,
							 ObjectIdGetDatum(objectId),
							 0, 0, 0);
		break;

	default:
		elog(ERROR, "unexpected class OID: %u", classOid);
		break;
	}
	
	if (HeapTupleIsValid(tup))
	{
		sid = sepgsqlGetTupleContext(classOid, tup, tclass);
		ReleaseSysCache(tup);
	}

	return sid;
}

/*
 * sepgsqlGetTupleContext
 *
 * It returns a pair of relid/secid for the given HeapTuple.
 * A few system catalogs is handled as an attribute of other
 * system objects.
 * E.g) pg_attrdef is an attribute of a certain pg_attribute
 */
sepgsql_sid_t
sepgsqlGetTupleContext(Oid tableOid, HeapTuple tuple, uint16 *tclass)
{
	sepgsql_sid_t	sid = { InvalidOid, InvalidOid };
	HeapTuple		exttup;
	Oid				extid;
	Oid				extcls;
	AttrNumber		extsub;

	if (tclass)
		*tclass = SEPG_CLASS_DB_TUPLE;

	switch (tableOid)
	{
	case AggregateRelationId:
		sid.relid = ProcedureRelationId;
		extid = ((Form_pg_aggregate) GETSTRUCT(tuple))->aggfnoid;
		exttup = SearchSysCache(PROCOID,
								ObjectIdGetDatum(extid),
								0, 0, 0);
		break;

	case AccessMethodOperatorRelationId:
		sid.relid = OperatorFamilyRelationId;
		extid = ((Form_pg_amop) GETSTRUCT(tuple))->amopfamily;
		exttup = SearchSysCache(OPFAMILYOID,
								ObjectIdGetDatum(extid),
								0, 0, 0);
		break;

	case AccessMethodProcedureRelationId:
		sid.relid = OperatorFamilyRelationId;
		extid = ((Form_pg_amproc) GETSTRUCT(tuple))->amprocfamily;
		exttup = SearchSysCache(OPFAMILYOID,
								ObjectIdGetDatum(extid),
								0, 0, 0);
		break;

	case AttrDefaultRelationId:
		sid.relid = AttributeRelationId;
		extid = ((Form_pg_attrdef) GETSTRUCT(tuple))->adrelid;
		extsub = ((Form_pg_attrdef) GETSTRUCT(tuple))->adnum;
		exttup = SearchSysCache(ATTNUM,
								ObjectIdGetDatum(extid),
								Int16GetDatum(extsub),
								0, 0);
		break;

	case AuthMemRelationId:
		sid.relid = AuthIdRelationId;
		extid = ((Form_pg_auth_members) GETSTRUCT(tuple))->roleid;
		exttup = SearchSysCache(AUTHOID,
								ObjectIdGetDatum(extid),
								0, 0, 0);
		break;

	case ConstraintRelationId:
		/* CHECK constraint is an attribute of the relation */
		extid = ((Form_pg_constraint) GETSTRUCT(tuple))->conrelid;
		if (OidIsValid(extid))
		{
			sid.relid = RelationRelationId;
			exttup = SearchSysCache(RELOID,
									ObjectIdGetDatum(extid),
									0, 0, 0);
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
			break;
		}
		/* Database's context for global assertion */
		sid.relid = DatabaseRelationId;
		exttup = SearchSysCache(DATABASEOID,
								ObjectIdGetDatum(MyDatabaseId),
								0, 0, 0);
		break;

	case DescriptionRelationId:
		/* recursive call */
		extid = ((Form_pg_description) GETSTRUCT(tuple))->objoid;
		extcls = ((Form_pg_description) GETSTRUCT(tuple))->classoid;
		return sepgsqlGetSysobjContext(extcls, extid, 0, tclass);

	case EnumRelationId:
		sid.relid = TypeRelationId;
		extid = ((Form_pg_enum) GETSTRUCT(tuple))->enumtypid;
		exttup = SearchSysCache(TYPEOID,
								ObjectIdGetDatum(extid),
								0, 0, 0);
		break;

	case IndexRelationId:
		sid.relid = RelationRelationId;
		extid = ((Form_pg_index) GETSTRUCT(tuple))->indexrelid;
		exttup = SearchSysCache(RELOID,
								ObjectIdGetDatum(extid),
								0, 0, 0);
		break;

	case InheritsRelationId:
		sid.relid = RelationRelationId;
		extid = ((Form_pg_inherits) GETSTRUCT(tuple))->inhrelid;
		exttup = SearchSysCache(RELOID,
								ObjectIdGetDatum(extid),
								0, 0, 0);
		break;

	case RewriteRelationId:
		sid.relid = RelationRelationId;
		extid = ((Form_pg_rewrite) GETSTRUCT(tuple))->ev_class;
		exttup = SearchSysCache(RELOID,
								ObjectIdGetDatum(extid),
								0, 0, 0);
		break;

	case SharedDescriptionRelationId:
		/* recursive invocation */
		extid = ((Form_pg_shdescription) GETSTRUCT(tuple))->objoid;
		extcls = ((Form_pg_shdescription) GETSTRUCT(tuple))->classoid;
		return sepgsqlGetSysobjContext(extcls, extid, 0, tclass);

	case StatisticRelationId:
		sid.relid = AttributeRelationId;
		extid = ((Form_pg_statistic) GETSTRUCT(tuple))->starelid;
		extsub = ((Form_pg_statistic) GETSTRUCT(tuple))->staattnum;
		exttup = SearchSysCache(ATTNUM,
								ObjectIdGetDatum(extid),
								Int16GetDatum(extsub),
								0, 0);
		break;

	case TriggerRelationId:
		sid.relid = RelationRelationId;
		extid = ((Form_pg_trigger) GETSTRUCT(tuple))->tgrelid;
		exttup = SearchSysCache(RELOID,
								ObjectIdGetDatum(extid),
								0, 0, 0);
		break;

	default:
		exttup = tuple;
		sid.relid = tableOid;
		break;
	}

	if (HeapTupleIsValid(exttup))
	{
		sid.secid = HeapTupleGetSecid(exttup);

		if (tclass)
			*tclass = sepgsqlTupleObjectClass(sid.relid, exttup);

		if (exttup != tuple)
			ReleaseSysCache(exttup);
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

	sid = sepgsqlGetTupleContext(relid, tuple, NULL);

	return securityTransSecLabelOut(sid.relid, sid.secid);
}
