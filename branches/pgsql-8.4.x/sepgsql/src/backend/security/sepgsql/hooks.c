/*
 * src/backend/security/sepgsql/hooks.c
 *    SE-PostgreSQL security hooks
 *
 * Portions Copyright (c) 1996-2009, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 */
#include "postgres.h"

#include "catalog/indexing.h"
#include "catalog/namespace.h"
#include "catalog/pg_database.h"
#include "catalog/pg_foreign_data_wrapper.h"
#include "catalog/pg_language.h"
#include "catalog/pg_largeobject.h"
#include "catalog/pg_namespace.h"
#include "catalog/pg_opclass.h"
#include "catalog/pg_operator.h"
#include "catalog/pg_opfamily.h"
#include "catalog/pg_proc.h"
#include "catalog/pg_security.h"
#include "catalog/pg_trigger.h"
#include "catalog/pg_ts_dict.h"
#include "catalog/pg_ts_parser.h"
#include "catalog/pg_ts_template.h"
#include "catalog/pg_type.h"
#include "catalog/pg_security.h"
#include "commands/dbcommands.h"
#include "miscadmin.h"
#include "security/sepgsql.h"
#include "utils/builtins.h"
#include "utils/fmgroids.h"
#include "utils/lsyscache.h"
#include "utils/syscache.h"
#include "utils/tqual.h"


/* ------------------------------------------------------------ *
 *   Hooks corresponding to db_column object class
 * ------------------------------------------------------------ */
#if 0
/*
 * NOTE: db_column:{create} is checked on sepgsqlCreateTableColumns()
 *       which is invoked on CREATE TABLE statement.
 *       The sepgsqlCheckColumnCreate() is called on the ALTER TABLE
 *       ... ADD COLUMN path.
 */
Oid
sepgsqlCheckColumnCreate(Oid table_oid, const char *attname, DefElem *newLabel)
{
	sepgsql_sid_t	attSid;
	char			relkind;
	char			auname[NAMEDATALEN * 2 + 3];

	if (!sepgsqlIsEnabled())
	{
		if (newLabel)
			ereport(ERROR,
					(errcode(ERRCODE_SELINUX_ERROR),
					 errmsg("SELinux is disabled now")));
		return InvalidOid;
	}

	relkind = get_rel_relkind(table_oid);
	if (relkind != RELKIND_RELATION)
	{
		if (newLabel)
			ereport(ERROR,
					(errcode(ERRCODE_SELINUX_ERROR),
					 errmsg("Unable to assign security label")));
		return InvalidOid;
	}

	if (!newLabel)
		attSid = sepgsqlGetDefaultColumnSecid(table_oid);
	else
	{
		attSid.relid = AttributeRelationId;
		attSid.secid = securityTransSecLabelIn(attSid.relid,
											   strVal(newLabel->arg));
	}

	sprintf(auname, "%s.%s", get_rel_name(table_oid), attname);
	sepgsqlClientHasPerms(attSid,
						  SEPG_CLASS_DB_COLUMN,
						  SEPG_DB_COLUMN__CREATE,
						  auname, true);
	return attSid.secid;
}

static void
checkColumnCommon(Oid relOid, AttrNumber attno, uint32 required)
{
	Form_pg_attribute	attr;
	sepgsql_sid_t		attSid;
	HeapTuple			tuple;
	uint16				tclass;
	char				auname[2 * NAMEDATALEN + 3];
	char				relkind;

	if (!sepgsqlIsEnabled())
		return;

	relkind = get_rel_relkind(relOid);
	if (relkind != RELKIND_RELATION)
		return;

	tuple = SearchSysCache(ATTNUM,
						   ObjectIdGetDatum(relOid),
						   Int16GetDatum(attno),
						   0, 0);
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "cache lookup failed for attribute %d of relation %u",
			 attno, relOid);

	attr = (Form_pg_attribute) GETSTRUCT(tuple);
	if (!attr->attisdropped)
	{
		sprintf(auname, "%s.%s",
				get_rel_name(relOid),
				NameStr(attr->attname));
		attSid = sepgsqlGetTupleSecid(AttributeRelationId,
									  tuple, &tclass);
		sepgsqlClientHasPerms(attSid, tclass, required,
							  auname, true);
	}

	ReleaseSysCache(tuple);
}

void
sepgsqlCheckColumnDrop(Oid relOid, AttrNumber attno)
{
	checkColumnCommon(relOid, attno, SEPG_DB_COLUMN__DROP);
}

void
sepgsqlCheckColumnSetattr(Oid relOid, AttrNumber attno)
{
	checkColumnCommon(relOid, attno, SEPG_DB_COLUMN__SETATTR);
}

Oid
sepgsqlCheckColumnRelabel(Oid relOid, AttrNumber attno, DefElem *newLabel)
{
	sepgsql_sid_t	attSid;
	char			relkind;

	if (!sepgsqlIsEnabled())
	{
		if (newLabel)
			ereport(ERROR,
					(errcode(ERRCODE_SELINUX_ERROR),
					 errmsg("SELinux is disabled now")));
		return InvalidOid;
	}

	relkind = get_rel_relkind(relOid);
	if (relkind != RELKIND_RELATION)
		ereport(ERROR,
				(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
				 errmsg("Unable to set security label on \"%s.%s\"",
						get_rel_name(relOid),
						get_attname(relOid, attno))));

	attSid.relid = AttributeRelationId;
	attSid.secid = securityTransSecLabelIn(attSid.relid,
										   strVal(newLabel->arg));

	/* db_column:{setattr relabelfrom} for older seclabel */
	checkColumnCommon(relOid, attno,
					  SEPG_DB_COLUMN__SETATTR |
					  SEPG_DB_COLUMN__RELABELFROM);

	/* db_column:{relabelto} for newer seclabel */
	sepgsqlClientHasPerms(attSid,
						  SEPG_CLASS_DB_COLUMN,
						  SEPG_DB_COLUMN__RELABELTO,
						  get_attname(relOid, attno), true);
	return attSid.secid;
}

/* ------------------------------------------------------------ *
 *   Hooks corresponding to db_table object class
 * ------------------------------------------------------------ */

/*
 * NOTE: db_table/db_sequence:{create} permission is checked
 *       at sepgsqlCreateTableColumns() due to the reason
 *       for implementation.
 *
 * sepgsqlCheckTableReference
 *   checks db_table:{reference} and db_column:{reference} permission
 *   when the client tries to set up a foreign key constraint on the
 *   certain tables and columns.
 */

static void
checkTableCommon(Oid table_oid, access_vector_t required)
{
	HeapTuple		tuple;
	sepgsql_sid_t	relSid;
	uint16			tclass;
	const char	   *auname;

	if (!sepgsqlIsEnabled())
		return;

	tuple = SearchSysCache(RELOID,
						   ObjectIdGetDatum(table_oid),
						   0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "cache lookup failed for relation %u", table_oid);

	auname = NameStr(((Form_pg_class) GETSTRUCT(tuple))->relname);
	relSid = sepgsqlGetTupleSecid(RelationRelationId,
								  tuple, &tclass);
	sepgsqlClientHasPerms(relSid, tclass, required,
						  auname, true);
	ReleaseSysCache(tuple);
}

void
sepgsqlCheckTableDrop(Oid table_oid)
{
	checkTableCommon(table_oid, SEPG_DB_TABLE__DROP);
}

void
sepgsqlCheckTableSetattr(Oid table_oid)
{
	checkTableCommon(table_oid, SEPG_DB_TABLE__SETATTR);
}

Oid
sepgsqlCheckTableRelabel(Oid table_oid, DefElem *newLabel)
{
	sepgsql_sid_t	relSid;
	char			relkind;

	if (!sepgsqlIsEnabled())
	{
		if (newLabel)
			ereport(ERROR,
					(errcode(ERRCODE_SELINUX_ERROR),
					 errmsg("SELinux is disabled now")));
		return InvalidOid;
	}

	relkind = get_rel_relkind(table_oid);
	if (relkind != RELKIND_RELATION && relkind != RELKIND_SEQUENCE)
		ereport(ERROR,
				(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
				 errmsg("Unable to set security label on \"%s\"",
						get_rel_name(table_oid))));

	relSid.relid = RelationRelationId;
	relSid.secid = securityTransSecLabelIn(relSid.relid,
										   strVal(newLabel->arg));

	/* db_table/db_sequence:{setattr relabelfrom} for older seclabel  */
	checkTableCommon(table_oid,
					 SEPG_DB_TABLE__SETATTR |
					 SEPG_DB_TABLE__RELABELFROM);

	/* db_table/db_sequence:{relabelto} for newer seclabel */
	sepgsqlClientHasPerms(relSid,
						  (relkind == RELKIND_RELATION
						   ? SEPG_CLASS_DB_TABLE
						   : SEPG_CLASS_DB_SEQUENCE),
						  SEPG_DB_TABLE__RELABELTO,
						  get_rel_name(table_oid), true);
	return relSid.secid;
}

void
sepgsqlCheckTableLock(Oid table_oid)
{
	checkTableCommon(table_oid, SEPG_DB_TABLE__LOCK);
}

void
sepgsqlCheckTableTruncate(Relation rel)
{
	HeapScanDesc		scan;
	HeapTuple			tuple;
	sepgsql_sid_t		tupSid;
	uint16				tclass;

	if (!sepgsqlIsEnabled())
		return;

	/* check db_table:{delete} permission */
	checkTableCommon(RelationGetRelid(rel), SEPG_DB_TABLE__DELETE);

	/* row-level access control is enabled? */
	if (!sepostgresql_row_level)
		return;

	/* check db_tuple:{delete} permission */
	scan = heap_beginscan(rel, SnapshotNow, 0, NULL);

	while ((tuple = heap_getnext(scan, ForwardScanDirection)) != NULL)
	{
		tupSid = sepgsqlGetTupleSecid(RelationGetRelid(rel),
									  tuple, &tclass);
		sepgsqlClientHasPerms(tupSid,
							  tclass, SEPG_DB_TUPLE__DELETE,
							  NULL, true);
	}
	heap_endscan(scan);
}

void
sepgsqlCheckTableReference(Relation rel, int16 *attnums, int natts)
{
	int		i;

	checkTableCommon(RelationGetRelid(rel), SEPG_DB_TABLE__REFERENCE);

	for (i=0; i < natts; i++)
	{
		checkColumnCommon(RelationGetRelid(rel),
						  attnums[i], SEPG_DB_COLUMN__REFERENCE);
	}
}

/* ------------------------------------------------------------ *
 *   Hooks corresponding to db_sequence object class
 * ------------------------------------------------------------ */
void sepgsqlCheckSequenceGetValue(Oid seqOid)
{
	checkTableCommon(seqOid, SEPG_DB_SEQUENCE__GET_VALUE);
}

void sepgsqlCheckSequenceNextValue(Oid seqOid)
{
	checkTableCommon(seqOid, SEPG_DB_SEQUENCE__NEXT_VALUE);
}

void sepgsqlCheckSequenceSetValue(Oid seqOid)
{
	checkTableCommon(seqOid, SEPG_DB_SEQUENCE__SET_VALUE);
}
#endif
/* ------------------------------------------------------------ *
 *   Hooks corresponding to db_procedure object class
 * ------------------------------------------------------------ */

/*
 * sepgsqlCheckBlobCreate
 *   assigns a default security label and checks db_blob:{create}
 */
void
sepgsqlCheckBlobCreate(Relation rel, HeapTuple lotup)
{
	sepgsql_sid_t	loSid;
	Oid				relid = RelationGetRelid(rel);

	if (!sepgsqlIsEnabled())
		return;

	/* set a default security context */
	sepgsqlSetDefaultSecid(rel, lotup);

	loSid = sepgsqlGetTupleSecid(relid, lotup, NULL);
	sepgsqlClientHasPerms(loSid,
						  SEPG_CLASS_DB_BLOB,
						  SEPG_DB_BLOB__CREATE,
						  NULL, true);
}

/*
 * sepgsqlCheckBlobDrop
 *   checks db_blob:{drop} permission
 */
void
sepgsqlCheckBlobDrop(Relation rel, HeapTuple lotup)
{
	sepgsql_sid_t	loSid;
	Oid				relid = RelationGetRelid(rel);

	if (!sepgsqlIsEnabled())
		return;

	loSid = sepgsqlGetTupleSecid(relid, lotup, NULL);
	sepgsqlClientHasPerms(loSid,
						  SEPG_CLASS_DB_BLOB,
						  SEPG_DB_BLOB__DROP,
						  NULL, true);
}

/*
 * sepgsqlCheckBlobRead
 *   checks db_blob:{read} permission
 */
void
sepgsqlCheckBlobRead(LargeObjectDesc *lobj)
{
	sepgsql_sid_t	loSid;

	if (!sepgsqlIsEnabled())
		return;

	loSid.relid = LargeObjectRelationId;
	loSid.secid = lobj->secid;
	sepgsqlClientHasPerms(loSid,
						  SEPG_CLASS_DB_BLOB,
						  SEPG_DB_BLOB__READ,
						  NULL, true);
}

/*
 * sepgsqlCheckBlobWrite
 *   check db_blob:{write} permission
 */
void
sepgsqlCheckBlobWrite(LargeObjectDesc *lobj)
{
	sepgsql_sid_t	loSid;

	if (!sepgsqlIsEnabled())
		return;

	loSid.relid = LargeObjectRelationId;
	loSid.secid = lobj->secid;
	sepgsqlClientHasPerms(loSid,
						  SEPG_CLASS_DB_BLOB,
						  SEPG_DB_BLOB__WRITE,
						  NULL, true);
}

/*
 * sepgsqlCheckBlobGetattr
 *   check db_blob:{getattr} permission
 */
void
sepgsqlCheckBlobGetattr(HeapTuple tuple)
{
	sepgsql_sid_t	loSid;

	if (!sepgsqlIsEnabled())
		return;

	loSid.relid = LargeObjectRelationId;
	loSid.secid = HeapTupleGetSecid(tuple);
	sepgsqlClientHasPerms(loSid,
						  SEPG_CLASS_DB_BLOB,
						  SEPG_DB_BLOB__GETATTR,
						  NULL, true);
}

/*
 * sepgsqlCheckBlobSetattr
 *   check db_blob:{setattr} permission
 */
void
sepgsqlCheckBlobSetattr(HeapTuple tuple)
{
	sepgsql_sid_t	loSid;

	if (!sepgsqlIsEnabled())
		return;

	loSid.relid = LargeObjectRelationId;
	loSid.secid = HeapTupleGetSecid(tuple);
	sepgsqlClientHasPerms(loSid,
						  SEPG_CLASS_DB_BLOB,
						  SEPG_DB_BLOB__SETATTR,
						  NULL, true);
}

/*
 * sepgsqlCheckBlobExport
 *   check db_blob:{read export} and file:{write} permission
 */
void
sepgsqlCheckBlobExport(LargeObjectDesc *lobj,
					   int fdesc, const char *filename)
{
	sepgsql_sid_t	loSid;

	if (!sepgsqlIsEnabled())
		return;

	/* db_blob:{read export} */
	loSid.relid = LargeObjectRelationId;
	loSid.secid = lobj->secid;
	sepgsqlClientHasPerms(loSid,
						  SEPG_CLASS_DB_BLOB,
						  SEPG_DB_BLOB__READ | SEPG_DB_BLOB__EXPORT,
						  NULL, true);
	/* file:{write} */
	sepgsqlCheckFileWrite(fdesc, filename);
}

/*
 * sepgsqlCheckBlobImport
 *   check db_blob:{write import} and file:{read} permission
 */
void
sepgsqlCheckBlobImport(LargeObjectDesc *lobj,
					   int fdesc, const char *filename)
{
	sepgsql_sid_t	loSid;

	if (!sepgsqlIsEnabled())
		return;

	/* db_blob:{write import} */
	loSid.relid = LargeObjectRelationId;
	loSid.secid = lobj->secid;
	sepgsqlClientHasPerms(loSid,
						  SEPG_CLASS_DB_BLOB,
						  SEPG_DB_BLOB__WRITE | SEPG_DB_BLOB__IMPORT,
						  NULL, true);
	/* file:{read} */
	sepgsqlCheckFileRead(fdesc, filename);
}

/*
 * sepgsqlCheckBlobRelabel
 *   check db_blob:{setattr relabelfrom relabelto}
 */
void
sepgsqlCheckBlobRelabel(HeapTuple oldtup, HeapTuple newtup)
{
	sepgsql_sid_t		loSid;
	access_vector_t		required = SEPG_DB_BLOB__SETATTR;

	if (HeapTupleGetSecid(oldtup) != HeapTupleGetSecid(newtup))
		required |= SEPG_DB_BLOB__RELABELFROM;

	/* db_blob:{setattr relabelfrom} */
	loSid = sepgsqlGetTupleSecid(LargeObjectRelationId, oldtup, NULL);
	sepgsqlClientHasPerms(loSid,
						  SEPG_CLASS_DB_BLOB,
						  required,
						  NULL, true);

	if ((required & SEPG_DB_BLOB__RELABELFROM) == 0)
		return;

	/* db_blob:{relabelto} */
	loSid = sepgsqlGetTupleSecid(LargeObjectRelationId, newtup, NULL);
	sepgsqlClientHasPerms(loSid,
						  SEPG_CLASS_DB_BLOB,
						  SEPG_DB_BLOB__RELABELTO,
						  NULL, true);
}

/*
 * sepgsqlCheckFileRead
 * sepgsqlCheckFileWrite
 *   check file:{read} or file:{write} permission on the given file,
 *   and raises an error if violated.
 */
static void
checkFileCommon(int fdesc, const char *filename, access_vector_t perms)
{
	security_context_t	context;
	security_class_t	tclass;

	if (!sepgsqlIsEnabled())
		return;

	tclass = sepgsqlFileObjectClass(fdesc);

	if (fgetfilecon_raw(fdesc, &context) < 0)
		ereport(ERROR,
				(errcode(ERRCODE_SELINUX_ERROR),
				 errmsg("SELinux: could not get context of %s", filename)));
	PG_TRY();
	{
		sepgsqlComputePerms(sepgsqlGetClientLabel(),
							context,
							tclass,
							perms,
							filename, true);
	}
	PG_CATCH();
	{
		freecon(context);
		PG_RE_THROW();
	}
	PG_END_TRY();
	freecon(context);
}

void
sepgsqlCheckFileRead(int fdesc, const char *filename)
{
	checkFileCommon(fdesc, filename, SEPG_FILE__READ);
}

void
sepgsqlCheckFileWrite(int fdesc, const char *filename)
{
	checkFileCommon(fdesc, filename, SEPG_FILE__WRITE);
}
