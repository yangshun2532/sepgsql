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

#if 0
/* ------------------------------------------------------------ *
 *   Hooks corresponding to db_blob object class
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
sepgsqlCheckBlobExport(LargeObjectDesc *lobj, const char *filename)
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
	sepgsql_file_write(filename);
}

/*
 * sepgsqlCheckBlobImport
 *   check db_blob:{write import} and file:{read} permission
 */
void
sepgsqlCheckBlobImport(LargeObjectDesc *lobj, const char *filename)
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
	sepgsql_file_read(filename);
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
#endif
