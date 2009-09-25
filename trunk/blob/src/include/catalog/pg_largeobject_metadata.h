/*-------------------------------------------------------------------------
 *
 * pg_largeobject_meta.h
 *	  definition of the system "largeobject_meta" relation (pg_largeobject_meta)
 *	  along with the relation's initial contents.
 *
 *
 * Portions Copyright (c) 1996-2009, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * $PostgreSQL: pgsql/src/include/catalog/pg_largeobject_meta.h,v 1.24 2009/01/01 17:23:57 momjian Exp $
 *
 * NOTES
 *	  the genbki.sh script reads this file and generates .bki
 *	  information from the DATA() statements.
 *
 *-------------------------------------------------------------------------
 */
#ifndef PG_LARGEOBJECT_META_H
#define PG_LARGEOBJECT_META_H

#include "catalog/genbki.h"

/* ----------------
 *		pg_largeobject definition.	cpp turns this into
 *		typedef struct FormData_pg_largeobject_meta
 * ----------------
 */
#define LargeObjectMetadataRelationId  2336

CATALOG(pg_largeobject_metadata,2336)
{
	Oid			lomowner;		/* OID of the largeobject owner */
	aclitem		lomacl[1];		/* access permissions */
} FormData_pg_largeobject_metadata;

/* ----------------
 *		Form_pg_largeobject_metadata corresponds to a pointer to a tuple
 *		with the format of pg_largeobject_metadata relation.
 * ----------------
 */
typedef FormData_pg_largeobject_metadata *Form_pg_largeobject_metadata;

/* ----------------
 *		compiler constants for pg_largeobject_metadata
 * ----------------
 */
#define Natts_pg_largeobject_metadata			2
#define Anum_pg_largeobject_metadata_lomowner	1
#define Anum_pg_largeobject_metadata_lomacl		2

extern Oid  CreateLargeObject(Oid loid);
extern void DropLargeObject(Oid loid);
extern void AlterLargeObjectOwner(Oid loid, Oid newOwnerId);

/* to be moved to backend/security/access_control.c */
extern bool ac_largeobject_check_acl;
extern void ac_largeobject_create(Oid loid);
extern void ac_largeobject_alter(Oid loid, Oid newOwner);
extern void ac_largeobject_drop(Oid loid, bool dacSkip);
extern void ac_largeobject_comment(Oid loid);
extern void ac_largeobject_read(Oid loid);
extern void ac_largeobject_write(Oid loid);
extern void ac_largeobject_export(Oid loid, const char *filename);
extern void ac_largeobject_import(Oid loid, const char *filename);

#endif   /* PG_LARGEOBJECT_META_H */
