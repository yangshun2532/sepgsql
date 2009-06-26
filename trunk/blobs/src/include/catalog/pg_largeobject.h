/*-------------------------------------------------------------------------
 *
 * pg_largeobject.h
 *	  definition of the system "largeobject" relation (pg_largeobject)
 *	  along with the relation's initial contents.
 *
 *
 * Portions Copyright (c) 1996-2009, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * $PostgreSQL: pgsql/src/include/catalog/pg_largeobject.h,v 1.24 2009/01/01 17:23:57 momjian Exp $
 *
 * NOTES
 *	  the genbki.sh script reads this file and generates .bki
 *	  information from the DATA() statements.
 *
 *-------------------------------------------------------------------------
 */
#ifndef PG_LARGEOBJECT_H
#define PG_LARGEOBJECT_H

#include "catalog/genbki.h"

/* ----------------
 *		pg_largeobject definition.	cpp turns this into
 *		typedef struct FormData_pg_largeobject
 * ----------------
 */
#define LargeObjectRelationId  2613

CATALOG(pg_largeobject,2613)
{
	Oid			lonsp;			/* OID of the namespace */

	Oid			loowner;		/* OID of the owner */

	aclitem		loacl[1];		/* access permissions */
} FormData_pg_largeobject;

/* ----------------
 *		Form_pg_largeobject corresponds to a pointer to a tuple with
 *		the format of pg_largeobject relation.
 * ----------------
 */
typedef FormData_pg_largeobject *Form_pg_largeobject;

/* ----------------
 *		compiler constants for pg_largeobject
 * ----------------
 */
#define Natts_pg_largeobject			3
#define Anum_pg_largeobject_lonsp		1
#define Anum_pg_largeobject_loowner		2
#define Anum_pg_largeobject_loacl		3

extern void LargeObjectCreate(Oid loid, Oid lonsp, Oid loowner);
extern void LargeObjectDrop(Oid loid);
extern bool LargeObjectExists(Oid loid);
extern const char *LargeObjectGetName(Oid loid);
extern void LargeObjectAlterNamespace(List *loid_list, const char *newschema);
extern void LargeObjectAlterOwner(List *loid_list, Oid newowner);

#endif   /* PG_LARGEOBJECT_H */
