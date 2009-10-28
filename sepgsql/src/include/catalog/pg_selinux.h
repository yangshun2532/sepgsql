/* -------------------------------------------------------------------------
 *
 * pg_selinux.h
 *     definition of the system relation to manage security context
 *     of database objects (pg_selinux).
 *
 * Portions Copyright (c) 1996-2009, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * -------------------------------------------------------------------------
 */
#ifndef PG_SELINUX_H
#define PG_SELINUX_H

#include "catalog/genbki.h"

/* ----------------
 *      pg_selinux definition.  cpp turns this into
 *      typedef struct FormData_pg_selinux
 * ----------------
 */

#define SELinuxRelationId	3400

CATALOG(pg_selinux,3400) BKI_SHARED_RELATION
{
	/* OID of database containing object, or 0 if shared relation */
	Oid		seldatid;

	/* OID of table containing object */
	Oid		selrelid;

	/* OID of object itself */
	Oid		selobjid;

	/* column number, or 0 if not used */
	int4	selsubid;

	/* text representation of security context */
	text	selcontext;
} FormData_pg_selinux;

/* ----------------
 *		Form_pg_selinux corresponds to a pointer to a tuple with
 *		the format of pg_class relation.
 * ----------------
 */
typedef FormData_pg_selinux *Form_pg_selinux;

/* ----------------
 *		compiler constants for pg_selinux
 * ----------------
 */
#define Natts_pg_selinux				5
#define Anum_pg_selinux_seldatid		1
#define Anum_pg_selinux_selrelid		2
#define Anum_pg_selinux_selobjid		3
#define Anum_pg_selinux_selsubid		4
#define Anum_pg_selinux_selcontext		5

#endif	/* PG_SELINUX_H */

