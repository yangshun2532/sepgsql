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

CATALOG(pg_selinux,3400) BKI_SHARED_RELATION BKI_WITHOUT_OIDS
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

#endif	/* PG_SELINUX_H */
