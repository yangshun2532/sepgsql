/*
 * pg_security.h
 *    definition of the system "security label" relation (pg_security)
 *
 * Portions Copyright (c) 1996-2009, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 */
#ifndef PG_SECURITY_H
#define PG_SECURITY_H

#define SecurityRelationId		3400

CATALOG(pg_security,3400) BKI_SHARED_RELATION
{
	text		seclabel;		/* text representation of security label */
} FormData_pg_security;

/*
 * Form_pg_security corresponds to a pointer to a tuple with
 * the format of pg_security relation.
 */

typedef FormData_pg_security *Form_pg_security;

/*
 * compiler constants for pg_selinux
 */
#define Natts_pg_security				1
#define Anum_pg_security_seclabel		1

#endif	/* PG_SECURITY_H */
