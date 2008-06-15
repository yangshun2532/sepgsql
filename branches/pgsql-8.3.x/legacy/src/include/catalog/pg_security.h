/*
 * src/include/catalog/pg_security.h
 *    Definition of the security label relation (pg_security)
 *
 * Copyright (c) 2006 - 2007 KaiGai Kohei <kaigai@kaigai.gr.jp>
 */
#ifndef PG_SECURITY_H
#define PG_SECURITY_H

#define SecurityRelationId		3400

CATALOG(pg_security,3400) BKI_SHARED_RELATION
{
	text		seclabel;		/* text representation of security label */
} FormData_pg_security;

/* ----------------
 *     Form_pg_security corresponds to a pointer to a tuple with
 *     the format of pg_security relation.
 * ----------------
 */
typedef FormData_pg_security *Form_pg_security;

/* ----------------
 *		compiler constants for pg_selinux
 * ----------------
 */
#define Natts_pg_security				1
#define Anum_pg_security_seclabel		1

#endif   /* PG_SELINUX_H */
