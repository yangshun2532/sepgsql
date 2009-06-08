/*
 * src/include/catalog/pg_security.h
 *    Definition of the security label relation (pg_security)
 *
 * Portions Copyright (c) 1996-2009, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 */
#ifndef PG_SHSECURITY_H
#define PG_SHSECURITY_H

#include "catalog/genbki.h"

#define SharedSecurityRelationId        3400

CATALOG(pg_shsecurity,3400) BKI_SHARED_RELATION BKI_WITHOUT_OIDS
{
	/* OID of the table which refers the entry */
	Oid		relid;

	/* Identifier of the security attribute */
	Oid		secid;

	/* 'a' = security_acl, 'l' = security_label */
	char	seckind;

	/* Text representation of security attribute */
	text	secattr;
} FormData_pg_shsecurity;

/*
 * Form_pg_security corresponds to a pointer to a tuple with
 * the format of pg_security relation.
 */
typedef FormData_pg_shsecurity *Form_pg_shsecurity;

/*
 * Compiler constants for pg_shsecurity
 */
#define Natts_pg_shsecurity				4
#define Anum_pg_shsecurity_relid		1
#define Anum_pg_shsecurity_secid		2
#define Anum_pg_shsecurity_seckind		3
#define Anum_pg_shsecurity_secattr		4

#endif		/* PG_SHSECURITY_H */
