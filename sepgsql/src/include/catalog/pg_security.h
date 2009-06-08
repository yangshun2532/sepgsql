/*
 * src/include/catalog/pg_security.h
 *    Definition of the security label relation (pg_security)
 *
 * Portions Copyright (c) 1996-2009, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 */
#ifndef PG_SECURITY_H
#define PG_SECURITY_H

#include "catalog/genbki.h"

#include "access/htup.h"
#include "nodes/parsenodes.h"
#include "utils/acl.h"
#include "utils/relcache.h"

#define SecurityRelationId        3405

CATALOG(pg_security,3405) BKI_WITHOUT_OIDS
{
	/* Identifier of the security attribute */
	Oid		secid;

	/* OID of the table which refers the entry */
	Oid		relid;

	/* 'a' = security_acl, 'l' = security_label */
	char	seckind;

	/* Text representation of security attribute */
	text	secattr;
} FormData_pg_security;

/*
 * Form_pg_security corresponds to a pointer to a tuple with
 * the format of pg_security relation.
 */
typedef FormData_pg_security *Form_pg_security;

/*
 * Compiler constants for pg_security
 */
#define Natts_pg_security				4
#define Anum_pg_security_secid			1
#define Anum_pg_security_relid			2
#define Anum_pg_security_seckind		3
#define Anum_pg_security_secattr		4

/*
 * Compiler constants for pg_security.seckind
 */
#define SECKIND_SECURITY_ACL			'a'
#define SECKIND_SECURITY_LABEL			'l'

/*
 * Functions to translate between security label and identifier
 */
extern void
securityPostBootstrapingMode(void);

extern bool
securityTupleDescHasRowAcl(Relation rel);

extern bool
securityTupleDescHasSecLabel(Relation rel);

extern Oid
securityRawSecLabelIn(Oid relid, char *seclabel);

extern char *
securityRawSecLabelOut(Oid relid, Oid secid);

extern Oid
securityTransSecLabelIn(Oid relid, char *seclabel);

extern char *
securityTransSecLabelOut(Oid relid, Oid secid);

extern Oid
securityTransRowAclIn(Oid relid, Acl *acl);

extern Acl *
securityTransRowAclOut(Oid relid, Oid secid, Oid ownid);

extern Datum
securityHeapGetRowAclSysattr(HeapTuple tuple);

extern Datum
securityHeapGetSecLabelSysattr(HeapTuple tuple);

extern void
securityReclaimOnTableDrop(Oid relid);

extern Datum
security_reclaim_acl(PG_FUNCTION_ARGS);

extern Datum
security_reclaim_table_acl(PG_FUNCTION_ARGS);

extern Datum
security_reclaim_label(PG_FUNCTION_ARGS);

extern Datum
security_reclaim_table_label(PG_FUNCTION_ARGS);

#endif		/* PG_SECURITY_H */
