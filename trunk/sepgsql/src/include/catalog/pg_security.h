/*
 * src/include/catalog/pg_security.h
 *    Definition of the security label relation (pg_security)
 *
 * Portions Copyright (c) 1996-2009, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 */
#ifndef PG_SECURITY_H
#define PG_SECURITY_H

#include "access/htup.h"
#include "nodes/parsenodes.h"
#include "utils/acl.h"
#include "utils/relcache.h"

#define SecurityRelationId        3400

CATALOG(pg_security,3400) BKI_SHARED_RELATION
{
	/*
	 * seclabel is a text representation of security identifier
	 */
	text		seclabel;
} FormData_pg_security;

/*
 * Form_pg_security corresponds to a pointer to a tuple with
 * the format of pg_security relation.
 */
typedef FormData_pg_security *Form_pg_security;

/*
 * compiler constants for pg_selinux
 */
#define Natts_pg_security             1
#define Anum_pg_security_seclabel     1

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
securityLookupSecurityId(const char *seclabel);

extern char *
securityLookupSecurityLabel(Oid secid);

extern Oid
securityTransSecLabelIn(char *seclabel);

extern char *
securityTransSecLabelOut(Oid secid);

extern Oid
securityTransRowAclIn(Acl *acl);

extern Acl *
securityTransRowAclOut(Oid secid, Oid relowner);

extern Datum
securityHeapGetRowAclSysattr(HeapTuple tuple);

extern Datum
securityHeapGetSecLabelSysattr(HeapTuple tuple);

#endif		/* PG_SECURITY_H */
