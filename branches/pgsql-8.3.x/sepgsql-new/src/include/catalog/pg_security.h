/*
 * src/include/catalog/pg_security.h
 *    Definition of the security label relation (pg_security)
 *
 * Copyright (c) 2006 - 2007 KaiGai Kohei <kaigai@kaigai.gr.jp>
 */
#ifndef PG_SECURITY_H
#define PG_SECURITY_H

#include "access/htup.h"
#include "utils/relcache.h"

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

/*
 * functions to translate between security label and identifier
 */
extern void
securityPostBootstrapingMode(void);

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

extern Datum
securityHeapGetSecLabelSysattr(HeapTuple tuple);

#endif   /* PG_SELINUX_H */
