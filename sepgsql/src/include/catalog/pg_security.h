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

#define SecurityRelationId        3400

CATALOG(pg_security,3400) BKI_SHARED_RELATION BKI_WITHOUT_OIDS
{
	/* Identifier of the security attribute  */
	Oid		secid;

	/* OID of the database which referes the entry */
	Oid		datid;

	/* OID of the table which refers the entry */
	Oid		relid;

	/* See the SECKIND_SECURITY_* definition */
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
#define Natts_pg_security				5
#define Anum_pg_security_secid			1
#define Anum_pg_security_datid			2
#define Anum_pg_security_relid			3
#define Anum_pg_security_seckind		4
#define Anum_pg_security_secattr		5

/*
 * Compiler constants for pg_security.seckind
 */
#define SECKIND_SECURITY_LABEL			'l'

/*
 * Functions to translate between security label and identifier
 */
extern void
securityPostBootstrapingMode(void);

extern void
securityOnCreateDatabase(Oid src_datid, Oid dst_datid);

extern void
securityOnDropDatabase(Oid datid);

extern bool
securityTupleDescHasSecLabel(Oid relid, char relkind);

extern Oid
securityRawSecLabelIn(Oid relid, char *seclabel);

extern char *
securityRawSecLabelOut(Oid relid, Oid secid);

extern Oid
securityTransSecLabelIn(Oid relid, char *seclabel);

extern char *
securityTransSecLabelOut(Oid relid, Oid secid);

extern Oid
securityMoveSecLabel(Oid dst_relid, Oid src_relid, Oid secid);

Datum
securityHeapGetSecLabelSysattr(HeapTuple tuple);

extern void
securityReclaimOnDropTable(Oid relid);

extern Datum
security_reclaim_label(PG_FUNCTION_ARGS);

extern Datum
security_reclaim_table_label(PG_FUNCTION_ARGS);

extern Datum
security_label_to_secid(PG_FUNCTION_ARGS);

#endif		/* PG_SECURITY_H */
