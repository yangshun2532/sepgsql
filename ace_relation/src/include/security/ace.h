/*
 * ace.h
 *
 * Header file for the ACE framework
 *
 * Portions Copyright (c) 1996-2010, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 */
#ifndef SECURITY_ACE_H
#define SECURITY_ACE_H

#include "utils/acl.h"

/*
 * ace_misc.c - miscellaneous security hook routines
 */
extern void
check_provider_initialize(void);

/*
 * ace_database.c - hooks related to databases
 */
extern void
check_database_create(const char *datName, Oid srcDatOid,
					  Oid datOwner, Oid datTblspc);
extern void
check_database_alter(Oid datOid);
extern void
check_database_alter_rename(Oid datOid, const char *newName);
extern void
check_database_alter_owner(Oid datOid, Oid newOwner);
extern void
check_database_alter_tablespace(Oid datOid, Oid newTblspc);
extern void
check_database_drop(Oid datOid, bool cascade);
extern void
check_database_getattr(Oid datOid);
extern void
check_database_grant(Oid datOid);
extern void
check_database_comment(Oid datOid);
extern void
check_database_connect(Oid datOid);
extern void
check_database_reindex(Oid datOid);

/*
 * ace_schema.c - hooks related to schema
 */
extern void
check_schema_create(const char *nspName, Oid nspOwner, bool isTemp);
extern void
check_schema_alter_rename(Oid nspOid, const char *newName);
extern void
check_schema_alter_owner(Oid nspOid, Oid newOwner);
extern void
check_schema_drop(Oid nspOid, bool cascade);
extern void
check_schema_grant(Oid nspOid);
extern bool
check_schema_search(Oid nspOid, bool abort);
extern void
check_schema_comment(Oid nspOid);

#endif	/* SECURITY_ACE_H */
