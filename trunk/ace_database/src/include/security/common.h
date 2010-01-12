/*
 * security/common.h
 *
 * Header file for common access controls.
 *
 * Portions Copyright (c) 1996-2010, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 */
#ifndef SECURITY_COMMON_H
#define SECURITY_COMMON_H

#include "utils/acl.h"

/*
 * database.c - hooks related to databases
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

#endif	/* SECURITY_COMMON_H */
