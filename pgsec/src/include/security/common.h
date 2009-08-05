/*
 * src/include/security/common.h
 *   Common abstraction layer of access controls
 *
 * Portions Copyright (c) 1996-2009, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 */
#ifndef SECURITY_COMMON_H
#define SECURITY_COMMON_H

#include "utils/acl.h"
#include "nodes/bitmapset.h"

/* regular query permissions */
extern bool
ac_relation_perms(Oid relOid, Oid roleId,
				  AclMode requiredPerms,
				  Bitmapset *selectedCols,
				  Bitmapset *modifiedCols,
				  bool abort);
/* pg_dataabse */
extern void
ac_database_create(const char *datName,
				   Oid srcDatOid, bool srcIsTemp,
				   Oid datOwner, Oid datTblspc);
extern void
ac_database_alter(Oid datOid, const char *newName,
				  Oid newTblspc, Oid newOwner, Datum *newAcl);
extern void
ac_database_drop(Oid datOid, bool cascade);

extern void
ac_database_grant(Oid datOid, bool isGrant, AclMode privileges,
				  Oid grantor, AclMode goptions);
extern void
ac_database_connect(Oid datOid);

extern void
ac_database_calculate_size(Oid datOid);

extern void
ac_database_reindex(Oid datOid);

extern void
ac_database_comment(Oid datOid);

/* pg_namespace */
extern void
ac_namespace_create(const char *nspName, Oid nspOwner, bool isTemp);

extern void
ac_namespace_alter(Oid nspOid, const char *newName,
				   Oid newOwner, Datum *newAcl);
extern void
ac_namespace_drop(Oid nspOid, bool cascade);

extern void
ac_namespace_grant(Oid nspOid, bool isGrant, AclMode privs,
				   Oid grantor, AclMode goptions);
extern bool
ac_namespace_search(Oid nspOid, bool abort);

extern void
ac_namespace_comment(Oid nspOid);

#endif
