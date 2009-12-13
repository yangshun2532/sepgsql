/*
 * security/ace.h
 *
 * Header file of the ACE framework
 *
 * Portions Copyright (c) 1996-2010, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 */
#ifndef SECURITY_ACE_H
#define SECURITY_ACE_H

#include "utils/acl.h"

/* ace_misc.c */
extern void
ace_provider_initialize(void);

/* ace_database.c */
extern void
ace_database_create(const char *datName,
					Oid srcDatOid, bool srcIsTemplate,
                    Oid datOwner, Oid datTblspc);
extern void
ace_database_alter(Oid datOid, const char *newName,
                   Oid newTblspc, Oid newOwner);
extern void
ace_database_drop(Oid datOid, bool cascade);
extern void
ace_database_grant(Oid datOid, Oid grantor, AclMode goptions);
extern void
ace_database_comment(Oid datOid);
extern void
ace_database_connect(Oid datOid);
extern void
ace_database_reindex(Oid datOid);
extern void
ace_database_calculate_size(Oid datOid);

/* ace_schema.c */
extern void
ace_schema_create(const char *nspName, Oid nspOwner, bool isTemp);
extern void
ace_schema_alter(Oid nspOid, const char *newName, Oid newOwner);
extern void
ace_schema_drop(Oid nspOid, bool cascade);
extern void
ace_schema_grant(Oid nspOid, Oid grantor, AclMode goptions);
extern bool
ace_schema_search(Oid nspOid, bool abort);
extern void
ace_schema_comment(Oid nspOid);

#endif	/* SECURITY_ACE_H */
