/*
 * src/include/utils/security.h
 *
 *   Headers for common access control facilities
 *
 * Portions Copyright (c) 1996-2009, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 */
#ifndef UTILS_SECURITY_H
#define UTILS_SECURITY_H


/* pg_rewrite */
extern void
ac_rule_create(Oid relOid, const char *ruleName);
extern void
ac_rule_drop(Oid relOid, const char *ruleName, bool cascade);
extern void
ac_rule_comment(Oid relOid, const char *ruleName);
extern void
ac_rule_toggle(Oid relOid, const char *ruleName, char fire_when);

#endif	/* UTILS_SECURITY_H */
