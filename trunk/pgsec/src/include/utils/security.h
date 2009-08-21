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

/* pg_ts_config */
extern void
ac_ts_config_create(const char *cfgName, Oid cfgNsp);
extern void
ac_ts_config_alter(Oid cfgOid, const char *newName, Oid newOwner);
extern void
ac_ts_config_drop(Oid cfgOid, bool cascade);
extern void
ac_ts_config_comment(Oid cfgOid);

/* pg_ts_dict */
extern void
ac_ts_dict_create(const char *dictName, Oid dictNsp);
extern void
ac_ts_dict_alter(Oid dictOid, const char *newName, Oid newOwner);
extern void
ac_ts_dict_drop(Oid dictOid, bool cascade);
extern void
ac_ts_dict_comment(Oid dictOid);

/* pg_ts_parser */
extern void
ac_ts_parser_create(const char *prsName, Oid prsNsp,
					Oid startFn, Oid tokenFn, Oid sendFn,
					Oid headlineFn, Oid lextypeFn);
extern void
ac_ts_parser_alter(Oid prsOid, const char *newName);
extern void
ac_ts_parser_drop(Oid prsOid, bool cascade);
extern void
ac_ts_parser_comment(Oid prsOid);

/* pg_ts_template */
extern void
ac_ts_template_create(const char *tmplName, Oid tmplNsp,
                      Oid initFn, Oid lexizeFn);
extern void
ac_ts_template_alter(Oid tmplOid, const char *newName);
extern void
ac_ts_template_drop(Oid tmplOid, bool cascade);
extern void
ac_ts_template_comment(Oid tmplOid);

#endif	/* UTILS_SECURITY_H */
