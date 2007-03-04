#ifndef SEPGSQL_INTERNAL_H
#define SEPGSQL_INTERNAL_H

/* system catalogs */
#include "catalog/catalog.h"
#include "catalog/indexing.h"
#include "catalog/pg_am.h"
#include "catalog/pg_attribute.h"
#include "catalog/pg_authid.h"
#include "catalog/pg_class.h"
#include "catalog/pg_constraint.h"
#include "catalog/pg_conversion.h"
#include "catalog/pg_database.h"
#include "catalog/pg_language.h"
#include "catalog/pg_largeobject.h"
#include "catalog/pg_listener.h"
#include "catalog/pg_namespace.h"
#include "catalog/pg_opclass.h"
#include "catalog/pg_operator.h"
#include "catalog/pg_pltemplate.h"
#include "catalog/pg_proc.h"
#include "catalog/pg_rewrite.h"
#include "catalog/pg_selinux.h"
#include "catalog/pg_tablespace.h"
#include "catalog/pg_trigger.h"
#include "catalog/pg_type.h"

#include <selinux/selinux.h>
#include <selinux/flask.h>
#include <selinux/av_permissions.h>

#define selerror(fmt, ...)												\
	ereport(ERROR,  (errcode(ERRCODE_INTERNAL_ERROR),					\
					 errmsg("%s(%d): " fmt, __FUNCTION__, __LINE__, ##__VA_ARGS__)))
#define selnotice(fmt, ...)												\
	ereport(NOTICE, (errcode(ERRCODE_WARNING),							\
					 errmsg("%s(%d): " fmt, __FUNCTION__, __LINE__, ##__VA_ARGS__)))
#define seldebug(fmt, ...)												\
	ereport(NOTICE, (errcode(ERRCODE_WARNING),							\
					 errmsg("%s(%d): " fmt, __FUNCTION__, __LINE__, ##__VA_ARGS__)))
#define selbugon(x)	do { if (x)((char *)NULL)[0] = 'a'; }while(0)

/* object classes and access vectors are not included, in default */
#define SECCLASS_DATABASE			(60)	/* next to SECCLASS_CONTEXT */
#define SECCLASS_TABLE				(SECCLASS_DATABASE + 1)
#define SECCLASS_PROCEDURE			(SECCLASS_DATABASE + 2)
#define SECCLASS_COLUMN				(SECCLASS_DATABASE + 3)
#define SECCLASS_TUPLE				(SECCLASS_DATABASE + 4)
#define SECCLASS_BLOB				(SECCLASS_DATABASE + 5)

#define COMMON_DATABASE__CREATE                   0x00000001UL
#define COMMON_DATABASE__DROP                     0x00000002UL
#define COMMON_DATABASE__GETATTR                  0x00000004UL
#define COMMON_DATABASE__SETATTR                  0x00000008UL
#define COMMON_DATABASE__RELABELFROM              0x00000010UL
#define COMMON_DATABASE__RELABELTO                0x00000020UL

#define DATABASE__CREATE                          0x00000001UL
#define DATABASE__DROP                            0x00000002UL
#define DATABASE__GETATTR                         0x00000004UL
#define DATABASE__SETATTR                         0x00000008UL
#define DATABASE__RELABELFROM                     0x00000010UL
#define DATABASE__RELABELTO                       0x00000020UL
#define DATABASE__ACCESS                          0x00000040UL
#define DATABASE__INSTALL_MODULE                  0x00000080UL
#define DATABASE__LOAD_MODULE                     0x00000100UL
#define DATABASE__GET_PARAM                       0x00000200UL
#define DATABASE__SET_PARAM                       0x00000400UL
#define TABLE__CREATE                             0x00000001UL
#define TABLE__DROP                               0x00000002UL
#define TABLE__GETATTR                            0x00000004UL
#define TABLE__SETATTR                            0x00000008UL
#define TABLE__RELABELFROM                        0x00000010UL
#define TABLE__RELABELTO                          0x00000020UL
#define TABLE__SELECT                             0x00000040UL
#define TABLE__UPDATE                             0x00000080UL
#define TABLE__INSERT                             0x00000100UL
#define TABLE__DELETE                             0x00000200UL
#define TABLE__LOCK                               0x00000400UL
#define PROCEDURE__CREATE                         0x00000001UL
#define PROCEDURE__DROP                           0x00000002UL
#define PROCEDURE__GETATTR                        0x00000004UL
#define PROCEDURE__SETATTR                        0x00000008UL
#define PROCEDURE__RELABELFROM                    0x00000010UL
#define PROCEDURE__RELABELTO                      0x00000020UL
#define PROCEDURE__EXECUTE                        0x00000040UL
#define PROCEDURE__ENTRYPOINT                     0x00000080UL
#define COLUMN__CREATE                            0x00000001UL
#define COLUMN__DROP                              0x00000002UL
#define COLUMN__GETATTR                           0x00000004UL
#define COLUMN__SETATTR                           0x00000008UL
#define COLUMN__RELABELFROM                       0x00000010UL
#define COLUMN__RELABELTO                         0x00000020UL
#define COLUMN__SELECT                            0x00000040UL
#define COLUMN__UPDATE                            0x00000080UL
#define COLUMN__INSERT                            0x00000100UL
#define TUPLE__RELABELFROM                        0x00000001UL
#define TUPLE__RELABELTO                          0x00000002UL
#define TUPLE__SELECT                             0x00000004UL
#define TUPLE__UPDATE                             0x00000008UL
#define TUPLE__INSERT                             0x00000010UL
#define TUPLE__DELETE                             0x00000020UL
#define BLOB__CREATE                              0x00000001UL
#define BLOB__DROP                                0x00000002UL
#define BLOB__GETATTR                             0x00000004UL
#define BLOB__SETATTR                             0x00000008UL
#define BLOB__RELABELFROM                         0x00000010UL
#define BLOB__RELABELTO                           0x00000020UL
#define BLOB__READ                                0x00000040UL
#define BLOB__WRITE                               0x00000080UL
#define BLOB__IMPORT                              0x00000100UL
#define BLOB__EXPORT                              0x00000200UL
#define TUPLE__PERMS_MASK           ((TUPLE__DELETE << 1) - 1)

extern bool sepgsql_avc_permission_noaudit(psid ssid, psid tsid, uint16 tclass,
										   uint32 perms, char **audit, char *objname);
extern void  sepgsql_avc_permission(psid ssid, psid tsid, uint16 tclass,
									uint32 perms, char *objname);
extern void  sepgsql_audit(bool result, char *message);
extern psid  sepgsql_avc_createcon(psid ssid, psid tsid, uint16 tclass);
extern psid  sepgsql_avc_relabelcon(psid ssid, psid tsid, uint16 tclass);
extern psid  sepgsql_context_to_psid(char *context);
extern char *sepgsql_psid_to_context(psid sid);
extern bool  sepgsql_check_context(char *context);

extern psid  sepgsqlGetServerPsid(void);
extern psid  sepgsqlGetClientPsid(void);
extern void  sepgsqlSetClientPsid(psid new_ctx);
extern psid  sepgsqlGetDatabasePsid(void);
extern char *sepgsqlGetDatabaseName(void);

extern List *sepgsqlProxyQuery(Query *query);
extern List *sepgsqlProxyQueryList(List *queryList);
extern void sepgsqlVerifyQueryList(List *queryList);

extern psid sepgsqlComputeImplicitContext(Relation rel, HeapTuple tuple);
extern bool sepgsqlCheckTuplePerms(Relation rel, HeapTuple tuple, HeapTuple oldtup,
								   uint32 perms, bool abort);

/*
 * Internal utilities
 */
static inline char *HeapTupleGetRelationName(HeapTuple tuple) {
	Form_pg_class pgclass = (Form_pg_class) GETSTRUCT(tuple);
	return NameStr(pgclass->relname);
}

static inline char *HeapTupleGetAttributeName(HeapTuple tuple) {
	Form_pg_attribute pgattr = (Form_pg_attribute) GETSTRUCT(tuple);
	return NameStr(pgattr->attname);
}

static inline char *HeapTupleGetProcedureName(HeapTuple tuple) {
	Form_pg_proc pgproc = (Form_pg_proc) GETSTRUCT(tuple);
	return NameStr(pgproc->proname);
}

static inline char *HeapTupleGetDatabaseName(HeapTuple tuple) {
	Form_pg_database pgdat = (Form_pg_database) GETSTRUCT(tuple);
	return NameStr(pgdat->datname);
}

#endif /* SEPGSQL_INTERNAL_H */
