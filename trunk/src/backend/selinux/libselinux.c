/*
 * src/backend/selinux/libselinux.c
 *    SE-PgSQL libselinux wrapper functions
 *
 * Copyright (c) 2006 - 2007 KaiGai Kohei <kaigai@kaigai.gr.jp>
 */
#include "postgres.h"

#include "access/heapam.h"
#include "access/genam.h"
#include "access/tupdesc.h"
#include "access/xact.h"
#include "catalog/indexing.h"
#include "catalog/pg_selinux.h"
#include "miscadmin.h"
#include "sepgsql.h"
#include "storage/lwlock.h"
#include "utils/builtins.h"
#include "utils/fmgroids.h"
#include "utils/rel.h"
#include "utils/syscache.h"

#include <selinux/selinux.h>
#include <selinux/flask.h>
#include <selinux/av_permissions.h>

/* security_class_to_string() and security_av_perm_to_string() will be
 * provided by new version of libselinux. The followings are provisional
 * works
 */
static const char *security_class_to_string(uint16 tclass)
{
	static char *class_to_string[] = {
		"database",
		"table",
		"procedure",
		"column",
		"tuple",
		"blob",
	};

	if (tclass >= SECCLASS_DATABASE && tclass <= SECCLASS_BLOB)
		return class_to_string[tclass - SECCLASS_DATABASE];
	return "unknown";
}

static const char *security_av_perm_to_string(uint16 tclass, uint32 perm)
{
	static struct {
		uint16 tclass;
		uint32 perm;
		char *name;
	} perm_to_string[] = {
		/* databases */
		{ SECCLASS_DATABASE,	DATABASE__CREATE,		"create" },
		{ SECCLASS_DATABASE,	DATABASE__DROP,			"drop" },
		{ SECCLASS_DATABASE,	DATABASE__GETATTR,		"getattr" },
		{ SECCLASS_DATABASE,	DATABASE__SETATTR,		"setattr" },
		{ SECCLASS_DATABASE,	DATABASE__RELABELFROM,	"relabelfrom" },
		{ SECCLASS_DATABASE,	DATABASE__RELABELTO,	"relabelto" },
		{ SECCLASS_DATABASE,	DATABASE__ACCESS,		"access" },
		{ SECCLASS_DATABASE,	DATABASE__CREATE_OBJ,	"create_obj" },
		{ SECCLASS_DATABASE,	DATABASE__DROP_OBJ,		"drop_obj" },
		/* table */
		{ SECCLASS_TABLE,		TABLE__CREATE,			"create" },
		{ SECCLASS_TABLE,		TABLE__DROP,			"drop" },
		{ SECCLASS_TABLE,		TABLE__GETATTR,			"getattr" },
		{ SECCLASS_TABLE,		TABLE__SETATTR,			"setattr" },
		{ SECCLASS_TABLE,		TABLE__RELABELFROM,		"relabelfrom" },
		{ SECCLASS_TABLE,		TABLE__RELABELTO,		"relabelto" },
		{ SECCLASS_TABLE,		TABLE__SELECT,			"select" },
		{ SECCLASS_TABLE,		TABLE__UPDATE,			"update" },
		{ SECCLASS_TABLE,		TABLE__INSERT,			"insert" },
		{ SECCLASS_TABLE,		TABLE__DELETE,			"delete" },
		/* procedrue */
		{ SECCLASS_PROCEDURE,	PROCEDURE__CREATE,		"create" },
		{ SECCLASS_PROCEDURE,	PROCEDURE__DROP,		"drop" },
		{ SECCLASS_PROCEDURE,	PROCEDURE__GETATTR,		"getattr" },
		{ SECCLASS_PROCEDURE,	PROCEDURE__SETATTR,		"setattr" },
		{ SECCLASS_PROCEDURE,	PROCEDURE__RELABELFROM,	"relabelfrom" },
		{ SECCLASS_PROCEDURE,	PROCEDURE__RELABELTO,	"relabelto" },
		{ SECCLASS_PROCEDURE,	PROCEDURE__EXECUTE,		"execute" },
		{ SECCLASS_PROCEDURE,	PROCEDURE__ENTRYPOINT,	"entrypoint" },
		/* column */
		{ SECCLASS_COLUMN,		COLUMN__CREATE,			"create" },
		{ SECCLASS_COLUMN,		COLUMN__DROP,			"drop" },
		{ SECCLASS_COLUMN,		COLUMN__GETATTR,		"getattr" },
		{ SECCLASS_COLUMN,		COLUMN__SETATTR,		"setattr" },
		{ SECCLASS_COLUMN,		COLUMN__RELABELFROM,	"relabelfrom" },
		{ SECCLASS_COLUMN,		COLUMN__RELABELTO,		"relabelto" },
		{ SECCLASS_COLUMN,		COLUMN__SELECT,			"select" },
		{ SECCLASS_COLUMN,		COLUMN__UPDATE,			"update" },
		{ SECCLASS_COLUMN,		COLUMN__INSERT,			"insert" },
		/* tuple */
		{ SECCLASS_TUPLE,		TUPLE__RELABELFROM,		"relabelfrom" },
		{ SECCLASS_TUPLE,		TUPLE__RELABELTO,		"relabelto" },
		{ SECCLASS_TUPLE,		TUPLE__SELECT,			"select" },
		{ SECCLASS_TUPLE,		TUPLE__UPDATE,			"update" },
		{ SECCLASS_TUPLE,		TUPLE__INSERT,			"insert" },
		{ SECCLASS_TUPLE,		TUPLE__DELETE,			"delete" },
		/* blob */
		{ SECCLASS_BLOB,		BLOB__CREATE,			"create" },
		{ SECCLASS_BLOB,		BLOB__DROP,				"drop" },
		{ SECCLASS_BLOB,		BLOB__GETATTR,			"getattr" },
		{ SECCLASS_BLOB,		BLOB__SETATTR,			"setattr" },
		{ SECCLASS_BLOB,		BLOB__RELABELFROM,		"relabelfrom" },
		{ SECCLASS_BLOB,		BLOB__RELABELTO,		"relabelto" },
		{ SECCLASS_BLOB,		BLOB__READ,				"read" },
		{ SECCLASS_BLOB,		BLOB__WRITE,			"write" },
		{ 0, 0, NULL }
	};
	int i;

	for (i=0; perm_to_string[i].name; i++) {
		if (tclass == perm_to_string[i].tclass && perm == perm_to_string[i].perm)
			return perm_to_string[i].name;
	}
	return "unknown";
}

struct avc_datum {
	SHMEM_OFFSET next;

	psid ssid;				/* subject context */
	psid tsid;				/* object context */
	uint16 tclass;			/* object class */

	uint32 allowed;
	uint32 decided;
	uint32 auditallow;
	uint32 auditdeny;

	psid create;			/* newly created context */
	bool is_hot;
};

#define AVC_DATUM_CACHE_SLOTS    512
#define AVC_DATUM_CACHE_MAXNODES 800
static struct {
	LWLockId lock;
	SHMEM_OFFSET slot[AVC_DATUM_CACHE_SLOTS];
	SHMEM_OFFSET freelist;
	int lru_hint;
	int enforcing;
	struct avc_datum entry[AVC_DATUM_CACHE_MAXNODES];
} *avc_shmem = NULL;

Size sepgsql_shmem_size()
{
	return sizeof(*avc_shmem);
}

void sepgsql_init_libselinux()
{
	bool found_avc;

	avc_shmem = ShmemInitStruct("SELinux userspace AVC",
								sepgsql_shmem_size(), &found_avc);
	if (!found_avc) {
		avc_shmem->lock = LWLockAssign();
		sepgsql_avc_reset();
		seldebug("AVC Shmem segment created");
	} else {
		seldebug("AVC Shmem segment attached");
	}
}

static void sepgsql_compute_av(psid ssid, psid tsid, uint16 tclass, struct avc_datum *avd)
{
	/* we have to hold LW_EXCLUSIVE lock */
	security_context_t scon, tcon;
	struct av_decision x;
	
	scon = sepgsql_psid_to_context(ssid);
	tcon = sepgsql_psid_to_context(tsid);

	if (security_compute_av_raw(scon, tcon, tclass, 0, &x))
		selerror("could not obtain access vector decision "
				 " scon='%s' tcon='%s' tclass=%u", scon, tcon, tclass);
	pfree(scon);
	pfree(tcon);

	avd->allowed = x.allowed;
	avd->decided = x.decided;
	avd->auditallow = x.auditallow;
	avd->auditdeny = x.auditdeny;
}

static void sepgsql_compute_create(psid ssid, psid tsid, uint16 tclass, struct avc_datum *avd)
{
	/* we have to hold LW_EXCLUSIVE lock */
	security_context_t scon, tcon, ncon;

	scon = sepgsql_psid_to_context(ssid);
	tcon = sepgsql_psid_to_context(tsid);

	if (security_compute_create_raw(scon, tcon, tclass, &ncon) != 0)
		selerror("could not obtain a newly created security context "
				 "scon='%s' tcon='%s' tclass=%u", scon, tcon, tclass);
	PG_TRY();
	{
		avd->create = sepgsql_context_to_psid(ncon);
	}
	PG_CATCH();
	{
		freecon(ncon);
		PG_RE_THROW();
	}
	PG_END_TRY();
	
	pfree(scon);
	pfree(tcon);
	freecon(ncon);
}

static psid sepgsql_compute_relabel(psid ssid, psid tsid, uint16 tclass)
{
	security_context_t scon, tcon, ncon;
	psid nsid;

	scon = sepgsql_psid_to_context(ssid);
	tcon = sepgsql_psid_to_context(tsid);

	if (security_compute_relabel_raw(scon, tcon, tclass, &ncon) != 0)
		selerror("could not obtain a newly relabeled security context "
				 "scon='%s' tcon='%s' tclass=%u", scon, tcon, tclass);

	PG_TRY();
	{
		nsid = sepgsql_context_to_psid(ncon);
	}
	PG_CATCH();
	{
		freecon(ncon);
		PG_RE_THROW();
	}
	PG_END_TRY();

	freecon(ncon);
	pfree(scon);
	pfree(tcon);
	
	return nsid;
}

void sepgsql_avc_reset()
{
	int i, enforcing;

	enforcing = security_getenforce();
	Assert(enforcing==0 || enforcing==1);

	LWLockAcquire(avc_shmem->lock, LW_EXCLUSIVE);

	for (i=0; i < AVC_DATUM_CACHE_SLOTS; i++)
		avc_shmem->slot[i] = INVALID_OFFSET;
	avc_shmem->freelist = INVALID_OFFSET;
	for (i=0; i < AVC_DATUM_CACHE_MAXNODES; i++) {
		struct avc_datum *avd = avc_shmem->entry + i;

		memset(avd, 0, sizeof(struct avc_datum));
		avd->next = avc_shmem->freelist;
		avc_shmem->freelist = MAKE_OFFSET(avd);
	}
	avc_shmem->enforcing = enforcing;

	LWLockRelease(avc_shmem->lock);
}

static char *sepgsql_avc_audit(uint32 perms, struct avc_datum *avd)
{
	/* we have to hold LW_SHARED lock at least */
	uint32 denied, audited, mask;
	char buffer[4096];
	security_context_t context;
	char *raw_context;
	int len;

	denied = perms & ~avd->allowed;
	audited = denied ? (denied & avd->auditdeny) : (perms & avd->auditallow);
	if (!audited)
		return NULL;

	len = snprintf(buffer, sizeof(buffer), "%s {", denied ? "denied" : "granted");
	for (mask=1; mask; mask <<= 1) {
		if (audited & mask) {
			len += snprintf(buffer + len, sizeof(buffer) - len, " %s",
							security_av_perm_to_string(avd->tclass, mask));
		}
	}
	len += snprintf(buffer + len, sizeof(buffer) - len, " }");

	raw_context = sepgsql_psid_to_context(avd->ssid);
	if (!selinux_raw_to_trans_context(raw_context, &context)) {
		len += snprintf(buffer + len, sizeof(buffer) - len, " scontext=%s", context);
		freecon(context);
	} else {
		len += snprintf(buffer + len, sizeof(buffer) - len, " scontext=%s", raw_context);
	}
	pfree(raw_context);

	raw_context = sepgsql_psid_to_context(avd->tsid);
	if (!selinux_raw_to_trans_context(raw_context, &context)) {
		len += snprintf(buffer + len, sizeof(buffer) - len, " tcontext=%s", context);
		freecon(context);
	} else {
		len += snprintf(buffer + len, sizeof(buffer) - len, " tcontext=%s", raw_context);
	}
	pfree(raw_context);

	len += snprintf(buffer + len, sizeof(buffer) - len, " tclass=%s",
					security_class_to_string(avd->tclass));

	return pstrdup(buffer);
}

static inline int sepgsql_avc_hash(psid ssid, psid tsid, uint16 tclass)
{
	return ((uint32)ssid ^ ((uint32)tsid << 2) ^ tclass) % AVC_DATUM_CACHE_SLOTS;
}

static struct avc_datum *sepgsql_avc_lookup(psid ssid, psid tsid, uint16 tclass, uint32 perms)
{
	/* we have to hold LW_SHARED lock at least */
	struct avc_datum *avd;
	SHMEM_OFFSET curr;
	int hashkey = sepgsql_avc_hash(ssid, tsid, tclass);

	for (curr = avc_shmem->slot[hashkey];
		 SHM_OFFSET_VALID(curr);
		 curr = avd->next) {
		avd = (void *)MAKE_PTR(curr);
		if (avd->ssid==ssid && avd->tsid==tsid && avd->tclass==tclass
			&& (perms & avd->decided)==perms)
			return avd;
	}
	return NULL;
}

static void sepgsql_avc_reclaim() {
	/* we have to hold LW_EXCLUSIVE lock */
	SHMEM_OFFSET *prev, next;
	struct avc_datum *avd;

	while (!SHM_OFFSET_VALID(avc_shmem->freelist)) {
		prev = avc_shmem->slot + avc_shmem->lru_hint;
		next = *prev;
		while (!SHM_OFFSET_VALID(next)) {
			avd = (void *)MAKE_PTR(next);
			next = avd->next;
			if (avd->is_hot) {
				avd->is_hot = false;
			} else {
				*prev = avd->next;
				avd->next = avc_shmem->freelist;
				avc_shmem->freelist = MAKE_OFFSET(avd);
			}
			avd = (void *)MAKE_PTR(next);
		}
		avc_shmem->lru_hint = (avc_shmem->lru_hint + 1) % AVC_DATUM_CACHE_SLOTS;
	}
}

static void sepgsql_avc_insert(struct avc_datum *tmp)
{
	/* we have to hold LW_EXCLUSIVE lock */
	struct avc_datum *avd;
	int hashkey;

	avd = sepgsql_avc_lookup(tmp->ssid, tmp->tsid, tmp->tclass, tmp->decided);
	if (avd)
		return;

	if (!SHM_OFFSET_VALID(avc_shmem->freelist))
		sepgsql_avc_reclaim();
	Assert(SHM_OFFSET_VALID(avc_shmem->freelist));

	avd = (void *)MAKE_PTR(avc_shmem->freelist);
	avc_shmem->freelist = avd->next;

	memcpy(avd, tmp, sizeof(struct avc_datum));
	avd->is_hot = true;

	hashkey = sepgsql_avc_hash(avd->ssid, avd->tsid, avd->tclass);
	avd->next = avc_shmem->slot[hashkey];
	avc_shmem->slot[hashkey] = MAKE_OFFSET(avd);

	return;
}

int sepgsql_avc_permission(psid ssid, psid tsid, uint16 tclass, uint32 perms, char **audit)
{
	struct avc_datum *avd, lavd;
	uint32 denied;
	int rc = 0;

	LWLockAcquire(avc_shmem->lock, LW_SHARED);
	avd = sepgsql_avc_lookup(ssid, tsid, tclass, perms);
	if (!avd) {
		LWLockRelease(avc_shmem->lock);

		/* compute a new avc_datum */
		memset(&lavd, 0, sizeof(struct avc_datum));
		sepgsql_compute_av(ssid, tsid, tclass, &lavd);
		sepgsql_compute_create(ssid, tsid, tclass, &lavd);

		LWLockAcquire(avc_shmem->lock, LW_EXCLUSIVE);
		sepgsql_avc_insert(&lavd);
	} else {
		memcpy(&lavd, avd, sizeof(struct avc_datum));
	}
	denied = perms & ~lavd.allowed;
	if ((!perms || denied) && avc_shmem->enforcing) {
		errno = EACCES;
		rc = -1;
	}
	LWLockRelease(avc_shmem->lock);
	if (audit)
		*audit = sepgsql_avc_audit(perms, &lavd);

	return rc;
}

psid sepgsql_avc_createcon(psid ssid, psid tsid, uint16 tclass)
{
	struct avc_datum *avd, lavd;
	psid nsid;

	LWLockAcquire(avc_shmem->lock, LW_SHARED);
	avd = sepgsql_avc_lookup(ssid, tsid, tclass, 0);
	if (!avd) {
		LWLockRelease(avc_shmem->lock);

		/* compute a new avc_datum */
		memset(&lavd, 0, sizeof(struct avc_datum));
		sepgsql_compute_av(ssid, tsid, tclass, &lavd);
		sepgsql_compute_create(ssid, tsid, tclass, &lavd);

		LWLockAcquire(avc_shmem->lock, LW_EXCLUSIVE);
		sepgsql_avc_insert(&lavd);
		nsid = lavd.create;
	} else {
		nsid = avd->create;
	}
	LWLockRelease(avc_shmem->lock);

	return nsid;
}

psid sepgsql_avc_relabelcon(psid ssid, psid tsid, uint16 tclass)
{
	/* currently no avc support on relabeling */
	return sepgsql_compute_relabel(ssid, tsid, tclass);
}

extern psid selinuxBootstrap_context_to_psid(char *context);
extern char *selinuxBootstrap_psid_to_context(psid psid);

/* sepgsql_context_to_psid() returns psid corresponding to
 * the context. This context have to be writen in the raw format.
 */
psid sepgsql_context_to_psid(char *context)
{
	HeapTuple tuple;
	Datum tcon;
	psid sid;

	if (IsBootstrapProcessingMode())
		return selinuxBootstrap_context_to_psid(context);

	tcon = DirectFunctionCall1(textin, CStringGetDatum(context));
	tuple = SearchSysCache(SELINUXCONTEXT, tcon, 0, 0, 0);
	if (HeapTupleIsValid(tuple)) {
		sid = HeapTupleGetOid(tuple);
		ReleaseSysCache(tuple);
	} else {
		/* insert a new security context into pg_selinux and index */
		Relation pg_selinux;
		CatalogIndexState indstate;
		Datum values[1] = { tcon };
		char nulls[1] = {' '};

		if (sepgsql_check_context(context) != true)
			selerror("'%s' is not valid security context", context);

		pg_selinux = heap_open(SelinuxRelationId, RowExclusiveLock);
		indstate = CatalogOpenIndexes(pg_selinux);

		tuple = heap_formtuple(RelationGetDescr(pg_selinux), values, nulls);
		sid = simple_heap_insert(pg_selinux, tuple);
		CatalogIndexInsert(indstate, tuple);

		CatalogCloseIndexes(indstate);
		heap_close(pg_selinux, NoLock);

		CommandCounterIncrement();
		CatalogCacheFlushRelation(SelinuxRelationId);
	}
	return sid;
}

/* sepgsql_psid_to_context() returns the security context
 * in raw format corresponding to the psid.
 */
char *sepgsql_psid_to_context(psid sid)
{
	Relation pg_selinux;
	HeapTuple tuple;
	Datum tcon;
	char *context;
	bool isnull;

	if (IsBootstrapProcessingMode())
		return selinuxBootstrap_psid_to_context(sid);

	pg_selinux = heap_open(SelinuxRelationId, AccessShareLock);

	tuple = SearchSysCache(SELINUXOID, ObjectIdGetDatum(sid), 0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		selerror("No string expression for psid=%u", sid);

	tcon = heap_getattr(tuple, Anum_pg_selinux_selcontext,
						RelationGetDescr(pg_selinux), &isnull);
	context = DatumGetCString(DirectFunctionCall1(textout, PointerGetDatum(tcon)));

	ReleaseSysCache(tuple);
	heap_close(pg_selinux, NoLock);

	return context;
}

bool sepgsql_check_context(char *context)
{
	return (security_check_context_raw(context) == 0 ? true : false);
}

psid sepgsql_getcon()
{
	security_context_t context;
	psid ssid;

	if (getcon_raw(&context) != 0)
		selerror("could not obtain security context of server process");

	PG_TRY();
	{
		ssid = sepgsql_context_to_psid(context);
	}
	PG_CATCH();
	{
		freecon(context);
		PG_RE_THROW();
	}
	PG_END_TRY();
	freecon(context);
	return ssid;
}

psid sepgsql_getpeercon(int sockfd)
{
	security_context_t context;
	psid ssid;

	if (getpeercon_raw(sockfd, &context) != 0)
		selerror("could not obtain security context of client process");

	PG_TRY();
	{
		ssid = sepgsql_context_to_psid(context);
	}
	PG_CATCH();
	{
		freecon(context);
		PG_RE_THROW();
	}
	PG_END_TRY();
	freecon(context);
	return ssid;
}
