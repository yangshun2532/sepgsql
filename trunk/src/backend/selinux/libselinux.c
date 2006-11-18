/*
 * src/backend/selinux/libselinux.c
 *    SE-PgSQL libselinux wrapper functions
 *
 * Copyright (c) 2006 - 2007 KaiGai Kohei <kaigai@kaigai.gr.jp>
 */
#include "postgres.h"

#include "access/heapam.h"
#include "access/tupdesc.h"
#include "catalog/indexing.h"
#include "catalog/pg_selinux.h"
#include "miscadmin.h"
#include "sepgsql.h"
#include "utils/builtins.h"
#include "utils/rel.h"
#include "utils/syscache.h"

#include <selinux/selinux.h>
#include <selinux/flask.h>
#include <selinux/av_permissions.h>

static char *class_to_string[] = {
	"database",
	"table",
	"procedure",
	"column",
	"tuple",
	"blob",
};

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

struct avc_datum {
	struct avc_datum *next;

	psid ssid;				/* subject context */
	psid tsid;				/* object context */
	uint16 tclass;			/* object class */

	uint32 allowed;
	uint32 decided;
	uint32 auditallow;
	uint32 auditdeny;

	psid create;			/* newly created context */
	bool is_hot;
	bool has_perm;
	bool has_create;
};

static void libselinux_compute_av(psid ssid, psid tsid, uint16 tclass, struct avc_datum *avd)
{
	security_context_t scon, tcon;
	struct av_decision x;
	
	scon = libselinux_psid_to_context(ssid);
	tcon = libselinux_psid_to_context(tsid);

	if (security_compute_av(scon, tcon, tclass, 0, &x))
		selerror("could not obtain access vector decision "
				 " scon='%s' tcon='%s' tclass=%u", scon, tcon, tclass);
	pfree(scon);
	pfree(tcon);

	avd->allowed = x.allowed;
	avd->decided = x.decided;
	avd->auditallow = x.auditallow;
	avd->auditdeny = x.auditdeny;
}

static psid libselinux_compute_create(psid ssid, psid tsid, uint16 tclass)
{
	security_context_t scon, tcon, ncon;
	psid nsid;

	scon = libselinux_psid_to_context(ssid);
	tcon = libselinux_psid_to_context(tsid);

	if (security_compute_create(scon, tcon, tclass, &ncon) != 0)
		selerror("could not obtain a newly created security context "
				 "scon='%s' tcon='%s' tclass=%u", scon, tcon, tclass);
	PG_TRY();
	{
		nsid = libselinux_context_to_psid(ncon);
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

	return nsid;
}

static psid libselinux_compute_relabel(psid ssid, psid tsid, uint16 tclass)
{
	security_context_t scon, tcon, ncon;
	psid nsid;

	scon = libselinux_psid_to_context(ssid);
	tcon = libselinux_psid_to_context(tsid);

	if (security_compute_relabel(scon, tcon, tclass, &ncon) != 0)
		selerror("could not obtain a newly relabeled security context "
				 "scon='%s' tcon='%s' tclass=%u", scon, tcon, tclass);

	PG_TRY();
	{
		nsid = libselinux_context_to_psid(ncon);
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

#define AVC_DATUM_CACHE_SLOTS    512
#define AVC_DATUM_CACHE_MAXNODES 800
static struct {
	struct avc_datum *slot[AVC_DATUM_CACHE_SLOTS];
	struct avc_datum *freelist;
	int lru_hint;
	struct avc_datum entry[AVC_DATUM_CACHE_MAXNODES];
} avc_cache;

static int selinux_enforcing;

void libselinux_avc_reset()
{
	int i;

	memset(&avc_cache, 0, sizeof(avc_cache));
	for (i=0; i < AVC_DATUM_CACHE_MAXNODES; i++) {
		struct avc_datum *avd = &avc_cache.entry[i];
		
		avd->next = avc_cache.freelist;
		avc_cache.freelist = avd;
	}
	selinux_enforcing = security_getenforce();
	Assert(selinux_enforcing==0 || selinux_enforcing==1);
}

static char *libselinux_avc_audit(psid ssid, psid tsid, uint16 tclass, uint32 perms, struct avc_datum *avd)
{
	uint32 denied, audited;
	char buffer[4096];
	char *context;
	int len, i;

	denied = perms & ~avd->allowed;
	if (denied) {
		audited = (denied & avd->auditdeny);
		if (!audited)
			return NULL;
	} else {
		audited = (perms & avd->auditallow);
		if (!audited)
			return NULL;
	}

	len = snprintf(buffer, sizeof(buffer), "SELinux: %s {", denied ? "denied" : "granted");
	for (i=0; perm_to_string[i].name; i++) {
		if (perm_to_string[i].tclass == tclass
			&& (perm_to_string[i].perm & audited) != 0)
			len += snprintf(buffer + len, sizeof(buffer) - len, " %s", perm_to_string[i].name);
	}
	len += snprintf(buffer + len, sizeof(buffer) - len, " }");

	context = libselinux_psid_to_context(ssid);
	len += snprintf(buffer + len, sizeof(buffer) - len, " scontext=%s", context);

	context = libselinux_psid_to_context(tsid);
	len += snprintf(buffer + len, sizeof(buffer) - len, " tcontext=%s", context);

	if (tclass >= SECCLASS_DATABASE && tclass <= SECCLASS_BLOB) {
		len += snprintf(buffer + len, sizeof(buffer) - len, " tclass=%s",
						class_to_string[tclass - SECCLASS_DATABASE]);
	} else {
		len += snprintf(buffer + len, sizeof(buffer) - len, " tclass=0x%04x", tclass);
	}

	return strdup(buffer);
}

static inline int libselinux_avc_hash(psid ssid, psid tsid, uint16 tclass)
{
	return ((uint32)ssid ^ ((uint32)tsid << 2) ^ tclass) % AVC_DATUM_CACHE_SLOTS;
}

static struct avc_datum *libselinux_avc_lookup(psid ssid, psid tsid, uint16 tclass, uint32 perms)
{
	struct avc_datum *avd, **prev;
	int hashkey = libselinux_avc_hash(ssid, tsid, tclass);
	
retry:
	for (prev = &avc_cache.slot[hashkey], avd = *prev;
		 avd;
		 prev = &avd->next, avd = *prev) {
		if (avd->ssid == ssid && avd->tsid == tsid && avd->tclass == tclass) {
			if ((perms & avd->decided) == perms)
				return avd;
			*prev = avd->next;
			avd->next = avc_cache.freelist;
			avc_cache.freelist = avd;
			goto retry;
		}
	}
	return NULL;
}

static struct avc_datum *libselinux_avc_insert(psid ssid, psid tsid, uint16 tclass)
{
	struct avc_datum *avd = avc_cache.freelist;
	int hashkey = libselinux_avc_hash(ssid, tsid, tclass);

	Assert(avd != NULL);

	avd->ssid = ssid;
	avd->tsid = tsid;
	avd->tclass = tclass;
	avd->is_hot = true;

	libselinux_compute_av(ssid, tsid, tclass, avd);
	avd->create = libselinux_compute_create(ssid, tsid, tclass);

	avc_cache.freelist = avd->next;
	avd->next = avc_cache.slot[hashkey];
	avc_cache.slot[hashkey] = avd;

	return avd;
}

static void libselinux_avc_reclaim() {
	struct avc_datum *avd, **prev;

	while (!avc_cache.freelist) {
		for (prev = avc_cache.slot + avc_cache.lru_hint, avd = *prev;
			 avd;
			 prev = &avd->next, avd = *prev) {
			if (avd->is_hot == true) {
				avd->is_hot = false;
			} else {
				*prev = avd->next;
				avd->next = avc_cache.freelist;
				avc_cache.freelist = avd;
			}
		}
		avc_cache.lru_hint = (avc_cache.lru_hint + 1) % AVC_DATUM_CACHE_SLOTS;
	}
}

int libselinux_avc_permission(psid ssid, psid tsid, uint16 tclass, uint32 perms, char **audit)
{
	struct avc_datum *avd;
	uint32 denied;
	int rc = 0;

	avd = libselinux_avc_lookup(ssid, tsid, tclass, perms);
	if (!avd) {
		if (!avc_cache.freelist)
			libselinux_avc_reclaim();
		avd = libselinux_avc_insert(ssid, tsid, tclass);
	}

	/* check permission */
	denied = perms & ~(avd->allowed);
	if ((!perms || denied) && selinux_enforcing) {
		errno = EACCES;
		rc = -1;
	}

	if (audit)
		*audit = libselinux_avc_audit(ssid, tsid, tclass, perms, avd);
	return rc;
}

psid libselinux_avc_createcon(psid ssid, psid tsid, uint16 tclass)
{
	struct avc_datum *avd;

	avd = libselinux_avc_lookup(ssid, tsid, tclass, 0);
	if (avd == NULL) {
		if (avc_cache.freelist == NULL)
			libselinux_avc_reclaim();
		avd = libselinux_avc_insert(ssid, tsid, tclass);
	}
	return avd->create;
}

psid libselinux_avc_relabelcon(psid ssid, psid tsid, uint16 tclass)
{
	/* currently no avc support on relabeling */
	return libselinux_compute_relabel(ssid, tsid, tclass);
}

extern psid selinuxBootstrap_context_to_psid(char *context);
extern char *selinuxBootstrap_psid_to_context(psid psid);

psid libselinux_context_to_psid(char *context)
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

		if (libselinux_check_context(context) != true)
			selerror("'%s' is an invalid security context", context);

		pg_selinux = heap_open(SelinuxRelationId, RowExclusiveLock);
		indstate = CatalogOpenIndexes(pg_selinux);

		tuple = heap_formtuple(RelationGetDescr(pg_selinux), values, nulls);
		sid = simple_heap_insert(pg_selinux, tuple);
		CatalogIndexInsert(indstate, tuple);

		CatalogCloseIndexes(indstate);
		heap_close(pg_selinux, NoLock);
	}
	return sid;
}

char *libselinux_psid_to_context(psid sid)
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

bool libselinux_check_context(char *context)
{
	return (security_check_context(context) == 0 ? true : false);
}

psid libselinux_getcon()
{
	security_context_t context;
	psid ssid;

	if (getcon(&context) != 0)
		selerror("could not obtain security context of server process");

	PG_TRY();
	{
		ssid = libselinux_context_to_psid(context);
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

psid libselinux_getpeercon(int sockfd)
{
	security_context_t context;
	psid ssid;

	if (getpeercon(sockfd, &context) != 0)
		selerror("could not obtain security context of client process");

	PG_TRY();
	{
		ssid = libselinux_context_to_psid(context);
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
