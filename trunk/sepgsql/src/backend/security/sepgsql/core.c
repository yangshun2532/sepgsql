/*
 * src/backend/security/sepgsqlCore.c
 *   SE-PostgreSQL core facilities like userspace AVC, policy state monitoring.
 *
 * Copyright (c) 2007 KaiGai Kohei <kaigai@kaigai.gr.jp>
 */
#include "postgres.h"

#include "access/heapam.h"
#include "access/genam.h"
#include "access/tupdesc.h"
#include "access/xact.h"
#include "libpq/libpq-be.h"
#include "libpq/pqsignal.h"
#include "miscadmin.h"
#include "security/pgace.h"
#include "security/sepgsql.h"
#include "storage/lwlock.h"
#include "utils/builtins.h"
#include "utils/fmgroids.h"
#include "utils/rel.h"
#include "utils/syscache.h"
#include <linux/netlink.h>
#include <linux/selinux_netlink.h>
#include <sched.h>
#include <signal.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static struct {
	struct {
		char *name;		/* name of object class */
		uint16 inum;	/* internal identifier number */
	} tclass;
	struct {
		char *name;		/* name of access vector */
		uint32 inum;	/* internal identifier number */
	} av_perms[sizeof(access_vector_t) * 8];
} selinux_catalog[] = {
	{
		{ "db_database", SECCLASS_DB_DATABASE },
		{
			{ "create",			DB_DATABASE__CREATE },
			{ "drop",			DB_DATABASE__DROP },
			{ "getattr",		DB_DATABASE__GETATTR },
			{ "setattr",		DB_DATABASE__SETATTR },
			{ "relabelfrom",	DB_DATABASE__RELABELFROM },
			{ "relabelto",		DB_DATABASE__RELABELTO },
			{ "access",			DB_DATABASE__ACCESS },
			{ "install_module",	DB_DATABASE__INSTALL_MODULE },
			{ "load_module",	DB_DATABASE__LOAD_MODULE },
			{ "get_param",		DB_DATABASE__GET_PARAM },
			{ "set_param",		DB_DATABASE__SET_PARAM },
			{ NULL,				0UL },
		}
	},
	{
		{ "db_table", SECCLASS_DB_TABLE },
		{
			{ "create",			DB_TABLE__CREATE },
			{ "drop",			DB_TABLE__DROP },
			{ "getattr",		DB_TABLE__GETATTR },
			{ "setattr",		DB_TABLE__SETATTR },
			{ "relabelfrom",	DB_TABLE__RELABELFROM },
			{ "relabelto",		DB_TABLE__RELABELTO },
			{ "use",			DB_TABLE__USE },
			{ "select",			DB_TABLE__SELECT },
			{ "update",			DB_TABLE__UPDATE },
			{ "insert",			DB_TABLE__INSERT },
			{ "delete",			DB_TABLE__DELETE },
			{ "lock",			DB_TABLE__LOCK },
			{ NULL,				0UL },
		}
	},
	{
		{ "db_procedure", SECCLASS_DB_PROCEDURE },
		{
			{ "create",			DB_PROCEDURE__CREATE },
			{ "drop",			DB_PROCEDURE__DROP },
			{ "getattr",		DB_PROCEDURE__GETATTR },
			{ "setattr",		DB_PROCEDURE__SETATTR },
			{ "relabelfrom",	DB_PROCEDURE__RELABELFROM },
			{ "relabelto",		DB_PROCEDURE__RELABELTO },
			{ "execute",		DB_PROCEDURE__EXECUTE },
			{ "entrypoint",		DB_PROCEDURE__ENTRYPOINT },
			{ NULL,				0UL },
		}
	},
	{
		{ "db_column", SECCLASS_DB_COLUMN },
		{
			{ "create",			DB_COLUMN__CREATE },
			{ "drop",			DB_COLUMN__DROP },
			{ "getattr",		DB_COLUMN__GETATTR },
			{ "setattr",		DB_COLUMN__SETATTR },
			{ "relabelfrom",	DB_COLUMN__RELABELFROM },
			{ "relabelto",		DB_COLUMN__RELABELTO },
			{ "use",			DB_COLUMN__USE },
			{ "select",			DB_COLUMN__SELECT },
			{ "update",			DB_COLUMN__UPDATE },
			{ "insert",			DB_COLUMN__INSERT },
			{ NULL,				0UL },
		}
	},
	{
		{ "db_tuple", SECCLASS_DB_TUPLE },
		{
			{ "relabelfrom",	DB_TUPLE__RELABELFROM },
			{ "relabelto",		DB_TUPLE__RELABELTO },
			{ "use",			DB_TUPLE__USE },
			{ "select",			DB_TUPLE__SELECT },
			{ "update",			DB_TUPLE__UPDATE },
			{ "insert",			DB_TUPLE__INSERT },
			{ "delete",			DB_TUPLE__DELETE },
			{ NULL,				0UL },
		}
	},
	{
		{ "db_blob", SECCLASS_DB_BLOB },
		{
			{ "create",			DB_BLOB__CREATE },
			{ "drop",			DB_BLOB__DROP },
			{ "getattr",		DB_BLOB__GETATTR },
			{ "setattr",		DB_BLOB__SETATTR },
			{ "relabelfrom",	DB_BLOB__RELABELFROM },
			{ "relabelto",		DB_BLOB__RELABELTO },
			{ "read",			DB_BLOB__READ },
			{ "write",			DB_BLOB__WRITE },
			{ "import",			DB_BLOB__IMPORT },
			{ "export",			DB_BLOB__EXPORT },
			{ NULL,				0UL },
		}
	},
};
#define NUM_SELINUX_CATALOG (sizeof(selinux_catalog) / sizeof(selinux_catalog[0]))

static const char *sepgsql_class_to_string(uint16 tclass)
{
	int i;

	for (i=0; i < NUM_SELINUX_CATALOG; i++) {
		if (selinux_catalog[i].tclass.inum == tclass)
			return selinux_catalog[i].tclass.name;
	}
#ifdef SEPGSQLOPT_LIBSELINUX_1_33
	/* for legacy libselinux (Fedora core 6) */
	/* This code will be replaced near future */
	if (tclass == SECCLASS_PROCESS)
		return "process";
	return "unknown";
#else
	/* because tclass didn't match with userspace object classes,
	 * its external representation is always same as internal one */
	return security_class_to_string((security_class_t) tclass);
#endif
}

static const char *sepgsql_av_perm_to_string(uint16 tclass, uint32 perm)
{
	int i, j;

	for (i=0; i < NUM_SELINUX_CATALOG; i++) {
		if (selinux_catalog[i].tclass.inum == tclass) {
			char *perm_name;

			for (j=0; (perm_name = selinux_catalog[i].av_perms[j].name); j++) {
				if (selinux_catalog[i].av_perms[j].inum == perm)
					return perm_name;
			}
			return "unknown";
		}
	}
#ifdef SEPGSQLOPT_LIBSELINUX_1_33
	/* for legacy libselinux (Fedora core 6) */
	/* This code will be replaced near future */
	if (tclass == SECCLASS_PROCESS && perm == PROCESS__TRANSITION)
		return "transition";
	return "unknown";
#else
	/* because tclass/perm didn't match with userspace object classes,
	 * its external representation is always same as internal one */
	return security_av_perm_to_string((security_class_t) tclass, (access_vector_t) perm);
#endif
}

/*
 * SE-PostgreSQL Internal AVC(Access Vector Cache) implementation.
 * 
 */
struct avc_datum {
	SHMEM_OFFSET next;

	Oid ssid;				/* subject context */
	Oid tsid;				/* object context */
	uint16 tclass;			/* object class */

	uint32 allowed;
	uint32 decided;
	uint32 auditallow;
	uint32 auditdeny;

	Oid create;			/* newly created context */
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

	/* dynamic object class/av permission mapping */
	struct {
		struct {
			uint16 internal;
			security_class_t external;
		} tclass;
		struct {
			uint32 internal;
			access_vector_t external;
		} av_perms[sizeof(access_vector_t) * 8];
	} catalog[NUM_SELINUX_CATALOG];
} *avc_shmem = NULL;

Size sepgsqlShmemSize(void)
{
	return sizeof(*avc_shmem);
}

static void sepgsql_load_class_av_mapping()
{
	extern char *selinux_mnt;
	char buffer[PATH_MAX];
	struct stat st_buf;
	int i, j, fd, len;

	if (!selinux_mnt)
		goto legacy_mapping;

	/* Does '/selinux/class' exist? */
	snprintf(buffer, sizeof(buffer), "%s/class", selinux_mnt);
	if (lstat(buffer, &st_buf) || !S_ISDIR(st_buf.st_mode))
		goto legacy_mapping;

	for (i=0; i < NUM_SELINUX_CATALOG; i++) {
		/* obtain external object class number */
		snprintf(buffer, sizeof(buffer), "%s/class/%s/index",
				 selinux_mnt, selinux_catalog[i].tclass.name);
		fd = open(buffer, O_RDONLY);
		if (fd < 0)
			goto legacy_mapping;

		len = read(fd, buffer, sizeof(buffer));
		close(fd);
		if (len < 1)
			goto legacy_mapping;
		buffer[len] = '\0';

		avc_shmem->catalog[i].tclass.internal
			= selinux_catalog[i].tclass.inum;
		avc_shmem->catalog[i].tclass.external
			= atoi(buffer);

		/* obtain external access vector number */
		for (j=0; selinux_catalog[i].av_perms[j].name; j++) {
			snprintf(buffer, sizeof(buffer), "%s/class/%s/perms/%s",
					 selinux_mnt,
					 selinux_catalog[i].tclass.name,
					 selinux_catalog[i].av_perms[j].name);
			fd = open(buffer, O_RDONLY);
			if (fd < 0)
				goto legacy_mapping;

			len = read(fd, buffer, sizeof(buffer));
			close(fd);
			if (len < 1)
				goto legacy_mapping;
			buffer[len] = '\0';

			avc_shmem->catalog[i].av_perms[j].internal
				= selinux_catalog[i].av_perms[j].inum;
			avc_shmem->catalog[i].av_perms[j].external
				= (0x0001UL << (atoi(buffer) - 1));
		}
	}
	return;

legacy_mapping:
	for (i=0; i < NUM_SELINUX_CATALOG; i++) {
		uint16 tclass = selinux_catalog[i].tclass.inum;

		avc_shmem->catalog[i].tclass.internal = tclass;
		avc_shmem->catalog[i].tclass.external = tclass;

		for (j=0; selinux_catalog[i].av_perms[j].name; j++) {
			uint32 av_perm = selinux_catalog[i].av_perms[j].inum;

			avc_shmem->catalog[i].av_perms[j].internal = av_perm;
			avc_shmem->catalog[i].av_perms[j].external = av_perm;
		}
	}
	return;
}

static void sepgsql_avc_reset()
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
	sepgsql_load_class_av_mapping();
	avc_shmem->enforcing = enforcing;

	LWLockRelease(avc_shmem->lock);
}

static void sepgsql_avc_init()
{
	bool found_avc;

	avc_shmem = ShmemInitStruct("SELinux userspace AVC",
								sepgsqlShmemSize(), &found_avc);
	if (!found_avc) {
		avc_shmem->lock = LWLockAssign();
		sepgsql_avc_reset();
	}
}

static uint32 sepgsql_validate_av_perms(security_class_t tclass, access_vector_t perms)
{
	/* we have to hold LW_SHARED lock at least */
	int i, j;

	for (i=0; i < NUM_SELINUX_CATALOG; i++) {
		if (avc_shmem->catalog[i].tclass.external == tclass) {
			uint32 __perms = 0;

			for (j=0; j < sizeof(access_vector_t) * 8; j++) {
				if (avc_shmem->catalog[i].av_perms[j].external & perms)
					__perms |= avc_shmem->catalog[i].av_perms[j].internal;
			}
			//selnotice("tclass(ext:%d -> int:%d) av_perms(ext:%08x -> int:%08x) validated",
			//		  tclass, avc_shmem->catalog[i].tclass.internal,
			//		  perms, __perms);
			return __perms;
		}
	}
	//selnotice("tclass = %d is not user tclass, perms (%08x) is used as is", tclass, perms);

	return (uint32) perms;
}

static void sepgsql_compute_avc_datum(Oid ssid, Oid tsid, uint16 tclass,
									  struct avc_datum *avd)
{
	security_class_t tclass_external = tclass;
	security_context_t scon, tcon, ncon;
	struct av_decision x;
	Datum tmp;
	int i;

	memset(avd, 0, sizeof(struct avc_datum));
	tmp = DirectFunctionCall1(security_label_raw_out,
							  ObjectIdGetDatum(ssid));
	scon = DatumGetCString(tmp);
	tmp = DirectFunctionCall1(security_label_raw_out,
							  ObjectIdGetDatum(tsid));
	tcon = DatumGetCString(tmp);

	LWLockAcquire(avc_shmem->lock, LW_SHARED);
	/* translate internal tclass into external one, to query the kernel */
	for (i=0; i < NUM_SELINUX_CATALOG; i++) {
		if (avc_shmem->catalog[i].tclass.internal == tclass) {
			tclass_external = avc_shmem->catalog[i].tclass.external;
			break;
		}
	}

	if (security_compute_av_raw(scon, tcon, tclass_external, 0, &x))
		selerror("could not obtain access vector decision "
				 " scon='%s' tcon='%s' tclass=%u", scon, tcon, tclass);
	if (security_compute_create_raw(scon, tcon, tclass_external, &ncon) != 0)
		selerror("could not obtain a newly created security context "
				 "scon='%s' tcon='%s' tclass=%u", scon, tcon, tclass);

	avd->ssid = ssid;
	avd->tsid = tsid;
	avd->tclass = tclass;

	avd->allowed = sepgsql_validate_av_perms(tclass_external, x.allowed);
	avd->decided = sepgsql_validate_av_perms(tclass_external, x.decided);
	avd->auditallow = sepgsql_validate_av_perms(tclass_external, x.auditallow);
	avd->auditdeny = sepgsql_validate_av_perms(tclass_external, x.auditdeny);
	LWLockRelease(avc_shmem->lock);

	PG_TRY();
	{
		tmp = DirectFunctionCall1(security_label_raw_in,
								  CStringGetDatum(ncon));
		avd->create = DatumGetObjectId(tmp);
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

static Oid sepgsql_compute_relabel(Oid ssid, Oid tsid, uint16 tclass)
{
	security_context_t scon, tcon, ncon;
	Oid nsid;
	Datum tmp;

	tmp = DirectFunctionCall1(security_label_raw_out,
							  ObjectIdGetDatum(ssid));
	scon = DatumGetCString(tmp);
	tmp = DirectFunctionCall1(security_label_raw_out,
							  ObjectIdGetDatum(tsid));
	tcon = DatumGetCString(tmp);

	if (security_compute_relabel_raw(scon, tcon, tclass, &ncon) != 0)
		selerror("could not obtain a newly relabeled security context "
				 "scon='%s' tcon='%s' tclass=%u", scon, tcon, tclass);

	PG_TRY();
	{
		tmp = DirectFunctionCall1(security_label_raw_in,
								  CStringGetDatum(ncon));
		nsid = DatumGetObjectId(tmp);
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

static char *sepgsql_avc_audit(uint32 perms, struct avc_datum *avd, char *objname)
{
	/* we have to hold LW_SHARED lock at least */
	uint32 denied, audited, mask;
	char buffer[4096];
	char *context;
	int len;

	denied = perms & ~avd->allowed;
	audited = denied ? (denied & avd->auditdeny) : (perms & avd->auditallow);
	if (!audited)
		return NULL;

	len = snprintf(buffer, sizeof(buffer), "%s {", denied ? "denied" : "granted");
	for (mask=1; mask; mask <<= 1) {
		if (audited & mask) {
			len += snprintf(buffer + len, sizeof(buffer) - len, " %s",
							sepgsql_av_perm_to_string(avd->tclass, mask));
		}
	}
	len += snprintf(buffer + len, sizeof(buffer) - len, " }");

	context = DatumGetCString(DirectFunctionCall1(security_label_out, 
												  ObjectIdGetDatum(avd->ssid)));
	len += snprintf(buffer + len, sizeof(buffer) - len, " scontext=%s", context);
	pfree(context);

	context =  DatumGetCString(DirectFunctionCall1(security_label_out,
												   ObjectIdGetDatum(avd->tsid)));
	len += snprintf(buffer + len, sizeof(buffer) - len, " tcontext=%s", context);
	pfree(context);

	len += snprintf(buffer + len, sizeof(buffer) - len, " tclass=%s",
					sepgsql_class_to_string(avd->tclass));
	if (objname)
		len += snprintf(buffer + len, sizeof(buffer) - len, " name=%s", objname);

	return pstrdup(buffer);
}

static inline int sepgsql_avc_hash(Oid ssid, Oid tsid, uint16 tclass)
{
	return ((uint32)ssid ^ ((uint32)tsid << 2) ^ tclass) % AVC_DATUM_CACHE_SLOTS;
}

static struct avc_datum *
sepgsql_avc_lookup(Oid ssid, Oid tsid, uint16 tclass, uint32 perms)
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

bool sepgsql_avc_permission_noaudit(Oid ssid, Oid tsid, uint16 tclass, uint32 perms,
									char **audit, char *objname)
{
	struct avc_datum *avd, lavd;
	uint32 denied;
	bool rc = true;
	bool wlock = false;

	LWLockAcquire(avc_shmem->lock, LW_SHARED);
retry:
	avd = sepgsql_avc_lookup(ssid, tsid, tclass, perms);
	if (!avd) {
		LWLockRelease(avc_shmem->lock);

		sepgsql_compute_avc_datum(ssid, tsid, tclass, &lavd);

		LWLockAcquire(avc_shmem->lock, LW_EXCLUSIVE);
		wlock = true;
		sepgsql_avc_insert(&lavd);
	} else {
		memcpy(&lavd, avd, sizeof(struct avc_datum));
	}
	denied = perms & ~lavd.allowed;
	if (!perms || denied) {
		if (avc_shmem->enforcing) {
			errno = EACCES;
			rc = false;
		} else {
			if (!wlock) {
				/* update avd need LW_EXCLUSIVE lock onto shmem */
				LWLockRelease(avc_shmem->lock);
				LWLockAcquire(avc_shmem->lock, LW_EXCLUSIVE);
				wlock = true;
				goto retry;
			}
			/* grant permission to avoid flood of access denied log */
			if (!avd)
				avd = sepgsql_avc_lookup(ssid, tsid, tclass, perms);
			if (avd)
				avd->allowed |= denied;
		}
	}
	LWLockRelease(avc_shmem->lock);
	if (audit)
		*audit = sepgsql_avc_audit(perms, &lavd, objname);

	return rc;
}

void sepgsql_avc_permission(Oid ssid, Oid tsid, uint16 tclass, uint32 perms, char *objname)
{
	char *audit;
	bool rc;

	rc = sepgsql_avc_permission_noaudit(ssid, tsid, tclass, perms, &audit, objname);
	sepgsql_audit(rc, audit);

	if (audit)
		pfree(audit);
}

void sepgsql_audit(bool result, char *message)
{
	if (message) {
		ereport((result ? NOTICE : ERROR),
				(errcode(ERRCODE_INTERNAL_ERROR),
				 errmsg("SELinux: %s", message)));
	} else if (!result) {
		ereport(ERROR,
				(errcode(ERRCODE_INTERNAL_ERROR),
				 errmsg("Transaction aborted due to SELinux access denied.")));
	}
}

Oid sepgsql_avc_createcon(Oid ssid, Oid tsid, uint16 tclass)
{
	struct avc_datum *avd, lavd;
	Oid nsid;

	LWLockAcquire(avc_shmem->lock, LW_SHARED);
	avd = sepgsql_avc_lookup(ssid, tsid, tclass, 0);
	if (!avd) {
		LWLockRelease(avc_shmem->lock);

		sepgsql_compute_avc_datum(ssid, tsid, tclass, &lavd);

		LWLockAcquire(avc_shmem->lock, LW_EXCLUSIVE);
		sepgsql_avc_insert(&lavd);
		nsid = lavd.create;
	} else {
		nsid = avd->create;
	}
	LWLockRelease(avc_shmem->lock);

	return nsid;
}

Oid sepgsql_avc_relabelcon(Oid ssid, Oid tsid, uint16 tclass)
{
	/* currently no avc support on relabeling */
	return sepgsql_compute_relabel(ssid, tsid, tclass);
}

/* sepgsql_getcon() -- returns a security context of client */
Datum
sepgsql_getcon(PG_FUNCTION_ARGS)
{
	PG_RETURN_OID(sepgsqlGetClientContext());
}

/* sepgsql_system_getcon() -- obtain the server's context */
static Oid sepgsql_system_getcon()
{
	security_context_t context;
	Oid ssid;

	if (getcon_raw(&context) != 0)
		selerror("could not obtain security context of server process");

	PG_TRY();
	{
		ssid = DatumGetObjectId(DirectFunctionCall1(security_label_raw_in,
													CStringGetDatum(context)));
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

/* sepgsql_system_getpeercon() -- obtain the client's context */
static Oid sepgsql_system_getpeercon(int sockfd)
{
	security_context_t context, __context;
	Oid ssid;

	if (getpeercon_raw(sockfd, &context)) {
		/* we can set finally fallbacked context */
		__context = getenv("SEPGSQL_FALLBACK_CONTEXT");
		if (!__context)
			selerror("could not obtain security context of database client");
		if (security_check_context(__context) ||
			selinux_trans_to_raw_context(__context, &context))
			selerror("'%s' is not a valid context", __context);
	}

	PG_TRY();
	{
		ssid = DatumGetObjectId(DirectFunctionCall1(security_label_raw_in,
													CStringGetDatum(context)));
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

/*
 * SE-PostgreSQL core functions
 *
 * sepgsqlGetServerContext() -- obtains server's context
 * sepgsqlGetClientContext() -- obtains client's context via getpeercon()
 * sepgsqlSetClientContext() -- changes client's context for trusted procedure
 * sepgsqlInitialize() -- called when initializing 'postgres' includes bootstraping
 * sepgsqlInitializePostmaster() -- called when initializing 'postmaster'
 * sepgsqlFinalizePostmaster() -- called when finalizing 'postmaster' to kill
 *                                policy state monitoring process.
 * sepgsqlMonitoringPolicyState() -- is implementation of policy state monitoring
 *                                   process.
 * 
 */
static Oid sepgsqlServerContext = InvalidOid;
static Oid sepgsqlClientContext = InvalidOid;

Oid sepgsqlGetServerContext()
{
	return sepgsqlServerContext;
}

Oid sepgsqlGetClientContext()
{
	return sepgsqlClientContext;
}

void sepgsqlSetClientContext(Oid new_context)
{
	sepgsqlClientContext = new_context;
}

Oid sepgsqlGetDatabaseContext()
{
	HeapTuple tuple;
	Oid datcon;

	if (IsBootstrapProcessingMode()) {
		return sepgsql_avc_createcon(sepgsqlGetClientContext(),
									 sepgsqlGetServerContext(),
									 SECCLASS_DB_DATABASE);
	}

	tuple = SearchSysCache(DATABASEOID,
						   ObjectIdGetDatum(MyDatabaseId),
						   0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		selerror("cache lookup failed for Database %u", MyDatabaseId);
	datcon = HeapTupleGetSecurity(tuple);
	ReleaseSysCache(tuple);

	return datcon;
}

char *sepgsqlGetDatabaseName()
{
	Form_pg_database dat_form;
	HeapTuple tuple;
	char *datname;

	if (IsBootstrapProcessingMode())
		return NULL;

	tuple = SearchSysCache(DATABASEOID,
						   ObjectIdGetDatum(MyDatabaseId),
						   0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		selerror("cache lookup failed for Database %u", MyDatabaseId);
	dat_form = (Form_pg_database) GETSTRUCT(tuple);
	datname = pstrdup(NameStr(dat_form->datname));
	ReleaseSysCache(tuple);

	return datname;
}

void sepgsqlInitialize(bool is_bootstrap)
{
	sepgsql_avc_init();

	if (IsBootstrapProcessingMode()) {
		sepgsqlServerContext = sepgsql_system_getcon();
		sepgsqlClientContext = sepgsql_system_getcon();
		sepgsql_avc_permission(sepgsqlGetClientContext(),
							   sepgsqlGetDatabaseContext(),
							   SECCLASS_DB_DATABASE,
							   DB_DATABASE__ACCESS,
							   NULL);
		return;
	}

	/* obtain security context of server process */
	sepgsqlServerContext = sepgsql_system_getcon();

	/* obtain security context of client process */
	if (MyProcPort != NULL) {
		sepgsqlClientContext = sepgsql_system_getpeercon(MyProcPort->sock);
	} else {
		sepgsqlClientContext = sepgsql_system_getcon();
	}

	sepgsql_avc_permission(sepgsqlGetClientContext(),
						   sepgsqlGetDatabaseContext(),
						   SECCLASS_DB_DATABASE,
						   DB_DATABASE__ACCESS,
						   sepgsqlGetDatabaseName());
}

/* sepgsqlMonitoringPolicyState() is worker process to monitor
 * the status of SELinux policy. When it is changed, light after the worker
 * thread receive a notification via netlink socket. The notification is
 * delivered into any PostgreSQL instance by reseting shared avc.
 */
static void sepgsqlMonitoringPolicyState_SIGHUP(int signum)
{
	selnotice("selinux userspace AVC reset, by receiving SIGHUP");
	sepgsql_avc_reset();
}

static int sepgsqlMonitoringPolicyState()
{
	char buffer[2048];
	struct sockaddr_nl addr;
	socklen_t addrlen;
	struct nlmsghdr *nlh;
	int i, rc, nl_sockfd;

	seldebug("%s pid=%u", __FUNCTION__, getpid());

	/* close listen port */
	for (i=3; !close(i); i++);

	/* map shared memory segment */
	sepgsql_avc_init();

	/* setup the signal handler */
	pqinitmask();
	pqsignal(SIGHUP,  sepgsqlMonitoringPolicyState_SIGHUP);
	pqsignal(SIGINT,  SIG_DFL);
	pqsignal(SIGQUIT, SIG_DFL);
	pqsignal(SIGTERM, SIG_DFL);
	pqsignal(SIGUSR1, SIG_DFL);
	pqsignal(SIGUSR2, SIG_DFL);
	pqsignal(SIGCHLD, SIG_DFL);
	PG_SETMASK(&UnBlockSig);

	/* open netlink socket */
	nl_sockfd = socket(PF_NETLINK, SOCK_RAW, NETLINK_SELINUX);
	if (nl_sockfd < 0) {
		selnotice("could not create netlink socket");
		return 1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.nl_family = AF_NETLINK;
	addr.nl_groups = SELNL_GRP_AVC;
	if (bind(nl_sockfd, (struct sockaddr *)&addr, sizeof(addr))) {
		selnotice("could not bind netlink socket");
		return 1;
	}

	/* waiting loop */
	while (true) {
		addrlen = sizeof(addr);
		rc = recvfrom(nl_sockfd, buffer, sizeof(buffer), 0,
					  (struct sockaddr *)&addr, &addrlen);
		if (rc < 0) {
			if (errno == EINTR)
				continue;
			selnotice("selinux netlink: recvfrom() error=%d, %s",
					  errno, strerror(errno));
			return 1;
		}

		if (addrlen != sizeof(addr)) {
			selnotice("selinux netlink: netlink address truncated (len = %d)", addrlen);
			return 1;
		}

		if (addr.nl_pid) {
			selnotice("selinux netlink: received spoofed packet from: %u", addr.nl_pid);
			continue;
		}

		if (rc == 0) {
			selnotice("selinux netlink: received EOF on socket");
			return 1;
		}

		nlh = (struct nlmsghdr *)buffer;

		if (nlh->nlmsg_flags & MSG_TRUNC
			|| nlh->nlmsg_len > (unsigned int)rc) {
			selnotice("selinux netlink: incomplete netlink message");
			return 1;
		}

		switch (nlh->nlmsg_type) {
		case NLMSG_ERROR: {
			struct nlmsgerr *err = NLMSG_DATA(nlh);
			if (err->error == 0)
				break;
			selnotice("selinux netlink: error message %d", -err->error);
			return 1;
		}
		case SELNL_MSG_SETENFORCE: {
			struct selnl_msg_setenforce *msg = NLMSG_DATA(nlh);
			selnotice("selinux netlink: received setenforce notice (enforcing=%d)", msg->val);
			sepgsql_avc_reset();
			break;
		}
		case SELNL_MSG_POLICYLOAD: {
			struct selnl_msg_policyload *msg = NLMSG_DATA(nlh);
			selnotice("selinux netlink: received policyload notice (seqno=%d)", msg->seqno);
			sepgsql_avc_reset();
			break;
		}
		default:
			selnotice("selinux netlink: unknown message type (%d)", nlh->nlmsg_type);
			return 1;
		}
	}
	return 0;
}

static pid_t MonitoringPolicyStatePid = -1;

int sepgsqlInitializePostmaster()
{
	MonitoringPolicyStatePid = fork();
	if (MonitoringPolicyStatePid == 0) {
		exit(sepgsqlMonitoringPolicyState());
	} else if (MonitoringPolicyStatePid < 0) {
		selnotice("could not create a child process to monitor the policy state");
		return false;
	}
	return true;
}

void sepgsqlFinalizePostmaster()
{
	int status;

	if (!sepgsqlIsEnabled())
		return;

	if (MonitoringPolicyStatePid > 0) {
		if (kill(MonitoringPolicyStatePid, SIGTERM) < 0) {
			selnotice("could not kill(%u, SIGTERM), errno=%d (%s)",
					  MonitoringPolicyStatePid, errno, strerror(errno));
			return;
		}
		waitpid(MonitoringPolicyStatePid, &status, 0);
	}
}

bool sepgsqlIsEnabled()
{
	static int enabled = -1;

	if (enabled < 0)
		enabled = is_selinux_enabled();

	return enabled > 0 ? true : false;
}
