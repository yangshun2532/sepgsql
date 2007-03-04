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
#include "security/sepgsql.h"
#include "security/sepgsql_internal.h"
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
#include <sys/wait.h>
#include <unistd.h>
#include <unistd.h>

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
	if (tclass == SECCLASS_PROCESS)
		return "process";
	return "unknown";
}

static const char *security_av_perm_to_string(uint16 tclass, uint32 perm)
{
	static struct {
		uint16 tclass;
		uint32 perm;
		char *name;
	} perm_to_string[] = {
		/* process */
		{ SECCLASS_PROCESS,		PROCESS__TRANSITION,	"transition" },
		/* databases */
		{ SECCLASS_DATABASE,	DATABASE__CREATE,		"create" },
		{ SECCLASS_DATABASE,	DATABASE__DROP,			"drop" },
		{ SECCLASS_DATABASE,	DATABASE__GETATTR,		"getattr" },
		{ SECCLASS_DATABASE,	DATABASE__SETATTR,		"setattr" },
		{ SECCLASS_DATABASE,	DATABASE__RELABELFROM,	"relabelfrom" },
		{ SECCLASS_DATABASE,	DATABASE__RELABELTO,	"relabelto" },
		{ SECCLASS_DATABASE,	DATABASE__ACCESS,		"access" },
		{ SECCLASS_DATABASE,	DATABASE__INSTALL_MODULE,	"install_module" },
		{ SECCLASS_DATABASE,	DATABASE__LOAD_MODULE,	"load_module" },
		{ SECCLASS_DATABASE,	DATABASE__GET_PARAM,	"get_param" },
		{ SECCLASS_DATABASE,	DATABASE__SET_PARAM,	"set_param" },
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
		{ SECCLASS_TABLE,		TABLE__LOCK,  		  	"lock" },
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
		{ SECCLASS_BLOB,		BLOB__IMPORT,			"import" },
		{ SECCLASS_BLOB,		BLOB__EXPORT,			"export" },
		{ 0, 0, NULL }
	};
	int i;

	for (i=0; perm_to_string[i].name; i++) {
		if (tclass == perm_to_string[i].tclass && perm == perm_to_string[i].perm)
			return perm_to_string[i].name;
	}
	return "unknown";
}

/*
 * SE-PostgreSQL Internal AVC(Access Vector Cache) implementation.
 * 
 */
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

Size sepgsqlShmemSize()
{
	if (!sepgsqlIsEnabled())
		return 0;

	return sizeof(*avc_shmem);
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

static void sepgsql_compute_avc_datum(psid ssid, psid tsid, uint16 tclass,
									  struct avc_datum *avd)
{
	security_context_t scon, tcon, ncon;
	struct av_decision x;

	memset(avd, 0, sizeof(struct avc_datum));

	scon = sepgsql_psid_to_context(ssid);
	tcon = sepgsql_psid_to_context(tsid);

	if (security_compute_av_raw(scon, tcon, tclass, 0, &x))
		selerror("could not obtain access vector decision "
				 " scon='%s' tcon='%s' tclass=%u", scon, tcon, tclass);
	if (security_compute_create_raw(scon, tcon, tclass, &ncon) != 0)
		selerror("could not obtain a newly created security context "
				 "scon='%s' tcon='%s' tclass=%u", scon, tcon, tclass);

	avd->ssid = ssid;
	avd->tsid = tsid;
	avd->tclass = tclass;

	avd->allowed = x.allowed;
	avd->decided = x.decided;
	avd->auditallow = x.auditallow;
	avd->auditdeny = x.auditdeny;

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

static char *sepgsql_avc_audit(uint32 perms, struct avc_datum *avd, char *objname)
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
	if (objname)
		len += snprintf(buffer + len, sizeof(buffer) - len, " name=%s", objname);

	return pstrdup(buffer);
}

static inline int sepgsql_avc_hash(psid ssid, psid tsid, uint16 tclass)
{
	return ((uint32)ssid ^ ((uint32)tsid << 2) ^ tclass) % AVC_DATUM_CACHE_SLOTS;
}

static struct avc_datum *
sepgsql_avc_lookup(psid ssid, psid tsid, uint16 tclass, uint32 perms)
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

bool sepgsql_avc_permission_noaudit(psid ssid, psid tsid, uint16 tclass, uint32 perms,
									char **audit, char *objname)
{
	struct avc_datum *avd, lavd;
	uint32 denied;
	int rc = true;

	LWLockAcquire(avc_shmem->lock, LW_SHARED);
	avd = sepgsql_avc_lookup(ssid, tsid, tclass, perms);
	if (!avd) {
		LWLockRelease(avc_shmem->lock);

		sepgsql_compute_avc_datum(ssid, tsid, tclass, &lavd);

		LWLockAcquire(avc_shmem->lock, LW_EXCLUSIVE);
		sepgsql_avc_insert(&lavd);
	} else {
		memcpy(&lavd, avd, sizeof(struct avc_datum));
	}
	denied = perms & ~lavd.allowed;
	if ((!perms || denied) && avc_shmem->enforcing) {
		errno = EACCES;
		rc = false;
	}
	LWLockRelease(avc_shmem->lock);
	if (audit)
		*audit = sepgsql_avc_audit(perms, &lavd, objname);

	return rc;
}

void sepgsql_avc_permission(psid ssid, psid tsid, uint16 tclass, uint32 perms, char *objname)
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
				 "Transaction aborted due to SELinux access denied."));
	}
}

psid sepgsql_avc_createcon(psid ssid, psid tsid, uint16 tclass)
{
	struct avc_datum *avd, lavd;
	psid nsid;

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

psid sepgsql_avc_relabelcon(psid ssid, psid tsid, uint16 tclass)
{
	/* currently no avc support on relabeling */
	return sepgsql_compute_relabel(ssid, tsid, tclass);
}

/* sepgsql_getcon() -- returns a security context of client */
Datum
sepgsql_getcon(PG_FUNCTION_ARGS)
{
	PG_RETURN_OID(sepgsqlGetClientPsid());
}

/* sepgsql_system_getcon() -- obtain the server's context in psid */
static psid sepgsql_system_getcon()
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

/* sepgsql_system_getpeercon() -- obtain the client's context in psid */
static psid sepgsql_system_getpeercon(int sockfd)
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

/*
 * SE-PostgreSQL core functions
 *
 * sepgsqlGetServerPsid() -- obtains server's context
 * sepgsqlGetClientPsid() -- obtains client's context via getpeercon()
 * sepgsqlSetClientPsid() -- changes client's context for trusted procedure
 * sepgsqlInitialize() -- called when initializing 'postgres' includes bootstraping
 * sepgsqlInitializePostmaster() -- called when initializing 'postmaster'
 * sepgsqlFinalizePostmaster() -- called when finalizing 'postmaster' to kill
 *                                policy state monitoring process.
 * sepgsqlMonitoringPolicyState() -- is implementation of policy state monitoring
 *                                   process.
 * 
 */
static psid sepgsqlServerPsid = InvalidOid;
static psid sepgsqlClientPsid = InvalidOid;

psid sepgsqlGetServerPsid()
{
	return sepgsqlServerPsid;
}

psid sepgsqlGetClientPsid()
{
	return sepgsqlClientPsid;
}

void sepgsqlSetClientPsid(psid new_ctx)
{
	sepgsqlClientPsid = new_ctx;
}

psid sepgsqlGetDatabasePsid()
{
	HeapTuple tuple;
	psid datcon;

	if (IsBootstrapProcessingMode()) {
		return sepgsql_avc_createcon(sepgsqlGetClientPsid(),
									 sepgsqlGetServerPsid(),
									 SECCLASS_DATABASE);
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
	Form_pg_database pgdat;
	HeapTuple tuple;
	char *datname;

	if (IsBootstrapProcessingMode())
		return NULL;

	tuple = SearchSysCache(DATABASEOID,
						   ObjectIdGetDatum(MyDatabaseId),
						   0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		selerror("cache lookup failed for Database %u", MyDatabaseId);
	pgdat = (Form_pg_database) GETSTRUCT(tuple);
	datname = pstrdup(NameStr(pgdat->datname));
	ReleaseSysCache(tuple);

	return datname;
}

void sepgsqlInitialize()
{
	if (!sepgsqlIsEnabled())
		return;

	sepgsql_avc_init();

	if (IsBootstrapProcessingMode()) {
		sepgsqlServerPsid = sepgsql_system_getcon();
		sepgsqlClientPsid = sepgsql_system_getcon();
		sepgsql_avc_permission(sepgsqlGetClientPsid(),
							   sepgsqlGetDatabasePsid(),
							   SECCLASS_DATABASE,
							   DATABASE__ACCESS,
							   NULL);
		return;
	}

	/* obtain security context of server process */
	sepgsqlServerPsid = sepgsql_system_getcon();

	/* obtain security context of client process */
	if (MyProcPort != NULL) {
		sepgsqlClientPsid = sepgsql_system_getpeercon(MyProcPort->sock);
	} else {
		sepgsqlClientPsid = sepgsql_system_getcon();
	}

	sepgsql_avc_permission(sepgsqlGetClientPsid(),
						   sepgsqlGetDatabasePsid(),
						   SECCLASS_DATABASE,
						   DATABASE__ACCESS,
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
	if (!sepgsqlIsEnabled())
		return 0;

	sepgsql_avc_init();

	MonitoringPolicyStatePid = fork();
	if (MonitoringPolicyStatePid == 0) {
		exit(sepgsqlMonitoringPolicyState());
	} else if (MonitoringPolicyStatePid < 0) {
		selnotice("could not create a child process to monitor the policy state");
		return 1;
	}
	return 0;
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
	return (is_selinux_enabled() > 0 ? true : false);
}
