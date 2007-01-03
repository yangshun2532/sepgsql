/*
 * src/backend/selinux/selinux.c
 *    SE-PgSQL bootstrap hook functions.
 *
 * Copyright (c) 2006 - 2007 KaiGai Kohei <kaigai@kaigai.gr.jp>
 */
#include "postgres.h"

#include "access/htup.h"
#include "catalog/pg_attribute.h"
#include "catalog/pg_class.h"
#include "catalog/pg_database.h"
#include "catalog/pg_largeobject.h"
#include "catalog/pg_proc.h"
#include "catalog/pg_type.h"
#include "libpq/libpq-be.h"
#include "libpq/pqsignal.h"
#include "miscadmin.h"
#include "sepgsql.h"
#include "utils/syscache.h"
#include <unistd.h>
#include <signal.h>
#include <sched.h>
#include <sys/wait.h>
#include <linux/netlink.h>
#include <linux/selinux_netlink.h>
#include <selinux/flask.h>
#include <selinux/av_permissions.h>

static psid sepgsqlServerPsid = InvalidOid;
static psid sepgsqlClientPsid = InvalidOid;
static psid sepgsqlDatabasePsid = InvalidOid;

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
	return sepgsqlDatabasePsid;
}

void sepgsqlInitialize()
{
	sepgsql_init_libselinux();

	if (IsBootstrapProcessingMode()) {
		sepgsqlServerPsid = sepgsql_getcon();
		sepgsqlClientPsid = sepgsql_getcon();
		sepgsqlDatabasePsid = sepgsql_avc_createcon(sepgsqlGetClientPsid(),
													sepgsqlGetServerPsid(),
													SECCLASS_DATABASE);
		return;
	}

	/* obtain security context of server process */
	sepgsqlServerPsid = sepgsql_getcon();

	/* obtain security context of client process */
	if (MyProcPort != NULL) {
		sepgsqlClientPsid = sepgsql_getpeercon(MyProcPort->sock);
	} else {
		sepgsqlClientPsid = sepgsql_getcon();
	}

	/* obtain security context of database */
	if (MyDatabaseId == TemplateDbOid) {
		sepgsqlDatabasePsid = sepgsql_avc_createcon(sepgsqlGetClientPsid(),
													sepgsqlGetServerPsid(),
													SECCLASS_DATABASE);
	} else {
		HeapTuple tuple;
		
		tuple = SearchSysCache(DATABASEOID, ObjectIdGetDatum(MyDatabaseId), 0, 0, 0);
		if (!HeapTupleIsValid(tuple))
			selerror("could not obtain security context of database");
		sepgsqlDatabasePsid = ((Form_pg_database) GETSTRUCT(tuple))->datselcon;
		ReleaseSysCache(tuple);
	}
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
	sepgsql_init_libselinux();

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

	if (MonitoringPolicyStatePid > 0) {
		if (kill(MonitoringPolicyStatePid, SIGTERM) < 0) {
			selnotice("could not kill(%u, SIGTERM), errno=%d (%s)",
					  MonitoringPolicyStatePid, errno, strerror(errno));
			return;
		}
		waitpid(MonitoringPolicyStatePid, &status, 0);
	}
}

Query *sepgsqlProxy(Query *query)
{
	Node *stmt;

	switch (query->commandType) {
	case CMD_SELECT:
		query = selinuxProxySelect(query);
		break;
	case CMD_UPDATE:
		query = selinuxProxyUpdate(query);
		break;
	case CMD_INSERT:
		query = selinuxProxyInsert(query);
		break;
	case CMD_DELETE:
		query = selinuxProxyDelete(query);
		break;
	case CMD_UTILITY:
		stmt = query->utilityStmt;
		switch (nodeTag(stmt)) {
		case T_CreateStmt:
			query = selinuxProxyCreateTable(query);
			break;
		case T_CreateFunctionStmt:
			query = selinuxProxyCreateProcedure(query);
			break;
		default:
			/* do nothing */
			break;
		}
		break;
	case CMD_NOTHING:
		/* do nothing */
		break;
	default:
		selerror("SELinux: unknown command type (%d) found", query->commandType);
		break;
	}

	return query;
}

/* ------------------------------------------------
 * None categolized utility functions
 * ------------------------------------------------ */

/* sepgsqlComputeImplicitContext() -- returns security context
 * of new tuple.
 * @relid : Oid of relation which is tried to insert.
 * @relselcon : psid of relation which is tried to insert.
 */
psid sepgsqlComputeImplicitContext(Oid relid, psid relselcon, uint16 *p_tclass)
{
	psid tsid;
	uint16 tclass;
	
    switch (relid) {
    case AttributeRelationId:
        tclass = SECCLASS_COLUMN;
        tsid = relselcon;
        break;
    case RelationRelationId:
        tclass = SECCLASS_TABLE;
        tsid = sepgsqlGetDatabasePsid();
        break;
    case DatabaseRelationId:
        tclass = SECCLASS_DATABASE;
        tsid = sepgsqlGetServerPsid();
        break;
    case ProcedureRelationId:
        tclass = SECCLASS_PROCEDURE;
        tsid = sepgsqlGetDatabasePsid();
        break;
    case LargeObjectRelationId:
		tclass = SECCLASS_BLOB;
		tsid = sepgsqlGetDatabasePsid();
		break;
    default:
        tclass = SECCLASS_TUPLE;
        tsid = relselcon;
        break;
    }

	if (p_tclass)
		*p_tclass = tclass;

	return sepgsql_avc_createcon(sepgsqlGetClientPsid(), tsid, tclass);
}

bool sepgsqlAttributeIsPsid(Form_pg_attribute attr)
{
	bool rc;

	switch (attr->attrelid) {
	case AttributeRelationId:
		rc = ((attr->attnum == Anum_pg_attribute_attselcon) ? true : false);
		break;
	case RelationRelationId:
		rc = ((attr->attnum == Anum_pg_class_relselcon) ? true : false);
		break;
	case DatabaseRelationId:
		rc = ((attr->attnum == Anum_pg_database_datselcon) ? true : false);
		break;
	case ProcedureRelationId:
		rc = ((attr->attnum == Anum_pg_proc_proselcon) ? true : false);
		break;
	case LargeObjectRelationId:
		rc = ((attr->attnum == Anum_pg_largeobject_selcon) ? true : false);
		break;
	default:
		rc = attr->attispsid ? true : false;
		break;
	}

	return rc;
}

/* ------------------------------------------------
 * SQL functions in Security Enhanced PostgreSQL
 * ------------------------------------------------ */

/* selinux_getcon() -- returns a security context of client
 * process.
 */
Datum
selinux_getcon(PG_FUNCTION_ARGS)
{
	PG_RETURN_OID(sepgsqlGetClientPsid());
}

/* selinux_permission()/selinux_permission_noaudit()
 * checks permissions based on security policy between ssid,
 * tsid and tclass.
 * In selinux_permission(), it may print an audit message if generated,
 * @ssid : security context of subject
 * @tsid : security context of object
 * @tclass : object class
 * @perms : permission set
 */
Datum
selinux_permission(PG_FUNCTION_ARGS)
{
	psid ssid = PG_GETARG_OID(0);
	psid tsid = PG_GETARG_OID(1);
	uint16 tclass = PG_GETARG_UINT32(2);
	uint32 perms = PG_GETARG_UINT32(3);
	int rc;
	char *audit;

	rc = sepgsql_avc_permission(ssid, tsid, tclass, perms, &audit);
	if (audit)
		selnotice(audit);
	PG_RETURN_BOOL(rc == 0);
}

Datum
selinux_permission_noaudit(PG_FUNCTION_ARGS)
{
	psid ssid = PG_GETARG_OID(0);
	psid tsid = PG_GETARG_OID(1);
	uint16 tclass = PG_GETARG_UINT32(2);
	uint32 perms = PG_GETARG_UINT32(3);
	int rc;

	rc = sepgsql_avc_permission(ssid, tsid, tclass, perms, NULL);
	PG_RETURN_BOOL(rc == 0);
}

/* selinux_sql_check_context_insert() -- abort transaction
 * if subject didn't have a permission to insert a new tuple
 * into a table.
 * @ssid : security context of subject
 * @isid : security context automatically computed
 * @esid : security context which to be applied
 * @tclass : object class
 */
Datum
selinux_check_context_insert(PG_FUNCTION_ARGS)
{
	psid ssid = PG_GETARG_OID(0);
	psid isid = PG_GETARG_OID(1);
	psid esid = PG_GETARG_OID(2);
	uint16 tclass = PG_GETARG_INT32(3);
	char *audit;
	uint32 perms;
	int rc;

	if (tclass == SECCLASS_TUPLE) {
		perms = TUPLE__INSERT;
		if (isid != esid)
			perms |= TUPLE__RELABELFROM;
	} else {
		perms = COMMON_DATABASE__SETATTR;
		if (isid != esid)
			perms |= COMMON_DATABASE__RELABELFROM;
	}

	rc = sepgsql_avc_permission(ssid, isid, tclass, perms, &audit);
	selinux_audit(rc, audit, NULL);

	if (isid != esid) {
		perms = (tclass == SECCLASS_TUPLE) ? TUPLE__RELABELTO : COMMON_DATABASE__RELABELTO;
		rc = sepgsql_avc_permission(ssid, esid, tclass, perms, &audit);
		selinux_audit(rc, audit, NULL);
	}
	PG_RETURN_OID(esid);
}

/* selinux_check_context_update() -- abort transaction
 * if subject didn't have a permission to relabel the old
 * security context to the new one.
 * @ssid : security context of subject
 * @osid : old security context of object
 * @nsid : new security context of object
 * @tclass : object class
 */
Datum
selinux_check_context_update(PG_FUNCTION_ARGS)
{
	psid ssid = PG_GETARG_OID(0);
	psid osid = PG_GETARG_OID(1);
	psid nsid = PG_GETARG_OID(2);
	uint16 tclass = PG_GETARG_INT32(3);
	char *audit;
	uint32 perms;
	int rc;

	if (tclass == SECCLASS_TUPLE) {
		perms = TUPLE__UPDATE;
		if (osid != nsid)
			perms |= TUPLE__RELABELFROM;
	} else {
		perms = COMMON_DATABASE__SETATTR;
		if (osid != nsid)
			perms |= COMMON_DATABASE__RELABELFROM;
	}
	
	rc = sepgsql_avc_permission(ssid, osid, tclass, perms, &audit);
	selinux_audit(rc, audit, NULL);
	
	if (osid != nsid) {
		perms = (tclass == SECCLASS_TUPLE) ? TUPLE__RELABELTO : COMMON_DATABASE__RELABELTO;
		rc = sepgsql_avc_permission(ssid, nsid, tclass, perms, &audit);
		selinux_audit(rc, audit, NULL);
	}
	PG_RETURN_OID(nsid);
}
