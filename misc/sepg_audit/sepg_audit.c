/*
 * sepg_audit
 *
 * SE-PostgreSQL audit integration with system audit mechanism
 *
 * Copyright (c) 2009, KaiGai Kohei, NEC
 */
#include "postgres.h"

#include "fmgr.h"
#include "miscadmin.h"
#include <libaudit.h>

PG_MODULE_MAGIC;

static int audit_fd;

/*
 * External definitions
 */
extern void (*sepgsql_audit_hook) (bool denied,
								   const char *scontext,
								   const char *tcontext,
								   const char *tclass,
								   const char *permissions,
								   const char *audit_name);


static void
sepg_audit_log(bool denied,
			   const char *scontext,
			   const char *tcontext,
			   const char *tclass,
			   const char *permissions,
			   const char *audit_name)
{
	char	buffer[MAX_AUDIT_MESSAGE_LENGTH];
	size_t	offset = 0;

	if (audit_fd < 0)
		return;

	offset += snprintf(buffer + offset, sizeof(buffer) - offset,
					   "%s %s scontext=%s tcontext=%s tclass=%s",
					   denied ? "denied" : "allowed", permissions,
					   scontext, tcontext, tclass);
	if (audit_name)
		offset += snprintf(buffer + offset, sizeof(buffer) - offset,
						   " name=%s", audit_name);

	audit_log_user_avc_message(audit_fd, AUDIT_USER_AVC,
							   buffer, NULL, NULL, "", GetSessionUserId());
}

void
_PG_init(void)
{
	sepgsql_audit_hook = sepg_audit_log;	

	audit_fd = audit_open();
}
