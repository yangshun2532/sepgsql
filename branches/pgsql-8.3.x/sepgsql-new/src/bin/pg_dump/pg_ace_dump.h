#ifndef PG_ACE_DUMP_H
#define PG_ACE_DUMP_H

#include "pg_backup.h"
#include "pg_dump.h"

#define PG_ACE_FEATURE_NOTHING		0
#define PG_ACE_FEATURE_SELINUX		1

#define SELINUX_SYSATTR_NAME		"security_context"

/*
 * pg_ace_dumpCheckServerFeature
 *
 * This hook checks whether the server has required feature, or not.
 */
static inline void
pg_ace_dumpCheckServerFeature(int feature, PGconn *conn)
{
	const char *serv_feature;

	if (feature == PG_ACE_FEATURE_NOTHING)
		return;

	serv_feature = PQparameterStatus(conn, "pgace_security_feature");
	if (!serv_feature)
	{
		fprintf(stderr, "could not get pgace_feature parameter.\n");
		exit(1);
	}

	if (feature == PG_ACE_FEATURE_SELINUX)
	{
		if (strcmp(serv_feature, "selinux") != 0)
		{
			fprintf(stderr, "server does not have SELinux feature\n");
			exit(1);
		}
	}
}

/*
 * pg_ace_dumpDatabaseXXXX
 *
 * These hooks gives a chance to inject a security system column
 * on dumping pg_database system catalog.
 * A modified part must have ",d.<security column>" style, and
 * its result should be printed to buf.
 */
static inline const char *
pg_ace_dumpDatabaseQuery(int feature)
{
	if (feature == PG_ACE_FEATURE_SELINUX)
		return (",d." SELINUX_SYSATTR_NAME);

	return "";
}

static inline void
pg_ace_dumpDatabasePrint(int feature, PQExpBuffer buf,
						 PGresult *res, int index)
{
	if (feature == PG_ACE_FEATURE_SELINUX)
	{
		int i_security = PQfnumber(res, SELINUX_SYSATTR_NAME);
		char *dbsecurity = PQgetvalue(res, index, i_security);

		if (dbsecurity && dbsecurity[0] != '\0')
			appendPQExpBuffer(buf, " SECURITY_CONTEXT = '%s'", dbsecurity);
	}
}

/*
 * pg_ace_dumpClassXXXX
 *
 * These hooks give a chance to inject a security system column
 * on dumping pg_class system catalog. The modified part has to
 * be formalized to ",c.<security column>" style. The result
 * should be preserved at TableInfo->relsecurity to print later,
 * if exist.
 */
static inline const char *
pg_ace_dumpClassQuery(int feature)
{
	if (feature == PG_ACE_FEATURE_SELINUX)
		return (",c." SELINUX_SYSATTR_NAME);

	return "";
}

static inline char *
pg_ace_dumpClassPreserve(int feature, PGresult *res, int index)
{
	if (feature == PG_ACE_FEATURE_SELINUX)
	{
		int		attno = PQfnumber(res, SELINUX_SYSATTR_NAME);
		char   *relcontext;

		if (attno < 0)
			return NULL;

		relcontext = PQgetvalue(res, index, attno);

		if (!relcontext || relcontext[0] == '\0')
			return NULL;

		return strdup(relcontext);
	}

	return NULL;
}

static inline void
pg_ace_dumpClassPrint(int feature, PQExpBuffer buf, TableInfo *tbinfo)
{
	if (feature == PG_ACE_FEATURE_SELINUX)
	{
		char   *relcontext = tbinfo->relsecurity;

		if (relcontext)
			appendPQExpBuffer(buf, " SECURITY_CONTEXT = '%s'", relcontext);

		return;
	}
}

/*
 * pg_ace_dumpAttributeXXXX
 *
 * These hooks give a chance to inject a security system column
 * on dumping pg_attribute system catalog. The modified part has
 * to be formalized to ",a.<security conlumn>" style. The result
 * should be preserved at TableInfo->attsecurity[index] to print
 * later, if exist.
 */
static inline const char *
pg_ace_dumpAttributeQuery(int feature)
{
	if (feature == PG_ACE_FEATURE_SELINUX)
		return (",a." SELINUX_SYSATTR_NAME);

	return "";
}

static inline char *
pg_ace_dumpAttributePreserve(int feature, PGresult *res, int index)
{
	if (feature == PG_ACE_FEATURE_SELINUX)
	{
		int		attno = PQfnumber(res, SELINUX_SYSATTR_NAME);
		char   *attcontext;

		if (attno < 0)
			return NULL;

		attcontext = PQgetvalue(res, index, attno);
		if (!attcontext || attcontext[0] == '\0')
			return NULL;

		return strdup(attcontext);
	}

	return NULL;
}

static inline void
pg_ace_dumpAttributePrint(int feature, PQExpBuffer buf,
						  TableInfo *tbinfo, int index)
{
	if (feature == PG_ACE_FEATURE_SELINUX)
	{
		char   *relcontext = tbinfo->relsecurity;
		char   *attcontext = tbinfo->attsecurity[index];

		if (attcontext)
		{
			if (relcontext && strcmp(relcontext, attcontext) == 0)
				return;

			appendPQExpBuffer(buf, " SECURITY_CONTEXT = '%s'", attcontext);
		}
		return;
	}
}

/*
 * pg_ace_dumpProcXXXX
 *
 * These hooks give a chance to inject a security system column
 * on dumping pg_proc system catalog. The modified part has to be
 * formalized to "<security conlumn>" style. The result should be
 * printed later, if exist.
 */
static inline const char *
pg_ace_dumpProcQuery(int feature)
{
	if (feature == PG_ACE_FEATURE_SELINUX)
		return ("," SELINUX_SYSATTR_NAME);

	return "";
}

static inline void
pg_ace_dumpProcPrint(int feature, PQExpBuffer buf,
					 PGresult *res, int index)
{
	if (feature == PG_ACE_FEATURE_SELINUX)
	{
		int		i_selinux = PQfnumber(res, SELINUX_SYSATTR_NAME);
		char   *prosecurity;

		if (i_selinux < 0)
			return;

		prosecurity = PQgetvalue(res, index, i_selinux);
		if (prosecurity && prosecurity[0] != '\0')
			appendPQExpBuffer(buf, " SECURITY_CONTEXT = '%s'", prosecurity);
	}
}

/*
 * pg_ace_dumpTableDataQuery
 *
 * This hook gives a chance to inject a security attribute system column
 * on dumping of user's table.
 * It must have ",<security column>" style.
 */
static inline const char *
pg_ace_dumpTableDataQuery(int feature)
{
	if (feature == PG_ACE_FEATURE_SELINUX)
		return ("," SELINUX_SYSATTR_NAME);

	return "";
}

/*
 * pg_ace_dumpCopyColumnList
 *
 * This hook gives a chance to inject a security attribute column within
 * COPY statement. When a column is added, you have to return true. It
 * enables to set needComma 'true', otherwise 'false'.
 */
static inline bool
pg_ace_dumpCopyColumnList(int feature, PQExpBuffer buf)
{
	if (feature == PG_ACE_FEATURE_SELINUX)
	{
		appendPQExpBuffer(buf, SELINUX_SYSATTR_NAME);
		return true;
	}

	return false;
}

/*
 * pg_ace_dumpBlobComments
 *
 * This hook gives a chance to inject a query to restore a security
 * attribute of binary large object.
 */
static inline void
pg_ace_dumpBlobComments(int feature, Archive *AH, PGconn *conn, Oid blobOid)
{
	if (feature == PG_ACE_FEATURE_SELINUX)
	{
		PGresult   *res;
		char		query[256];

		snprintf(query, sizeof(query),
				 "SELECT lo_get_security(%u)", blobOid);
		res = PQexec(conn, query);
		if (!res)
			return;

		if (PQresultStatus(res) == PGRES_TUPLES_OK && PQntuples(res) == 1)
			archprintf(AH, "SELECT lo_set_security(%u, '%s');\n",
					   blobOid, PQgetvalue(res, 0, 0));

		PQclear(res);
	}
}

#endif
