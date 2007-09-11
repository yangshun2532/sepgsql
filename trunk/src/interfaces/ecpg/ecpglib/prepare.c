/* $PostgreSQL: pgsql/src/interfaces/ecpg/ecpglib/prepare.c,v 1.19 2007/08/14 10:01:52 meskes Exp $ */

#define POSTGRES_ECPG_INTERNAL
#include "postgres_fe.h"

#include <ctype.h>

#include "ecpgtype.h"
#include "ecpglib.h"
#include "ecpgerrno.h"
#include "extern.h"
#include "sqlca.h"

static struct prepared_statement
{
	char	*name;
	bool	prepared;
	struct statement *stmt;
	struct prepared_statement *next;
}	*prep_stmts = NULL;

#define STMTID_SIZE 32

typedef struct 
{
    int         lineno;
    char        stmtID[STMTID_SIZE];
    char        *ecpgQuery;
    long        execs;                  /* # of executions      */
    char        *connection;            /* connection for the statement     */
} stmtCacheEntry;

static int             nextStmtID               = 1;
static int             stmtCacheNBuckets        = 2039;     /* # buckets - a prime # */
static int             stmtCacheEntPerBucket    = 8;        /* # entries/bucket     */
static stmtCacheEntry  stmtCacheEntries[16384] = {{0,{0},0,0,0}};

static bool
isvarchar(unsigned char c)
{
	if (isalnum(c))
		return true;

	if (c == '_' || c == '>' || c == '-' || c == '.')
		return true;

	if (c >= 128)
		return true;

	return (false);
}

static bool
replace_variables(char **text, int lineno, bool questionmarks)
{
	bool	string = false;
	int 	counter = 1, ptr = 0;

	for (; (*text)[ptr] != '\0'; ptr++)
	{
		if ((*text)[ptr] == '\'')
			string = string ? false : true;

		if (string || (((*text)[ptr] != ':') && ((*text)[ptr] != '?')))
			continue;

		if (((*text)[ptr] == ':') && ((*text)[ptr+1] == ':')) 
			ptr += 2;		/* skip  '::' */
		else
		{
			int len;
			int buffersize = sizeof(int) * CHAR_BIT * 10 / 3; /* a rough guess of the size we need */
			char *buffer, *newcopy;

			if (!(buffer = (char *) ECPGalloc(buffersize, lineno)))
				return false;

			snprintf(buffer, buffersize, "$%d", counter++);

			for (len=1; (*text)[ptr+len] && isvarchar((*text)[ptr+len]); len++);
			if (!(newcopy = (char *) ECPGalloc(strlen(*text) - len + strlen(buffer) + 1, lineno)))
			{
				ECPGfree(buffer);
				return false;
			}

			strncpy(newcopy, *text, ptr);
			strcpy(newcopy + ptr, buffer);
			strcat(newcopy, (*text) + ptr + len);

			ECPGfree(*text);
			ECPGfree(buffer);

			*text = newcopy;

			if ((*text)[ptr] == '\0')		/* we reached the end */
				ptr--;		/* since we will (*text)[ptr]++ in the top level for
							 * loop */
		}
	}
	return true;
}

/* handle the EXEC SQL PREPARE statement */
bool
ECPGprepare(int lineno, const char *connection_name, const int questionmarks, const char *name, const char *variable)
{
	struct statement *stmt;
	struct prepared_statement *this;
	struct sqlca_t *sqlca = ECPGget_sqlca();
	PGresult   *query;

	ECPGinit_sqlca(sqlca);

	/* check if we already have prepared this statement */
	for (this = prep_stmts; this != NULL && strcmp(this->name, name) != 0; this = this->next);
	if (this)
	{
		bool		b = ECPGdeallocate(lineno, ECPG_COMPAT_PGSQL, name);

		if (!b)
			return false;
	}

	this = (struct prepared_statement *) ECPGalloc(sizeof(struct prepared_statement), lineno);
	if (!this)
		return false;

	stmt = (struct statement *) ECPGalloc(sizeof(struct statement), lineno);
	if (!stmt)
	{
		ECPGfree(this);
		return false;
	}

	/* create statement */
	stmt->lineno = lineno;
	stmt->connection = ECPGget_connection(connection_name);
	stmt->command = ECPGstrdup(variable, lineno);
	stmt->inlist = stmt->outlist = NULL;

	/* if we have C variables in our statment replace them with '?' */
	replace_variables(&(stmt->command), lineno, questionmarks);

	/* add prepared statement to our list */
	this->name = (char *) name;
	this->stmt = stmt;

	/* and finally really prepare the statement */
	query = PQprepare(stmt->connection->connection, name, stmt->command, 0, NULL);
	if (!ECPGcheck_PQresult(query, stmt->lineno, stmt->connection->connection, stmt->compat))
	{
		ECPGfree(stmt->command);
		ECPGfree(this);
		ECPGfree(stmt);
		return false;
	}

	ECPGlog("ECPGprepare line %d: NAME: %s QUERY: %s\n", stmt->lineno, name, stmt->command);
	PQclear(query);
	this->prepared = true;

	if (prep_stmts == NULL)
		this->next = NULL;
	else
		this->next = prep_stmts;

	prep_stmts = this;
	return true;
}

static bool
deallocate_one(int lineno, const char *name)
{
	struct prepared_statement *this,
			   *prev;

	/* check if we really have prepared this statement */
	for (this = prep_stmts, prev = NULL; this != NULL && strcmp(this->name, name) != 0; prev = this, this = this->next);
	if (this)
	{
		/* first deallocate the statement in the backend */
		if (this->prepared)
		{
			char *text;
			PGresult *query;
			
			if (!(text = (char *) ECPGalloc(strlen("deallocate \"\" ") + strlen(this->name), this->stmt->lineno)))
				return false;
			else
			{
				sprintf(text, "deallocate \"%s\"", this->name);
				query = PQexec(this->stmt->connection->connection, text);
				ECPGfree(text);
				if (!ECPGcheck_PQresult(query, lineno, this->stmt->connection->connection, this->stmt->compat))
					return false;
				PQclear(query);
			}
		}
		
		/* okay, free all the resources */
		ECPGfree(this->stmt->command);
		ECPGfree(this->stmt);
		if (prev != NULL)
			prev->next = this->next;
		else
			prep_stmts = this->next;

		ECPGfree(this);
		return true;
	}
	return false;
}

/* handle the EXEC SQL DEALLOCATE PREPARE statement */
bool
ECPGdeallocate(int lineno, int c, const char *name)
{
	bool		ret = deallocate_one(lineno, name);
	enum COMPAT_MODE compat = c;

	ECPGlog("ECPGdeallocate line %d: NAME: %s\n", lineno, name);
	if (INFORMIX_MODE(compat))
	{
		/*
		 * Just ignore all errors since we do not know the list of cursors we
		 * are allowed to free. We have to trust the software.
		 */
		return true;
	}

	if (!ret)
		ECPGraise(lineno, ECPG_INVALID_STMT, ECPG_SQLSTATE_INVALID_SQL_STATEMENT_NAME, name);

	return ret;
}

bool
ECPGdeallocate_all(int lineno, int compat)
{
	/* deallocate all prepared statements */
	while (prep_stmts != NULL)
	{
		bool		b = ECPGdeallocate(lineno, compat, prep_stmts->name);

		if (!b)
			return false;
	}

	return true;
}

char *
ECPGprepared(const char *name, int lineno)
{
	struct prepared_statement *this;

	for (this = prep_stmts; this != NULL && ((strcmp(this->name, name) != 0) || this->prepared == false); this = this->next);
	return (this) ? this->stmt->command : NULL;
}

/* return the prepared statement */
char *
ECPGprepared_statement(const char *name, int lineno)
{
	struct prepared_statement *this;

	for (this = prep_stmts; this != NULL && strcmp(this->name, name) != 0; this = this->next);
	return (this) ? this->stmt->command : NULL;
}

/*
 * hash a SQL statement -  returns entry # of first entry in the bucket
 */
static int
HashStmt(const char *ecpgQuery)
{
    int             stmtIx, bucketNo, hashLeng, stmtLeng;
    long long       hashVal, rotVal;

    stmtLeng = strlen(ecpgQuery);
    hashLeng = 50;                          /* use 1st 50 characters of statement       */
    if(hashLeng > stmtLeng)                 /* if the statement isn't that long         */
        hashLeng = stmtLeng;                /*      use its actual length               */

    hashVal = 0;
    for(stmtIx = 0; stmtIx < hashLeng; ++stmtIx)
    {
        hashVal = hashVal +  (int) ecpgQuery[stmtIx];
        hashVal = hashVal << 13;
        rotVal  = (hashVal & 0x1fff00000000LL) >> 32;
        hashVal = (hashVal & 0xffffffffLL) | rotVal;
    }

    bucketNo  = hashVal % stmtCacheNBuckets;
    bucketNo += 1;                                      /* don't use bucket # 0         */

    return (bucketNo * stmtCacheEntPerBucket);
}

/*
 * search the statement cache - search for entry with matching ECPG-format query
 * Returns entry # in cache if found
 *   OR  zero if not present (zero'th entry isn't used)
 */
static int
SearchStmtCache(const char *ecpgQuery)
{
    int             entNo, entIx;

/* hash the statement           */
    entNo = HashStmt(ecpgQuery);

/* search the cache     */
    for(entIx = 0; entIx < stmtCacheEntPerBucket; ++entIx)
    {
        if(stmtCacheEntries[entNo].stmtID[0])   /* check if entry is in use     */
        {
		if(!strcmp(ecpgQuery, stmtCacheEntries[entNo].ecpgQuery))
                	break;                          /* found it     */
        }
        ++entNo;                                /* incr entry #     */
    }

/* if entry wasn't found - set entry # to zero  */
    if(entIx >= stmtCacheEntPerBucket)
        entNo = 0;

    return(entNo);
}

/*
 * free an entry in the statement cache
 * Returns entry # in cache used
 *   OR  negative error code
 */
static int
ECPGfreeStmtCacheEntry(int      entNo)          /* entry # to free          */
{
    stmtCacheEntry  *entry;
    PGresult        *results;
    char            deallocText[100];
    struct connection *con;

    entry = &stmtCacheEntries[entNo];
    if(!entry->stmtID[0])                       /* return if the entry isn't in use     */
        return(0);

    con = ECPGget_connection(entry->connection);
/* free the server resources for the statement                                          */
    ECPGlog("ECPGfreeStmtCacheEntry line %d: deallocate %s, cache entry #%d\n", entry->lineno, entry->stmtID, entNo);
    sprintf(deallocText, "DEALLOCATE PREPARE %s", entry->stmtID);
    results = PQexec(con->connection, deallocText);

    if (!ECPGcheck_PQresult(results, entry->lineno, con->connection, ECPG_COMPAT_PGSQL))
    	return(-1);
    PQclear(results);

    entry->stmtID[0] = '\0';

/* free the memory used by the cache entry      */
    if(entry->ecpgQuery)
    {
	ECPGfree(entry->ecpgQuery);
        entry->ecpgQuery = 0;
    }

    return(entNo);
}

/*
 * add an entry to the statement cache
 * returns entry # in cache used  OR  negative error code
 */
static int
AddStmtToCache(int      	lineno,         /* line # of statement      */
               char		*stmtID,        /* statement ID             */
               const char	*connection,    /* connection               */
               const char	*ecpgQuery)     /* query                    */
{
    int             ix, initEntNo, luEntNo, entNo;
    stmtCacheEntry  *entry;

/* hash the statement                                                                   */
    initEntNo = HashStmt(ecpgQuery);

/* search for an unused entry                                                           */
    entNo   = initEntNo;            /* start with the initial entry # for the bucket    */
    luEntNo = initEntNo;            /* use it as the initial 'least used' entry         */
    for(ix = 0; ix < stmtCacheEntPerBucket; ++ix)
    {
        entry = &stmtCacheEntries[entNo];
        if(!entry->stmtID[0])                       /* unused entry  -  use it          */
            break;
        if(entry->execs < stmtCacheEntries[luEntNo].execs)
            luEntNo = entNo;                        /* save new 'least used' entry      */
        ++entNo;                                    /* increment entry #                */
    }

/* if no unused entries were found - use the 'least used' entry found in the bucket     */
    if(ix >= stmtCacheEntPerBucket)                 /* if no unused entries were found  */
        entNo = luEntNo;                            /* re-use the 'least used' entry    */

/* 'entNo' is the entry to use - make sure its free                                     */
    if (ECPGfreeStmtCacheEntry(entNo) < 0)
    	return (-1);

/* add the query to the entry                                                           */
    entry = &stmtCacheEntries[entNo];
    entry->lineno = lineno;
    entry->ecpgQuery = ECPGstrdup(ecpgQuery, lineno);
    entry->connection = (char *)connection;
    entry->execs = 0;
    memcpy(entry->stmtID, stmtID, sizeof(entry->stmtID));

    return(entNo);
}

/* handle cache and preparation of statments in auto-prepare mode */
bool
ECPGauto_prepare(int lineno, const char *connection_name, const int questionmarks, char **name, const char *query)
{
	int entNo;

	/* search the statement cache for this statement    */
	entNo = SearchStmtCache(query);

	/* if not found - add the statement to the cache    */
        if(entNo)
	{
	        ECPGlog("ECPGauto_prepare line %d: stmt found in cache, entry %d\n", lineno, entNo);
		*name = ECPGstrdup(stmtCacheEntries[entNo].stmtID, lineno); 
	}
	else
	{
	        ECPGlog("ECPGauto_prepare line %d: stmt not in cache; inserting\n", lineno);

		/* generate a statement ID */
		*name = (char *) ECPGalloc(STMTID_SIZE, lineno);
		sprintf(*name, "ecpg%d", nextStmtID++);

		if (!ECPGprepare(lineno, connection_name, questionmarks, ECPGstrdup(*name, lineno), query))
			return(false);
		if (AddStmtToCache(lineno, *name, connection_name, query) < 0)
			return(false);
	}

	/* increase usage counter */
	stmtCacheEntries[entNo].execs++;

	return(true);
}

