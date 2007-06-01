/* -------------------------------------------------------
 * pgcheck -- a SE-PostgreSQL regression test utility
 *
 * copyright: 2007 - KaiGai Kohei <kaigai@kaigai.gr.jp>
 * ------------------------------------------------------- */
#include <libpq-fe.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <error.h>
#include <errno.h>
#include <unistd.h>
#include <getopt.h>
#include <ctype.h>

struct templateElem {
	struct templateElem *next;
	char val_kind;
	union {
		int    val_bool;
		long   val_integer;
		double val_float;
		char   val_text[1];
	};
};
#define TEMPELEM_NULL    (0)
#define TEMPELEM_BOOL    (1)
#define TEMPELEM_INT     (2)
#define TEMPELEM_FLOAT   (3)
#define TEMPELEM_TEXT    (4)

static FILE *errmsg;
static char *opt_dbname = NULL;
static char *opt_hostname = NULL;
static char *opt_username = NULL;
static int   opt_portno = -1;
static char *opt_password = NULL;
static struct templateElem **opt_template = NULL;
static char *query_string = NULL;

static void usage() {
	fprintf(errmsg,
			"pgcheck -- PostgreSQL query checking utility.\n"
			"\n"
			"Usage: pgcheck [OPTIONS] ... [QUERY]\n"
			"\n"
			"  -d DBNAME     specify database name to connect to \n"
			"  -h HOSTNAME   database server host or socket directory \n"
			"  -p PORT       database server port \n"
			"  -u NAME       database user name \n"
			"  -P PASSWORD   password to connect \n"
			"  -t TEMPLATE   template expression, if required \n");
	exit(1);
}

static struct templateElem *__parse_template_token(char *template_string, int *p_offset) {
	struct templateElem *retval = NULL;
	int phase = 0;
	int offset = *p_offset;
	int token_offset;
	int flags;
	int c;

	while (1) {
	retry:
		if ((c = template_string[offset]) == '\0')
			break;
		//printf("phase=%d:   %c\n", phase, c);
		switch (phase) {
		case 0: {
			if (isspace(c))
				break;

			if (isdigit(c) || c=='+' || c=='-' || c=='.') {
				phase = 1;
				token_offset = offset;
				flags = (c == '.' ? 1 : 0);
				break;
			}
			if (isalpha(c)) {
				phase = 2;
				token_offset = offset;
				break;
			}
			if (c == '\'' || c == '"') {
				phase = 3;
				token_offset = offset + 1;
				flags = c;
				break;
			}
			return NULL; /* syntax error */
		}
		case 1: {
			/* numerical value */
			if (c == '.') {
				if (flags)
					return NULL;
				flags = 1;
			} else if (!isdigit(c)) {
				retval = malloc(sizeof(struct templateElem));
				if (!retval)
					return NULL;
				memset(retval, 0, sizeof(struct templateElem));
				retval->val_kind = (flags ? TEMPELEM_FLOAT : TEMPELEM_INT);
				
				template_string[offset] = '\0';
				if (flags) {
					retval->val_float = atof(template_string + token_offset);
				} else {
					retval->val_integer = atol(template_string + token_offset);
				}
				template_string[offset] = c; /* restore */
				phase = 255;
				goto retry;
			}
			break;
		}
		case 2: {
			/* null or bool value */
			if (!isalpha(c)) {
				retval = malloc(sizeof(struct templateElem));
				if (!retval)
					return NULL;
				memset(retval, 0, sizeof(struct templateElem));

				template_string[offset] = '\0';
				if (!strcasecmp(template_string + token_offset, "null")) {
					retval->val_kind = TEMPELEM_NULL;
				} else if (!strcasecmp(template_string + token_offset, "true")) {
					retval->val_kind = TEMPELEM_BOOL;
					retval->val_bool = 1;
				} else if (!strcasecmp(template_string + token_offset, "false")) {
					retval->val_kind = TEMPELEM_BOOL;
					retval->val_bool = 0;
				} else {
					return NULL;
				}
				template_string[offset] = c; /* restore */
				phase = 255;
				goto retry;
			}
			break;
		}
		case 3: {
			/* string value */
			if (c == flags) {
				int len = offset - token_offset;
				int i, j, code;
				
				retval = malloc(sizeof(struct templateElem) + len);
				if (!retval)
					return NULL;
				memset(retval, 0, sizeof(struct templateElem) + len);

				retval->val_kind = TEMPELEM_TEXT;
				for (i = token_offset, j = 0; i < offset; i++, j++) {
					code = template_string[i];
					if (code == '\\') {
						if (++i == offset)
							return NULL;
						code = template_string[i];
					}
					retval->val_text[j] = code;
				}
				phase = 255;
			}
			break;
		}
		case 255: {
			/* final state */
			*p_offset = offset - 1;
			return retval;
			break;
		}
		default:
			return NULL; /* BUG */
		}
		offset++;
	}
	return NULL; /* unexpected termination */
}

static struct templateElem *__parse_template_tuple(char *template_string, int *p_offset) {
	struct templateElem *head = NULL;
	int phase = 0;
	int offset = *p_offset;
	int c;

	while (1) {
	retry:
		if ((c = template_string[offset]) == '\0')
			break;
		//printf("phase=%d:  %c\n", phase, c);
		switch (phase) {
		case 0: {
			if (isspace(c))
				break;
			if (c == '{') {
				phase = 1;
				break;
			}
			return NULL; /* syntax error */
		}
		case 1: {
			struct templateElem *next, *tail;

			next = __parse_template_token(template_string, &offset);
			if (!next)
				return NULL; /* syntax error */
			if (!head) {
				head = next;
			} else {
				for (tail = head; tail->next; tail = tail->next);
				tail->next = next;
			}
			phase = 2;
			break;
		}
		case 2: {
			/* wait for ',' or '}' */
			if (c == ',') {
				phase = 1;
			} else if (c == '}') {
				*p_offset = offset;
				return head;
			} else if (!isspace(c)) {
				return NULL; /* syntax error */
			}
			break;
		}
		default:
			return NULL; /* BUG */
		}
		offset++;
	}
	return NULL; /* unexpected termination */
}

static void do_parse_template (char *template_string) {
	struct templateElem **template = NULL;
	int temp_max, temp_cur, phase = 0;
	int c, offset = 0;

	while (1) {
	retry:
		if ((c = template_string[offset]) == '\0')
			break;
		//printf("phase=%d: %c\n", phase, c);
		switch (phase) {
		case 0: {
			if (isspace(c)) {
				break;
			} else if (c == '{') {
				phase = 1;
				break;
			}
			goto syntax_error;
		}
		case 1: {
			struct templateElem *next;

			next = __parse_template_tuple(template_string, &offset);
			if (!next)
				goto syntax_error;
			if (!template) {
				temp_max = 4;
				temp_cur = 0;
				template = malloc(sizeof(struct templateElem *) * temp_max);
			} else if (temp_cur == temp_max - 1) {
				temp_max *= 2;
				template = realloc(template, sizeof(struct templateElem *) * temp_max);
			}
			template[temp_cur++] = next;
			template[temp_cur] = NULL;
			phase = 2;
			break;
		}
		case 2: {
			if (c == ',') {
				phase = 1;
			} else if (c == '}') {
				phase = 3;
			} else if (!isspace(c)) {
				goto syntax_error;
			}
			break;
		}
		case 3: {
			if (!isspace(c))
				goto syntax_error;
			break;
		}
		default:
			goto syntax_error; /* BUG */
		}
		offset++;
	}
	opt_template = template;
	return;

syntax_error:
	fprintf(errmsg, "Syntax error at offset %d of '%s'\n",
			offset - 1, template_string);
	exit(1);
}

static void do_print_template (struct templateElem *tempList[]) {
	struct templateElem *cur;
	int i, j;

	for (i=0; tempList[i]; i++) {
		printf("% 2d: [", i);
		for (j=0, cur=opt_template[i]; cur; j++, cur = cur->next) {
			if (j > 0)
				putchar(',');
			switch (cur->val_kind) {
			case TEMPELEM_NULL:
				printf("null");
				break;
			case TEMPELEM_BOOL:
				printf("%s", cur->val_bool ? "true" : "false");
				break;
			case TEMPELEM_FLOAT:
				printf("%.6f", cur->val_float);
				break;
			case TEMPELEM_INT:
				printf("%ld", cur->val_integer);
				break;
			case TEMPELEM_TEXT:
				printf("'%s'", cur->val_text);
				break;
			}
		}
		printf("]\n");
	}
}

static void do_parse_options (int argc, char *argv[]) {
	int c;

	opterr = fileno(stderr);
	while ((c = getopt(argc, argv, "d:h:p:u:P:t:")) > 0) {
		switch (c) {
		case 'd':
			if (opt_dbname)
				goto duplicate_option;
			opt_dbname = optarg;
			break;
		case 'h':
			if (opt_hostname)
				goto duplicate_option;
			opt_hostname = optarg;
			break;
		case 'p':
			if (opt_username)
				goto duplicate_option;
			opt_username = optarg;
			break;
		case 'u':
			if (opt_portno > 0)
				goto duplicate_option;
			opt_portno = atoi(optarg);
			break;
		case 'P':
			if (opt_password)
				goto duplicate_option;
			opt_password = optarg;
			break;
		case 't':
			if (opt_template)
				goto duplicate_option;
			do_parse_template(optarg);
			break;
		default:
			usage();
			break;
		}
	}
	if (optind == argc) {
		fprintf(errmsg, "No queries are specified.\n");
		usage();
	} else if (optind < argc - 1) {
		fprintf(errmsg, "Multiple queries are specified.\n");
		usage();
	}
	query_string = argv[optind];

	return;

duplicate_option:
	fprintf(errmsg, "option -%c was found twice\n", c);
	usage();
}

static PGconn *connectDatabase() {
	char buffer[2048];
	int offset = 0;
	PGconn *pgconn;

	/* connect to database */
	buffer[offset] = '\0';
	if (opt_dbname)
		offset += snprintf(buffer + offset, sizeof(buffer) - offset,
						   " dbname=%s", opt_dbname);
	if (opt_hostname)
		offset += snprintf(buffer + offset, sizeof(buffer) - offset,
						   " host=%s", opt_hostname);
	if (opt_portno > 0)
		offset += snprintf(buffer + offset, sizeof(buffer) - offset,
						   " port=%d", opt_portno);
	if (opt_username)
		offset += snprintf(buffer + offset, sizeof(buffer) - offset,
						   " user=%s", opt_username);
	if (opt_password)
		offset += snprintf(buffer + offset, sizeof(buffer) - offset,
						   " password=%s", opt_password);

	pgconn = PQconnectdb(buffer);
	if (!pgconn || PQstatus(pgconn) != CONNECTION_OK) {
		fprintf(errmsg, "could not connect PostgreSQL with '%s'\n", buffer);
		exit(1);
	}
	return pgconn;
}

static PGresult *executeQuery(PGconn *pgconn, const char *query) {
	PGresult *res;
	ExecStatusType status;
	char *message;
	Oid new_oid;
	int i, ncols;

	res = PQexec(pgconn, query_string);
	if (!res) {
		fprintf(errmsg, "FATAL: PQexec('%s') returned NULL\n", query);
		exit(1);
	}

	status = PQresultStatus(res);
	printf("STATUS: %s\n", PQresStatus(status));

	message = PQresultErrorMessage(res);
	if (message[0] != '\0')
		printf("ERROR: %s\n", message);

	if (status == PGRES_TUPLES_OK)
		printf("NTUPLES: %d\n", PQntuples(res));

	for (i=0, ncols = PQnfields(res); i < ncols; i++)
		printf("FIELD: %d %s %d\n", i, PQfname(res, i), PQftype(res, i));

	message = PQcmdTuples(res);
	if (message[0] != '\0')
		printf("AFFECTED_ROWS: %s\n", message);

	new_oid = PQoidValue(res);
	if (new_oid != InvalidOid)
		printf("NEW_OID: %u\n", new_oid);

	return res;
}

int main (int argc, char *argv[]) {
	PGconn *pgconn;
	PGresult *res;

	/* redirection */
	errmsg = stderr;
	stderr = stdout;

	/* parse options */
	do_parse_options(argc, argv);

	/* open connection */
	pgconn = connectDatabase();

	/* exec query */
	res = executeQuery(pgconn, query_string);


	/* clear result */
	PQclear(res);

	/* close connection*/
	PQfinish(pgconn);

	return 0;
}
