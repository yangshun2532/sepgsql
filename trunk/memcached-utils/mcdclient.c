/*
 * mcdbench.c - memcached test utility
 *
 * Copyright (C) 2010, NEC Corporation
 *
 * Authors: KaiGai Kohei <kaigai@ak.jp.nec.com>
 *
 * This program is distributed under the modified BSD license.
 * See the LICENSE file for full text.
 */
#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <libmemcached/memcached.h>

/*
 * option variable
 */
static bool		verbose = false;

static int
exec_get(memcached_st *mcd, const char *key)
{
	memcached_return_t	error;
	uint32_t			flags;
	char			   *value;
	size_t				value_length;

	value = memcached_get(mcd, key, strlen(key),
						  &value_length, &flags, &error);
	if (value != NULL)
		printf("get: key=%s value=%.*s flags=%08x\n",
			   key, value_length, value, flags);
	else
		printf("get: key=%s error=%s\n",
			   key, memcached_strerror(mcd, error));
	return 0;
}

static int
exec_add(memcached_st *mcd, const char *key, const char *value,
		 time_t expire, uint32_t flags)
{
	memcached_return_t	error = memcached_add(mcd, key, strlen(key),
											  value, strlen(value),
											  expire, flags);
	if (error == MEMCACHED_SUCCESS)
		printf("add: key=%s value=%s expire=%lu flags=%u\n",
			   key, value, expire, flags);
	else
		printf("add: key=%s error=%s\n",
			   key, memcached_strerror(mcd, error));
	return 0;
}

static int
exec_set(memcached_st *mcd, const char *key, const char *value,
		 time_t expire, uint32_t flags)
{
	memcached_return_t	error = memcached_set(mcd, key, strlen(key),
											  value, strlen(value),
											  expire, flags);
	if (error == MEMCACHED_SUCCESS)
		printf("set: key=%s value=%s expire=%lu flags=%u\n",
			   key, value, expire, flags);
	else
		printf("set: key=%s error=%s\n",
			   key, memcached_strerror(mcd, error));
	return 0;
}

static int
exec_replace(memcached_st *mcd, const char *key, const char *value,
			 time_t expire, uint32_t flags)
{
	memcached_return_t  error = memcached_replace(mcd, key, strlen(key),
												  value, strlen(value),
												  expire, flags);
	if (error == MEMCACHED_SUCCESS)
		printf("replace: key=%s value=%s expire=%lu flags=%u\n",
			   key, value, expire, flags);
	else
		printf("replace: key=%s error=%s\n",
			   key, memcached_strerror(mcd, error));
	return 0;
}

static int
exec_append(memcached_st *mcd, const char *key, const char *value,
			 time_t expire, uint32_t flags)
{
	memcached_return_t  error = memcached_append(mcd, key, strlen(key),
												 value, strlen(value),
												 expire, flags);
	if (error == MEMCACHED_SUCCESS)
		printf("append: key=%s value=%s expire=%lu flags=%u\n",
			   key, value, expire, flags);
	else
		printf("append: key=%s error=%s\n",
			   key, memcached_strerror(mcd, error));
	return 0;
}

static int
exec_prepend(memcached_st *mcd, const char *key, const char *value,
			 time_t expire, uint32_t flags)
{
	memcached_return_t  error = memcached_replace(mcd, key, strlen(key),
												  value, strlen(value),
												  expire, flags);
	if (error == MEMCACHED_SUCCESS)
		printf("prepend: key=%s value=%s expire=%lu flags=%u\n",
			   key, value, expire, flags);
	else
		printf("prepend: key=%s error=%s\n",
			   key, memcached_strerror(mcd, error));
	return 0;
}

static int
exec_cas(memcached_st *mcd, const char *key, const char *value, uint64_t cas,
		 time_t expire, uint32_t flags)
{
	memcached_return_t  error = memcached_cas(mcd, key, strlen(key),
											  value, strlen(value),
											  expire, flags, cas);
	if (error == MEMCACHED_SUCCESS)
		printf("cas: key=%s value=%s cas=%llu expire=%lu flags=%u\n",
			   key, value, cas, expire, flags);
	else
		printf("cas: key=%s cas=%llu error=%s\n",
			   key, cas, memcached_strerror(mcd, error));
	return 0;
}

static int
exec_delete(memcached_st *mcd, const char *key, time_t expire)
{
	memcached_return_t	error =  memcached_delete(mcd, key, strlen(key),
												  expire);
	if (error == MEMCACHED_SUCCESS)
		printf("delete: key=%s expire=%lu\n", key, expire);
	else
		printf("delete: key=%s expire=%lu error=%s\n",
			   key, expire, memcached_strerror(mcd, error));
	return 0;
}

static int
exec_incr(memcached_st *mcd, const char *key)
{
	memcached_return_t	error;
	uint64_t			value;

	error = memcached_increment(mcd, key, strlen(key), 0, &value);
	if (error == MEMCACHED_SUCCESS)
		printf("incr: key=%s value=%llu\n", key, value);
	else
		printf("incr: key=%s error=%s\n",
			   key, memcached_strerror(mcd, error));
	return 0;
}

static int
exec_decr(memcached_st *mcd, const char *key)
{
	memcached_return_t	error;
	uint64_t			value;

	error = memcached_increment(mcd, key, strlen(key), 0, &value);
	if (error == MEMCACHED_SUCCESS)
		printf("decr: key=%s value=%llu\n", key, value);
	else
		printf("decr: key=%s error=%s\n",
			   key, memcached_strerror(mcd, error));
	return 0;
}

static int
exec_flush(memcached_st *mcd, time_t expire)
{
	memcached_return_t	error = memcached_flush(mcd, expire);

	if (error == MEMCACHED_SUCCESS)
		printf("flush: expire=%lu\n", expire);
	else
		printf("flush: expire=%lu error=%s\n",
			   expire, memcached_strerror(mcd, error));
	return 0;
}

static void
make_pseudo_value(unsigned int seed, char *value, int *vlen)
{
	int		length, pos = 0;

	length = ((rand_r(&seed) & 15) *
			  (rand_r(&seed) & 15) *
			  (rand_r(&seed) & 15) + 64) & ~0x0007;

	while (pos < length)
		pos += sprintf(value + pos, "%08x", rand_r(&seed));

	*vlen = length;
}

static int
exec_simple_bench(memcached_st *mcd, double scale)
{
	char	kbuf[256];
	char	vbuf[1024 * 1024];
	int		klen, vlen;
	int		i, n, count;
	int		num_gets = 0;
	int		num_adds = 0;
	long	total = 0;
	long	interval;
	struct timeval tv1, tv2;

	if (scale < 100.0)
		scale = 100.0;

	n = (int)(scale * 64);
	count = (int)(scale * 512);

	srand(count);

	gettimeofday(&tv1, NULL);

	memcached_flush(mcd, 0);

	while (count-- > 0)
	{
		memcached_return_t	error;
		uint32_t	flags;
		char	   *value;
		size_t		value_length;

		i = rand() % n;

		klen = sprintf(kbuf, "mcdbench_key%06u", i);

		value = memcached_get(mcd, kbuf, klen, &value_length, &flags, &error);
		if (value == NULL)
		{
			if (error != MEMCACHED_NOTFOUND)
			{
				printf("key=%s error=%s\n", kbuf, memcached_strerror(mcd, error));
				continue;
			}
			make_pseudo_value(i, vbuf, &vlen);
			error = memcached_add(mcd, kbuf, klen, vbuf, vlen, 0, 0);
			if (error != MEMCACHED_SUCCESS)
			{
				printf("key=%s error=%s\n", kbuf, memcached_strerror(mcd, error));
				continue;
			}
			num_adds++;
			total += vlen;
		}
		else
		{
			num_gets++;
			total += value_length;
			free(value);
		}
	}
	gettimeofday(&tv2, NULL);

	interval = (tv2.tv_sec - tv1.tv_sec) * 1000000 + (tv2.tv_usec - tv1.tv_usec);

	printf("time: %.2f  adds: %u  gets: %u  transfer: %lubytes\n",
		   ((double)interval) / 1000000.0,
		   num_adds, num_gets, total);
	return 0;
}

static int
exec_command(memcached_st *mcd, int n_cmds, char * const cmds[])
{
	int	retval = 1;

	if (strcmp(cmds[0], "get") == 0 && n_cmds == 2)
		retval = exec_get(mcd, cmds[1]);
	else if (strcmp(cmds[0], "add") == 0 && (n_cmds >= 3 && n_cmds <= 5))
		retval = exec_add(mcd, cmds[1], cmds[2],
						  n_cmds > 3 ? atol(cmds[3]) : 0,
						  n_cmds > 4 ? atol(cmds[4]) : 0);
	else if (strcmp(cmds[0], "set") == 0 && (n_cmds >= 3 && n_cmds <= 5))
		retval = exec_set(mcd, cmds[1], cmds[2],
						  n_cmds > 3 ? atol(cmds[3]) : 0,
						  n_cmds > 4 ? atol(cmds[4]) : 0);
	else if (strcmp(cmds[0], "replace") == 0 && (n_cmds >= 3 && n_cmds <= 5))
		retval = exec_replace(mcd, cmds[1], cmds[2],
							  n_cmds > 3 ? atol(cmds[3]) : 0,
							  n_cmds > 4 ? atol(cmds[4]) : 0);
	else if (strcmp(cmds[0], "append") == 0 && (n_cmds >= 3 && n_cmds <= 5))
		retval = exec_append(mcd, cmds[1], cmds[2],
							 n_cmds > 3 ? atol(cmds[3]) : 0,
							 n_cmds > 4 ? atol(cmds[4]) : 0);
	else if (strcmp(cmds[0], "prepend") == 0 && (n_cmds >= 3 && n_cmds <= 5))
		retval = exec_prepend(mcd, cmds[1], cmds[2],
							 n_cmds > 3 ? atol(cmds[3]) : 0,
							 n_cmds > 4 ? atol(cmds[4]) : 0);
	else if (strcmp(cmds[0], "cas") == 0 && (n_cmds >= 4 && n_cmds <= 6))
		retval = exec_cas(mcd, cmds[1], cmds[2], atol(cmds[3]),
						  n_cmds > 4 ? atol(cmds[4]) : 0,
						  n_cmds > 5 ? atol(cmds[5]) : 0);
	else if (strcmp(cmds[0], "delete") == 0 && (n_cmds >= 2 && n_cmds <= 3))
		retval = exec_delete(mcd, cmds[1],
							 n_cmds > 2 ? atol(cmds[2]) : 0);
	else if (strcmp(cmds[0], "incr") == 0 && n_cmds == 2)
		retval = exec_incr(mcd, cmds[1]);
	else if (strcmp(cmds[0], "decr") == 0 && n_cmds == 2)
		retval = exec_decr(mcd, cmds[1]);
	else if (strcmp(cmds[0], "flush") == 0 && (n_cmds >= 1 && n_cmds <=2))
		retval = exec_flush(mcd, n_cmds > 1 ? atol(cmds[1]) : 0);
	else if (strcmp(cmds[0], "simple_bench") == 0 &&
			 (n_cmds >= 1 && n_cmds <=2))
		retval = exec_simple_bench(mcd, n_cmds > 1 ? atof(cmds[1]) : 100.0);

	return retval;
}

static void
parse_connection(char *conn, in_port_t *port, uint32_t *weight)
{
	char   *pos;
	char   *cur;

	if (weight != NULL)
	{
		*weight = 100;	/* default */

		if ((pos = strrchr(conn, '/')) != NULL)
		{
			for (cur = pos + 1; isdigit(*cur); cur++);
			if (*cur == '\0')
			{
				*weight = atoi(pos+1);
				*pos = '\0';
			}
		}
	}

	if (port != NULL)
	{
		*port = 11211;	/* default */

		if ((pos = strrchr(conn, ':')) != NULL)
		{
			for (cur = pos + 1; isdigit(*cur); cur++);
			if (*cur == '\0')
			{
				*weight = atoi(pos+1);
				*pos = '\0';
			}
		}
	}
}

int
main(int argc, char * const argv[])
{
	memcached_st   *mcd;
	in_port_t		port;
	uint32_t		weight;
	int				num_conns = 0;
	int				retval;
	int				code;

	mcd = memcached_create(NULL);
	if (!mcd)
	{
		fprintf(stderr, "memcached_create(NULL) : %s\n", strerror(errno));
		return 1;
	}

	while ((code = getopt(argc, argv, "c:vh")) > 0)
	{
		memcached_return_t	rc;

		switch (code)
		{
			case 'c':
				if (strncmp(optarg, "tcp://", 6) == 0)
				{
					parse_connection(optarg+6, &port, &weight);
					rc = memcached_server_add_with_weight(mcd, optarg+6, port, weight);
					if (rc != MEMCACHED_SUCCESS)
					{
						fprintf(stderr, "failed to add tcp://%s:%d/%u\n",
								optarg+6, port, weight);
						return 1;
					}
				}
				else if (strncmp(optarg, "udp://", 6) == 0)
				{
					parse_connection(optarg+6, &port, &weight);
					rc = memcached_server_add_udp_with_weight(mcd, optarg+6, port, weight);
					if (rc != MEMCACHED_SUCCESS)
					{
						fprintf(stderr, "failed to add udp://%s:%d/%u\n",
								optarg+6, port, weight);
						return 1;
					}
				}
				else if (strncmp(optarg, "unix://", 7) == 0)
				{
					parse_connection(optarg+7, NULL, &weight);
					rc = memcached_server_add_unix_socket_with_weight(mcd, optarg+7, weight);
					if (rc != MEMCACHED_SUCCESS)
					{
						fprintf(stderr, "failed to add unix://%s/%u\n",
								optarg+7, weight);
						return 1;
					}
				}
				else
				{
					parse_connection(optarg, &port, &weight);
					rc = memcached_server_add_with_weight(mcd, optarg, port, weight);
					if (rc != MEMCACHED_SUCCESS)
					{
						fprintf(stderr, "failed to add tcp://%s:%d/%u\n",
                                optarg, port, weight);
                        return 1;
					}
				}
				num_conns++;
				break;
			case 'v':
				verbose = true;
				break;
			default:
				fprintf(stderr,
						"usage: %s [options] [<commands>]\n"
						"\n"
						"[options]\n"
						"  -c <server>  server to be connected\n"
						"         [tcp://]<host>[:<port>][/<weight>]\n"
						"         udp://<host>[:<port>][/<weight>]\n"
						"         unix://<path>[/<weight>]\n"
						"\n"
						"[<command>]\n"
						"  get <key>\n"
						"  add <key> <value> [<expire> [<flags>]]\n"
						"  set <key> <value> [<expire> [<flags>]]\n"
						"  replace <key> <value> [<expire> [<flags>]]\n"
						"  append <key> <value> [<expire> [<flags>]]\n"
						"  prepend <key> <value> [<expire> [<flags>]]\n"
						"  cas <key> <value> <cas> [<expire> [<flags>]]\n"
						"  delete <key> [<expire>]\n"
						"  incr <key>\n"
						"  decr <key>\n"
						"  flush [<when>]\n"
						"  ----\n"
						"  simple_bench [<scale>]\n",
						argv[0]);
				return 1;
		}
	}

	/*
	 * If no server specified, a default is implicitly used
	 */
	if (num_conns == 0)
	{
		if (memcached_server_add(mcd, "localhost", 11211) != MEMCACHED_SUCCESS)
		{
			fprintf(stderr, "failed to add tcp://localhost:11211\n");
			return 1;
		}
	}

	if (optind == argc)
	{
		char	buffer[10240];
		char  **cmds = NULL;
		int		n_cmds = 0;

		while(fgets(buffer, sizeof(buffer), stdin) != NULL)
		{
			char   *tok = strtok(buffer, " \t\n");
			int		index = 0;

			while (tok != NULL)
			{
				if (index == n_cmds)
				{
					n_cmds = (n_cmds ? 2 * n_cmds : 10);

					cmds = realloc(cmds, sizeof(char *) * n_cmds);
					if (!cmds)
					{
						fprintf(stderr, "realloc() failed: %d(%s)\n",
								errno, strerror(errno));
						return 1;
					}
				}
				cmds[index++] = tok;
				tok = strtok(NULL, " \t\n");
			}
			if (index == 0)
				continue;

			retval = exec_command(mcd, index, cmds);
			if (retval != 0)
				return retval;
		}
	}
	else
	{
		retval = exec_command(mcd, argc - optind, argv + optind);
	}
	return retval;
}
