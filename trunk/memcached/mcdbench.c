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
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <libmemcached/memcached.h>

/*
 * option variable
 */
static double	scaling = 1000.0;
static int		num_threads = 1;
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
	if (!value)
		printf("get: key=%s error=%s\n",
			   key, memcached_strerror(mcd, error));
	else
		printf("get: key=%s value=%.*s flags=%08x\n",
			   key, value_length, value, flags);

	return 0;
}

static int
exec_add(memcached_st *mcd, const char *key, const char *value,
		 time_t expire, uint32_t flags)
{
	memcached_return_t	error;

	if (MEMCACHED_SUCCESS != memcached_add(mcd, key, strlen(key),
										   value, strlen(value),
										   expire, flags))
		printf("add: key=%s error=%s\n",
			   key, memcached_strerror(mcd, error));
	else
		printf("add: key=%s value=%s expire=%u flags=%u\n",
			   key, value, expire, flags);
	return 0;
}

static int
exec_set(memcached_st *mcd, const char *key, const char *value,
		 time_t expire, uint32_t flags)
{
	memcached_return_t	error;

	if (MEMCACHED_SUCCESS != memcached_set(mcd, key, strlen(key),
										   value, strlen(value),
										   expire, flags))
		printf("set: key=%s error=%s\n",
			   key, memcached_strerror(mcd, error));
	else
		printf("set: key=%s value=%s expire=%u flags=%u\n",
			   key, value, expire, flags);
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
	return retval;

#if 0
						"  get <key> [<keys>...]\n"
						"  add <key> <value> [<expire> [<flags>]]\n"
						"  set <key> <value> [<expire> [<flags>]]\n"
						"  replace <key> <value> [<expire> [<flags>]]\n"
						"  cas <key> <value> <cas> [<expire> [<flags>]]\n"
						"  delete <key> <value>\n"
						"  incr <key> <delta>\n"
						"  decr <key> <delta>\n"
						"  flush <when>\n"
#endif
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
		fprintf(stderr, "memcached_create : %d(%s)\n",
				errno, strerror(errno));
		return 1;
	}

	while ((code = getopt(argc, argv, "c:n:s:vh")) > 0)
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
			case 'n':
				num_threads = atoi(optarg);
				if (num_threads < 1)
				{
					fprintf(stderr, "invalid number of threads: %d\n", num_threads);
					return 1;
				}
				break;
			case 's':
				scaling = atof(optarg);
				if (scaling < 1000.0)
				{
					fprintf(stderr, "too small scaling factor: %f\n", scaling);
					return 1;
				}
				break;
			case 'v':
				verbose = true;
				break;
			default:
				fprintf(stderr,
						"usage: %s [options] [<command>]\n"
						"\n"
						"[options]\n"
						"  -c <server>  server to be connected\n"
						"         [tcp://]<host>[:<port>][/<weight>]\n"
						"         udp://<host>[:<port>][/<weight>]\n"
						"         unix://<path>[/<weight>]\n"
						"  -n <num>     number of threads\n"
						"  -s <scale>   scaling factor\n"
						"\n"
						"[<command>]\n"
						"  get <key> [<keys>...]\n"
						"  add <key> <value> [<expire> [<flags>]]\n"
						"  set <key> <value> [<expire> [<flags>]]\n"
						"  replace <key> <value> [<expire> [<flags>]]\n"
						"  cas <key> <value> <cas> [<expire> [<flags>]]\n"
						"  delete <key> <value>\n"
						"  incr <key> <delta>\n"
						"  decr <key> <delta>\n"
						"  flush <when>\n"
						"  ----\n"
						"  simple_test\n",
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
