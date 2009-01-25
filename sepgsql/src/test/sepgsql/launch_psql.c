/*
 * launch_psql.c
 *
 * It invokes psql with proper security context.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <selinux/selinux.h>

int main(int argc, char *const argv[])
{
	char buffer[2048], cmd[512];
	FILE *filp = NULL;
	int i, ofs;

	if (argc < 2)
	{
		fprintf(stderr, "usage: %s <command> [<options> ...]\n", argv[0]);
		return 1;
	}

	for (i=1, ofs=0; argv[i] != NULL; i++)
		ofs += snprintf(cmd + ofs, sizeof(cmd) - ofs, " %s", argv[i]);

	while (fgets(buffer, sizeof(buffer), stdin) != NULL)
	{
		if (strncasecmp(buffer, ":SECURITY_CONTEXT=", 18) == 0)
		{
			security_context_t context = buffer + 18;
			char *pos;

			/* set exec security context */
			pos = strchr(context, '#');
			if (pos)
				*pos = '\0';
			pos = context + strlen(context) - 1;
			while (isspace(*pos))
				*pos-- = '\0';
			if (setexeccon(context) < 0)
			{
				fprintf(stderr, "%s: setexeccon('%s') = %s\n",
						argv[0], context, strerror(errno));
				return 1;
			}

			if (filp != NULL)
			{
				pclose(filp);
				filp = NULL;
			}
			continue;
		}

		if (filp == NULL)
		{
			filp = popen(cmd, "w");
			if (!filp)
			{
				fprintf(stderr, "%s: popen('%s', 'w') = %s\n",
						argv[0], cmd, strerror(errno));
				return 1;
			}
		}

		if (fwrite(buffer, 1, strlen(buffer), filp) < 0)
		{
			fprintf(stderr, "%s: fwrite(...) = %s\n",
					argv[0], strerror(errno));
			return 1;
		}
	}

	if (filp)
		pclose(filp);

	return 0;
}



