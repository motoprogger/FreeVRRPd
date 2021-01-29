/*
 * Copyright (c) 2020-2021 Dmitriy Kryuk <kryukdmitriy@rambler.ru>
 *
 * Redistribution and use in source forms, with and without modification,
 * are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution. Obviously, it
 *    would be nice if you gave credit where credit is due but requiring it
 *    would be too onerous.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by Sebastien Petit.
 * 4. Neither the name of its contributors may be used to endorse or promote
 *    products derived from this software without specific prior written
 *    permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $Id$
 */

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <assert.h>
#include <spawn.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "vrrp_script.h"

struct envvar {
	const char* varname;
	const char* varvalue;
};

static int
stringlist_length(const char* const* strings)
{
	int count = 0;
	if (!strings)
		return count;
	while (*strings) {
		strings++;
		count++;
	}
	return count;
}

static int
envlist_length(const struct envvar *vars)
{
	int count = 0;
	if (!vars)
		return count;
	while (vars->varname) {
		vars++;
		count++;
	}
	return count;
}

static int
execute_script(const char* script, const char* const* scriptargs, const struct envvar *vars)
{
	int argcount = stringlist_length(scriptargs);
	int parentenvcount = stringlist_length((const char* const*)environ);
	int envcount = envlist_length(vars);
	int envc = parentenvcount + envcount;
	/*  Calculate how much memory we need to allocate */
	size_t stringslen = 0;
	int i;
	/* For each new environment variable count its name length, its value length, the '=' character, and the terminating '\0' character */
	for (i=0; i<envcount; i++)
		stringslen = stringslen + strlen(vars[i].varname) + strlen(vars[i].varvalue) + 2;
	/* Allocate space for pointers:
         * 1) Arguments: the script name, the arguments themselves, and the terminating NULL pointer
	 * 2) Environment variables: the variables themselves and the terminating NULL pointer
	 * And for the environment strings
	 */
	size_t allocsize = sizeof(void*) * (argcount+envc+3) + sizeof(char) * stringslen;
	void *buff = malloc(allocsize);
	if (!buff)
		return -ENOMEM;
	char** args = (char**) buff;
	char* const* firstarg = args;
	char **env = args + argcount + 2;
	char* const* firstenv = env;
	char **afterenv = env + envc + 1;
	char **afterargs = env;
	char *strings = (char*) (void*) afterenv;
	char *afterstrings = ((char*) buff) + allocsize;
	/* Place script name as the 0th argument */
	assert(args<afterargs);
	*(args++) = (char*) script;
	/* Copy the other arguments in order */
	for (i=0; i<argcount; i++) {
		assert(args<afterargs);
		*(args++) = (char*) (scriptargs[i]);
	}
	/* Terminate the arguments list with a NULL pointer */
	assert(args<afterargs);
	*args = NULL;
	/* Copy the current environment string pointers */
	for (i=0; i<parentenvcount; i++) {
		assert(env<afterenv);
		*(env++) = environ[i];
	}
	/* Apply the new environment provided */
	for (i=0; i<envcount; i++) {
		char** cur;
		/* Check if the variable is already set */
		for (cur=(char**)firstenv; cur<env; cur++) {
			/* Check if the environment string starts with the variable name with '=' appended */
			size_t namelen = strlen(vars[i].varname);
			if (strncmp(*cur, vars[i].varname, namelen)==0) {
				/* If we've found the variable string, replace it. Leave cur pointing to the pointer to replace */
				if (*cur[namelen]=='=') break;
			}
		}
		/* If the corresponding variable wasn't found, cur==env */
		assert(cur<afterenv);
		assert(strings<afterstrings);
		if (cur>=env) env++;
		/* Set the pointer to the first free position in the string buffer */
		*cur = strings;
		/* Append variable name to the string buffer */
		strings = stpncpy(strings, vars[i].varname, afterstrings-strings);
		/* Append the '=' character to the string buffer */
		assert(strings<afterstrings);
		*(strings++) = '=';
		/* Append variable value to the string buffer */
		assert(strings<afterstrings);
		strings = stpncpy(strings, vars[i].varvalue, afterstrings-strings);
		/* Check if the string fits in the buffer (including the terminating '\0' character) */
		assert(strings<afterstrings);
		/* Leave the terminating '\0' in place and use the next buffer character for the next string */
		strings++;
	}
	/* Terminate the environment list with a NULL pointer */
	assert(env<afterenv);
	*env = NULL;
	/* Spawn a new process */
	pid_t pid;
	int res = posix_spawn(&pid, script, NULL, NULL, firstarg, firstenv);
	if (res!=0) {
		free(buff);
		return -res;
	}
	/* Wait for the process to terminate */
	/* waitpid */
	int status;
	pid_t waitres;
	int wait_errno;
	waitres = waitpid(pid, &status, 0);
	wait_errno = errno;
	if (waitres==pid) {
		free(buff);
		if (WIFEXITED(status))
			return WEXITSTATUS(status);
		else
			return -EINTR;
	} else {
		free(buff);
		return -wait_errno;
	}
}

static int
format_ipaddrs(struct vrrp_vr *vr, char **result)
{
	size_t allocsize = vr->cnt_ip*20+2;
	char *ifaddrs = (char*) malloc(allocsize);
	if (!ifaddrs)
		return ENOMEM;
	char *cur = ifaddrs;
	char *last = ifaddrs+allocsize/sizeof(char);
	int i;
	for (i=0; i<vr->cnt_ip; i++) {
		assert(cur<last);
		const char *res = inet_ntop(AF_INET, &(vr->vr_ip[i].addr.s_addr), cur, last-cur);
		if (!res) {
			int err = errno;
			free(ifaddrs);
			return err;
		}
		cur += strnlen(cur, last-cur);
		assert(cur<last);
		int count = snprintf(cur, last-cur, "/%u ", vr->vr_netmask[i]);
		cur += count;
		assert(cur<last);
	}
	cur--;
	assert(cur<last);
	*cur = '\0';
	*result = ifaddrs;
	return 0;
}

int
vrrp_script_run(struct vrrp_vr * vr, const char* verb)
{
	if (vr->state_script) {
		/* vr->vr_ip[i].addr.s_addr */
		char *ifaddrs;
		int res = format_ipaddrs(vr, &ifaddrs);
		if (res) {
			syslog(LOG_ERR, "Formatting arguments for script %s for interface %s failed with error %i\n", vr->state_script, vr->vr_if->if_name, res);
			return res;
		}
		/* vr->bridgeif_name */
		char dladdr[20];
		char *dltoares = vrrp_misc_dltoa(&(vr->ethaddr), dladdr, sizeof(dladdr));
		if (!dltoares) {
			int dltoa_err = errno;
			free(ifaddrs);
			syslog(LOG_ERR, "Formatting hardware address for interface %s failed with error %i\n", vr->vr_if->if_name, dltoa_err);
			return -dltoa_err;
		}
		const struct envvar envs[] = {
			{
				"BRIDGEIF_NAME",
				(const char*) vr->bridgeif_name
			},
			{
				"BRIDGEIF_DLADDR",
				dladdr
			},
			{
				0,
				0
			}
		};
		const char* args[] = { verb, vr->vr_if->if_name, ifaddrs, 0 };
		syslog(LOG_NOTICE, "Running script %s with verb %s for interface %s\n", vr->state_script, verb, vr->vr_if->if_name);
		res = execute_script(vr->state_script, args, envs);
		if (res>=0)
			syslog(LOG_NOTICE, "Script %s exited with status %i\n", vr->state_script, res);
		else
			syslog(LOG_NOTICE, "Running script %s failed with error %i\n", vr->state_script, -res);
		free(ifaddrs);
		return res;
	}
	return 0;
}

