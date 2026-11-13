// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * system(3) for the flake's packetdrill runner, linked with -Wl,--wrap=system.
 *
 * glibc's system() always runs /bin/sh. The runner inherits LD_PRELOAD of the
 * ntcp plugin, which is built against Nix's glibc, and passes it to the shell
 * that runs a script's commands and %{ }% code; a host /bin/sh linked against
 * the host's glibc cannot load it. This is glibc's sysdeps/posix/system.c with
 * NTCP_SHELL, the Nix bash, in place of /bin/sh: the same signal handling,
 * arguments and statuses.
 */
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <spawn.h>
#include <stddef.h>
#include <sys/wait.h>

extern char **environ;

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static int references;
static struct sigaction intr, quit;

int __wrap_system(const char *line)
{
	if (line == NULL)
		return 1;
	int status = -1;
	pid_t pid;
	struct sigaction sa = { .sa_handler = SIG_IGN };
	sigset_t omask, reset;

	sigemptyset(&sa.sa_mask);
	pthread_mutex_lock(&lock);
	if (references++ == 0) {
		sigaction(SIGINT, &sa, &intr);
		sigaction(SIGQUIT, &sa, &quit);
	}
	pthread_mutex_unlock(&lock);

	sigaddset(&sa.sa_mask, SIGCHLD);
	sigprocmask(SIG_BLOCK, &sa.sa_mask, &omask);

	sigemptyset(&reset);
	if (intr.sa_handler != SIG_IGN)
		sigaddset(&reset, SIGINT);
	if (quit.sa_handler != SIG_IGN)
		sigaddset(&reset, SIGQUIT);

	posix_spawnattr_t attr;
	posix_spawnattr_init(&attr);
	posix_spawnattr_setsigmask(&attr, &omask);
	posix_spawnattr_setsigdefault(&attr, &reset);
	posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETSIGDEF | POSIX_SPAWN_SETSIGMASK);
	int ret = posix_spawn(&pid, NTCP_SHELL, NULL, &attr,
			      (char *const[]){ "sh", "-c", "--", (char *)line, NULL },
			      environ);
	posix_spawnattr_destroy(&attr);

	if (ret == 0) {
		pid_t waited;
		do
			waited = waitpid(pid, &status, 0);
		while (waited == -1 && errno == EINTR);
		if (waited != pid)
			status = -1;
	} else if (ret == EAGAIN || ret == ENOMEM) {
		status = -1;
	} else {
		status = 127 << 8;
	}

	pthread_mutex_lock(&lock);
	if (--references == 0) {
		sigaction(SIGINT, &intr, NULL);
		sigaction(SIGQUIT, &quit, NULL);
	}
	pthread_mutex_unlock(&lock);
	sigprocmask(SIG_SETMASK, &omask, NULL);

	if (ret != 0)
		errno = ret;
	return status;
}
