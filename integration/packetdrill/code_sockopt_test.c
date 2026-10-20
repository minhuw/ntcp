/* SPDX-License-Identifier: GPL-2.0-or-later
 * Linked against the real patched code.c; only timing and socket input are fake.
 */
#include "code.h"
#include "run.h"
#include "tcp.h"
#include <stdarg.h>
#include <errno.h>

int opt_debug;
static int calls[3], count, fail_option;

void wait_for_event(struct state *state) {}
void die(char *format, ...)
{
	va_list args;
	va_start(args, format);
	vfprintf(stderr, format, args);
	va_end(args);
	exit(42);
}
void die_perror(char *message) { perror(message); exit(43); }

int getsockopt(int fd, int level, int option, void *data, socklen_t *len)
{
	assert(fd == 123);
	assert(count < 3);
	calls[count++] = option;
	if (option == fail_option) {
		errno = ENOPROTOOPT;
		return -1;
	}
	if (option == TCP_INFO) {
		if (getenv("TCP_INFO_TRACE"))
			fprintf(stderr, "requested TCP_INFO %u\n", (unsigned)*len);
		const char *limit = getenv("TCP_INFO_LIMIT");
		if (limit && *len > atoi(limit)) {
			errno = EOPNOTSUPP;
			return -1;
		}
	}
	memset(data, 0, *len);
	if (option == TCP_INFO) {
		const char *reply = getenv("TCP_INFO_RETURN_LEN");
		if (reply)
			*len = atoi(reply);
	}
	return 0;
}

int main(int argc, char **argv)
{
	assert(argc == 4);
	struct config config = { .code_format = "python", .code_sockopt = argv[1],
		.code_command_line = "python3 -I", .script_path = "snapshot-fixture.pkt" };
	struct socket socket = {0};
	socket.fd.live_fd = 123;
	struct state state = { .config = &config, .socket_under_test = &socket,
		.code = code_new(&config) };
	struct event event = { .line_number = 1 };
	fail_option = atoi(argv[2]);
	enum code_data_t selection = state.code->data_type;
	for (int i = 0; i < 2; ++i) {
		count = 0;
		const char *second = getenv("TCP_INFO_SECOND_SNIPPET");
		run_code_event(&state, &event, i == 1 && second ? second : argv[3]);
		assert(state.code->data_type == selection);
		if (selection == DATA_NONE) {
			assert(count == 3);
			assert(calls[0] == TCP_INFO && calls[1] == TCP_CC_INFO && calls[2] == SO_MEMINFO);
		} else {
			assert(count == 1);
			assert(calls[0] == (selection == DATA_TCP_INFO ? TCP_INFO :
				selection == DATA_TCP_CC_INFO ? TCP_CC_INFO : SO_MEMINFO));
		}
	}
	char *error = NULL;
	int result = code_execute(state.code, &error);
	if (error) fprintf(stderr, "%s\n", error);
	free(error);
	code_free(state.code);
	return result == STATUS_OK ? 0 : 1;
}
