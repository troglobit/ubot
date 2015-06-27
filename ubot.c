/* ubot - a very small and stupid irc bot
 *
 * Copyright (c) 2015  Joachim Nilsson <troglobit@gmail.com>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#define _GNU_SOURCE

#include <arpa/inet.h>		/* inet_pton() */
#include <errno.h>
#include <error.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>		/* _GNU_SOURCE => strcasestr() */
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>		/* close() */

#define VERSION "0.1"

#define SERVER  "127.0.0.1"
#define PORT    6667
#define CHANNEL "spam"
#define NICK    "ubot"
#define NAME    "ubot rulez"

extern char *__progname;


static FILE *do_connect(char *server, unsigned int port)
{
	int sd, ret;
	FILE *fp;
	struct sockaddr_in sin;

	sd = socket(AF_INET, SOCK_STREAM, 0);
	if (sd < 0)
		return NULL;

	memset(&sin, 0, sizeof(sin));
	if (inet_pton(AF_INET, server, &sin.sin_addr) <= 0) {
		close(sd);
		return NULL;
	}

	sin.sin_family = AF_INET;
	sin.sin_port = htons(port);
	ret = connect(sd, (struct sockaddr *)&sin, sizeof(sin));
	if (ret < 0) {
		close(sd);
		return NULL;
	}

	fp = fdopen(sd, "rw");
	if (!fp) {
		close(sd);
		return NULL;
	}

	return fp;
}

static char *chomp(char *str)
{
	char *p;

	if (!str || strlen(str) < 1) {
		errno = EINVAL;
		return NULL;
	}

	p = str + strlen(str) - 1;
        while (*p == '\n' || *p == '\r')
		*p-- = 0;

	return str;
}

static int bot(char *server, int port, char *channel)
{
	FILE *fp;
	char line[256];

	fp = do_connect(server, port);
	if (!fp)
		error(1, errno, "Failed connecting to %s:%d", server, port);

	fprintf(fp, "NICK %s\r\n", NICK);
	fprintf(fp, "USER %s 0 0 : %s\r\n", NICK, NAME);
	fprintf(fp, "JOIN #%s\r\n", channel);

	while (1) {
		if (fgets(line, sizeof(line), fp)) {
			chomp(line);

			if (!strcasestr(line, "PING")) {
				char *pos = strstr(line, " ") + 1;
				fprintf(fp, "PONG %s\r\n", pos);
			}
		}
	}

	return fclose(fp);
}

static int usage(int rc)
{
	fprintf(stderr, "Usage: %s [OPTIONS] SERVER CHANNEL\n\n"
		"Options:\n"
		"  -h, --help            This help text\n"
		"  -V, --version         Show version\n\n", __progname);

	return rc;
}

int main(int argc, char *argv[])
{
	int c, port = PORT;
	char channel[42] = CHANNEL;
	char server[256] = SERVER;
	struct option long_options[] = {
		{ "help",    0, NULL, 'h' },
		{ "version", 0, NULL, 'v' },
		{ "port",    1, NULL, 'p' },
		{ NULL, 0, NULL, 0 }
	};

	while ((c = getopt_long(argc, argv, "h?vp:", long_options, NULL)) != EOF) {
		switch(c) {
		case 'p':
			port = atoi(optarg);
			break;

		case 'v':
			return puts("v" VERSION) == EOF;

		case 'h':
		case '?':
			return usage(0);
		}
	}

	if (optind < argc)
		strncpy(server, argv[optind++], sizeof(server));
	if (optind < argc)
		strncpy(channel, argv[optind++], sizeof(channel));

	return bot(server, port, channel);
}

/**
 * Local Variables:
 *  version-control: t
 *  indent-tabs-mode: t
 *  c-file-style: "linux"
 * End:
 */
