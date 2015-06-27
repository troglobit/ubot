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

#include <arpa/inet.h>		/* inet_pton() */
#include <errno.h>
#include <error.h>
#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>		/* close() */

#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/tls1.h>
#include <openssl/err.h>

#define DBG(fmt, args...) if (debug) fprintf(stderr, fmt "\n", ##args)

#define BUFSZ   8192
#define SERVER  "127.0.0.1"
#define PORT    "6667"
#define CHANNEL "ubot"
#define NICK    "ubot"
#define NAME    "ubot rulez"
#define PARTMSG "ubot has left the building"

static SSL     *ssl;
static SSL_CTX *ssl_ctx;
static int      sd = -1;
static int      debug = 0;
static int      loop = 1;
static char    *port = PORT;
static char     partmsg[42] = PARTMSG;
static char     channel[42] = CHANNEL;
static char    *pass = NULL;
extern char  *__progname;

static int ssl_init(void)
{
	SSL_library_init();
	SSL_load_error_strings();

	ssl_ctx = SSL_CTX_new(SSLv23_client_method());
	if (!ssl_ctx)
		return -1;

	/* POODLE, only allow TLSv1.x or later */
	SSL_CTX_set_options(ssl_ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);

	ssl = SSL_new(ssl_ctx);
	if (!ssl)
		return -1;

#ifdef SSL_MODE_SEND_FALLBACK_SCSV
	SSL_set_mode(ssl, SSL_MODE_SEND_FALLBACK_SCSV);
#endif

	return 0;
}

static int ssl_connect(int sd)
{
	char buf[256];
	X509 *cert;

	SSL_set_fd(ssl, sd);
	if (-1 == SSL_connect(ssl))
		return -1;

	DBG("SSL connection using %s", SSL_get_cipher(ssl));

	/* Get server's certificate (note: beware of dynamic allocation) - opt */
	cert = SSL_get_peer_certificate(ssl);
	if (!cert)
		return -1;

	/* Logging some cert details. Please note: X509_NAME_oneline doesn't
	   work when giving NULL instead of a buffer. */
	X509_NAME_oneline(X509_get_subject_name(cert), buf, sizeof(buf));
	DBG("SSL server cert subject: %s", buf);
	X509_NAME_oneline(X509_get_issuer_name(cert), buf, sizeof(buf));
	DBG("SSL server cert issuer: %s", buf);

	/* We could do all sorts of certificate verification stuff here before
	   deallocating the certificate. */
	X509_free(cert);

	return 0;
}

static int do_connect(char *server, char *port)
{
	int sd, ret;
	struct addrinfo hints;
	struct addrinfo *result, *rp;

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;    /* Allow IPv4 or IPv6 */
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = 0;
	hints.ai_protocol = 0;

	ret = getaddrinfo(server, port, &hints, &result);
	if (ret)
		return -1;

	/* Iterate over all replys until we connect ... */
	for (rp = result; rp; rp = rp->ai_next) {
		sd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if (sd < 0)
			continue;

		if (!connect(sd, rp->ai_addr, rp->ai_addrlen))
			break;          /* Success */

		close(sd);
	}

	if (result)
		freeaddrinfo(result);   /* No longer needed */

	if (!rp)		        /* No address succeeded */
		return -1;

	if (ssl) {
		ret = ssl_connect(sd);
		if (ret < 0)
			goto err;
	}

	return sd;
err:
	close(sd);
	return -1;
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

static int do_send(const char *fmt, ...)
{
	int num;
	char buf[256];
	size_t len;
	va_list ap;

	va_start(ap, fmt);
	len = vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);

	if (ssl)
		num = SSL_write(ssl, buf, len);
	else
		num = (int)write(sd, buf, len);

	if (num <= 0)
		return -1;

	DBG(">> %s\n", chomp(buf));

	return 0;
}

static ssize_t do_recv(char *buf, size_t len)
{
	int num;

	if (ssl)
		num = SSL_read(ssl, buf, (int)len);
	else
		num = read(sd, buf, len);

	if (num <= 0)
		return -1;

	buf[num] = 0;
	chomp(buf);
	DBG("<< %s", buf);

	return 0;
}

static int bot(char *server, char *port)
{
	char *buf;

	sd = do_connect(server, port);
	if (sd < 0)
		error(1, errno, "Failed connecting to %s:%s", server, port);

	buf = malloc(BUFSZ);
	if (!buf)
		goto exit;

	if (pass)
		do_send("PASS %s\r\n", pass);
	do_send("NICK %s\r\n", NICK);
	do_send("USER %s 0 0 :%s\r\n", NICK, NAME);

	while (loop) {
		if (!do_recv(buf, BUFSZ)) {
			char *pos = strstr(buf, " ") + 1;

			if (!pos)
				continue;

			if (strstr(buf, " 001 "))       /* Authenicated/registered */
				do_send("JOIN #%s\r\n", channel);

			if (!strncmp(buf, "PING ", 5)) /* Keepalive */
				do_send("PONG %s\r\n", pos);

			if (!strncmp(pos, "PRIVMSG ", 8)) {
				pos = strchr(buf, '!');
				if (pos)
					*pos = 0;
				do_send("PRIVMSG #%s %s: :Why hello there, stranger!\r\n", channel, &buf[1]);
			}
		}
	}

	free(buf);
exit:
	return close(sd);
}

static int usage(int rc)
{
	fprintf(stderr, "Usage: %s [OPTIONS] SERVER CHANNEL\n\n"
		"Options:\n"
		"  -h, --help            This help text\n"
		"      --password=PWD    Send PASS PWD to connect, use SSL!\n"
		"  -p, --port=PORT       Connect to this port, default: 6667\n"
		"  -s, --ssl             Connect using SSL/TLS\n"
		"  -v, --version         Show version\n\n", __progname);

	return rc;
}

void sigint_cb(int signo __attribute__ ((unused)))
{
	do_send("PART #%s :%s\r\n", channel, partmsg);
	loop = 0;
}

int main(int argc, char *argv[])
{
	int c;
	char server[256] = SERVER;
	struct option long_options[] = {
		{ "help",     0, NULL, 'h' },
		{ "password", 1, NULL, 'l' },
		{ "port",     1, NULL, 'p' },
		{ "ssl",      0, NULL, 's' },
		{ "version",  0, NULL, 'v' },
		{ NULL, 0, NULL, 0 }
	};

	signal(SIGINT,  sigint_cb);
	signal(SIGTERM, sigint_cb);
	while ((c = getopt_long(argc, argv, "h?l:p:sv", long_options, NULL)) != EOF) {
		switch(c) {
		case 'l':
			pass = strdup(optarg);
			break;

		case 'p':
			port = strdup(optarg);
			break;

		case 'v':
			return puts("v" VERSION) == EOF;

		case 's':
			if (ssl_init())
				error(1, 0, "Failed creating SSL context, missing library?");
			break;

		case 'h':
		case '?':
			return usage(0);
		}
	}

	if (optind < argc)
		strncpy(server, argv[optind++], sizeof(server));
	if (optind < argc)
		strncpy(channel, argv[optind++], sizeof(channel));

	return bot(server, port);
}

/**
 * Local Variables:
 *  version-control: t
 *  indent-tabs-mode: t
 *  c-file-style: "linux"
 * End:
 */
