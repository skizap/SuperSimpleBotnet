#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/socket.h>
#include <arpa/inet.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#define PORT 443
#define MAXCH 10

void init_ssl(void);
void err_exit(char *s);
SSL_CTX *ssl_ctx(char *cert, char *key);
int sock_listn(void);

void
err_exit(char *s)
{
	fprintf(stderr, s);
	exit(-1);
}

int
sock_listn(void)
{
	int lfd;
	struct sockaddr_in adr;

	memset(&adr, 0, sizeof(adr)); /* Zero out the struct */

	adr.sin_family = AF_INET; /* IPv4 */
	adr.sin_addr.s_addr = htonl(INADDR_ANY); /* 0.0.0.0 */
	adr.sin_port = htons(PORT);

	if ((lfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) /* IPv4, TCP, Default based on request */
		err_exit("Failed to create socket\n");
	if (bind(lfd, (struct sockaddr*) &adr, sizeof(adr)) < 0)
		err_exit("Failed to bind\n");
	if (listen(lfd, 3) < 0)
		err_exit("Failed to listen\n");
	return lfd;
}

SSL_CTX *
ssl_ctx(char *cert, char *key)
{
	const SSL_METHOD * m;
	SSL_CTX *ctx;

	m = SSLv23_server_method();
	if (!(ctx = SSL_CTX_new(m)))
		err_exit("Failed to create SSL context\n");

	SSL_CTX_set_ecdh_auto(ctx, 1);
    if (SSL_CTX_use_certificate_file(ctx, cert, SSL_FILETYPE_PEM) <= 0)
		err_exit("Failed to use SSL cert\n");
    if (SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) <= 0 )
		err_exit("Failed to use SSL key\n");
	return ctx;
}

void
init_ssl(void)
{
	SSL_load_error_strings();
	OpenSSL_add_ssl_algorithms();
}

int
main(int argc, char **argv)
{
	int lfd, cfd;
	SSL_CTX *ctx;

	if (argc < 3)
		err_exit("USAGE: ./ssb-server <SSL-CERT> <SSL-PRIV-KEY>\n");
	if (getuid())
		err_exit("Run as root\n");
	/* Example taken from: https://wiki.openssl.org/index.php/Simple_TLS_Server
	 * Setup SSL
	 */
	init_ssl();
	ctx = ssl_ctx(argv[1], argv[2]);

	lfd = sock_listn();

	while (1) {
		SSL *ssl;
		struct sockaddr_in inc_adr;
		FILE *fp;
		char reply[MAXCH], buf[4096];
		char *data, *c_adr;
		int recv = -1;
		size_t adr_len;

		memset(&inc_adr, 0, sizeof(inc_adr));
		adr_len = sizeof(inc_adr);

		/* Read the command to client using a textfile */
		if (!(fp = fopen("cmd", "r")))
			err_exit("Failed to open command file\n");

		fscanf(fp, "%s", reply);
		fclose(fp);

		if ((cfd = accept(lfd, (struct sockaddr*) &inc_adr, (socklen_t*) &adr_len)) < 0)
			err_exit("Failed to accept connections\n");

		ssl = SSL_new(ctx);
		SSL_set_fd(ssl, cfd);
		if (SSL_accept(ssl) == 1) {
			SSL_write(ssl, reply, strlen(reply));
			if ((recv = SSL_read(ssl, buf, sizeof(buf))) <= 0)
				err_exit("Failed to read data\n");
		} else
			err_exit("Failed to accept SSL connections\n");
		buf[recv] = '\0';
		data = strrchr(buf, '\n');
		c_adr = inet_ntoa(inc_adr.sin_addr);
		printf("DATA RECEIVED FROM '%s': %s\n",c_adr ,data);
		SSL_free(ssl);
		close(cfd);
	}
	/* Cleanup */
	close(lfd);
	SSL_CTX_free(ctx);
	EVP_cleanup();
}
