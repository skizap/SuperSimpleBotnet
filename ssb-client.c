#include <stdio.h>

#include <sys/socket.h>
#include <arpa/inet.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#define PORT 443

void err_exit(char *s);

void
err_exit(char *s)
{
	fprintf(stderr, s);
	exit(-1);
}

int
main(int argc, char **argv)
{
	if (argc < 2)
		err_exit("USAGE: ./ssb-client <SERVER>\n");
}
