CC=gcc
CLIBS=-lssl -lcrypt
OBJ=ssb-server.c

all: ssb-server

ssb-server: $(OBJ)
	$(CC) -o $@ $^ $(CLIBS)
