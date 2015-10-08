CC = gcc -std=c99 -pedantic -Wall -masm=intel -fomit-frame-pointer 
OBJ = crypt3client crypt3server
.PHONY: all clean

includes = crypt3.h

all: $(OBJ)

crypt3client: crypt3client.c ${includes}
	$(CC) -Icrypt.h -lcrypt -lpthread -O3 -o $@ $<
crypt3server: crypt3server.c ${includes}
	$(CC) -Icrypt.h -o $@ $<

clean:
	rm -r $(OBJ)
