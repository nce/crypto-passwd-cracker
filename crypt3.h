#ifndef CRYPT_3_H_INCLUDED
#define CRYPT_3_H_INCLUDED

#define _BSD_SOURCE
#define _XOPEN_SOURCE 600

#define FQDN 51
#define HOSTNAMESIZE 10
#define MAXMESSAGE 112


/* * * * * * * * * * * * * * * * * 
 * CONFIG (no modifications above)
 * * * * * * * * * * * * * * * * */

// relative to ~; or absolute
#define CLIENTPATH "./foobar/crypt3client" 
// charset... only unique chars!
#define CHARSET "abcdefghijklmnopqrstuvwxyz"
// how many crypt(3) cycles per workload.  
// reasonable amount for MD5: >10000
// reasonable amount for SHA512: <5000
#define LIMIT 8000 
// amount of nodes; Max 94; Min 1; (see EOF);
#define CRYPTNODES 94 

#include<stdlib.h>
#include<unistd.h>
#include<stdio.h>
#include<string.h>
#include<getopt.h>
#include<signal.h>
#include<errno.h>

#include<sys/types.h>
#include<sys/socket.h>
#include<sys/prctl.h>
#include<netdb.h>

/** 
 * Server 
 */

/**
 * start the server after checking all parameters
 */
extern int launchServer(int port, FILE *shadow);

/**
 * fork a ssh connection to the given server and launch the crypt3 client there
 */
extern pid_t execClient(char *remoteHost, char *serverName, char *port, char *threads);

/**
 * read one line of the given shadow password file
 */
extern char *readLineFromShadow(FILE *shadow);

/**
 * send Workload to client
 */
extern char *dispatchWorkload();

/**
 * adds new node to our cryptnode management list
 */
extern int addNode(int fd, char *hostname);

/**
 * removes node from list, by given filedescriptor
 */
extern int rmNode(int fd);

/**
 * initiates shutdown with cleanup of memory; shutdown of all clients; catch zombies
 */
extern void serverShutdown(int nodes);

/**
 * gets Hostname by given fd from the list
 */
extern char *getHostname(int fd);



/**
 * Client
 */

/**
 * launches the client 
 */
extern int launchClient(char *host, char *port, int threads);
/**
 * increments the passwords until given limit; compares calculated hashes with tragethash 
 */
extern void *crack(void *arg);
/**
 * ask for workload from master server
 */
extern char *requestWorkload(int socket, char *buf);
/**
 * use nonblocking socket to check for messages from the server
 */
extern int checkMessage(int socket, char *buf);



/**
 * send complete message to client/server, preventing partial send()s
 * Protocol:
 * 1Byte    3Byte          120Byte
 * length   status code    message buffer
 */
static int sendMessage(int socket, char *buf, int len) {
	int total = 0;   // bytes we have sent
	int left = len;  // bytes left to send
	int n;
	
	memcpy(buf, &left, 1); // write length to 1byte  

	while(total < len) {
		if(-1 == (n = send(socket, buf+total, left, 0))) 
			return -1;
		total += n;
		left  -= n;
	}
	//*len = total;

	//printf("sent: %s; in bytes: %d\n", buf, total);

	return 0;
}

static int recvMessage(int socket, char *buf) {
	int length = 0;
	int received = 0;
	int n;

	if(1 != recv(socket, &length, 1, MSG_PEEK))
		return -1;
	
	while(received < length) {
		if(-1 == (n = recv(socket, buf+received, MAXMESSAGE-received, 0)))
			return -1;
		received += n;
	}
	buf[length] = '\0';
	buf[0] = '0';
	
	//printf("buf: %s\n", buf);
	return received;
}

/**
 * initializes the charset array
 * in the charsetTable every char is stored at its predecessors ascii representation, e.g. 'B' is stored at 65
 * the first char of our charset is stored at '0' and used as a boundary for cyclic increment
 */
static char charsetTable[256];
static char plaintext[256];

static void initCharset() {
	char charset[256];
	memset(charsetTable, 0, sizeof(charsetTable));
	memset(plaintext, 0, sizeof(plaintext));

	strcpy(charset, CHARSET); // copy the charset

	for(int i = 0, k = 0 ;; i++) {
		charsetTable[k] = (unsigned char) charset[i];
		if(!charset[i]) return;

		k = (unsigned char) charset[i];
	}
	return;
}

/* static volatile int heartbeat = 0;
static void alarmhandler(int sig) {
	heartbeat = 1;
}
 */
/** 
 * indicate wrong usage 
 */
static void usageError(char *name) {
	fprintf(stderr, "Usage: %s\n\
	\033[1mCLIENT\033[0m\n\
		-p <port>\n\
			Port the client should connect to\n\
		-n <name>\n\
			Hostname of the server\n\
		-t <threads>\n\
			Threads the client should execute\n\
	\n\t\033[1mSERVER\033[0m\n\
		-p <port>\n\
			Port the server should bind to\n\
		-s <shadowfile>\n\
			Path to the shadow file\n", name);
	exit(EXIT_FAILURE);
}


static char *hosts[94][2] = {
	// quad cores == 2 threads
	// rest 1
	  {"faui0sr0", "4"}
	, {"faui0sr1", "4"}

	// 20 AMD Opteron(tm) Processor 148
	, {"faui00a" , "1"}, {"faui00b" , "1"}, {"faui00c" , "1"}, {"faui00d" , "1"}, {"faui00e" , "1"}
	, {"faui00f" , "1"}, {"faui00g" , "1"}, {"faui00h" , "1"}, {"faui00i" , "1"}, {"faui00j" , "1"}
	, {"faui00k" , "1"}, {"faui00l" , "1"}, {"faui00m" , "1"}, {"faui00n" , "1"}, {"faui00r" , "1"}
	, {"faui00s" , "1"}, {"faui00t" , "1"}, {"faui00u" , "1"}, {"faui00v" , "1"}, {"faui00w" , "1"}
	
	// 21 Celsius W360, Intel Core2 Quad Workstations (Linux, 8GB RAM)
	, {"faui02a" , "2"}, {"faui02b" , "2"}, {"faui02c" , "2"}, {"faui02d" , "2"}, {"faui02e" , "2"}
	, {"faui02f" , "2"}, {"faui02g" , "2"}, {"faui02h" , "2"}, {"faui02i" , "2"}, {"faui02j" , "2"}
	, {"faui02k" , "2"}, {"faui02l" , "2"}, {"faui02m" , "2"}, {"faui02n" , "2"}, {"faui02r" , "2"}
	, {"faui02s" , "2"}, {"faui02t" , "2"}, {"faui02u" , "2"}, {"faui02v" , "2"}, {"faui02w" , "2"}
	, {"faui02x" , "2"}
	
	// 3 Intel(R) Core(TM)2 Quad CPU    Q6600  @ 2.40GHz
	, {"faui03a" , "2"}, {"faui03b" , "2"}, {"faui03c" , "2"}
	
	// faui04x kein zugang
	
	// 8 Intel(R) Core(TM)2 Duo CPU     E8400  @ 3.00GHz
	, {"faui05a" , "1"}, {"faui05b" , "1"}, {"faui05c" , "1"}, {"faui05d" , "1"}, {"faui05e" , "1"} 
	, {"faui05f" , "1"}, {"faui05g" , "1"}, {"faui05h" , "1"}
	
	// 14 Intel(R) Core(TM)2 Quad CPU    Q6600  @ 2.40GHz  CIP 1. Stock
	, {"faui06a" , "2"}, {"faui06b" , "2"}, {"faui06c" , "2"}, {"faui06d" , "2"}, {"faui06e" , "2"}
	, {"faui06f" , "2"}, {"faui06g" , "2"}, {"faui06h" , "2"}, {"faui06i" , "2"}, {"faui06j" , "2"}
	, {"faui06k" , "2"}, {"faui06l" , "2"}, {"faui06m" , "2"}, {"faui06n" , "2"}, {"faui06o" , "2"}
	, {"faui06p" , "2"}  
	
	// faui07x nicht erreichbar
	
	// 15 Intel(R) Core(TM)2 Quad CPU    Q6600  @ 2.40GHz CIP 2. Stock
	, {"faui08a" , "2"}, {"faui08b" , "2"}, {"faui08c" , "2"}, {"faui08d" , "2"}, {"faui08e" , "2"}
	, {"faui08f" , "2"}, {"faui08g" , "2"}, {"faui08h" , "2"}, {"faui08i" , "2"}, {"faui08j" , "2"}
	, {"faui08k" , "2"}, {"faui08l" , "2"}, {"faui08m" , "2"}, {"faui08n" , "2"}, {"faui08p" , "2"}

	// 9 Intel Core2 Duo Workstations (Linux, 4GB RAM) 
	, {"faui09a" , "1"}, {"faui09b" , "1"}, {"faui09c" , "1"}, {"faui09d" , "1"}, {"faui09e" , "1"}
	, {"faui09f" , "1"}, {"faui09g" , "1"}, {"faui09h" , "1"}, {"faui09i" , "1"}
};

#endif

