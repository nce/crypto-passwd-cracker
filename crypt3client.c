/*
 * =====================================================================================
 *
 *       Filename: crypt3client.c
 *
 *    Description: 
 *
 *        Version: 1.0
 *        Created: Wed, 08.06.2011 - 14:30:49
 *  Last modified: Sun, 09.06.2013 - 15:39:38
 *       Revision: none
 *       Compiler: gcc -std=c99 -pedantic -Wall -masm=intel -fomit-frame-pointer -Icrypt.h -lcrypt -lpthread -O3
 *
 *         Author: Ulli Goschler, siulgosc@stud.informatik.uni-erlangen.de
 *
 * =====================================================================================
 */

#include"crypt3.h"
#include<semaphore.h>
#include<pthread.h>

#define __USE_GNU
#include<crypt.h>

pthread_mutex_t mutex1;

static sem_t sem, request, delivered;
static char workset[100];
static char final[50];
static pthread_key_t tsd_key;
	

struct threadArgs {
	int threadID;
	int socket;
	char methodAndSalt[21]; // 16chars salt; 3x '$'; 1x crypt(3) method
	char cipher[87];        // sha-512 is 86 chars
};

static void cleanup(void *);

int main(int argc, char **argv) {
	if(1 == argc) 
		usageError(argv[0]);
	
	char *quake = "/usr/local/games/quake";
	char *quakeShort = "quake";

	if(-1 == prctl(PR_SET_NAME, quakeShort, NULL, NULL, NULL)) {
		perror("prctl");
		fprintf(stderr, "Could not modify prg name, processchecker kills after ~30min! Beware\n");
	}

	if(strlen(argv[0]) > strlen(quake)) {
		memset(argv[0], 0, strlen(argv[0]));
		strcpy(argv[0], quake);
	} else if(strlen(argv[0]) > 6)
		strcpy(argv[0], quakeShort);

	int port = 0;            // store port as int
	char portString[6];      // store port as string
	int threads = 0;         // number of threads to be launched for this client
	char *serverName = NULL; // name of the master node
	int c;

	while(-1 != (c = getopt(argc, argv, "p:t:n:"))) {
		switch(c) {
			case 'p':
				port = atoi(optarg);
				break;
			case 'n':
				serverName = optarg;
				break;
			case 't':
				threads = atoi(optarg);
				break;
			case '?':
				usageError(argv[0]);
				break;
			default:
				usageError(argv[0]);
		}
	}

	if(0 == port) {
		fprintf(stderr, "\033[1m-p <port> is required and should be valid\033[0m\n");
		usageError(argv[0]);
	} else if(port < 1024 || port > 65535) {
		fprintf(stderr, "\033[1mChosen port should be between 1024 and 65535\033[0m\n");
		usageError(argv[0]);
	} else if(0 == threads) {
		fprintf(stderr, "\033[1m-t <threads> is required and be greater than one\033[0m\n");
		usageError(argv[0]);
	} else if(NULL == serverName) {
		fprintf(stderr, "\033[1m-n <serverName> is required\033[0m\n");
		usageError(argv[0]);
	}
	sprintf(portString, "%d", port);

	launchClient(serverName, portString, threads);

	return 0;
}

int launchClient(char *host, char *port, int threads) {

	struct addrinfo hints, *res, *p;
	int sock, gai, ret;
	int shutdown = 0; // indicate client shutdown
	
	/* 
	struct sigaction act;    // signal handler for heartbeats */

	pthread_t thread[threads];
	struct threadArgs args[threads];

	/* 
	 * establish connection the the master node 
	 */ 
	memset(&hints, 0, sizeof(hints));
	hints.ai_socktype = SOCK_STREAM;    // use tcp socket
	hints.ai_family   = PF_UNSPEC;      // use ipv4 or ipv6
	hints.ai_flags    = AI_ADDRCONFIG;  // use ipv6 if we have interface

	if(0 != (gai = getaddrinfo(host, port, &hints, &res))) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(gai));
		exit(EXIT_FAILURE);
	}

	/* as no domain was specified, use both (v4/v6) and check which connects properly */
	for(p = res; p != NULL; p = p->ai_next) {
		sock = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
		if(0 == connect(sock, p->ai_addr, p->ai_addrlen)) 
			break;
	}
	if(NULL == p) {
		perror("socket");
		exit(EXIT_FAILURE);
	}

	/**
	 * establish heartbeats; NO HEARTBEATS AVAILABLE 
	 * machen kein sinn, da der client sich eh regelmaessig beim server meldet um neuen workload zu holen
	 */
	/* act.sa_handler = alarmhandler;
	sigemptyset(&act.sa_mask);
	act.sa_flags = 0;
 */
	/* if(-1 == sigaction(SIGALRM, &act, 0)) {
		perror("sigaction");
		exit(EXIT_FAILURE); // if we cant establish heartbeats, client will "die" anyways
	} */

	initCharset();
	
	char buf[MAXMESSAGE +1];
	char inc[MAXMESSAGE +1];
	memset(inc, 0, sizeof(inc));
	strcpy(buf+1, "201");

	if(-1 == sendMessage(sock, buf, strlen(buf))) {
		perror("send; 201 create");
		exit(EXIT_FAILURE);
	}

	recvMessage(sock, buf);
	char methodAndSalt[21];
	char hash[87];
	strncpy(methodAndSalt, buf+4, 20); // +4: skip statuscode
	strcpy(hash, buf+strlen(methodAndSalt)+2+4); // +2: \0&whitespace; +4: statuscode

	int lock = 1;
	int received = 0;


	for(;;) {
		/**
		 * init semaphore struct
		 */
		if(-1 == sem_init(&sem,0,1) || -1 == sem_init(&request,0,0) || -1 == sem_init(&delivered,0,0)) {
			perror("sem_init");
			exit(EXIT_FAILURE);
		}
		pthread_mutex_init(&mutex1, NULL);

		(void)pthread_key_create(&tsd_key, NULL);

		memset(plaintext, 0, sizeof(plaintext));

		for(int i = 0; i < threads; i++) { // START THREADS
			args[i].threadID = i;
			args[i].socket = sock;
			strcpy(args[i].methodAndSalt, methodAndSalt);
			strcpy(args[i].cipher, hash);

			if(0 != pthread_create(&thread[i], NULL, crack, (void *) &args[i])) {
				perror("pthread_create");
				exit(EXIT_FAILURE);
			}
		}

		for(;;) { // main thread loop
			
			usleep(5000);
			if(0 == sem_trywait(&request)) { // check if a thread requested anything
				if(0 == memcmp(workset, "giev", 4)) { // thread requested new workload
					memset(workset, 0, sizeof(workset));
					memset(inc, 0, sizeof(inc));
					strcpy(workset, requestWorkload(sock, inc));	

					if(0 != sem_post(&delivered)) // workload delivered; thread can continue
						perror("sem_post");
				}

			} else if(errno != EAGAIN) // in case of EAGAIN, there is no request. proceed.
				perror("sem_trywait");

			if((ret = checkMessage(sock, buf)) > 0) {
				if(0 == memcmp(buf+1, "302410", 6)) { // received 302-hash-found and 410-shutdown
					shutdown = 1; // indicate complete client shutdown
					break;	
				

				 } else if(0 == memcmp(buf+1, "302", 3)) { // received 302-hash-found
					strncpy(methodAndSalt, buf+8, 20); // +4: skip statuscode
					strcpy(hash, buf+strlen(methodAndSalt)+2+4+4); // +2: \0&whitespace; +4: statuscode
					printf("1method: %s; hash: %s\n", methodAndSalt, hash);
					received = 1;
					break;
				} else 
				printf("ffasodf\n"); 
			} else if(ret == 0) {
				fprintf(stderr, "Server closed the connection\n");
				shutdown = 1;
				break;
			}

			sem_getvalue(&sem, &lock);
			if(0 == lock) { printf("own thread FOUND\n"); break; }


		}
	
		 for(int i = 0; i < threads; i++) {
			if(0 != pthread_cancel(thread[i]))
				perror("pthread_cancel"); // threads might already be cancelld by selfexit
		} 

		for(int i = 0; i < threads; i++) {
			if(0 != pthread_join(thread[i], NULL))
				perror("pthread_join");
		}
		
		if(0 == lock) { // send our plaintext to the server
			if(-1 == sendMessage(sock, final, strlen(final))) {
				if(-1 == sendMessage(sock, final, strlen(final))) {
					perror("send; final solution"); 
					break; // end 
				}
			}
		}
		if(received == 0) {
		recvMessage(sock, buf);
		if(0 == memcmp(buf+1, "302", 3)) { // received 302-hash-found
					strncpy(methodAndSalt, buf+8, 20); // +4: skip statuscode
					strcpy(hash, buf+strlen(methodAndSalt)+2+4+4); // +2: \0&whitespace; +4: statuscode
					//printf("method: %s; hash: %s\n", methodAndSalt, hash);
			}
		}
		received = 0;


		

		if(-1 == sem_destroy(&sem) || -1 == sem_destroy(&request) || -1 == sem_destroy(&delivered))
			perror("sem_destroy");

		/* useless in linux (see pthread_mutex_destroy manpage
		 * if(0 != pthread_mutex_destroy(&mutex1) || 0 != pthread_mutex_destroy(&mutex2))
			perror("pthread_mutex_destroy"); */
		
		// semaphore destroy; mutex destroy
		if(shutdown ==1 )
			break;
	}



	printf("SHUTDOWN\n");

	close(sock);
	freeaddrinfo(res);

	return 0;
}
void cleanup(void *arg) {
	struct { char *ptr;} *tmp = arg;
	free(tmp->ptr);
	free(tmp);
} 

void *crack(void *arg) {
	struct threadArgs *param = arg;
	struct crypt_data crypt; // storage for reentrant version of crypt(3)
	int lock = 1; // semaphore

	char *tmpHash = NULL;

	size_t len = strlen(param->methodAndSalt);
	size_t cipherlen = strlen(param->cipher);

	struct { char *plain; } *str = pthread_getspecific(tsd_key);

	if (str == NULL) {
		str = malloc(sizeof(char *)); // TODO: fail
		str->plain = malloc(256); // TODO: plaintext size
		memset(str->plain, 0, sizeof(str->plain));
		strcpy(str->plain, plaintext);          /* put the data for this thread in */
		pthread_setspecific(tsd_key, str);
	}
	
	pthread_cleanup_push(cleanup, str); // prevent leaking

	pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL); // allow the thread to be cancelled at any time; doesnt get stuck on mutex waiting

	crypt.initialized = 0;
	for(;;) {
		pthread_mutex_lock(&mutex1);
		strcpy(workset, "giev");
		sem_post(&request);

		sem_wait(&delivered);
		strcpy(str->plain, workset);
		pthread_mutex_unlock(&mutex1);
		
		//printf("[c] %s\n", str->plain);

		for(int i = 0; i <= LIMIT; i++) {
			tmpHash = crypt_r(str->plain, param->methodAndSalt, &crypt);
			
			//printf("[c] %s\n", plt); sleep(1);

			if(0 == memcmp(tmpHash+len, param->cipher, cipherlen)) {
				printf("success: %s\n", str->plain);
							
				strcpy(final, "0302");
				strcpy(final+4, str->plain);	
				sem_wait(&sem);

				pthread_exit(NULL);
			}

			__asm__ __volatile__ ("pushad\n\t"    // INTEL SYNTAX
			"push tsd_key\n\t"                    // push argument
			"call pthread_getspecific\n\t"        // get the str
			"add esp, 4\n\t"                      // rm argument
			"mov edi, [eax]\n\t"                  // store the plaintext
			"mov ebx, offset charsetTable\n\t"    // store the charsetTable
			"L1: movzx eax, byte ptr [edi]\n\t"
			"	 movzx eax, byte ptr [charsetTable+eax]\n\t"
			"	 cmp al, 0\n\t"
			"	 je L2\n\t"
			"	 mov [edi],al\n\t"                // replace char with next one
			"	 jmp L3\n\t"
			"L2: xlat\n\t"                        // al has first char 
			"	 mov [edi],al\n\t"                // store in edi
			"	 inc edi\n\t"
			"	 jmp L1\n\t"
			"L3: popad\n\t":::"memory");


		}
		sem_getvalue(&sem, &lock);
		if(0 == lock) {  printf("id:%d FOUND\n", param->threadID);pthread_exit(NULL); }


	} // END infinite for

	pthread_cleanup_pop(0);
	return 0;
}

char *requestWorkload(int socket, char *buf) {
	static char workload[50];
	memset(buf, 0, sizeof(buf));

	strcpy(buf+1, "204");
	if(-1 == sendMessage(socket, buf, 4)) {
		if(-1 == sendMessage(socket, buf, 4))
			perror("send req. workload");
			// TODO: shutdown? was machen?
	}

	recvMessage(socket, buf);
	strcpy(workload, buf+4);

	return workload;
}

int checkMessage(int socket, char *buf) {
	int ret;

	ret = recv(socket, buf, 4, MSG_PEEK | MSG_DONTWAIT);
	if(ret > 1) {
		// data received 
		if(memcmp(buf+1, "302", 3) == 0)  { // 302-hash-found is the message we were looking for
			ret = recvMessage(socket, buf);
			return (ret > 0) ? ret : -1;
		}
	}
	
	if(ret == 0)
		return 0; // server connection has shutdown; fatal
	
	return -1; // recv errno
}
