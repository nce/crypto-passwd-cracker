/*
 * =====================================================================================
 *
 *       Filename: crypt3server.c
 *
 *    Description: 
 *
 *        Version: 1.0
 *        Created: Tue, 07.06.2011 - 14:30:49
 *  Last modified: Mon, 26.09.2011 - 03:42:49
 *       Revision: none
 *       Compiler: gcc -std=c99 -pedantic -Wall -masm=intel -fomit-frame-pointer -Icrypt.h
 *
 *         Author: Ulli Goschler, siulgosc@stud.informatik.uni-erlangen.de
 *
 * =====================================================================================
 */

#include"crypt3.h"

#include<arpa/inet.h>
#include<time.h>
#include<sys/wait.h>

#undef __FD_ZERO_STOS
#define __FD_ZERO_STOS "stosd" // otherwise problem with gcc inline asm

struct cryptNode {
	time_t startTime;
	time_t lastHeartbeat;
	struct cryptNode *next;
	int fd;
	char *hostname;
};
static struct cryptNode *head = NULL;


int main(int argc, char **argv) {
 	if(argc == 1)
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
	
	int port = 0;
	char* filename = NULL;
	FILE* shadow = NULL;
	int c;

	while(-1 != (c = getopt(argc, argv, "p:s:"))) {
		switch(c) {
			case 'p':
				port = atoi(optarg);
				break;
			case 's': 
				filename = optarg;
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
	} else if(NULL == (shadow = fopen(filename, "r"))) {
		fprintf(stderr, "\033[1m-s <shadowfile> is required to be a valid/\
				readable unix shadow password file\033[0m\n");
		usageError(argv[0]);
	}

	launchServer(port, shadow);
	return 0;
}

int	launchServer(int port, FILE* shadow) {

	int sock, status;
	int sock_opt = 1;
	struct sockaddr_in6 addr;
	char hostname[FQDN];    
 	struct sockaddr_in6 peer;    // getpeername
	char hbuf[NI_MAXHOST];       // getnameinfo
	char straddr[100];           // inet_ntop
	socklen_t addr_len = sizeof(addr);
	socklen_t len;
	
	int fdmax, newfd;

	time_t start, end;

	int cryptnodes = 0;

	char buf[MAXMESSAGE+1];
	char *currentHash; // currently burteforced hash

	memset(&addr, 0, sizeof(addr));

	addr.sin6_port = htons(port);
	addr.sin6_family = AF_INET6;

	/* prefer ipv6 binding */	
	if(-1 == (sock = socket(AF_INET6, SOCK_STREAM, 0))) {
		perror("[server] socket");
		exit(EXIT_FAILURE);
	}
	
	// allow reuse of current port, faster for debugging
	if(-1 == setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &sock_opt, sizeof(int))) {
		perror("[server] setsockopt");
	}
	if(-1 == bind(sock, (struct sockaddr *) &addr, sizeof(addr))) {
		perror("[server] bind");
		exit(EXIT_FAILURE);
	}
	if(-1 == listen(sock, 1)) {
		perror("[server] listen");
		exit(EXIT_FAILURE);
	}
	if(-1 == gethostname(hostname, FQDN)) {
		perror("[server] gethostname");
		exit(EXIT_FAILURE);
	}
	
	char portString[6];
	sprintf(portString, "%d", port);

	for(int i = 0; i < CRYPTNODES; i++) {
		/* execute all clients, connecting to the server on given port with $number of threads running there */	
		execClient(hosts[i][0], hostname, portString, hosts[i][1]);
		cryptnodes++;
	}
	printf("[server] Listening on %s:%d\n",hostname, port);

	sigset_t mask, old;
	sigfillset(&mask);

	/*
	 * select
	 */
	fd_set master;
	fd_set read_fds; // tmp descriptor set
	
	FD_ZERO(&master);
	FD_ZERO(&read_fds);

	// add socket to set
	FD_SET(sock, &master);
	fdmax = sock;


	initCharset();
	currentHash = readLineFromShadow(shadow);
	start = time(NULL);

	for(;;) {
		read_fds = master; 
		if(select(fdmax+1, &read_fds, NULL, NULL, NULL) == -1) {
			perror("select");
			exit(EXIT_FAILURE);
		}

		for(int i = 0; i < cryptnodes; i++) {
			if(-1 == waitpid(-1, &status, WNOHANG)) 
				perror("waitpid");
			if(WIFEXITED(status)) {
				cryptnodes--;
			}
		}

		// main input loop
		for(int i = 0; i <= fdmax; i++) {
			if(FD_ISSET(i, &read_fds)) {
				if(i == sock) { // handle new connection
					if(-1 == (newfd = accept(sock, (struct sockaddr *) &addr, &addr_len)))
						perror("[server] accept");
					else {
						FD_SET(newfd, &master); // add new connection to our set
						if(newfd > fdmax) fdmax = newfd; // adjust max fd
					
						len = sizeof(addr);	
						if(-1 == getpeername(newfd, (struct sockaddr*) &peer, &len)) {
							perror("[server] getpeername");
							continue;
						}

						inet_ntop(AF_INET6, &peer.sin6_addr, straddr, sizeof(straddr));
						if(-1 == getnameinfo((struct sockaddr*) &peer, len, hbuf, sizeof(hbuf), NULL, 0, NI_NAMEREQD | NI_NOFQDN)) {
							perror("[server] getnameinfo");
							continue;
						}

						addNode(newfd, hbuf);

					}

				} else { // data from existing client
					
					if(-1 == sigprocmask(SIG_BLOCK, &mask, &old)) // block signals
						perror("sigblock"); // bad; not fatal; some nodes might lack proper shutdown :(

					
					if(-1 == recvMessage(i, buf)) {
						rmNode(i);
						close(i);
						FD_CLR(i, &master);
						
					} else { // data from client available

						if(0 == memcmp("0201", buf, 4)) { // 201 Created
							
							if(-1 == sendMessage(i, currentHash, MAXMESSAGE)) {
								perror("send"); // send failed; remove node
								rmNode(i);
								close(i);
								FD_CLR(i, &master);
							}


						} else if(0 == memcmp("0204", buf, 4)) { // 204 No Content

							strcpy(buf+4, dispatchWorkload()); // create new workload 
							setbuf(stdout, NULL);
							printf("Last Workload delivered to: %8s: %s\r", getHostname(i), buf+4);
							if(-1 == sendMessage(i, buf, strlen(buf))) {
								perror("send; dispatching workload");
								rmNode(i); close(i); FD_CLR(i, &master);
							}

						} else if(0 == memcmp("302", buf+1, 3)) {  // 302 Found 
							/* * * * *
							 * Sucess 
							 * * * * */

							end = time(NULL);

							printf("\n\033[0;32m%s:%s\033[0m Took: %.2fmin\n", currentHash+strlen(currentHash)+2, buf+4, (double) (end-start)/60);

							

							if(NULL == (currentHash = readLineFromShadow(shadow))) { // finished shadow file
								strcpy(buf, "0302410"); // shutdown 
								printf("shutdown inc\n");
								struct cryptNode *tmp = head;

								for(;tmp != NULL; tmp = head) { // SHIFT operation
									sendMessage(tmp->fd, buf, 7); // ignore errors
									close(tmp->fd); FD_CLR(tmp->fd, &master); rmNode(tmp->fd);
								}

								serverShutdown(cryptnodes);


							} else { // next line from shadow
								memset(plaintext, 0, sizeof(plaintext)); // restart!
								strcpy(buf, "0302"); // 302-new-hash
								memcpy(buf+4, currentHash, MAXMESSAGE-4);

								printf("[server] dispatching new hash to nodes\n");
								struct cryptNode *tmp = head;
								for(tmp = head; tmp != NULL; tmp = tmp->next) {
									if(-1 == sendMessage(tmp->fd, buf, MAXMESSAGE)) {
										perror("send; Send new hash to all");
										close(tmp->fd); FD_CLR(tmp->fd, &master); rmNode(tmp->fd);
									}
								}

							}
							
						} else {
							printf("[server] Received Message out of context: %s; From FD: %d\n", buf, i);
						}
					}

					if(-1 == sigprocmask(SIG_UNBLOCK, &mask, &old)) {
						perror("unblocksig"); 
						fprintf(stderr, "Unblocking signals failed. Process must be cancelled by sigkill. Some nodes might survive that\n");
						serverShutdown(cryptnodes);
					}


				} // END handle data

			} // END new incoming connection

		}  // END looping through fds

	} // END for(;;) loop

	return 0;
}

void serverShutdown(int nodes) {
	int status;
	
	while(nodes > 0) {
		if(-1 == waitpid(-1, &status, 0))  // TODO: waitpid?
			perror("waitpid");
		nodes--;
	}
	
	exit(EXIT_SUCCESS);
}

char *readLineFromShadow(FILE *shadow) {
	char buf[512];

	char user[33]; // username may be up to 32 chars long
	char hash[87]; // sha-512 has 86chars
	char salt[16]; // salt is max 16 chars

	static char ret[MAXMESSAGE + 1];
	memset(ret, 0, sizeof(ret));

	int userNameFound = 0;
	int hashmethod = 0;

	if(NULL == (fgets(buf, 512, shadow))) {
		fclose(shadow);
		return NULL;
	} else {
		int i = 0;
		while(buf[i] != '\n') {
		
			if(buf[i] == ':' && 0 == userNameFound) { // acquire username
                memcpy(user, buf, i); 
                user[i] = '\0';
                userNameFound = 1;
            }   
            if(buf[i] == '$' && buf[i-1] == ':') {
                 hashmethod = atoi(&buf[++i]);
                 char *p = salt;
                     
				 i++; // skip 1
				 i++; // skip 1$

                 while(buf[i] != '$') // get salt; $asdfasdf$
                    *p++ = buf[i++];  
                 *p = '\0';

                 p = hash; i++;
                 while(buf[i] != ':')  // get hash; 
                     *p++ = buf[i++];
                 *p = '\0';

				if(1 == hashmethod) {
                    printf("Username: %s; Alogrithm: MD5\n", user);
                } else if (5 == hashmethod) {
                    printf("Username: %s; Alogrithm: SHA-256\n", user);
                } else if (6 == hashmethod) {
                    printf("Username: %s; Alogrithm: SHA-512\n", user);
                } else {
                    printf("Invalid Algorithm for User: %s; skipping...\n", user);
                    break;
                }

			}
			i++;
		}
	}
	snprintf(ret, sizeof(ret), " 205$%d$%s$%c %s", hashmethod, salt, 0x00, hash);

	return ret;
}

char *dispatchWorkload() {
	static char workload[50];
	memset(workload, 0, sizeof(workload));
	strcpy(workload, plaintext);
	for(int i = 0; i < LIMIT; i++) {
		__asm__ __volatile__ ("pushad\n\t"
       "mov edi, offset plaintext\n\t"
       "mov ebx, offset charsetTable\n\t"
        "L1: movzx eax, byte ptr [edi]\n\t"
        "    movzx eax, byte ptr [charsetTable+eax]\n\t"
        "    cmp al, 0\n\t"
        "    je L2\n\t"
        "    mov [edi],al\n\t"
        "    jmp L3\n\t"
        "L2: xlat\n\t"
        "    mov [edi],al\n\t"
        "    inc edi\n\t"
        "    jmp L1\n\t"
        "L3: popad\n\t":::"memory");
	}

	return workload;
}

pid_t execClient(char *remoteHost, char *serverName, char *port, char *threads) {
	pid_t pid;

	if(-1 == (pid = fork())) {
		perror("fork");
		exit(EXIT_FAILURE);
	}

	if(0 == pid) {
		// child
		char *args[] = {"ssh", remoteHost, "-qn", "nohup", CLIENTPATH, "-p", port, "-n", serverName, "-t", threads, ">/dev/null 2>&1", NULL};
		execvp("ssh", args);		
	}

	return pid;
}

int addNode(int fd, char *name) {
	struct cryptNode *ptr = NULL;
	struct cryptNode *tmp = NULL;
	if(NULL == (ptr = (struct cryptNode *) malloc(sizeof(struct cryptNode)))) {
		perror("malloc");
		return -1; // problem allocating memory? fail...
	}
	if(NULL == (ptr->hostname = (char *) malloc(HOSTNAMESIZE * sizeof(char)))) {
		perror("malloc");
		return -1;
	}

	ptr->fd = fd;
	ptr->startTime = time(NULL);
	ptr->lastHeartbeat = time(NULL);
	strcpy(ptr->hostname, name);
	ptr->next = NULL;

	if(head == NULL) { // insert first item
		head = ptr;
	//printf("Added 1st Node: %s\n", ptr->hostname);
		return 0;
	}

	for(tmp = head; tmp->next != NULL; tmp = tmp->next); // cycle through all nodes till end

	tmp->next = ptr;
	//printf("Added Node: %s\n", ptr->hostname);
	return 0;

}

int rmNode(int fd) {
	/* attention: segfaults, if nonexistant item should be removed... */
	struct cryptNode *tmp, *freeme;

	if(head == NULL) // nothing there
		return -1;

	if(head->fd == fd) { // rm first node
		printf("head\n");
		freeme = head;
		head = head->next; 
		free(freeme->hostname);	
		free(freeme);
		return 0;
	}
	for(tmp = head; tmp->next != NULL && (tmp->next)->fd != fd; tmp = tmp->next); // stop one node ahead of the node

	
	freeme = tmp->next; // next node should be removed
	tmp->next = (tmp->next)->next; // skip the node

	free(freeme->hostname);
	free(freeme);
	return 0;
}

char *getHostname(int fd) {
	struct cryptNode *tmp;

	for(tmp = head; tmp != NULL && tmp->fd != fd; tmp = tmp->next);

	return tmp->hostname;
}
