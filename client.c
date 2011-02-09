#include <pcap.h>
#include <stdio.h>
#include <ctype.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <signal.h>
#include <unistd.h>

#include "types.h"
#include "dns.h"
#include "helper.h"
#include "shm.h"

uint64_t *qcounter;
uint64_t *acounter;

#define MODE_QUERY  1
#define MODE_ANSWER 2
#define MODE_TOTAL  3

void dump_counters() {
	int i;

	fprintf(stderr, "\x1B[2J");

	fprintf(stderr, "QUERY STATS:\n");
	for(i = 0; i < 255; i++) {
		if (qcounter[i] != 0)
			fprintf(stderr, "%5s: [%04X] = 0x%016llx\n", dns_record_type_name[i], i, qcounter[i]);
	}

	fprintf(stderr, "\nANSWER STATS:\n");

	for(i = 0; i < 255; i++) {
		if (qcounter[i] != 0)
			fprintf(stderr, "%5s: [%04X] = 0x%016llx\n", dns_record_type_name[i], i, qcounter[i]);
	}
}

void usage(char *prog) {
	fprintf(
		stderr,
		"Usage   : %s <options>\n\n"
	  "Options : -r RECORDTYPE\n"
		"          -q Count of incoming packets\n"
		"          -a Count of outgoing packets\n"
		"          -t Combined count\n\n", prog
	);
}

int main(int argc, char *argv[]) {
	int c, mode = 0, shmid, i, rec_idx=-1; 
	char *shm;
	char *record_type = NULL;
	uint64_t total = 0;

	while((c = getopt(argc, argv,  "qatr:")) != -1) {
		switch(c) {
			case 'r':
				record_type = optarg;
			break;

			case 'q':
				mode |= MODE_QUERY;			
			break;

			case 'a':
				mode |= MODE_ANSWER;
			break;

			case 't':
				mode |= MODE_TOTAL;
			break;
		}
	}

	if (record_type == NULL || mode == 0) {
		usage(argv[0]);
		exit(-1);
	}

	// check recordtype validity
	for(i = 0; i < 0x30; i++) {
		if (dns_record_type_name[i] == NULL)
			continue;

		if (strcmp(dns_record_type_name[i], record_type) == 0) {
			rec_idx = i;
			break;
		}
	}

	if (rec_idx == -1) {
		fprintf(stderr, "Invalid recordtype: '%s'\n", argv[1]);
		exit(-1);
	}

	// grab shm handle and all that
	if ((shmid = shmget(SHM_KEY, SHM_SIZE, 0666)) < 0) {
		perror("shmget");
		exit(-1);
	}

	if ((shm = shmat(shmid, NULL, 0)) == (char *) -1) {
		perror("shmat");
		exit(1);
	}

	// initialize counter pointers within shm object
	qcounter = (uint64_t*)shm;
	acounter = (qcounter + 256);

	if (mode & MODE_QUERY)
		total += qcounter[rec_idx];

	if (mode & MODE_ANSWER)
		total += acounter[rec_idx];

	printf("%llx\n", total);
	
	return 0;
}
