#include <pcap.h>
#include <stdio.h>
#include <ctype.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/shm.h>

#include "types.h"
#include "dns.h"
#include "helper.h"
#include "shm.h"

uint64_t *qcounter;
uint64_t *acounter;

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
		"Usage   : %s <recordtype> <direction>\n"
		"Examples: %s CNAME query\n"
		"          %s CNAME answer\n\n", prog, prog, prog
	);
}

int main(int argc, char *argv[]) {
	int shmid, i, rec_idx=-1, rec_dir=-1;
	char *shm;

	// check no. of params
	if (argc != 3) {
		usage(argv[0]);
		exit(-1);
	}

	// check recordtype validity
	for(i = 0; i < 0x30; i++) {
		if (dns_record_type_name[i] == NULL)
			continue;

		if (strcmp(dns_record_type_name[i], argv[1]) == 0) {
			rec_idx = i;
			break;
		}
	}

	if (rec_idx == -1) {
		fprintf(stderr, "Invalid recordtype: '%s'\n", argv[1]);
		exit(-1);
	}

	// check direction parameter validity
	if (strcmp(argv[2], "query") == 0)
		rec_dir = 0;
	else if (strcmp(argv[2], "answer") == 0)
		rec_dir = 1;

	if (rec_dir == -1) {
		fprintf(stderr, "Invalid direction: '%s'\n", argv[2]);
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

	// dump requested counter to stdout as asciihex
	if (rec_dir == 0)
		printf("%llx\n", qcounter[rec_idx]);
	else
		printf("%llx\n", acounter[rec_idx]);

	
	return 0;
}
