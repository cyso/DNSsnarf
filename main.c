#include <pcap.h>
#include <stdio.h>
#include <ctype.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <syslog.h>
#include <signal.h>
#include <unistd.h>

#include "types.h"
#include "dns.h"
#include "helper.h"
#include "shm.h"

int shmid;
char *shm = NULL;

uint64_t *qcounter;
uint64_t *acounter;

#ifdef DEBUG
	#define DPRINTF(s)  do { printf s; } while (0)
#else
	#define DPRINTF(s)  do {} while(0)
#endif

void exit_handler(int sig) {
	openlog("dnssnarf", LOG_PERROR, LOG_DAEMON);
	syslog(LOG_INFO, "killed by signal 0x%x.", sig);
	closelog();

	exit(0);
}

void init_counters() {
	int i;

	qcounter = (uint64_t*)shm;
	acounter = qcounter + 256;

	for(i = 0; i < 256; i++) {
		qcounter[i] = 0;
		acounter[i] = 0;
	}
}

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
		if (acounter[i] != 0)
			fprintf(stderr, "%5s: [%04X] = 0x%016llx\n", dns_record_type_name[i], i, acounter[i]);
	}
}

int extract_single(u8 *b, char *out) {
	u8 len;
	int i;

	len = b[0];

	for(i = 0; i < len; i++) {
		out[i] = b[1+i];
	}

	out[i] = 0;

	return len+1;
}

int extract_name(u8 *b, u8 *p, char *out) {
	int len;
	int i, k=0;

	while(k < 254) {
		len = *b++;

		if (len == 0)
			break;

		if ((len >> 6) == 3) { // compressed name packet?
			len &= ~0xc0; // clear top 2 bits
			len <<= 8; 
			len |= *b++;
		
			if (k != 0)
				*out++ = '.';

			extract_name(p + len, p, out);

			return k+2;
		}


		if (k != 0)
			*out++ = '.';

		k++;

		for(i = 0; i < len; i++) {
			*out++ = *b++;
			k++;
		}
	}

	*out = 0;

	return k+1;
}

void ipv4_to_ascii(u32 ip, char *out) {
	sprintf(out, "%d.%d.%d.%d", 
		ip >> 24,
		(ip >> 16)&0xff,
		(ip >>  8)&0xff,
		ip & 0xff
	);
}

int handle_question_entry(u8 *q, u8 *p) {
	char name[255];
	char log[64];
	int n = 0;	

	FILE *fp;

	// Question fields
	u16 qtype, qclass, qlen;
	u32 qttl;

	n += extract_name(q, p, name);
	q += n;

	qtype  = be16(q+0);
	qclass = be16(q+2);
	qttl   = be32(q+4);
	qlen   = be32(q+8);

	q += 4;
	n += 4;
	
	if (qtype >= 0 && qtype < 255)
		qcounter[qtype]++;
	else
		qcounter[255]++;

	if (qtype == 0x0001) {
		fp = fopen("/opt/dns_stats.txt", "w+");

		if (fp != NULL) {
			sprintf(log, "0x%016llx", qcounter[1]);
			fwrite(log, strlen(log), 1, fp);
			fclose(fp);
		}
	}

	DPRINTF(("  `-- QUESTION   : [%5s] (%d) '%s' qclass:%04x\n", dns_record_type_name[qtype], qtype, name, qclass));

	return n;
}

int handle_complex_entry(u8 *q, u8 *p, u8 section_no) {
	char name[255];
	char admin[255];
	char txt_body[255];
	u16 pref;
	u8 *startq = q;
	int n=0, i=0;

	u8 sshfp_algo, sshfp_type;
	u8 sshfp[20];

	u16 srv_prio, srv_port, srv_unk;

	u16 naptr_order, naptr_prio;
	char naptr_flags[255], naptr_services[255], naptr_regexp[255], naptr_replace[255];
	char rp_mbox_name[255], rp_txt_name[255];

	// Answer fields
	u16 atype,aclass,alen;
	u32 attl;

	u32 serial, refresh, retry, expire, minttl;

	q += extract_name(q, p, name);

	atype  = be16(q+0);
	aclass = be16(q+2);
	attl   = be32(q+4);
	alen   = be16(q+8);
	
	q += 10;

	switch(section_no) {
		case DNS_SECTION_ANSWER    : DPRINTF(("  `-- ANSWER     : ")); break;
		case DNS_SECTION_AUTHORITY : DPRINTF(("  `-- AUTHORITY  : ")); break;
		case DNS_SECTION_ADDITIONAL: DPRINTF(("  `-- ADDITIONAL : ")); break;
	}
	
	DPRINTF(("[%5s] (%d) '%s' -- ttl:%dsec class:%04x len:%04x -- ", dns_record_type_name[atype], atype, name, attl, aclass, alen));

	if (atype >= 0 && atype < 255)
		acounter[atype]++;
	else
		acounter[255]++;

	switch(atype) {
		case DNS_RECORD_TYPE_A:
			DPRINTF(("IPv4: %d.%d.%d.%d\n",
				q[0], q[1], q[2], q[3]
			));
			q += 4;
		break;

		case DNS_RECORD_TYPE_AAAA:
			DPRINTF(("IPv6: %04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x\n",
				be16(q+0), be16(q+2) , be16(q+4 ), be16(q+6),	
				be16(q+8), be16(q+10), be16(q+12), be16(q+14)
			));

			q += 16;
		break;

		case DNS_RECORD_TYPE_CNAME:
			q += extract_name(q, p, name);
			DPRINTF(("CNAME: '%s'\n", name));
		break;

		case DNS_RECORD_TYPE_MX:
			pref = be16(q); q += 2;
			q += extract_name(q, p, name);
			DPRINTF(("pref:%d name: %s\n", pref, name));
		break;

		case DNS_RECORD_TYPE_NS:
			q += extract_name(q, p, name);
			DPRINTF(("NS: %s\n", name));
		break;

		case DNS_RECORD_TYPE_PTR:
			q += extract_name(q, p, name);
			DPRINTF(("PTR: %s\n", name));
		break;

		case DNS_RECORD_TYPE_SOA:
			q += extract_name(q, p, name);
			q += extract_name(q, p, admin);

			serial  = be32(q+0);
			refresh = be32(q+4);
			retry   = be32(q+8);
			expire  = be32(q+12);
			minttl  = be32(q+16);

			q += 20;

			DPRINTF(("SOA -- pns: '%s' admin: '%s' serial:%d refresh:%d retry:%d expire:%d minttl:%d\n", name, admin, serial, refresh, retry, expire, minttl));
		break;

		case DNS_RECORD_TYPE_SRV:
			srv_prio = be16(q+0);	
			srv_unk  = be16(q+2);	
			srv_port = be16(q+4);	

			q += 6;
			q += extract_name(q, p, name);

			DPRINTF(("SRV '%s' prio:%d unk:%d port:%d\n", name, srv_prio, srv_unk, srv_port));
		break;

		case DNS_RECORD_TYPE_RP:
			q += extract_name(q, p, rp_mbox_name);
			q += extract_name(q, p, rp_txt_name);

			DPRINTF(("RP: '%s' -> '%s'\n\n", rp_mbox_name, rp_txt_name));
		break;

		case DNS_RECORD_TYPE_NAPTR:
			naptr_order = be16(q+0);
			naptr_prio  = be16(q+2);

			q += 4;

			q += extract_single(q, naptr_flags);
			q += extract_single(q, naptr_services);
			q += extract_single(q, naptr_regexp);
			q += extract_single(q, naptr_replace);

			DPRINTF(("NAPTR order:%d prio:%d flags:'%s' services:'%s' regexp:'%s' replace:'%s'\n", naptr_order, naptr_prio, naptr_flags, naptr_services, naptr_regexp, naptr_replace));
		break;
		
		case DNS_RECORD_TYPE_SPF:
			q += extract_single(q, txt_body);

			DPRINTF(("SPF: '%s'\n", txt_body));
		break;

		case DNS_RECORD_TYPE_TXT:
			q += extract_single(q, txt_body);

			DPRINTF(("TXT: '%s'\n", txt_body));
		break;

		case DNS_RECORD_TYPE_SSHFP:
			sshfp_algo = q[0];
			sshfp_type = q[1];

			q += 2;

			memcpy(sshfp, q, 20);
			q += 20;
			
			DPRINTF(("SSHFP "));

			switch(sshfp_algo) {
				case 0: DPRINTF(("[reserved] ")); break;
				case 1: DPRINTF(("[RSA] ")); break;
				case 2: DPRINTF(("[DSS] ")); break;

				default: break;
			}

			for(i = 0; i < 20; i++)
				DPRINTF(("%02x", sshfp[i]));

			DPRINTF(("\n"));

		break;

		default: DPRINTF(("UNHANDLED RECORD_TYPE: '%02x' (%s)\n", atype, dns_record_type_name[atype])); break;
	}

	n = ((int)q - (int)startq);

	return n;
}

void handle_packet(u8 *args, const struct pcap_pkthdr *header, const u8 *packet) {
	u16 id, flags, qcount, ancount, nscount, arcount;
	u8 *p = (u8*)packet;

	// UDP fields
	u32 src_addr, dst_addr;
	u16 udp_len;

	u8 *q;
	int i;

	p += 0x1a; // what hdr?

	// UDP header starts here
	src_addr = be32(p+0);
	dst_addr = be32(p+4);
	udp_len  = be16(p+10);

	/*
	ipv4_to_ascii(src_addr, ip_buf);
	printf("UDP src: %s\n", ip_buf);
	ipv4_to_ascii(dst_addr, ip_buf);
	printf("UDP dst: %s\n", ip_buf);
	*/

	p += 0x10;	

	id      = be16(p+0);
	flags   = be16(p+2);
	qcount  = be16(p+4);
	ancount = be16(p+6);
	nscount = be16(p+8);
	arcount = be16(p+10);

	DPRINTF(("++ ID: %04x QR: %d OPCODE: %x QCOUNT: %d ANCOUNT: %d ARCOUNT: %d\n", id, 0, 0, qcount, ancount, arcount));

	q = p + 12;

	for(i = 0; i < qcount; i++) {
		q += handle_question_entry(q, p);
	}

	for(i = 0; i < ancount; i++) {
		q += handle_complex_entry(q, p, DNS_SECTION_ANSWER);
	}

	for(i = 0; i < nscount; i++) {
		q += handle_complex_entry(q, p, DNS_SECTION_AUTHORITY);
	}

	for(i = 0; i < arcount; i++) {
		q += handle_complex_entry(q, p, DNS_SECTION_ADDITIONAL);
	}

	DPRINTF(("\n"));

#ifdef DEBUG
	dump_counters();
#endif
}


int main(int argc, char *argv[]) {
	pcap_t *pcap_handle;
	char   *dev;
	char   errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program fp;
	pid_t pid;
	
	bpf_u_int32 mask;
	bpf_u_int32 net;
	
	char filter_exp[] = "udp port 53";

	if (getppid() == 1) return 0;

	pid = fork();

	if (pid < 0) {
		fprintf(stderr, "Unable to fork()\n");
		exit(-1);
	}

	if (pid > 0) {
		printf("Exitting parent..\n");
		exit(0);
	}

	openlog("dnssnarf", LOG_PERROR, LOG_DAEMON);
	syslog(LOG_INFO, "started.");
	closelog();

	signal(SIGINT , exit_handler);
	signal(SIGTERM , exit_handler);
	signal(SIGKILL, exit_handler);

	dev = pcap_lookupdev(errbuf);

	if (dev == NULL) {
		fprintf(stderr, "Couldnt find default device: %s\n", errbuf);
		return -1;
	}

	printf("Found default device '%s'\n", dev);

	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldnt get netmask for device %s: %s\n", dev, errbuf);
		net  = 0;
		mask = 0;
	}

	pcap_handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

	if (pcap_handle == NULL) {
		fprintf(stderr, "Couldnt open device %s: %s\n", dev, errbuf);
		return -1;
	}

	if (pcap_compile(pcap_handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldnt parse filter %s: %s\n", filter_exp, pcap_geterr(pcap_handle));
		return -1;
	}

	if (pcap_setfilter(pcap_handle, &fp) == -1) {
		fprintf(stderr, "Couldnt install filter %s: %s\n", filter_exp, pcap_geterr(pcap_handle));
		return -1;
	}


	// Register shared memory object
	if ((shmid = shmget(SHM_KEY, sizeof(uint64_t)*256*2, IPC_CREAT | 0666)) < 0) {
		perror("shmget");
		exit(1);
	}

	if ((shm = shmat(shmid, NULL, 0)) == (char*)(-1)) {
		perror("shmat");
		exit(1);
	}

	init_counters();

	pcap_loop(pcap_handle, -1, handle_packet, NULL);
	pcap_close(pcap_handle);

	return 0;
}
