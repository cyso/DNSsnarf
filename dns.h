#ifndef __DNS_H__
#define __DNS_H__

#define DNS_RECORD_TYPE_A			0x0001
#define DNS_RECORD_TYPE_NS		0x0002
#define DNS_RECORD_TYPE_MD		0x0003
#define DNS_RECORD_TYPE_MF		0x0004
#define DNS_RECORD_TYPE_CNAME	0x0005
#define DNS_RECORD_TYPE_SOA		0x0006
#define DNS_RECORD_TYPE_MB		0x0007
#define DNS_RECORD_TYPE_MG		0x0008
#define DNS_RECORD_TYPE_MR		0x0009
#define DNS_RECORD_TYPE_PTR		0x000c
#define DNS_RECORD_TYPE_MX		0x000f

#define DNS_RECORD_TYPE_AAAA	0x001c


#define DNS_SECTION_QUESTION   0
#define DNS_SECTION_ANSWER	   1
#define DNS_SECTION_AUTHORITY  2
#define DNS_SECTION_ADDITIONAL 3

char *dns_record_type_name[0x20]={
	NULL,
	"A",
	"NS",
	"MD",
	"MF",
	"CNAME",
	"SOA",
	"MB",
	"MG",
	"MR",
	NULL,
	NULL,
	"PTR",
	"HINFO",
	"MINFO",
	"MX",
	"TXT",
	"RP",
	"AFSDB",
	"X25",
	"ISDN",
	"RT",
	"NSAP",
	"NSAPPTR",
	"SIG",
	"KEY",
	"PX",
	"GPOS",
	"AAAA",
	"LOC",
	"NXT",
	"EID"
};

#endif
