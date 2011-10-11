/*
	This file is part of DNSsnarf.  DNSsnarf is free software: you can
	redistribute it and/or modify it under the terms of the GNU General Public
	License as published by the Free Software Foundation, version 2.

	This program is distributed in the hope that it will be useful, but WITHOUT
	ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
	FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
	details.

	You should have received a copy of the GNU General Public License along with
	this program; if not, write to the Free Software Foundation, Inc., 51
	Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

	Copyright Cyso
*/

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
#define DNS_RECORD_TYPE_TXT		0x0010

#define DNS_RECORD_TYPE_AAAA	0x001c
#define DNS_RECORD_TYPE_SRV		0x0021
#define DNS_RECORD_TYPE_SSHFP	0x002c
#define DNS_RECORD_TYPE_NAPTR	0x0023
#define DNS_RECORD_TYPE_RP		0x0011
#define DNS_RECORD_TYPE_SPF   0x0063

#define DNS_SECTION_QUESTION   0
#define DNS_SECTION_ANSWER	   1
#define DNS_SECTION_AUTHORITY  2
#define DNS_SECTION_ADDITIONAL 3

char *dns_record_type_name[255]={
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
	"NULL",
	"WKS",
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
	"NSAP-PTR",
	"SIG",
	"KEY",
	"PX",
	"GPOS",
	"AAAA",
	"LOC",
	"NXT",
	"EID",
	"NIMLOC",
	"SRV",
	"ATMA",
	"NAPTR",
	"KX",
	"CERT",
	"A6",
	"DNAME",
	"SINK",
	"OPT",
	"APL",
	"DS",
	"SSHFP",
	"IPSECKEY",
	"RRSIG",
	"NSEC",
	"DNSKEY",
	"DHCID",
	"NSEC3",
	"NSEC3PARAM",
	NULL,
	NULL,
	NULL,
	"HIP",
	"NINFO",
	"RKEY",
	"TALINK",

	/** 59-98 = unassigned **/
	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,	

	"SPF",
	"UINFO",
	"UID",
	"GID",
	"UNSPEC",

	/** 104-248 = unassigned **/
	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	NULL,

	"TKEY",
	"TSIG",
	"IXFR",
	"AXFR",
	"MAILB",
	"MAILA" 
};

#endif
