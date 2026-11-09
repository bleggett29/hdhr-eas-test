/*
 * Copyright (C) 2026 Brian Scott - HDHR EAS Test.
 * pcap_lite.h - the small part of the libpcap API RENDER uses, for reading
 * capture files without libpcap/Npcap (Windows builds). Reads classic pcap
 * (micro/nanosecond, either byte order) and pcapng. GPLv3.
 */
#ifndef PCAP_LITE_H
#define PCAP_LITE_H

#include <stdint.h>
#include <stdio.h>
#ifdef _WIN32
#include <winsock2.h>          /* struct timeval */
#else
#include <sys/time.h>
#endif

#ifndef _U_CHAR_DEFINED_PCAP_LITE
#define _U_CHAR_DEFINED_PCAP_LITE
typedef unsigned char u_char;
typedef unsigned short u_short;
typedef unsigned int u_int;
#endif
typedef uint32_t bpf_u_int32;

#define PCAP_ERRBUF_SIZE 256
#define PCAP_TSTAMP_PRECISION_MICRO 0
#define PCAP_TSTAMP_PRECISION_NANO  1

#ifndef DLT_EN10MB
#define DLT_EN10MB 1
#endif
#ifndef DLT_RAW
#define DLT_RAW 12
#endif
#ifndef DLT_IPV4
#define DLT_IPV4 228
#endif
#ifndef DLT_ATSC_ALP
#define DLT_ATSC_ALP 289
#endif

struct pcap_pkthdr {
    struct timeval ts;
    bpf_u_int32 caplen;
    bpf_u_int32 len;
};

typedef struct pcap pcap_t;
typedef void (*pcap_handler)(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes);

pcap_t *pcap_open_offline(const char *fname, char *errbuf);
pcap_t *pcap_open_offline_with_tstamp_precision(const char *fname, u_int precision, char *errbuf);
pcap_t *pcap_open_dead(int linktype, int snaplen);
int pcap_datalink(pcap_t *p);
FILE *pcap_file(pcap_t *p);
int pcap_loop(pcap_t *p, int cnt, pcap_handler callback, u_char *user);
void pcap_close(pcap_t *p);

#endif
