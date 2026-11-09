/*
 * Copyright (C) 2026 Brian Scott - HDHR EAS Test.
 * pcap_lite.c - minimal capture-file reader with the libpcap calls RENDER uses.
 * Classic pcap (LE/BE, micro/nano) and pcapng (SHB, IDB, EPB, SPB). GPLv3.
 */
#include "pcap_lite.h"

#include <stdlib.h>
#include <string.h>

struct pcap {
    FILE *f;
    int linktype;
    int swapped;
    int nano;            /* classic: nanosecond timestamps */
    int pcapng;
    /* pcapng interfaces */
    int nif;
    int if_linktype[16];
    uint64_t if_tsdiv[16];   /* ticks per second */
    unsigned char *buf;
    size_t bufcap;
};

static uint32_t sw32(uint32_t v) { return (v >> 24) | ((v >> 8) & 0xFF00) | ((v << 8) & 0xFF0000) | (v << 24); }
static uint16_t sw16(uint16_t v) { return (uint16_t)((v >> 8) | (v << 8)); }
static uint32_t r32(const pcap_t *p, const unsigned char *b) { uint32_t v; memcpy(&v, b, 4); return p->swapped ? sw32(v) : v; }
static uint16_t r16(const pcap_t *p, const unsigned char *b) { uint16_t v; memcpy(&v, b, 2); return p->swapped ? sw16(v) : v; }

static int grow(pcap_t *p, size_t n) {
    if (n <= p->bufcap) return 0;
    unsigned char *nb = realloc(p->buf, n);
    if (!nb) return -1;
    p->buf = nb;
    p->bufcap = n;
    return 0;
}

pcap_t *pcap_open_dead(int linktype, int snaplen) {
    (void)snaplen;
    pcap_t *p = calloc(1, sizeof(*p));
    if (p) p->linktype = linktype;
    return p;
}

pcap_t *pcap_open_offline_with_tstamp_precision(const char *fname, u_int precision, char *errbuf) {
    (void)precision;
    FILE *f = fopen(fname, "rb");
    if (!f) { if (errbuf) snprintf(errbuf, PCAP_ERRBUF_SIZE, "%s: cannot open", fname); return NULL; }
    unsigned char h[24];
    if (fread(h, 1, 24, f) != 24) { fclose(f); if (errbuf) snprintf(errbuf, PCAP_ERRBUF_SIZE, "%s: too short", fname); return NULL; }
    pcap_t *p = calloc(1, sizeof(*p));
    if (!p) { fclose(f); return NULL; }
    p->f = f;
    uint32_t m;
    memcpy(&m, h, 4);
    if (m == 0xa1b2c3d4u || m == 0xa1b23c4du || m == 0xd4c3b2a1u || m == 0x4d3cb2a1u) {
        p->swapped = (m == 0xd4c3b2a1u || m == 0x4d3cb2a1u);
        uint32_t mm = p->swapped ? sw32(m) : m;
        p->nano = (mm == 0xa1b23c4du);
        p->linktype = (int)(r32(p, h + 20) & 0x0FFFFFFF);
        return p;
    }
    if (m == 0x0A0D0D0Au) {          /* pcapng Section Header Block */
        uint32_t bom;
        memcpy(&bom, h + 8, 4);
        p->swapped = (bom == 0x4D3C2B1Au);
        p->pcapng = 1;
        uint32_t blen = r32(p, h + 4);
        if (blen < 28) { pcap_close(p); if (errbuf) snprintf(errbuf, PCAP_ERRBUF_SIZE, "bad pcapng header"); return NULL; }
        fseek(f, (long)blen, SEEK_SET);   /* skip the rest of the SHB */
        /* linktype comes from the first IDB; peek ahead for pcap_datalink() */
        long here = ftell(f);
        unsigned char bh[8];
        while (fread(bh, 1, 8, f) == 8) {
            uint32_t type = r32(p, bh), len = r32(p, bh + 4);
            if (len < 12) break;
            if (type == 1) {
                unsigned char lt[2];
                if (fread(lt, 1, 2, f) == 2) p->linktype = r16(p, lt);
                break;
            }
            fseek(f, (long)len - 8, SEEK_CUR);
        }
        fseek(f, here, SEEK_SET);
        return p;
    }
    pcap_close(p);
    if (errbuf) snprintf(errbuf, PCAP_ERRBUF_SIZE, "%s: not a pcap/pcapng file", fname);
    return NULL;
}

pcap_t *pcap_open_offline(const char *fname, char *errbuf) {
    return pcap_open_offline_with_tstamp_precision(fname, PCAP_TSTAMP_PRECISION_MICRO, errbuf);
}

int pcap_datalink(pcap_t *p) { return p ? p->linktype : -1; }
FILE *pcap_file(pcap_t *p) { return p ? p->f : NULL; }

static int loop_classic(pcap_t *p, int cnt, pcap_handler cb, u_char *user) {
    int n = 0;
    unsigned char rh[16];
    while ((cnt <= 0 || n < cnt) && fread(rh, 1, 16, p->f) == 16) {
        struct pcap_pkthdr h;
        uint32_t sec = r32(p, rh), frac = r32(p, rh + 4);
        h.ts.tv_sec = (long)sec;
        h.ts.tv_usec = (long)(p->nano ? frac / 1000 : frac);
        h.caplen = r32(p, rh + 8);
        h.len = r32(p, rh + 12);
        if (h.caplen > 16 * 1024 * 1024) break;
        if (grow(p, h.caplen ? h.caplen : 1) < 0) return -1;
        if (fread(p->buf, 1, h.caplen, p->f) != h.caplen) break;   /* truncated last record */
        cb(user, &h, p->buf);
        n++;
    }
    return 0;
}

static int loop_pcapng(pcap_t *p, int cnt, pcap_handler cb, u_char *user) {
    int n = 0;
    unsigned char bh[8];
    while ((cnt <= 0 || n < cnt) && fread(bh, 1, 8, p->f) == 8) {
        uint32_t type = r32(p, bh), len = r32(p, bh + 4);
        if (len < 12 || len > 64 * 1024 * 1024) break;
        size_t body = len - 8;
        if (grow(p, body) < 0) return -1;
        if (fread(p->buf, 1, body, p->f) != body) break;
        const unsigned char *b = p->buf;
        if (type == 0x0A0D0D0Au) {                      /* new section */
            p->nif = 0;
        } else if (type == 1 && p->nif < 16) {          /* Interface Description */
            p->if_linktype[p->nif] = r16(p, b);
            uint64_t div = 1000000;
            size_t off = 8;
            while (off + 4 <= body - 4) {               /* options */
                uint16_t code = r16(p, b + off), olen = r16(p, b + off + 2);
                if (code == 0) break;
                if (code == 9 && olen >= 1) {           /* if_tsresol */
                    uint8_t v = b[off + 4];
                    div = 1;
                    if (v & 0x80) for (int i = 0; i < (v & 0x7F); i++) div *= 2;
                    else for (int i = 0; i < v; i++) div *= 10;
                }
                off += 4 + ((olen + 3) & ~3u);
            }
            p->if_tsdiv[p->nif] = div ? div : 1000000;
            p->nif++;
        } else if (type == 6 && body >= 20) {           /* Enhanced Packet */
            uint32_t ifid = r32(p, b);
            uint64_t ts = ((uint64_t)r32(p, b + 4) << 32) | r32(p, b + 8);
            uint64_t div = (ifid < (uint32_t)p->nif) ? p->if_tsdiv[ifid] : 1000000;
            struct pcap_pkthdr h;
            h.caplen = r32(p, b + 12);
            h.len = r32(p, b + 16);
            if (20 + (size_t)h.caplen > body) break;
            h.ts.tv_sec = (long)(ts / div);
            h.ts.tv_usec = (long)((ts % div) * 1000000 / div);
            cb(user, &h, b + 20);
            n++;
        } else if (type == 3 && body >= 4) {            /* Simple Packet */
            struct pcap_pkthdr h;
            h.len = r32(p, b);
            h.caplen = (uint32_t)(body - 4 < h.len ? body - 4 : h.len);
            h.ts.tv_sec = 0;
            h.ts.tv_usec = 0;
            cb(user, &h, b + 4);
            n++;
        }
    }
    return 0;
}

int pcap_loop(pcap_t *p, int cnt, pcap_handler cb, u_char *user) {
    if (!p || !p->f) return -1;
    return p->pcapng ? loop_pcapng(p, cnt, cb, user) : loop_classic(p, cnt, cb, user);
}

void pcap_close(pcap_t *p) {
    if (!p) return;
    if (p->f) fclose(p->f);
    free(p->buf);
    free(p);
}
