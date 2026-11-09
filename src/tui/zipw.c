/*
 * Copyright (C) 2026 Brian Scott - HDHR EAS Test.
 * zipw.c - minimal ZIP64 writer for HDHR EAS Test. GPLv3.
 *
 * Every entry carries ZIP64 sizes, so archives over 4 GB (full test files)
 * open in Windows Explorer, 7-Zip, Info-ZIP and Python. Video captures are
 * stored; text files (reports, logs) are deflated with zlib.
 */
#include "zipw.h"
#include "plat.h"

#include <dirent.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <zlib.h>

#ifdef _WIN32
#  define ftell64 _ftelli64
#  define fseek64 _fseeki64
#else
#  define ftell64 ftello
#  define fseek64 fseeko
#endif

typedef struct {
    char name[600];
    uint64_t offset, csize, usize;
    uint32_t crc;
    uint16_t method, dtime, ddate;
} zentry_t;

static void w16(FILE *f, uint16_t v) { unsigned char b[2] = { v & 0xFF, v >> 8 }; fwrite(b, 1, 2, f); }
static void w32(FILE *f, uint32_t v) { unsigned char b[4] = { v & 0xFF, (v >> 8) & 0xFF, (v >> 16) & 0xFF, v >> 24 }; fwrite(b, 1, 4, f); }
static void w64(FILE *f, uint64_t v) { w32(f, (uint32_t)v); w32(f, (uint32_t)(v >> 32)); }

static int ends_with(const char *s, const char *suf) {
    size_t a = strlen(s), b = strlen(suf);
    return a >= b && strcmp(s + a - b, suf) == 0;
}

bool zipw_wants(const char *name, const char *what) {
    if (name[0] == '.' || ends_with(name, ".zip") || ends_with(name, ".part")) return false;
    if (!strcmp(what, "full")) return true;
    return ends_with(name, ".html") || ends_with(name, ".log") || ends_with(name, ".eas.tsv") ||
           ends_with(name, ".txt");
}

static int cmp_str(const void *a, const void *b) { return strcmp(*(char *const *)a, *(char *const *)b); }

static void dos_time(time_t t, uint16_t *dt, uint16_t *dd) {
    struct tm tm;
    plat_localtime(t, &tm);
    *dt = (uint16_t)((tm.tm_hour << 11) | (tm.tm_min << 5) | (tm.tm_sec / 2));
    *dd = (uint16_t)(((tm.tm_year - 80) << 9) | ((tm.tm_mon + 1) << 5) | tm.tm_mday);
}

static int add_file(FILE *zf, const char *path, const char *arcname, zentry_t *e, char *err, size_t errlen) {
    FILE *in = fopen(path, "rb");
    if (!in) { snprintf(err, errlen, "cannot read %s", path); return -1; }
    bool big = ends_with(path, ".ts") || ends_with(path, ".pcap") || ends_with(path, ".dbg");
    snprintf(e->name, sizeof(e->name), "%s", arcname);
    e->method = big ? 0 : 8;
    dos_time(time(NULL), &e->dtime, &e->ddate);
    e->offset = (uint64_t)ftell64(zf);
    uint16_t nlen = (uint16_t)strlen(e->name);

    /* local header with ZIP64 extra (sizes patched afterwards) */
    w32(zf, 0x04034b50); w16(zf, 45); w16(zf, 0x0800 /* UTF-8 names */); w16(zf, e->method);
    w16(zf, e->dtime); w16(zf, e->ddate);
    w32(zf, 0); w32(zf, 0xFFFFFFFF); w32(zf, 0xFFFFFFFF);
    w16(zf, nlen); w16(zf, 20);
    fwrite(e->name, 1, nlen, zf);
    long long extra_pos = ftell64(zf);
    w16(zf, 0x0001); w16(zf, 16); w64(zf, 0); w64(zf, 0);

    static unsigned char ibuf[1 << 20], obuf[1 << 20];
    uLong crc = crc32(0L, Z_NULL, 0);
    uint64_t usize = 0, csize = 0;
    z_stream zs;
    memset(&zs, 0, sizeof(zs));
    if (e->method == 8 && deflateInit2(&zs, 6, Z_DEFLATED, -15, 8, Z_DEFAULT_STRATEGY) != Z_OK) {
        fclose(in);
        snprintf(err, errlen, "zlib init failed");
        return -1;
    }
    size_t got;
    int flush;
    do {
        got = fread(ibuf, 1, sizeof(ibuf), in);
        usize += got;
        crc = crc32(crc, ibuf, (uInt)got);
        if (e->method == 0) {
            if (got && fwrite(ibuf, 1, got, zf) != got) { fclose(in); snprintf(err, errlen, "write failed (disk full?)"); return -1; }
            csize += got;
            continue;
        }
        flush = feof(in) || got < sizeof(ibuf) ? Z_FINISH : Z_NO_FLUSH;
        zs.next_in = ibuf;
        zs.avail_in = (uInt)got;
        do {
            zs.next_out = obuf;
            zs.avail_out = sizeof(obuf);
            deflate(&zs, flush);
            size_t have = sizeof(obuf) - zs.avail_out;
            if (have && fwrite(obuf, 1, have, zf) != have) { fclose(in); deflateEnd(&zs); snprintf(err, errlen, "write failed (disk full?)"); return -1; }
            csize += have;
        } while (zs.avail_out == 0);
    } while (got == sizeof(ibuf));
    if (e->method == 8) {
        /* make sure the stream is finished even if the last read was exactly a full buffer */
        int r;
        do {
            zs.next_in = NULL;
            zs.avail_in = 0;
            zs.next_out = obuf;
            zs.avail_out = sizeof(obuf);
            r = deflate(&zs, Z_FINISH);
            size_t have = sizeof(obuf) - zs.avail_out;
            if (have) { fwrite(obuf, 1, have, zf); csize += have; }
        } while (r == Z_OK);
        deflateEnd(&zs);
    }
    fclose(in);
    e->crc = (uint32_t)crc;
    e->usize = usize;
    e->csize = csize;

    long long end = ftell64(zf);
    fseek64(zf, (long long)e->offset + 14, SEEK_SET);
    w32(zf, e->crc);
    fseek64(zf, extra_pos + 4, SEEK_SET);
    w64(zf, e->usize);
    w64(zf, e->csize);
    fseek64(zf, end, SEEK_SET);
    return ferror(zf) ? -1 : 0;
}

int zipw_dir(const char *dir, const char *what, const char *out_zip, char *err, size_t errlen) {
    DIR *d = opendir(dir);
    if (!d) { snprintf(err, errlen, "cannot open %s", dir); return -1; }
    char **names = NULL;
    int n = 0;
    struct dirent *de;
    while ((de = readdir(d))) {
        if (!zipw_wants(de->d_name, what)) continue;
        char p[1300];
        snprintf(p, sizeof(p), "%s/%s", dir, de->d_name);
        if (!plat_is_file(p)) continue;
        names = realloc(names, sizeof(char *) * (n + 1));
        names[n++] = strdup(de->d_name);
    }
    closedir(d);
    if (n > 1) qsort(names, n, sizeof(char *), cmp_str);

    char top[400];
    const char *b = strrchr(dir, '/');
    snprintf(top, sizeof(top), "%s", b ? b + 1 : dir);

    char part[1300];
    snprintf(part, sizeof(part), "%s.part", out_zip);
    FILE *zf = fopen(part, "wb");
    if (!zf) { snprintf(err, errlen, "cannot write %s", part); return -1; }
    zentry_t *ents = calloc(n ? n : 1, sizeof(zentry_t));
    int rc = 0;
    for (int i = 0; i < n && rc == 0; i++) {
        char path[1300], arc[800];
        snprintf(path, sizeof(path), "%s/%s", dir, names[i]);
        snprintf(arc, sizeof(arc), "%s/%s", top, names[i]);
        rc = add_file(zf, path, arc, &ents[i], err, errlen);
    }
    if (rc == 0) {
        uint64_t cd_start = (uint64_t)ftell64(zf);
        for (int i = 0; i < n; i++) {
            zentry_t *e = &ents[i];
            uint16_t nlen = (uint16_t)strlen(e->name);
            w32(zf, 0x02014b50); w16(zf, 45); w16(zf, 45); w16(zf, 0x0800); w16(zf, e->method);
            w16(zf, e->dtime); w16(zf, e->ddate); w32(zf, e->crc);
            w32(zf, 0xFFFFFFFF); w32(zf, 0xFFFFFFFF);
            w16(zf, nlen); w16(zf, 28); w16(zf, 0); w16(zf, 0); w16(zf, 0); w32(zf, 0);
            w32(zf, 0xFFFFFFFF);
            fwrite(e->name, 1, nlen, zf);
            w16(zf, 0x0001); w16(zf, 24); w64(zf, e->usize); w64(zf, e->csize); w64(zf, e->offset);
        }
        uint64_t cd_end = (uint64_t)ftell64(zf);
        /* ZIP64 end of central directory + locator + classic end record */
        w32(zf, 0x06064b50); w64(zf, 44); w16(zf, 45); w16(zf, 45); w32(zf, 0); w32(zf, 0);
        w64(zf, (uint64_t)n); w64(zf, (uint64_t)n); w64(zf, cd_end - cd_start); w64(zf, cd_start);
        w32(zf, 0x07064b50); w32(zf, 0); w64(zf, cd_end); w32(zf, 1);
        w32(zf, 0x06054b50); w16(zf, 0); w16(zf, 0); w16(zf, 0xFFFF); w16(zf, 0xFFFF);
        w32(zf, 0xFFFFFFFF); w32(zf, 0xFFFFFFFF); w16(zf, 0);
        if (ferror(zf)) { rc = -1; snprintf(err, errlen, "write failed (disk full?)"); }
    }
    if (fclose(zf) != 0 && rc == 0) { rc = -1; snprintf(err, errlen, "write failed (disk full?)"); }
    for (int i = 0; i < n; i++) free(names[i]);
    free(names);
    free(ents);
    if (rc != 0) { remove(part); return -1; }
    return plat_rename_replace(part, out_zip);
}
