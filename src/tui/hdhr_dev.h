/*
 * Copyright (C) 2026 Brian Scott - HDHR EAS Test.
 * hdhr_dev.h - HDHomeRun device helpers shared by the GUI (no UI code here).
 * Logic follows HDHomeRun TUI v0.9 by Mark J. Colombo (RabbitEars). GPLv3.
 */
#ifndef HDHR_DEV_H
#define HDHR_DEV_H

#include <stdbool.h>
#include <stdint.h>
#include "plat.h"

struct hdhomerun_device_t;

#define HDHR_MAX_TUNERS 32
#define HDHR_MAX_PROGS  64
#define HDHR_MAX_PLPS   64
#define HDHR_MAX_CHANS  256
#define HDHR_MAX_MAPS   20

typedef struct {
    uint32_t device_id;
    char ip[64];
    int tuner;
    int tuners_on_device;
    bool legacy;
} hdhr_tuner_t;

typedef struct {
    bool ok;
    char channel[64];        /* raw, e.g. "atsc3:31:0+1" or "8vsb:27"      */
    char channel_disp[64];   /* "atsc3:31"                                   */
    char lock[32];           /* raw lock string                              */
    char lock_disp[64];      /* "atsc3:0+1" or "8vsb"                         */
    bool atsc3;
    bool locked;
    char id_label[8];        /* BSID / TSID                                   */
    long id;                 /* -1 unknown                                    */
    int ss, snq, seq;        /* percentages                                   */
    long ss_db, snq_db;      /* -999 unknown                                  */
    double mbps;
    char target[160];
    char vchannel[32], vname[64];
    int nprog;
    char progs[HDHR_MAX_PROGS][200];
    int nplp;
    char plps[HDHR_MAX_PLPS][220];
} hdhr_status_t;

typedef struct {
    char display[256];
    char program[16];
    int plp;
} hdhr_program_t;

int  hdhr_discover(hdhr_tuner_t *out, int max);
int  hdhr_add_by_ip(const char *ip, hdhr_tuner_t *list, int *count, int max);   /* tuners added */

int  hdhr_get_status(struct hdhomerun_device_t *hd, hdhr_status_t *st);
long hdhr_status_value(const char *s, const char *key);   /* -999 if missing */
long hdhr_db_value(const char *s, const char *key);

int  hdhr_channel_list(struct hdhomerun_device_t *hd, unsigned *out, int max);
unsigned hdhr_current_rf(struct hdhomerun_device_t *hd);
int  hdhr_tune(struct hdhomerun_device_t *hd, const char *what);              /* "auto:<what>" + wait for lock */
int  hdhr_step_channel(struct hdhomerun_device_t *hd, int dir);              /* left/right */
/* Seek to the next channel with signal; progress(ch, secs_left, user) may return false to stop. */
unsigned hdhr_seek(struct hdhomerun_device_t *hd, int dir,
                   bool (*progress)(unsigned ch, double left, void *user), void *user);
int  hdhr_channel_maps(struct hdhomerun_device_t *hd, char maps[][32], int max, char *current, size_t curlen);
int  hdhr_set_channel_map(struct hdhomerun_device_t *hd, const char *map);
/* "0,1" or "" (= all PLPs on the current ATSC 3.0 channel). */
int  hdhr_set_plps(struct hdhomerun_device_t *hd, const char *list, char *err, size_t errlen);
int  hdhr_programs(struct hdhomerun_device_t *hd, hdhr_program_t *out, int max);

/* ffplay: point the tuner's stream (MPEG-TS over UDP) at this computer and open
 * ffplay on it. ATSC 3.0 audio (AC-4) needs the AC-4 ffplay build. */
int  hdhr_free_udp_port(void);
/* set the program filter and send the stream to this computer, UDP <port> */
int  hdhr_stream_to_me(struct hdhomerun_device_t *hd, const hdhr_tuner_t *t, const char *program, int port,
                       char *msg, size_t msglen);
int  hdhr_play_start(struct hdhomerun_device_t *hd, const hdhr_tuner_t *t, const char *program,
                     plat_pid_t *pid, char *msg, size_t msglen);
void hdhr_play_stop(struct hdhomerun_device_t *hd, plat_pid_t *pid);

#endif
