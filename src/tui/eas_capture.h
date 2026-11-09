/*
 * Copyright (C) 2026 Brian Scott - HDHR EAS Test.
 * eas_capture.h - long-running, segmented, multi-tuner capture for the
 * nationwide EAS test (or any event you want to record across a window).
 *
 * Part of the EAS edition of HDHomeRun TUI. GPLv3, same as the TUI.
 */
#ifndef EAS_CAPTURE_H
#define EAS_CAPTURE_H

#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <time.h>

typedef enum {
    EAS_FMT_TS = 0,   /* ATSC 1.0: full MPEG transport stream (.ts)   */
    EAS_FMT_PCAP,     /* ATSC 3.0: ALP-PCAP (.pcap) - best for RENDER   */
    EAS_FMT_DBG       /* ATSC 3.0: HDHomeRun debug format (.dbg)        */
} eas_fmt_t;

typedef struct eas_job {
    /* ---- configuration (set before eas_job_start) ---- */
    char ip[64];
    int tuner;
    unsigned int rf;
    char plps[64];          /* "p0p1" for ATSC 3.0, "" for ATSC 1.0      */
    bool atsc3;
    eas_fmt_t fmt;          /* TS for 1.0; PCAP (default) or DBG for 3.0 */
    int seg_seconds;        /* segment length, aligned to the wall clock */
    time_t stop_time;       /* 0 = run until eas_job_request_stop()      */
    char outdir[512];
    bool force_release;     /* true: take the tuner even if it's streaming elsewhere */

    /* ---- runtime (owned by the job threads) ---- */
    volatile int stop_requested;
    pthread_t rx_thread, aux_thread;
    bool threads_started;

    pthread_mutex_t lock;   /* protects everything below */
    pthread_cond_t cond;
    bool running;
    char state[64];
    char cur_file[700];
    int segments;
    int reconnects;
    unsigned long long bytes_total;
    unsigned long long bytes_seg;
    char last_msg[256];
    char signal[160];
    long id_val;            /* BSID (3.0) or TSID (1.0); -1 = unknown    */
    char details_pending[700];
} eas_job_t;

/* Status snapshot for display (no locks inside). */
typedef struct {
    bool running;
    char state[64];
    char cur_file[700];
    int segments;
    int reconnects;
    unsigned long long bytes_total;
    unsigned long long bytes_seg;
    char last_msg[256];
    char signal[160];
    long id_val;
    eas_fmt_t fmt;
} eas_status_t;

void eas_job_init(eas_job_t *job);
/* Parses "33" (ATSC 1.0 full TS), "27p0" / "27p0p16" / "27:0+16" (ATSC 3.0 PLPs). */
int  eas_parse_channel_spec(const char *spec, eas_job_t *job, char *err, size_t errlen);
int  eas_job_start(eas_job_t *job);
void eas_job_request_stop(eas_job_t *job);
void eas_job_join(eas_job_t *job);
void eas_job_status(eas_job_t *job, eas_status_t *out);
void eas_job_destroy(eas_job_t *job);
const char *eas_fmt_name(eas_fmt_t fmt);
/* Frees a tuner someone else is holding: force-releases its lock, clears its
 * stream target and untunes it. Returns 0 if the device answered. */
int  eas_release_tuner(const char *ip, int tuner, char *msg, size_t msglen);
/* Reads a tuner's stream target into out ("none" if idle). Returns 0 if the device answered. */
int  eas_tuner_target(const char *ip, int tuner, char *out, size_t n);

/* The L1/PLP details parser isn't thread-safe; hold this around its calls. */
void eas_details_lock(void);
void eas_details_unlock(void);

/* Shared log file (eas_capture.log in the output dir). */
void eas_log_open(const char *outdir);
void eas_log_close(void);
void eas_logf(const char *fmt, ...);
void eas_set_log_echo(bool echo);   /* also print to stdout (headless mode) */


#endif
