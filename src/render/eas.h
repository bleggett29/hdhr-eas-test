/*
 * Copyright (C) 2026 Brian Scott - HDHR EAS Test.
 * eas.h - EAS / AEAT timeline support for RENDER (EAS edition).
 *
 * Records every AEAT (Advanced Emergency Alert Table) and On-Screen Message
 * Notification occurrence with the capture time it was seen, adds an
 * "EAS / Alert Timeline" section to the normal HTML report, writes a small
 * <capture>.eas.tsv sidecar per capture, and (render --eas-summary) merges
 * many sidecars into one timeline page across stations and segments.
 *
 * GPLv3, same as RENDER.
 */
#ifndef RENDER_EAS_H
#define RENDER_EAS_H

#include <stdio.h>
#include <sys/time.h>
#include "structures.h"

/* How packet times in this capture should be read. */
typedef enum {
    EAS_TIMING_ABSOLUTE = 0,  /* real pcap timestamps (epoch)                  */
    EAS_TIMING_RELATIVE,      /* estimated from -t, starting at 0 s             */
    EAS_TIMING_NONE           /* no usable timing (debug file without -t)       */
} eas_timing_t;

/* Called for every packet before it is processed. */
void eas_note_packet(const struct timeval *ts);

/* Called from parse_xml for every XML table seen. */
void eas_note_xml(const char *root_name, const char *xml, int len);
void eas_note_aeat(const AeatData *aeat);

/* Station details for the report/sidecar, gathered from the SLT by a3render. */
void eas_set_station(const char *bsid, const char *services, const char *eas_services);

/* Capture context: input file name and how to read the packet times. */
void eas_set_capture(const char *input_path, eas_timing_t timing,
                     const struct timeval *first, const struct timeval *last,
                     double duration_hint_s);

/* Normal report: the timeline section (call right after the <h1>). */
void eas_write_html_section(FILE *f);

/* <input-base>.eas.tsv next to the input. Returns 0 on success. */
int eas_write_sidecar(const char *input_path);

/* render --eas-summary <out.html> <dir|file.eas.tsv|capture>... */
int eas_summary_main(int argc, char **argv);

#endif
