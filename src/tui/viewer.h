/*
 * Copyright (C) 2026 Brian Scott - HDHR EAS Test.
 * viewer.h - built-in live viewer for the GUI: plays the MPEG-TS the tuner
 * sends over UDP, using FFmpeg (with the AC-4 decoder for ATSC 3.0 audio)
 * and SDL2 for sound. Video frames are handed to the GUI as RGBA. GPLv3.
 */
#ifndef HDHR_VIEWER_H
#define HDHR_VIEWER_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

typedef struct viewer viewer_t;

/* Called from the viewer's thread with a frame it owns; take it with
 * viewer_frame_free() when done (the GUI does that on its main thread). */
typedef struct {
    int w, h, stride;
    uint8_t *rgba;
} viewer_frame_t;

typedef void (*viewer_frame_cb)(void *user, viewer_frame_t *frame);
typedef void (*viewer_status_cb)(void *user, const char *text);   /* also from the viewer thread */

/* true when this build can show video at all (FFmpeg + SDL2 linked) */
bool viewer_available(void);
/* true when the linked FFmpeg has the AC-4 decoder */
bool viewer_has_ac4(void);

/* Start listening on UDP <port>. NULL + err on failure. */
viewer_t *viewer_start(int port, viewer_frame_cb on_frame, viewer_status_cb on_status, void *user,
                       char *err, size_t errlen);
void viewer_set_mute(viewer_t *v, bool mute);

/* Volume in percent, applied in software so it can go above 100% (with a soft
 * limiter). AC-4 (ATSC 3.0) audio is usually very quiet, so it has its own
 * setting; the viewer starts at 500% for AC-4 and 100% for everything else. */
void viewer_set_volume(viewer_t *v, int ac4_pct, int other_pct);

enum { VIEWER_AUDIO_NONE = 0, VIEWER_AUDIO_OTHER = 1, VIEWER_AUDIO_AC4 = 2 };
int  viewer_audio_kind(viewer_t *v);    /* which setting the current stream uses */
bool viewer_running(viewer_t *v);       /* false once the stream ended or failed */
void viewer_stop(viewer_t *v);          /* stops and frees */
void viewer_frame_free(viewer_frame_t *f);

#endif
