/*
 * Copyright (C) 2026 Brian Scott - HDHR EAS Test.
 * viewer.c - built-in live viewer (see viewer.h). GPLv3.
 *
 * Threads, like ffplay:
 *   reader  - reads the UDP MPEG-TS, sorts packets into a video and an audio queue
 *   video   - decodes, deinterlaces/scales (yadif+scale), queues RGBA frames
 *   audio   - decodes (AC-4 too), applies the volume/boost, feeds SDL
 *   shower  - hands each frame to the GUI when the audio clock reaches it
 * Audio and video decode separately, so a slow decoder on one side never
 * stalls the other.
 */
#include "viewer.h"

#include <math.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef HAVE_VIEWER

bool viewer_available(void) { return false; }
bool viewer_has_ac4(void) { return false; }
viewer_t *viewer_start(int port, viewer_frame_cb a, viewer_status_cb b, void *u, char *err, size_t n) {
    (void)port; (void)a; (void)b; (void)u;
    snprintf(err, n, "this build has no built-in viewer");
    return NULL;
}
void viewer_set_mute(viewer_t *v, bool m) { (void)v; (void)m; }
void viewer_set_volume(viewer_t *v, int ac4_pct, int other_pct) { (void)v; (void)ac4_pct; (void)other_pct; }
int  viewer_audio_kind(viewer_t *v) { (void)v; return VIEWER_AUDIO_NONE; }
bool viewer_running(viewer_t *v) { (void)v; return false; }
void viewer_stop(viewer_t *v) { (void)v; }
void viewer_frame_free(viewer_frame_t *f) { if (f) { free(f->rgba); free(f); } }

#else

#include <pthread.h>
#include <stdatomic.h>
#ifdef __GLIBC__
#include <malloc.h>            /* malloc_trim */
#endif
#include <time.h>
#ifdef _WIN32
#include <windows.h>
#include <timeapi.h>           /* timeBeginPeriod: 1 ms sleeps instead of 15.6 ms */
#endif

#define SDL_MAIN_HANDLED
#include <SDL.h>

#include <libavcodec/avcodec.h>
#include <libavfilter/avfilter.h>
#include <libavfilter/buffersink.h>
#include <libavfilter/buffersrc.h>
#include <libavformat/avformat.h>
#include <libavutil/channel_layout.h>
#include <libavutil/opt.h>
#include <libavutil/time.h>
#include <libswresample/swresample.h>

#define VQ_MAX      12         /* decoded frames waiting to be shown (~0.2-0.4 s) */
#define PQ_MAX      2000       /* packets waiting per decoder                       */
#define OUT_MAX_W   1280       /* frames are scaled to fit 1280x720                 */
#define OUT_MAX_H   720
#define AUDIO_RATE  48000
#define AUDIO_BPS   (AUDIO_RATE * 2 * 4)   /* stereo float32 bytes per second */
#define AUDIO_BASE_TARGET 0.30             /* seconds of sound kept queued (plus any delay added) */
#define AUDIO_MAX_STRETCH 0.015            /* sound is stretched/squeezed by up to 1.5%...      */
#define AUDIO_MAX_STRETCH_FAR 0.04         /* ...or 4% when the queue is far off target         */

/* ------------------------------------------------------------------ packet queue */
typedef struct pq_node { AVPacket *pkt; struct pq_node *next; } pq_node_t;
typedef struct {
    pq_node_t *head, *tail;
    int n;
    bool eof;
    pthread_mutex_t lock;
    pthread_cond_t cond;
} pq_t;

static void pq_init(pq_t *q) { memset(q, 0, sizeof(*q)); pthread_mutex_init(&q->lock, NULL); pthread_cond_init(&q->cond, NULL); }

static void pq_flush(pq_t *q) {
    pthread_mutex_lock(&q->lock);
    while (q->head) { pq_node_t *n = q->head; q->head = n->next; av_packet_free(&n->pkt); free(n); }
    q->tail = NULL; q->n = 0;
    pthread_mutex_unlock(&q->lock);
}

static void pq_destroy(pq_t *q) { pq_flush(q); pthread_mutex_destroy(&q->lock); pthread_cond_destroy(&q->cond); }

static void timed_wait(pthread_cond_t *c, pthread_mutex_t *m, int ms) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_nsec += (long)ms * 1000000L;
    while (ts.tv_nsec >= 1000000000L) { ts.tv_sec++; ts.tv_nsec -= 1000000000L; }
    pthread_cond_timedwait(c, m, &ts);
}

/* takes ownership of pkt; drops the oldest packet if the decoder is far behind */
static void pq_put(pq_t *q, AVPacket *pkt) {
    pq_node_t *n = malloc(sizeof(*n));
    if (!n) { av_packet_free(&pkt); return; }
    n->pkt = pkt; n->next = NULL;
    pthread_mutex_lock(&q->lock);
    if (q->n >= PQ_MAX && q->head) {
        pq_node_t *o = q->head; q->head = o->next; if (!q->head) q->tail = NULL;
        av_packet_free(&o->pkt); free(o); q->n--;
    }
    if (q->tail) q->tail->next = n; else q->head = n;
    q->tail = n; q->n++;
    pthread_cond_signal(&q->cond);
    pthread_mutex_unlock(&q->lock);
}

static void pq_set_eof(pq_t *q) {
    pthread_mutex_lock(&q->lock);
    q->eof = true;
    pthread_cond_broadcast(&q->cond);
    pthread_mutex_unlock(&q->lock);
}

/* NULL = end (eof or stop) */
static AVPacket *pq_get(pq_t *q, atomic_bool *stop) {
    pthread_mutex_lock(&q->lock);
    while (!q->head && !q->eof && !atomic_load(stop)) timed_wait(&q->cond, &q->lock, 100);
    AVPacket *p = NULL;
    if (q->head && !atomic_load(stop)) {
        pq_node_t *n = q->head; q->head = n->next; if (!q->head) q->tail = NULL; q->n--;
        p = n->pkt; free(n);
    }
    pthread_mutex_unlock(&q->lock);
    return p;
}

/* ------------------------------------------------------------------ decoded-frame queue */
#define FQ_MAX 8
typedef struct {
    AVFrame *f[FQ_MAX];
    int head, n;
    bool eof;
    pthread_mutex_t lock;
    pthread_cond_t cond;
} fq_t;

static void fq_init(fq_t *q) { memset(q, 0, sizeof(*q)); pthread_mutex_init(&q->lock, NULL); pthread_cond_init(&q->cond, NULL); }
static void fq_destroy(fq_t *q) {
    for (int i = 0; i < q->n; i++) av_frame_free(&q->f[(q->head + i) % FQ_MAX]);
    pthread_mutex_destroy(&q->lock); pthread_cond_destroy(&q->cond);
}
/* takes ownership; waits while full */
static void fq_put(fq_t *q, AVFrame *f, atomic_bool *stop) {
    pthread_mutex_lock(&q->lock);
    while (q->n >= FQ_MAX && !atomic_load(stop)) timed_wait(&q->cond, &q->lock, 100);
    if (atomic_load(stop)) { pthread_mutex_unlock(&q->lock); av_frame_free(&f); return; }
    q->f[(q->head + q->n) % FQ_MAX] = f;
    q->n++;
    pthread_cond_broadcast(&q->cond);
    pthread_mutex_unlock(&q->lock);
}
static void fq_set_eof(fq_t *q) {
    pthread_mutex_lock(&q->lock); q->eof = true; pthread_cond_broadcast(&q->cond); pthread_mutex_unlock(&q->lock);
}
static AVFrame *fq_get(fq_t *q, atomic_bool *stop) {
    pthread_mutex_lock(&q->lock);
    while (q->n == 0 && !q->eof && !atomic_load(stop)) timed_wait(&q->cond, &q->lock, 100);
    AVFrame *f = NULL;
    if (q->n > 0 && !atomic_load(stop)) { f = q->f[q->head]; q->head = (q->head + 1) % FQ_MAX; q->n--; pthread_cond_broadcast(&q->cond); }
    pthread_mutex_unlock(&q->lock);
    return f;
}

/* ------------------------------------------------------------------ viewer */
typedef struct { viewer_frame_t *f; double pts; } vq_item_t;

struct viewer {
    int port;
    viewer_frame_cb on_frame;
    viewer_status_cb on_status;
    void *user;

    pthread_t reader, vdec, vscale, adec, shower;
    bool vdec_started, vscale_started, adec_started, shower_started;
    fq_t rawq;                            /* decoded video frames waiting to be scaled */
    atomic_bool stop, ended, mute;
    atomic_int vol_ac4, vol_other;        /* percent */
    atomic_int audio_kind;

    /* set up by the reader before the decoders start */
    AVFormatContext *fc;
    AVCodecContext *vc, *ac;
    int vi, ai;
    pq_t vpq, apq;
    pthread_mutex_t setup_lock;           /* guards setup_done (the decoders exist) */
    pthread_cond_t setup_cond;
    bool setup_done;

    /* decoded video frames */
    pthread_mutex_t lock;
    pthread_cond_t cond;
    vq_item_t vq[VQ_MAX];
    int vq_head, vq_len;
    atomic_bool video_done;

    /* audio clock */
    SDL_AudioDeviceID dev;
    pthread_mutex_t clock_lock;
    double audio_end_pts;                 /* pts at the end of what's queued */
    bool have_audio_clock;
    double audio_target;                  /* seconds of sound to keep queued */

    double wall_base_pts, wall_base_t;
    bool wall_started;
    double av_offset;                     /* learned gap between video and audio timestamps */
};

static double now_s(void) { return av_gettime_relative() / 1e6; }

static void status(viewer_t *v, const char *fmt, ...) {
    if (!v->on_status) return;
    char buf[256];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    v->on_status(v->user, buf);
}

bool viewer_available(void) { return true; }
bool viewer_has_ac4(void) { return avcodec_find_decoder_by_name("ac4") != NULL; }
void viewer_frame_free(viewer_frame_t *f) { if (f) { free(f->rgba); free(f); } }

static int interrupt_cb(void *p) { viewer_t *v = p; return atomic_load(&v->stop); }

static double audio_clock(viewer_t *v) {
    if (!v->dev) return NAN;
    pthread_mutex_lock(&v->clock_lock);
    double c = NAN;
    if (v->have_audio_clock) c = v->audio_end_pts - SDL_GetQueuedAudioSize(v->dev) / (double)AUDIO_BPS;
    pthread_mutex_unlock(&v->clock_lock);
    return c;
}

/* ------------------------------------------------------------------ video filter */
typedef struct {
    AVFilterGraph *g;
    AVFilterContext *src, *sink;
    int w, h, fmt;
    AVRational sar;
    bool deint;                           /* yadif in the graph (seen an interlaced frame) */
} vfilter_t;

static void vf_free(vfilter_t *f) { bool d = f->deint; avfilter_graph_free(&f->g); memset(f, 0, sizeof(*f)); f->deint = d; }

static int vf_setup(vfilter_t *f, const AVFrame *in, AVRational tb) {
    vf_free(f);
    f->w = in->width; f->h = in->height; f->fmt = in->format; f->sar = in->sample_aspect_ratio;
    double sar = (in->sample_aspect_ratio.num && in->sample_aspect_ratio.den) ? av_q2d(in->sample_aspect_ratio) : 1.0;
    double dar = in->width * sar / (double)in->height;
    int oh = in->height < OUT_MAX_H ? in->height : OUT_MAX_H;
    int ow = (int)(oh * dar + 0.5);
    if (ow > OUT_MAX_W) { ow = OUT_MAX_W; oh = (int)(ow / dar + 0.5); }
    ow &= ~1; oh &= ~1;
    if (ow < 2 || oh < 2) return -1;

    f->g = avfilter_graph_alloc();
    if (!f->g) return -1;
    f->g->nb_threads = 0;                 /* scale/yadif slice threads: one per core */
    char args[256];
    snprintf(args, sizeof(args), "video_size=%dx%d:pix_fmt=%d:time_base=%d/%d:pixel_aspect=%d/%d",
             in->width, in->height, in->format, tb.num, tb.den,
             in->sample_aspect_ratio.num ? in->sample_aspect_ratio.num : 1,
             in->sample_aspect_ratio.den ? in->sample_aspect_ratio.den : 1);
    if (avfilter_graph_create_filter(&f->src, avfilter_get_by_name("buffer"), "in", args, NULL, f->g) < 0) return -1;
    if (avfilter_graph_create_filter(&f->sink, avfilter_get_by_name("buffersink"), "out", NULL, NULL, f->g) < 0) return -1;
    enum AVPixelFormat fmts[] = { AV_PIX_FMT_RGBA, AV_PIX_FMT_NONE };
    if (av_opt_set_int_list(f->sink, "pix_fmts", fmts, AV_PIX_FMT_NONE, AV_OPT_SEARCH_CHILDREN) < 0) return -1;

    char desc[200];
    /* deinterlace only interlaced video (ATSC 1.0 1080i/480i); ATSC 3.0 is progressive */
    snprintf(desc, sizeof(desc), "%sscale=%d:%d:flags=fast_bilinear,setsar=1,format=rgba",
             f->deint ? "yadif=mode=0:deint=interlaced," : "", ow, oh);
    AVFilterInOut *outs = avfilter_inout_alloc(), *ins = avfilter_inout_alloc();
    outs->name = av_strdup("in");  outs->filter_ctx = f->src;  outs->pad_idx = 0; outs->next = NULL;
    ins->name  = av_strdup("out"); ins->filter_ctx  = f->sink; ins->pad_idx  = 0; ins->next  = NULL;
    int r = avfilter_graph_parse_ptr(f->g, desc, &ins, &outs, NULL);
    avfilter_inout_free(&ins);
    avfilter_inout_free(&outs);
    if (r < 0) return -1;
    return avfilter_graph_config(f->g, NULL);
}

static void vq_push(viewer_t *v, viewer_frame_t *fr, double pts) {
    pthread_mutex_lock(&v->lock);
    while (v->vq_len >= VQ_MAX && !atomic_load(&v->stop)) timed_wait(&v->cond, &v->lock, 100);
    if (atomic_load(&v->stop)) { pthread_mutex_unlock(&v->lock); viewer_frame_free(fr); return; }
    int tail = (v->vq_head + v->vq_len) % VQ_MAX;
    v->vq[tail].f = fr;
    v->vq[tail].pts = pts;
    v->vq_len++;
    pthread_cond_broadcast(&v->cond);
    pthread_mutex_unlock(&v->lock);
}

static void filter_and_queue(viewer_t *v, vfilter_t *vf, AVFrame *in, AVRational tb, AVFrame *out) {
    bool inter = (in->flags & AV_FRAME_FLAG_INTERLACED) != 0;
    if (inter && !vf->deint) { vf->deint = true; vf_free(vf); vf->deint = true; }   /* add yadif from now on */
    if (!vf->g || in->width != vf->w || in->height != vf->h || in->format != vf->fmt ||
        av_cmp_q(in->sample_aspect_ratio, vf->sar)) {
        if (vf_setup(vf, in, tb) < 0) { vf_free(vf); return; }
    }
    /* in->pts holds the decoder's best timestamp (set in vdec_main); the
       filters keep .pts right when yadif changes the time base */
    if (av_buffersrc_add_frame_flags(vf->src, in, AV_BUFFERSRC_FLAG_KEEP_REF) < 0) return;
    while (av_buffersink_get_frame(vf->sink, out) >= 0) {
        double pts = out->pts == AV_NOPTS_VALUE ? NAN : out->pts * av_q2d(av_buffersink_get_time_base(vf->sink));
        viewer_frame_t *fr = calloc(1, sizeof(*fr));
        if (fr) {
            fr->w = out->width; fr->h = out->height; fr->stride = out->width * 4;
            fr->rgba = malloc((size_t)fr->stride * fr->h);
            if (fr->rgba) {
                if (out->linesize[0] == fr->stride)
                    memcpy(fr->rgba, out->data[0], (size_t)fr->stride * fr->h);
                else
                    for (int y = 0; y < fr->h; y++)
                        memcpy(fr->rgba + (size_t)y * fr->stride, out->data[0] + (size_t)y * out->linesize[0], fr->stride);
                vq_push(v, fr, pts);
            } else free(fr);
        }
        av_frame_unref(out);
    }
}

/* ------------------------------------------------------------------ video threads */
/* decode only; the next thread scales, so the two overlap (60 fps ATSC 3.0) */
static void *vdec_main(void *p) {
    viewer_t *v = p;
    AVFrame *fr = av_frame_alloc();
    AVPacket *pkt;
    while ((pkt = pq_get(&v->vpq, &v->stop)) != NULL) {
        if (avcodec_send_packet(v->vc, pkt) >= 0) {
            while (avcodec_receive_frame(v->vc, fr) >= 0) {
                if (fr->best_effort_timestamp != AV_NOPTS_VALUE) fr->pts = fr->best_effort_timestamp;
                AVFrame *c = av_frame_alloc();
                if (c) { av_frame_move_ref(c, fr); fq_put(&v->rawq, c, &v->stop); }
                av_frame_unref(fr);
            }
        }
        av_packet_free(&pkt);
    }
    av_frame_free(&fr);
    fq_set_eof(&v->rawq);
    return NULL;
}

static void *vscale_main(void *p) {
    viewer_t *v = p;
    AVFrame *out = av_frame_alloc();
    vfilter_t vf; memset(&vf, 0, sizeof(vf));
    AVRational tb = v->fc->streams[v->vi]->time_base;
    AVFrame *in;
    while ((in = fq_get(&v->rawq, &v->stop)) != NULL) {
        filter_and_queue(v, &vf, in, tb, out);
        av_frame_free(&in);
    }
    vf_free(&vf);
    av_frame_free(&out);
    atomic_store(&v->video_done, true);
    pthread_mutex_lock(&v->lock);
    pthread_cond_broadcast(&v->cond);
    pthread_mutex_unlock(&v->lock);
    return NULL;
}

/* ------------------------------------------------------------------ audio thread */
/* gain with a soft knee, so a big boost doesn't turn peaks into harsh clipping */
static inline float shape(float x, float g) {
    x *= g;
    float a = fabsf(x);
    if (a <= 0.8f) return x;
    float y = 0.8f + 0.2f * tanhf((a - 0.8f) / 0.2f);
    return x < 0 ? -y : y;
}

static void delay_audio(viewer_t *v, double secs);

static void *adec_main(void *p) {
    viewer_t *v = p;
    bool primed = false;
    double below_since = 0;
    AVFrame *fr = av_frame_alloc();
    SwrContext *swr = NULL;
    float *buf = NULL; int cap = 0;
    AVRational tb = v->fc->streams[v->ai]->time_base;
    bool ac4 = v->ac->codec_id == AV_CODEC_ID_AC4;
    AVPacket *pkt;
    while ((pkt = pq_get(&v->apq, &v->stop)) != NULL) {
        if (avcodec_send_packet(v->ac, pkt) >= 0) {
            while (avcodec_receive_frame(v->ac, fr) >= 0) {
                if (!swr) {
                    AVChannelLayout stereo = AV_CHANNEL_LAYOUT_STEREO;
                    if (swr_alloc_set_opts2(&swr, &stereo, AV_SAMPLE_FMT_FLT, AUDIO_RATE,
                                            &fr->ch_layout, fr->format, fr->sample_rate, 0, NULL) < 0 ||
                        swr_init(swr) < 0) { swr_free(&swr); av_frame_unref(fr); continue; }
                }
                /* Keep the queued sound at its target: the sound card's clock and
                   the broadcast's never match exactly (ATSC 3.0 drifted ~0.8% here),
                   and an emptying queue makes the picture race ahead and skip.
                   Stretch or squeeze by at most 1.5% - too little to hear - or by
                   up to 4% while the queue is far from its target. */
                if (primed) {
                    int nb = (int)av_rescale(fr->nb_samples, AUDIO_RATE, fr->sample_rate);
                    pthread_mutex_lock(&v->clock_lock);
                    double q = SDL_GetQueuedAudioSize(v->dev) / (double)AUDIO_BPS;
                    /* If the queue has stayed well below its target for a few
                       seconds, the target isn't reachable on this PC: bring it
                       down to what's there instead of stretching forever. */
                    if (q < v->audio_target - 0.25) {
                        if (below_since == 0) below_since = now_s();
                        else if (now_s() - below_since > 3.0) { v->audio_target = q + 0.10; below_since = 0; }
                    } else below_since = 0;
                    double err = q - v->audio_target;
                    pthread_mutex_unlock(&v->clock_lock);
                    int delta = 0;
                    if (fabs(err) > 0.03) {
                        delta = (int)(-err * AUDIO_RATE * 0.1);
                        int lim = (int)(nb * (fabs(err) > 0.15 ? AUDIO_MAX_STRETCH_FAR : AUDIO_MAX_STRETCH));
                        if (delta > lim) delta = lim;
                        if (delta < -lim) delta = -lim;
                    }
                    swr_set_compensation(swr, delta, nb);
                }
                int maxn = swr_get_out_samples(swr, fr->nb_samples) + 256;
                if (maxn * 2 > cap) { cap = maxn * 2 + 4096; float *nb = realloc(buf, (size_t)cap * sizeof(float)); if (!nb) break; buf = nb; }
                uint8_t *o[1] = { (uint8_t *)buf };
                int n = swr_convert(swr, o, maxn, (const uint8_t **)fr->extended_data, fr->nb_samples);
                if (n > 0) {
                    float g = atomic_load(&v->mute) ? 0.0f
                            : (ac4 ? atomic_load(&v->vol_ac4) : atomic_load(&v->vol_other)) / 100.0f;
                    if (g == 0.0f) memset(buf, 0, (size_t)n * 2 * sizeof(float));
                    else if (g != 1.0f) for (int i = 0; i < n * 2; i++) buf[i] = shape(buf[i], g);
                    int64_t ts = fr->best_effort_timestamp != AV_NOPTS_VALUE ? fr->best_effort_timestamp : fr->pts;
                    double pts = ts == AV_NOPTS_VALUE ? NAN : ts * av_q2d(tb);
                    if (SDL_GetQueuedAudioSize(v->dev) > (Uint32)(AUDIO_BPS * 8)) SDL_ClearQueuedAudio(v->dev);  /* > 8 s behind */
                    if (!primed) { delay_audio(v, AUDIO_BASE_TARGET); primed = true; }   /* cushion against gaps */
                    pthread_mutex_lock(&v->clock_lock);
                    SDL_QueueAudio(v->dev, buf, (Uint32)(n * 2 * sizeof(float)));
                    /* the frame's real duration, not the stretched sample count */
                    if (!isnan(pts)) { v->audio_end_pts = pts + fr->nb_samples / (double)fr->sample_rate; v->have_audio_clock = true; }
                    pthread_mutex_unlock(&v->clock_lock);
                }
                av_frame_unref(fr);
            }
        }
        av_packet_free(&pkt);
    }
    free(buf);
    swr_free(&swr);
    av_frame_free(&fr);
    return NULL;
}

/* ------------------------------------------------------------------ shower thread */
/* Delay the sound by `secs` (silence into SDL's queue). Live streams reach us
 * with the video behind the audio - decoder threads and the deinterlacer hold
 * frames back - so the audio waits for the picture instead of the picture
 * being thrown away. */
static void delay_audio(viewer_t *v, double secs) {
    static const float zero[4096] = { 0 };
    size_t bytes = (size_t)(secs * AUDIO_BPS) & ~(size_t)7;
    pthread_mutex_lock(&v->clock_lock);
    while (bytes > 0) {
        size_t c = bytes < sizeof(zero) ? bytes : sizeof(zero);
        SDL_QueueAudio(v->dev, zero, (Uint32)c);
        bytes -= c;
    }
    v->audio_target += secs;
    pthread_mutex_unlock(&v->clock_lock);
}

static void *shower_main(void *p) {
    viewer_t *v = p;
    int late_run = 0;
    /* HDHR_VIEWER_STATS=1 (to stderr) or =<file> (appended): shown/dropped
       frames every 5 s, for troubleshooting. The Windows GUI has no console,
       so give it a file name there. */
    const char *sv = getenv("HDHR_VIEWER_STATS");
    FILE *sf = NULL;
    if (sv && *sv) sf = strcmp(sv, "1") ? fopen(sv, "a") : stderr;
    bool stats = sf != NULL;
    long shown = 0, dropped = 0;
    double stats_t = now_s();
    int behind = 0;                 /* consecutive frames that were late */
    int far_run = 0;                /* consecutive frames > 2 s off the audio clock */
    double delayed = 0;             /* audio delay added so far */
    while (!atomic_load(&v->stop)) {
        pthread_mutex_lock(&v->lock);
        while (v->vq_len == 0 && !atomic_load(&v->stop) && !atomic_load(&v->video_done) && !atomic_load(&v->ended))
            timed_wait(&v->cond, &v->lock, 100);
        if (v->vq_len == 0) {
            bool done = atomic_load(&v->video_done) || (atomic_load(&v->ended) && !v->vscale_started);
            pthread_mutex_unlock(&v->lock);
            if (done) break;
            continue;
        }
        vq_item_t it = v->vq[v->vq_head];
        pthread_mutex_unlock(&v->lock);

        bool drop = false;
        for (;;) {
            if (atomic_load(&v->stop)) break;
            double clk = audio_clock(v);
            bool by_audio = !isnan(clk);
            if (by_audio) clk += v->av_offset;
            if (isnan(clk)) {                         /* no audio (yet): wall clock */
                if (isnan(it.pts)) break;
                if (!v->wall_started) { v->wall_base_pts = it.pts; v->wall_base_t = now_s(); v->wall_started = true; }
                clk = v->wall_base_pts + (now_s() - v->wall_base_t);
            } else {
                v->wall_started = false;
            }
            double d = isnan(it.pts) ? 0 : it.pts - clk;
            if (fabs(d) > 2.0) {
                /* More than 2 s off: a timestamp jump, or a station whose audio
                   and video timestamps are offset (seen: video 8 s "ahead").
                   Show it now; if it stays that way, learn the offset so frames
                   are paced smoothly again. */
                if (by_audio && ++far_run >= 30) {
                    v->av_offset += d;
                    far_run = 0;
                    if (stats) fprintf(sf, "viewer: video and audio timestamps differ by %.2f s - allowing for it\n", v->av_offset);
                }
                v->wall_started = false;
                break;
            }
            far_run = 0;
            if (d <= 0.002) {
                /* steadily behind the sound: hold the sound back to match */
                bool audio_master = v->dev && !isnan(audio_clock(v));
                if (audio_master && d < -0.06) behind++; else behind = 0;
                double queued_now = SDL_GetQueuedAudioSize(v->dev) / (double)AUDIO_BPS;
                if (audio_master && behind >= 8 && queued_now - d < 3.0) {
                    delay_audio(v, -d + 0.06);
                    delayed += -d + 0.06;
                    behind = 0;
                    if (stats) fprintf(sf, "viewer: video %.0f ms behind - delaying audio to match\n", -d * 1000);
                    continue;                                    /* re-check this frame */
                }
                drop = d < -0.25 && late_run < 15;
                break;
            }
            av_usleep((unsigned)((d > 0.02 ? 0.02 : d) * 1e6));
        }
        pthread_mutex_lock(&v->lock);
        v->vq_head = (v->vq_head + 1) % VQ_MAX;
        v->vq_len--;
        pthread_cond_broadcast(&v->cond);
        pthread_mutex_unlock(&v->lock);

        if (atomic_load(&v->stop)) { viewer_frame_free(it.f); break; }
        if (stats && now_s() - stats_t >= 5.0) {
            double c = audio_clock(v);
            fprintf(sf, "viewer: %ld shown, %ld dropped in %.1f s; video queue %d; frame pts %.3f, audio clock %.3f, "
                    "audio queued %.2f s (target %.2f), audio delay added %.2f s, offset %.2f s, wall %.3f\n",
                    shown, dropped, now_s() - stats_t, v->vq_len, it.pts, c,
                    v->dev ? SDL_GetQueuedAudioSize(v->dev) / (double)AUDIO_BPS : 0.0, v->audio_target, delayed, v->av_offset, now_s());
            fflush(sf);
            shown = dropped = 0; stats_t = now_s();
        }
        if (drop) { late_run++; dropped++; viewer_frame_free(it.f); continue; }
        late_run = 0;
        shown++;
        v->on_frame(v->user, it.f);                   /* GUI frees it */
    }
    if (sf && sf != stderr) fclose(sf);
    return NULL;
}

/* ------------------------------------------------------------------ reader thread */
static bool open_decoder(AVFormatContext *fc, int idx, AVCodecContext **out, bool video) {
    const AVCodec *c = avcodec_find_decoder(fc->streams[idx]->codecpar->codec_id);
    if (!c) return false;
    AVCodecContext *cc = avcodec_alloc_context3(c);
    if (!cc) return false;
    if (avcodec_parameters_to_context(cc, fc->streams[idx]->codecpar) < 0) { avcodec_free_context(&cc); return false; }
    if (video) {
        cc->thread_count = 0;                         /* one per CPU core */
        cc->thread_type = FF_THREAD_FRAME | FF_THREAD_SLICE;
    }
    if (avcodec_open2(cc, c, NULL) < 0) { avcodec_free_context(&cc); return false; }
    *out = cc;
    return true;
}

static void *reader_main(void *p) {
    viewer_t *v = p;
    v->vi = v->ai = -1;
    char url[200];
    snprintf(url, sizeof(url), "udp://0.0.0.0:%d?buffer_size=8388608&fifo_size=1000000&overrun_nonfatal=1&timeout=15000000", v->port);
    status(v, "Waiting for the stream...");
    v->fc = avformat_alloc_context();
    v->fc->interrupt_callback.callback = interrupt_cb;
    v->fc->interrupt_callback.opaque = v;
    /* Probe briefly, and don't replay what was read while probing: on a live
       stream that backlog arrives as a burst and puts the picture seconds
       behind the sound. Decoding starts fresh at the next keyframe. */
    v->fc->flags |= AVFMT_FLAG_NOBUFFER;
    AVDictionary *opt = NULL;
    av_dict_set(&opt, "probesize", "3000000", 0);
    av_dict_set(&opt, "analyzeduration", "2500000", 0);
    int r = avformat_open_input(&v->fc, url, av_find_input_format("mpegts"), &opt);
    av_dict_free(&opt);
    char anote[96] = "";
    if (r < 0) { if (!atomic_load(&v->stop)) status(v, "No stream arrived (is the tuner locked?)"); goto done; }
    if (avformat_find_stream_info(v->fc, NULL) < 0) { status(v, "Couldn't read the stream"); goto done; }

    v->vi = av_find_best_stream(v->fc, AVMEDIA_TYPE_VIDEO, -1, -1, NULL, 0);
    v->ai = av_find_best_stream(v->fc, AVMEDIA_TYPE_AUDIO, -1, v->vi, NULL, 0);
    if (v->vi >= 0 && !open_decoder(v->fc, v->vi, &v->vc, true)) v->vi = -1;
    if (v->ai >= 0) {
        enum AVCodecID id = v->fc->streams[v->ai]->codecpar->codec_id;
        if (!open_decoder(v->fc, v->ai, &v->ac, false)) {
            snprintf(anote, sizeof(anote), " - no decoder for %s audio (no sound)", avcodec_get_name(id));
            v->ai = -1;
        }
    }
    if (v->vi < 0 && v->ai < 0) { status(v, "No video or audio this viewer can play%s", anote); goto done; }
    if (v->ai >= 0) {
        SDL_AudioSpec want, have;
        memset(&want, 0, sizeof(want));
        want.freq = AUDIO_RATE; want.format = AUDIO_F32SYS; want.channels = 2; want.samples = 1024;
        v->dev = SDL_OpenAudioDevice(NULL, 0, &want, &have, 0);
        if (!v->dev) {
            snprintf(anote, sizeof(anote), " - no sound device (%s)", SDL_GetError());
            avcodec_free_context(&v->ac);
            v->ai = -1;
        } else {
            SDL_PauseAudioDevice(v->dev, 0);
            atomic_store(&v->audio_kind, v->ac->codec_id == AV_CODEC_ID_AC4 ? VIEWER_AUDIO_AC4 : VIEWER_AUDIO_OTHER);
        }
    }
    for (unsigned i = 0; i < v->fc->nb_streams; i++)
        if ((int)i != v->vi && (int)i != v->ai) v->fc->streams[i]->discard = AVDISCARD_ALL;

    status(v, "%s%s%s", v->vi >= 0 ? avcodec_get_name(v->vc->codec_id) : "no video",
           v->ai >= 0 ? " + " : "", v->ai >= 0 ? avcodec_get_name(v->ac->codec_id) : anote);

    /* Skip what piled up in the network buffer while probing (seconds of it
       on Windows): read until reads start having to wait for live data. */
    {
        AVPacket *junk = av_packet_alloc();
        double t_start = now_s();
        int skipped = 0;
        while (junk && !atomic_load(&v->stop) && now_s() - t_start < 5.0) {
            double t0 = now_s();
            if (av_read_frame(v->fc, junk) < 0) break;
            av_packet_unref(junk);
            skipped++;
            if (now_s() - t0 > 0.010) break;          /* waited for data: we're live */
        }
        av_packet_free(&junk);
        (void)skipped;
    }

    if (v->vi >= 0) {
        v->vdec_started = pthread_create(&v->vdec, NULL, vdec_main, v) == 0;
        v->vscale_started = v->vdec_started && pthread_create(&v->vscale, NULL, vscale_main, v) == 0;
    }
    if (v->ai >= 0) v->adec_started = pthread_create(&v->adec, NULL, adec_main, v) == 0;
    pthread_mutex_lock(&v->setup_lock);
    v->setup_done = true;
    pthread_cond_broadcast(&v->setup_cond);
    pthread_mutex_unlock(&v->setup_lock);

    AVPacket *pkt = av_packet_alloc();
    while (!atomic_load(&v->stop) && pkt) {
        r = av_read_frame(v->fc, pkt);
        if (r < 0) {
            if (r == AVERROR(EAGAIN)) { av_usleep(10000); continue; }
            if (!atomic_load(&v->stop)) status(v, "The stream stopped");
            break;
        }
        if (pkt->stream_index == v->vi && v->vdec_started) { pq_put(&v->vpq, pkt); pkt = av_packet_alloc(); }
        else if (pkt->stream_index == v->ai && v->adec_started) { pq_put(&v->apq, pkt); pkt = av_packet_alloc(); }
        else av_packet_unref(pkt);
    }
    av_packet_free(&pkt);

done:
    pq_set_eof(&v->vpq);
    pq_set_eof(&v->apq);
    atomic_store(&v->ended, true);
    pthread_mutex_lock(&v->setup_lock);
    v->setup_done = true;
    pthread_cond_broadcast(&v->setup_cond);
    pthread_mutex_unlock(&v->setup_lock);
    pthread_mutex_lock(&v->lock);
    pthread_cond_broadcast(&v->cond);
    pthread_mutex_unlock(&v->lock);
    return NULL;
}

/* ------------------------------------------------------------------ API */
viewer_t *viewer_start(int port, viewer_frame_cb on_frame, viewer_status_cb on_status, void *user,
                       char *err, size_t errlen) {
    static bool inited = false;
    if (!inited) {
        avformat_network_init();
        SDL_SetMainReady();
        /* SDL would otherwise take over SIGINT/SIGTERM and the GUI would stop
           responding to Ctrl-C and normal shutdown */
        SDL_SetHint(SDL_HINT_NO_SIGNAL_HANDLERS, "1");
        if (SDL_Init(SDL_INIT_AUDIO) < 0) { snprintf(err, errlen, "SDL audio: %s", SDL_GetError()); }
        inited = true;
    }
    viewer_t *v = calloc(1, sizeof(*v));
    if (!v) { snprintf(err, errlen, "out of memory"); return NULL; }
    v->port = port; v->on_frame = on_frame; v->on_status = on_status; v->user = user;
    atomic_store(&v->vol_ac4, 500);
    atomic_store(&v->vol_other, 100);
    pthread_mutex_init(&v->lock, NULL);
    pthread_cond_init(&v->cond, NULL);
    pthread_mutex_init(&v->setup_lock, NULL);
    pthread_cond_init(&v->setup_cond, NULL);
    pthread_mutex_init(&v->clock_lock, NULL);
    pq_init(&v->vpq);
    pq_init(&v->apq);
    fq_init(&v->rawq);
#ifdef _WIN32
    timeBeginPeriod(1);
#endif
    if (pthread_create(&v->reader, NULL, reader_main, v) != 0) {
        snprintf(err, errlen, "thread");
#ifdef _WIN32
        timeEndPeriod(1);
#endif
        free(v);
        return NULL;
    }
    v->shower_started = pthread_create(&v->shower, NULL, shower_main, v) == 0;
    return v;
}

void viewer_set_mute(viewer_t *v, bool mute) {
    if (!v) return;
    atomic_store(&v->mute, mute);
    if (mute && v->dev) SDL_ClearQueuedAudio(v->dev);
}

void viewer_set_volume(viewer_t *v, int ac4_pct, int other_pct) {
    if (!v) return;
    atomic_store(&v->vol_ac4, ac4_pct);
    atomic_store(&v->vol_other, other_pct);
}

int viewer_audio_kind(viewer_t *v) { return v ? atomic_load(&v->audio_kind) : VIEWER_AUDIO_NONE; }

bool viewer_running(viewer_t *v) { return v && !atomic_load(&v->ended); }

void viewer_stop(viewer_t *v) {
    if (!v) return;
    atomic_store(&v->stop, true);
    pq_set_eof(&v->vpq);
    pq_set_eof(&v->apq);
    fq_set_eof(&v->rawq);
    pthread_mutex_lock(&v->lock);
    pthread_cond_broadcast(&v->cond);
    pthread_mutex_unlock(&v->lock);
    pthread_join(v->reader, NULL);
    if (v->vdec_started) pthread_join(v->vdec, NULL);
    if (v->vscale_started) pthread_join(v->vscale, NULL);
    if (v->adec_started) pthread_join(v->adec, NULL);
    if (v->shower_started) pthread_join(v->shower, NULL);
    for (int i = 0; i < v->vq_len; i++) viewer_frame_free(v->vq[(v->vq_head + i) % VQ_MAX].f);
    if (v->dev) SDL_CloseAudioDevice(v->dev);
    avcodec_free_context(&v->vc);
    avcodec_free_context(&v->ac);
    avformat_close_input(&v->fc);
    pq_destroy(&v->vpq);
    pq_destroy(&v->apq);
    fq_destroy(&v->rawq);
    pthread_mutex_destroy(&v->lock);
    pthread_cond_destroy(&v->cond);
    pthread_mutex_destroy(&v->setup_lock);
    pthread_cond_destroy(&v->setup_cond);
    pthread_mutex_destroy(&v->clock_lock);
#ifdef _WIN32
    timeEndPeriod(1);
#endif
    free(v);
#ifdef __GLIBC__
    malloc_trim(0);            /* give the decoder threads' freed buffers back to the system */
#endif
}

#endif /* HAVE_VIEWER */
