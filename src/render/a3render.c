/******************************************************************************
 * render.c
 * 
 * RENDER = RabbitEars NextGen Data Evaluator and Reporter
 *
 * An ATSC 3.0 LLS and ROUTE/DASH Signaling parser.
 *
 * This tool reads an ATSC 3.0 PCAP file, finds UDP packets containing LLS
 * and ROUTE data, decompresses gzipped XML payloads, and parses the XML to
 * generate a human-readable HTML report.
 *
 * Author: Mark J. Colombo, along with Google Gemini and Anthropic Claude
 *
 *****************************************************************************/
#define _GNU_SOURCE // For memmem

#define RENDER_VERSION "0.4 (HDHR EAS Test v0.5)"

#include <stdio.h>
#include "debug_log.h"
#include "progress.h"
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <zlib.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <ctype.h>
#include <stdarg.h>
#include <math.h>
#include <sys/stat.h>
#include <time.h>
#include <stdbool.h>

#include "structures.h"
#include "eas.h"
#include "input.h"
#include "plp.h"
#include "l1_detail_parser.h"
#include "crypto.h"
#include "esg.h"
#include "bps.h"
#include "utility.h"
#include "mmt.h"
#include "egps.h"

// Forward declaration for STLTP L1 parsing
// We'll write the base64 to a temp file and use the existing parser
#include <unistd.h>  // for unlink

// LMT specific constants
#define LMT_TABLE_ID 0x01

// Enhanced LMT structures to store multicast destination info
typedef struct LmtMulticast {
    uint32_t src_ip;
    uint32_t dest_ip;
    uint16_t src_port;
    uint16_t dest_port;
    uint8_t sid_bit;
    uint8_t compression_bit;
    char dest_ip_str[16];
    char dest_port_str[8];
    struct LmtMulticast* next;
} LmtMulticast;

typedef struct LmtService {
    uint8_t service_id;
    uint8_t service_category;
    uint16_t plp_id;
    char service_name[64];
    LmtMulticast* multicasts;
    int duplicate_count;
    struct LmtService* next;
} LmtService;

typedef struct {
    uint8_t lmt_version;
    uint8_t num_services;
    LmtService* services;
    int duplicate_count;
    int total_entry_count; 
} LmtData;

// For SLT: Holds the list of all services
typedef struct {
    char bsid[16];
    ServiceInfo* head;
} SltData;

typedef struct {
    char currentUtcOffset[16];
    char ptpPrepend[16];
    char leap59[16];
    char leap61[16];
    char utcLocalOffset[16];
    char dsStatus[16];
    char dsDayOfMonth[16];
    char dsHour[16];
} SystemTimeData;

// For UCT: A single package element
typedef struct NdElement {
    char name[128];
    char tsi[16];
    struct NdElement* next;
} NdElement;

// For UCT: A single package
typedef struct NdPackage {
    char name[128];
    char dstIP[40];
    char dstPort[16];
    NdElement* head_element;
    struct NdPackage* next;
} NdPackage;

// For UCT: Holds the list of all packages
typedef struct {
    NdPackage* head_package;
} UctData;

// For UDST: a single reservation entry
typedef struct RsrvInfo {
    char name[64];
    char srvid[16];
    char sessionId[32];      // For <session> elements
    char destIP[40];
    char destPort[16];
    char orderId[128];
    char fileName[128];      // From <dsrv> child
    char endsAt[64];         // From <dsrv> child
    int is_session;          // 1 if from <session>, 0 if from <rsrv>
    struct RsrvInfo* next;
} RsrvInfo;

// For UDST: a single BroadSpan service
typedef struct BroadSpanServiceInfo {
    char name[128];
    RsrvInfo* head_rsrv;
    struct BroadSpanServiceInfo* next;
} BroadSpanServiceInfo;

// For UDST: Top-level container
typedef struct {
    char version[16];
    BroadSpanServiceInfo* head_service;
    UdsData* head_uds;  // For simple UDS entries (uses same struct as standalone UDS)
} UdstData;

// For SMT Signature blocks - now defined in structures.h

// For FDT: A single file entry
typedef struct FDTFileInfo {
    char contentLocation[256];
    char toi[16];
    char contentLength[16];
    char contentType[64];
    struct FDTFileInfo* next;
} FDTFileInfo;

// For FDT: Top-level container
typedef struct {
    char expires[32];
    FDTFileInfo* head;
} FDTInstanceData;

// For MPD: A single S element from a SegmentTimeline
typedef struct SegmentTimelineS {
    char t[32];
    char d[32];
    char r[16];
    struct SegmentTimelineS* next;
} SegmentTimelineS;

// For MPD: Segment template information
typedef struct {
    char initialization[256];
    char media[256];
    char timescale[32];
    char startNumber[16];
    char duration[32];
    SegmentTimelineS* timeline;
} SegmentTemplateData;

// For MPD: A single media representation (e.g., one quality level of video)
typedef struct MpdRepresentation {
    char id[64];
    char codecs[128];
    char bandwidth[32];
    char width[16];
    char height[16];
    char frameRate[16];
    char audioSamplingRate[16];
    char sar[16];
    char scanType[32];
    char audioChannelCount[16];
    char displayAspectRatio[16];
    DrmInfo* drmInfo;  
    SegmentTemplateData segmentTemplate;
    struct MpdRepresentation* next;
} MpdRepresentation;

// For MPD: A set of adaptable media representations (e.g., all video tracks)
typedef struct MpdAdaptationSet {
    char contentType[64];
    char lang[16];
    char mimeType[64];
    char par[16]; // pixel aspect ratio
    MpdRepresentation* head_rep;
    struct MpdAdaptationSet* next;
} MpdAdaptationSet;

// For MPD: Top-level container
typedef struct {
    char publishTime[64];
    char profiles[256];
    char type[32];
    char minBufferTime[32];
    MpdAdaptationSet* head_as;
} MpdData;

typedef struct {
    char bbandEntryPageUrl[512];
    char clearBbandEntryPageUrl[512];
    char coupledServices[128];
} HeldData;

// For BundleDescriptionROUTE (User Service Description)
typedef struct UsdEntry {
    char contentType[128];
    char version[16];
    char userAgent[128];
    char filterCodes[128];
    struct UsdEntry* next;
} UsdEntry;

typedef struct {
    UsdEntry* head;
} UserServiceDescriptionData;

// For metadataEnvelope (Service Signaling)
typedef struct ServiceSignalingFragment {
    char contentType[128];
    char version[16];
    struct ServiceSignalingFragment* next;
} ServiceSignalingFragment;

typedef struct {
    ServiceSignalingFragment* head;
} ServiceSignalingData;

// For S-TSID: a single content rating
typedef struct ContentRatingInfo {
    char value[256];
    struct ContentRatingInfo* next;
} ContentRatingInfo;

// For S-TSID: a file entry from embedded EFDT
typedef struct StsidFileEntry {
    uint32_t toi;
    char content_location[256];
    uint64_t content_length;
    char content_type[64];
    struct StsidFileEntry* next;
} StsidFileEntry;

// For S-TSID: a single logical stream
typedef struct StsidLogicalStream {
    char tsi[16];
    char repId[64];
    char contentType[64];
    ContentRatingInfo* head_rating;
    StsidFileEntry* head_file;      // File manifest from embedded EFDT
    int file_count;
    struct StsidLogicalStream* next;
} StsidLogicalStream;

typedef struct {
    char dIpAddr[40];
    char dPort[16];
    StsidLogicalStream* head_ls;
} StsidData;

typedef struct DwdData {
    char placeholder[32]; // Not fully parsed, just acknowledged
} DwdData;

// Struct to buffer ROUTE object fragments
typedef struct ReassemblyBuffer {
    uint32_t toi; // For ROUTE, this is TOI; for MMT, this is TOI from ALC
    uint32_t tsi; 
    int mmt_header_len;
    uint8_t* buffer;
    size_t size;
    char destinationIp[40];
    char destinationPort[16];
    struct ReassemblyBuffer* next;
} ReassemblyBuffer;

// Storage for images discovered in ROUTE objects (e.g., broadcaster logos)
// Keyed by destination IP:port + TSI, stored separately from DataUsageEntry
// to avoid modifying the struct definition in the header.
#define MAX_ROUTE_IMAGES 32
#define MAX_ROUTE_IMAGE_SIZE (64 * 1024)  // 64KB max per image
typedef struct {
    char destinationIp[40];
    char destinationPort[16];
    uint32_t tsi;
    uint8_t* data;       // malloc'd BMP/image data
    size_t data_len;
    int width;
    int height;
    int bpp;
    char format[8];      // "BMP", "PNG", "JPEG", etc.
} RouteImageEntry;

static RouteImageEntry g_route_images[MAX_ROUTE_IMAGES];
static int g_route_image_count = 0;

// Store a completed ROUTE image object
static void store_route_image(const char* destIp, const char* destPort, uint32_t tsi,
                              const uint8_t* data, size_t len,
                              int width, int height, int bpp, const char* format) {
    if (g_route_image_count >= MAX_ROUTE_IMAGES) return;
    if (len > MAX_ROUTE_IMAGE_SIZE) return;
    
    // Check for duplicate
    for (int i = 0; i < g_route_image_count; i++) {
        if (g_route_images[i].tsi == tsi &&
            strcmp(g_route_images[i].destinationIp, destIp) == 0 &&
            strcmp(g_route_images[i].destinationPort, destPort) == 0) {
            return;  // Already stored
        }
    }
    
    RouteImageEntry* entry = &g_route_images[g_route_image_count];
    strncpy(entry->destinationIp, destIp, sizeof(entry->destinationIp) - 1);
    strncpy(entry->destinationPort, destPort, sizeof(entry->destinationPort) - 1);
    entry->tsi = tsi;
    entry->data = malloc(len);
    if (!entry->data) return;
    memcpy(entry->data, data, len);
    entry->data_len = len;
    entry->width = width;
    entry->height = height;
    entry->bpp = bpp;
    strncpy(entry->format, format, sizeof(entry->format) - 1);
    g_route_image_count++;
    
    DBG_PRINTF("Stored ROUTE image: %s:%s TSI=%u, %dx%d %dbpp %s (%zu bytes)\n",
           destIp, destPort, tsi, width, height, bpp, format, len);
}

// Look up a stored image for a given stream
static RouteImageEntry* find_route_image(const char* destIp, const char* destPort, uint32_t tsi) {
    for (int i = 0; i < g_route_image_count; i++) {
        if (g_route_images[i].tsi == tsi &&
            strcmp(g_route_images[i].destinationIp, destIp) == 0 &&
            strcmp(g_route_images[i].destinationPort, destPort) == 0) {
            return &g_route_images[i];
        }
    }
    return NULL;
}

// --- Progress for pcap_loop() input (PCAP / ALP-PCAP files) ---
static progress_t g_loop_progress;
static FILE* g_loop_progress_file = NULL;
static uint32_t g_loop_progress_count = 0;

static void packet_handler_with_progress(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    void packet_handler(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet);
    packet_handler(user, pkthdr, packet);
    if ((++g_loop_progress_count & 255) == 0 && g_loop_progress_file) {
        progress_update(&g_loop_progress, (uint64_t)ftello(g_loop_progress_file));
    }
}

// --- Console debug output ---
// "Y" prints every diagnostic message (DEBUG lines, per-packet parse details,
// hex dumps, "Found ..." notices); "N" prints only progress, warnings and errors.
// The -d command-line option turns it on for a single run without rebuilding.
#define RENDER_DEBUG "N"
int g_render_debug = 0;   // see debug_log.h

// --- Global Variables ---
int g_packet_count = 0;
static int g_link_type;
LlsTable g_lls_tables[MAX_TABLES];
int g_lls_table_count = 0;
static ServiceDestination g_service_dests[MAX_SERVICES];
static int g_service_dest_count = 0;
static ReassemblyBuffer* g_reassembly_head = NULL;
static char g_input_filename[512] = "";
static int g_input_type = INPUT_TYPE_PCAP;
static int g_original_input_type = INPUT_TYPE_PCAP;
static struct timeval g_first_packet_time = {0, 0};
static struct timeval g_last_packet_time = {0, 0};
static int g_pcap_timing_valid = 0;
static DataUsageEntry g_data_usage[MAX_DATA_STREAMS];
static int g_data_usage_count = 0;
static uint64_t g_total_capture_bytes = 0;
static BpsData* g_bps_data = NULL;
static stltp_extract_t* g_stltp_stats = NULL;  // STLTP processing statistics (when input is STLTP)

// ---------------------------------------------------------------------------
// Instantaneous bitrate: bytes are counted per fixed time window (default 1 s,
// override with A3_RATE_WINDOW=<seconds>), per stream and for the whole capture.
// The report shows the min/max over the complete windows and a sparkline.
// ---------------------------------------------------------------------------
static double g_rate_window_s = 0.0;               // set on first use

// -t: capture length for inputs without timestamps (debug files, STLTP without
// timestamps). 0 = not given: those inputs then show no bitrates at all.
static double g_user_duration_s = 0.0;
static int g_timing_estimated = 0;   // packet times derived from -t by byte position
static uint32_t* g_total_rate_bins = NULL;
static uint32_t g_total_rate_bin_count = 0, g_total_rate_bin_cap = 0;

static double rate_window_s(void) {
    if (g_rate_window_s <= 0.0) {
        g_rate_window_s = 1.0;
        const char* env = getenv("A3_RATE_WINDOW");
        if (env && env[0]) {
            double w = atof(env);
            if (w >= 0.05 && w <= 600.0) g_rate_window_s = w;
        }
    }
    return g_rate_window_s;
}

/* Window index of a packet timestamp; 0 if capture timing isn't valid. */
static int rate_bin_index(const struct timeval* ts, uint32_t* idx) {
    if (!g_pcap_timing_valid || !ts) return 0;
    double t = (double)(ts->tv_sec - g_first_packet_time.tv_sec) +
               (double)(ts->tv_usec - g_first_packet_time.tv_usec) / 1000000.0;
    if (t < 0) t = 0;                              // slightly out-of-order packets
    double w = t / rate_window_s();
    if (w >= 50000000.0) return 0;                 // absurd span; don't allocate for it
    *idx = (uint32_t)w;
    return 1;
}

static void rate_bins_add(uint32_t** bins, uint32_t* count, uint32_t* cap, uint32_t idx, uint32_t bytes) {
    if (idx >= *cap) {
        uint32_t nc = *cap ? *cap : 64;
        while (nc <= idx) nc *= 2;
        uint32_t* nb = realloc(*bins, nc * sizeof(uint32_t));
        if (!nb) return;
        memset(nb + *cap, 0, (nc - *cap) * sizeof(uint32_t));
        *bins = nb;
        *cap = nc;
    }
    if (idx >= *count) *count = idx + 1;
    (*bins)[idx] += bytes;
}

/* Fold src's per-window bytes into dst and release src's (used when entries merge). */
static void merge_rate_bins(DataUsageEntry* dst, DataUsageEntry* src) {
    for (uint32_t i = 0; i < src->rate_bin_count; i++) {
        if (src->rate_bins[i]) {
            rate_bins_add(&dst->rate_bins, &dst->rate_bin_count, &dst->rate_bin_cap, i, src->rate_bins[i]);
        }
    }
    free(src->rate_bins);
    src->rate_bins = NULL;
    src->rate_bin_count = src->rate_bin_cap = 0;
}

/* Number of complete windows in the capture. The partial last window is
 * excluded so it can't show up as a false minimum. */
static uint32_t rate_full_windows(void) {
    if (!g_pcap_timing_valid || g_packet_count < 2) return 0;
    double d = (double)(g_last_packet_time.tv_sec - g_first_packet_time.tv_sec) +
               (double)(g_last_packet_time.tv_usec - g_first_packet_time.tv_usec) / 1000000.0;
    if (d <= 0) return 0;
    double n = d / rate_window_s();
    return n >= 50000000.0 ? 0 : (uint32_t)n;
}

typedef struct {
    int valid;
    double min_bps, max_bps, p5_bps, p50_bps, p95_bps;
} RateRange;

static int cmp_double(const void* a, const void* b) {
    double x = *(const double*)a, y = *(const double*)b;
    return (x > y) - (x < y);
}

/* Min/max and percentiles of the per-window bitrate. Windows with no packets
 * count as 0 bps. Needs at least 2 complete windows. */
static RateRange rate_range(const uint32_t* bins, uint32_t count, uint32_t full_windows) {
    RateRange r = {0};
    if (full_windows < 2) return r;
    double* v = malloc(full_windows * sizeof(double));
    if (!v) return r;
    double w = rate_window_s();
    for (uint32_t i = 0; i < full_windows; i++) {
        v[i] = (i < count && bins ? bins[i] : 0) * 8.0 / w;
    }
    qsort(v, full_windows, sizeof(double), cmp_double);
    r.valid = 1;
    r.min_bps = v[0];
    r.max_bps = v[full_windows - 1];
    r.p5_bps = v[(uint32_t)((full_windows - 1) * 0.05 + 0.5)];
    r.p50_bps = v[(uint32_t)((full_windows - 1) * 0.50 + 0.5)];
    r.p95_bps = v[(uint32_t)((full_windows - 1) * 0.95 + 0.5)];
    free(v);
    return r;
}

static void format_bps(double bps, char* out, size_t n) {
    if (bps >= 1000000) snprintf(out, n, "%.2f Mbps", bps / 1000000.0);
    else if (bps >= 1000) snprintf(out, n, "%.1f Kbps", bps / 1000.0);
    else snprintf(out, n, "%.0f bps", bps);
}

static const char* rate_window_label(void) {
    static char label[32];
    snprintf(label, sizeof(label), "%s%gs", g_timing_estimated ? "est. " : "", rate_window_s());
    return label;
}

/* Parse "SS[.f]", "M:SS[.f]" or "H:MM:SS[.f]" into seconds. Returns 0 on success. */
static int parse_duration_arg(const char* s, double* out) {
    double parts[3];
    int n = 0;
    const char* p = s;
    if (!s || !*s) return -1;
    for (;;) {
        char* end;
        if (n == 3 || !(isdigit((unsigned char)*p) || *p == '.')) return -1;
        parts[n++] = strtod(p, &end);
        if (end == p) return -1;
        if (*end == '\0') break;
        if (*end != ':') return -1;
        p = end + 1;
    }
    for (int i = 0; i < n - 1; i++) {             // only the last field may have a fraction
        if (parts[i] != (double)(long)parts[i]) return -1;
    }
    for (int i = 1; i < n; i++) {                  // 1:75 is a typo, not 2:15
        if (parts[i] >= 60.0) return -1;
    }
    double secs = 0;
    for (int i = 0; i < n; i++) secs = secs * 60.0 + parts[i];
    if (secs <= 0 || secs > 7 * 24 * 3600.0) return -1;
    *out = secs;
    return 0;
}

/* Replace the placeholder timestamps of a virtual pcap (debug / untimestamped
 * STLTP input) with times spread over `duration_s` by byte position: the first
 * packet at 0 s, the last at duration_s. Exact for averages; for ranges it
 * assumes data arrived at an even rate. */
static int apply_estimated_timestamps(uint8_t* pcap, size_t size, double duration_s) {
    uint64_t total = 0, last_len = 0;
    uint32_t count = 0;
    size_t pos = 24;
    while (pos + 16 <= size) {
        uint32_t incl;
        memcpy(&incl, pcap + pos + 8, 4);
        if (pos + 16 + incl > size) break;
        total += incl;
        last_len = incl;
        count++;
        pos += 16 + incl;
    }
    if (count < 2 || total <= last_len) return -1;

    uint64_t before = 0;
    pos = 24;
    while (pos + 16 <= size) {
        uint32_t incl;
        memcpy(&incl, pcap + pos + 8, 4);
        if (pos + 16 + incl > size) break;
        double t = (double)before / (double)(total - last_len) * duration_s;
        uint32_t sec = (uint32_t)t;
        uint32_t usec = (uint32_t)((t - sec) * 1000000.0 + 0.5);
        if (usec >= 1000000) { sec++; usec -= 1000000; }
        memcpy(pcap + pos, &sec, 4);
        memcpy(pcap + pos + 4, &usec, 4);
        before += incl;
        pos += 16 + incl;
    }
    return 0;
}

/* "1s range 2.10 Mbps – 7.80 Mbps" */
static void format_rate_range(const RateRange* r, char* out, size_t n) {
    char lo[32], hi[32];
    format_bps(r->min_bps, lo, sizeof(lo));
    format_bps(r->max_bps, hi, sizeof(hi));
    snprintf(out, n, "%s range %s &ndash; %s", rate_window_label(), lo, hi);
}

/* Inline SVG of the per-window rate across the capture. With more windows than
 * pixels, each column shows the min-max of its windows (light) and their mean. */
static void write_rate_sparkline(FILE* f, const uint32_t* bins, uint32_t count,
                                 uint32_t full_windows, const char* color, const RateRange* r) {
    const int W = 120, H = 18;
    if (full_windows < 2 || !r->valid || r->max_bps <= 0) return;
    uint32_t cols = full_windows < (uint32_t)W ? full_windows : (uint32_t)W;
    double peak = r->max_bps * rate_window_s() / 8.0;      // bytes per window at the peak
    double w = rate_window_s();
    char p5[32], p50[32], p95[32];
    format_bps(r->p5_bps, p5, sizeof(p5));
    format_bps(r->p50_bps, p50, sizeof(p50));
    format_bps(r->p95_bps, p95, sizeof(p95));

    fprintf(f, "<svg width='%d' height='%d' viewBox='0 0 %d %d' style='vertical-align:middle;display:block;margin-top:2px;'>", W, H, W, H);
    fprintf(f, "<title>Bitrate per %g s window across the capture (%u windows). 5th percentile %s, median %s, 95th percentile %s</title>",
            w, full_windows, p5, p50, p95);
    fprintf(f, "<rect x='0' y='0' width='%d' height='%d' fill='#f4f4f4'/>", W, H);

    char band[8192] = "";
    size_t bl = 0;
    fprintf(f, "<polyline fill='none' stroke='%s' stroke-width='1' points='", color);
    for (uint32_t c = 0; c < cols; c++) {
        uint32_t a = (uint32_t)((uint64_t)c * full_windows / cols);
        uint32_t b = (uint32_t)((uint64_t)(c + 1) * full_windows / cols);
        if (b <= a) b = a + 1;
        double lo = 1e300, hi = 0, sum = 0;
        for (uint32_t i = a; i < b; i++) {
            double v = (i < count && bins) ? bins[i] : 0;
            if (v < lo) lo = v;
            if (v > hi) hi = v;
            sum += v;
        }
        double mean = sum / (b - a);
        double x = (cols == 1) ? W / 2.0 : c * (W - 1.0) / (cols - 1);
        fprintf(f, "%.1f,%.1f ", x, (H - 1) - mean / peak * (H - 2));
        if (hi > lo && bl < sizeof(band) - 64) {
            bl += snprintf(band + bl, sizeof(band) - bl, "M%.1f %.1fV%.1f",
                           x, (H - 1) - lo / peak * (H - 2), (H - 1) - hi / peak * (H - 2));
        }
    }
    fprintf(f, "'/>");
    if (bl) fprintf(f, "<path d='%s' stroke='%s' stroke-opacity='0.35' stroke-width='1'/>", band, color);
    fprintf(f, "</svg>");
}

#ifdef STLTP_HAS_ROBUST_READER
// Human-readable capture link type for the STLTP statistics table
static const char* stltp_link_type_name(uint32_t lt) {
    switch (lt) {
        case 0:   return "BSD loopback";
        case 1:   return "Ethernet";
        case 101: return "Raw IP";
        case 108: return "OpenBSD loopback";
        case 113: return "Linux cooked v1 (tcpdump -i any)";
        case 228: return "Raw IPv4";
        case 276: return "Linux cooked v2 (tcpdump -i any)";
        default:  return "Other";
    }
}
#endif

// --- Function Prototypes ---
void packet_handler(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet);
void process_lls_payload(const u_char *payload, int len);
void process_route_payload(const u_char* payload, int len, const char* destIp, const char* destPort);
uint32_t get_lct_tsi(const u_char* payload, int len);
uint32_t get_lct_toi(const u_char* payload, int len);
uint16_t get_route_header_length(const u_char* payload, int len);
uint16_t get_route_payload_offset(const u_char* payload, int len);
void process_mime_object(uint32_t toi, const uint8_t* buffer, size_t size, const char* boundary_str, const char* destIp, const char* destPort);
void process_terminal_payload(uint32_t toi, const uint8_t* buffer, size_t size, const char* destIp, const char* destPort, int is_mmt, uint16_t packet_id);
void process_and_store_route_object(uint32_t toi, const uint8_t* buffer, size_t size, const char* destIp, const char* destPort);
void store_slt_destinations(SltData* slt_data);
char* decompress_gzip(const u_char *compressed_data, int len, int *decompressed_size, int* consumed_size);
void store_unique_table(const char* content, int len, TableType type, void* parsed_data, const char* destIp, const char* destPort, int is_in_smt, int smt_sig_index);
void generate_html_report(const char* filename);
int is_gzip_complete(const uint8_t* buffer, size_t size);
int is_xml_complete(const char* buffer, size_t size);
void cleanup();

void print_packet_id_log();

void process_multi_document_xml(const char* xml_data, size_t size, const char* destIp, const char* destPort, const char* source_id);
void remove_functionally_duplicate_tables();
int is_truncated_duplicate(const char* content1, const char* content2);
const char* get_enhanced_stream_description(const char* dest_ip, const char* dest_port, 
                                          uint32_t tsi_or_packet_id, const char* stream_type, int is_lls);
int compare_data_usage_by_bytes(const void *a, const void *b);
const char* get_media_type_from_stsid(const char* dest_ip, const char* dest_port, uint32_t tsi);
const char* get_media_type_from_mpt(const char* dest_ip, const char* dest_port, uint32_t packet_id);
const char* get_extended_stream_description(const char* dest_ip, const char* dest_port, uint32_t id, const char* stream_type);
const char* get_service_name_for_destination(const char* dest_ip, const char* dest_port);
int is_likely_route_packet(const uint8_t* payload, int len);
int is_likely_rtp_packet(const uint8_t* payload, int len);
const char* infer_content_type_from_context(const char* dest_ip, const char* dest_port, uint32_t id, const char* stream_type);
void reclassify_data_usage_after_slt();
void consolidate_data_usage_entries();
int has_lmt_data(void);
static int is_junk_entry(DataUsageEntry* entry);
int get_plps_for_service_enhanced(const char* dest_ip, const char* dest_port, char* plp_list, size_t plp_list_size);

// XML parsing functions
int parse_xml(const char* xml_content, int len, TableType* type, void** parsed_data_out, const char* source_identifier);
SltData* parse_slt(xmlDocPtr doc);
SystemTimeData* parse_system_time(xmlDocPtr doc);
RrtData* parse_rrt(xmlDocPtr doc);
UctData* parse_uct(xmlDocPtr doc);
UdstData* parse_udst(xmlDocPtr doc);
FDTInstanceData* parse_fdt(xmlDocPtr doc);
FDTInstanceData* parse_fdt_from_node(xmlNodePtr fdt_node);
void parse_embedded_children(xmlNodePtr parent_node, const char* destIp, const char* destPort);
StsidData* parse_stsid(xmlDocPtr doc);
MpdData* parse_mpd(xmlDocPtr doc);
HeldData* parse_held(xmlDocPtr doc);
UserServiceDescriptionData* parse_user_service_description(xmlDocPtr doc);
char* extract_node_as_xml(xmlNodePtr node);
UsdbData* parse_usbd(xmlDocPtr doc);
UsdData* parse_usd(xmlDocPtr doc);
DwdData* parse_dwd(xmlDocPtr doc);
UdsData* parse_uds(xmlDocPtr doc);
UdsData* parse_uds_from_node(xmlNodePtr node);
AeatData* parse_aeat(xmlDocPtr doc);
ServiceSignalingData* parse_service_signaling(xmlDocPtr doc);
MpTableData* parse_mp_table(xmlDocPtr doc);
int is_esg_service(const char* destIp, const char* destPort);
int is_bps_service(const char* destIp, const char* destPort);
int is_egps_service(const char* destIp, const char* destPort);
int normalize_xml_content(const char* xml_content, char* normalized_buffer, size_t buffer_size);
char* normalize_xml_declaration(const char* xml_content);
int is_functionally_equivalent(const char* content1, const char* content2);

/**
 * @brief Decodes AC-3/Dolby Digital Plus channel configuration from hex bitfield.
 * 
 * The value is a 4-digit hex representation of a 16-bit bitfield where each bit
 * represents channel presence. Bit 0 (MSB) is L, pairs count as 2 channels.
 * Per Dolby spec: tag:dolby.com,2014:dash:audio_channel_configuration:2011
 * 
 * @param hex_value The hex string (4 characters like "a000")
 * @param channel_count Output buffer for the channel count string
 * @param buffer_size Size of the output buffer
 * @return 1 if successfully decoded, 0 otherwise
 */
static int decode_ac3_channel_config(const char* hex_value, char* channel_count, size_t buffer_size) {
    if (!hex_value || strlen(hex_value) != 4) return 0;
    
    unsigned int bitfield = 0;
    if (sscanf(hex_value, "%04x", &bitfield) != 1) return 0;
    
    // Count channels - bits are numbered from MSB (bit 0 = L)
    // Bit 0: L, Bit 1: C, Bit 2: R, Bit 3: Ls, Bit 4: Rs (single channels)
    // Bit 5: Lc/Rc pair, Bit 6: Lrs/Rrs pair (2 channels each)
    // Bit 7: Cs, Bit 8: Ts (single channels)
    // Bit 9: Lsd/Rsd pair, Bit 10: Lw/Rw pair, Bit 11: Lvh/Rvh pair (2 channels each)
    // Bit 12: Cvh (single)
    // Bit 13: Lts/Rts pair (2 channels)
    // Bit 14: LFE2, Bit 15: LFE (single channels)
    
    int channels = 0;
    
    // Single channel bits: 0, 1, 2, 3, 4, 7, 8, 12, 14, 15
    if (bitfield & 0x8000) channels++;  // Bit 0: L
    if (bitfield & 0x4000) channels++;  // Bit 1: C
    if (bitfield & 0x2000) channels++;  // Bit 2: R
    if (bitfield & 0x1000) channels++;  // Bit 3: Ls
    if (bitfield & 0x0800) channels++;  // Bit 4: Rs
    if (bitfield & 0x0400) channels += 2;  // Bit 5: Lc/Rc pair
    if (bitfield & 0x0200) channels += 2;  // Bit 6: Lrs/Rrs pair
    if (bitfield & 0x0100) channels++;  // Bit 7: Cs
    if (bitfield & 0x0080) channels++;  // Bit 8: Ts
    if (bitfield & 0x0040) channels += 2;  // Bit 9: Lsd/Rsd pair
    if (bitfield & 0x0020) channels += 2;  // Bit 10: Lw/Rw pair
    if (bitfield & 0x0010) channels += 2;  // Bit 11: Lvh/Rvh pair
    if (bitfield & 0x0008) channels++;  // Bit 12: Cvh
    if (bitfield & 0x0004) channels += 2;  // Bit 13: Lts/Rts pair
    if (bitfield & 0x0002) channels++;  // Bit 14: LFE2
    if (bitfield & 0x0001) channels++;  // Bit 15: LFE
    
    snprintf(channel_count, buffer_size, "%d", channels);
    return 1;
}

/**
 * @brief Decodes AC-4 channel configuration from hex value.
 * 
 * The value is a 6-digit hex representation per Dolby AC-4 spec.
 * Per Dolby spec: urn:dolby:dash:audio_channel_configuration:2015
 * 
 * @param hex_value The hex string (6 characters)
 * @param channel_count Output buffer for the channel count string
 * @param buffer_size Size of the output buffer
 * @return 1 if successfully decoded, 0 otherwise
 */
static int decode_ac4_channel_config(const char* hex_value, char* channel_count, size_t buffer_size) {
    if (!hex_value || strlen(hex_value) != 6) return 0;
    
    unsigned int value = 0;
    if (sscanf(hex_value, "%06x", &value) != 1) return 0;
    
    // Map known AC-4 hex values to channel counts
    switch (value) {
        case 0x000002: snprintf(channel_count, buffer_size, "1"); break;   // 1.0 (C)
        case 0x000001: snprintf(channel_count, buffer_size, "2"); break;   // 2.0 (L, R)
        case 0x000047: snprintf(channel_count, buffer_size, "6"); break;   // 5.1
        case 0x0000C7: snprintf(channel_count, buffer_size, "8"); break;   // 5.1.2
        case 0x000077: snprintf(channel_count, buffer_size, "10"); break;  // 5.1.4
        case 0x0000CF: snprintf(channel_count, buffer_size, "10"); break;  // 7.1.2
        case 0x00007F: snprintf(channel_count, buffer_size, "12"); break;  // 7.1.4
        default:
            // Unknown value - store as-is
            snprintf(channel_count, buffer_size, "%s", hex_value);
            return 1;
    }
    return 1;
}

/**
 * @brief Parses AudioChannelConfiguration element and extracts channel count.
 * 
 * Handles multiple schemeIdUri formats:
 * - tag:dolby.com,2014:dash:audio_channel_configuration:2011 (AC-3/DD+, 4-digit hex bitfield)
 * - urn:dolby:dash:audio_channel_configuration:2015 (AC-4, 6-digit hex)
 * - urn:mpeg:dash:23003:3:audio_channel_configuration:2011 (MPEG, decimal)
 * - urn:mpeg:mpegB:cicp:ChannelConfiguration (MPEG CICP, decimal)
 * 
 * @param audio_config_node The AudioChannelConfiguration XML node
 * @param channel_count Output buffer for the channel count string
 * @param buffer_size Size of the output buffer
 * @return 1 if successfully parsed, 0 otherwise
 */
static int parse_audio_channel_config(xmlNodePtr audio_config_node, char* channel_count, size_t buffer_size) {
    if (!audio_config_node) return 0;
    
    xmlChar* scheme_uri = xmlGetProp(audio_config_node, (const xmlChar*)"schemeIdUri");
    xmlChar* value = xmlGetProp(audio_config_node, (const xmlChar*)"value");
    
    if (!value) {
        if (scheme_uri) xmlFree(scheme_uri);
        return 0;
    }
    
    int result = 0;
    
    if (scheme_uri) {
        if (strstr((char*)scheme_uri, "tag:dolby.com,2014:dash:audio_channel_configuration:2011") != NULL) {
            // AC-3/Dolby Digital Plus - 4-digit hex bitfield
            result = decode_ac3_channel_config((char*)value, channel_count, buffer_size);
        } else if (strstr((char*)scheme_uri, "urn:dolby:dash:audio_channel_configuration:2015") != NULL) {
            // AC-4 - 6-digit hex value
            result = decode_ac4_channel_config((char*)value, channel_count, buffer_size);
        } else if (strstr((char*)scheme_uri, "urn:mpeg:dash:23003:3:audio_channel_configuration:2011") != NULL ||
                   strstr((char*)scheme_uri, "urn:mpeg:mpegB:cicp:ChannelConfiguration") != NULL) {
            // MPEG standard - decimal value
            strncpy(channel_count, (char*)value, buffer_size - 1);
            channel_count[buffer_size - 1] = '\0';
            result = 1;
        } else {
            // Unknown scheme - try to interpret value intelligently
            size_t len = strlen((char*)value);
            if (len == 4 && strspn((char*)value, "0123456789abcdefABCDEF") == 4) {
                // Looks like AC-3 4-digit hex
                result = decode_ac3_channel_config((char*)value, channel_count, buffer_size);
            } else if (len == 6 && strspn((char*)value, "0123456789abcdefABCDEF") == 6) {
                // Looks like AC-4 6-digit hex
                result = decode_ac4_channel_config((char*)value, channel_count, buffer_size);
            } else {
                // Assume decimal
                strncpy(channel_count, (char*)value, buffer_size - 1);
                channel_count[buffer_size - 1] = '\0';
                result = 1;
            }
        }
        xmlFree(scheme_uri);
    } else {
        // No schemeIdUri - guess based on value format
        size_t len = strlen((char*)value);
        if (len == 4 && strspn((char*)value, "0123456789abcdefABCDEF") == 4) {
            result = decode_ac3_channel_config((char*)value, channel_count, buffer_size);
        } else if (len == 6 && strspn((char*)value, "0123456789abcdefABCDEF") == 6) {
            result = decode_ac4_channel_config((char*)value, channel_count, buffer_size);
        } else {
            strncpy(channel_count, (char*)value, buffer_size - 1);
            channel_count[buffer_size - 1] = '\0';
            result = 1;
        }
    }
    
    xmlFree(value);
    return result;
}

// ---------------------------------------------------------------------------
// MPD adaptation set classification. MPDs don't all mark audio the same way:
// some use contentType, some put mimeType on the AdaptationSet, some only on
// the Representation, and some give neither - so fall back to the codec.
// ---------------------------------------------------------------------------
static int codec_is_audio(const char* c) {
    static const char* fourcc[] = { "ac-3", "ec-3", "ac-4", "mp4a", "opus", "mhm1", "mhm2", "mha1",
                                    "mha2", "dtsc", "dtse", "dtsh", "dtsl", "dtsx", "alac", "flac", NULL };
    if (!c || !*c) return 0;
    for (int i = 0; fourcc[i]; i++) {
        if (strncasecmp(c, fourcc[i], 4) == 0) return 1;
    }
    return 0;
}

static int codec_is_video(const char* c) {
    static const char* fourcc[] = { "hev1", "hvc1", "avc1", "avc3", "vvc1", "vvi1", "av01", "vp09",
                                    "dvh1", "dvhe", "dva1", "dvav", NULL };
    if (!c || !*c) return 0;
    for (int i = 0; fourcc[i]; i++) {
        if (strncasecmp(c, fourcc[i], 4) == 0) return 1;
    }
    return 0;
}

static int mpd_as_is_audio(const MpdAdaptationSet* as) {
    if (!as) return 0;
    if (strcasecmp(as->contentType, "audio") == 0) return 1;
    if (strncasecmp(as->mimeType, "audio/", 6) == 0) return 1;
    if (as->contentType[0] || as->mimeType[0]) return 0;   // declared as something else
    return as->head_rep && codec_is_audio(as->head_rep->codecs);
}

static int mpd_as_is_video(const MpdAdaptationSet* as) {
    if (!as) return 0;
    if (strcasecmp(as->contentType, "video") == 0) return 1;
    if (strncasecmp(as->mimeType, "video/", 6) == 0) return 1;
    if (as->contentType[0] || as->mimeType[0]) return 0;
    return as->head_rep && codec_is_video(as->head_rep->codecs);
}

/* True if representation a is a better pick to summarize than b:
 * more channels first, then higher bandwidth. Works when channel counts are
 * missing (e.g. AC-3 MPDs without AudioChannelConfiguration). */
static int mpd_audio_rep_better(const MpdRepresentation* a, const MpdRepresentation* b) {
    if (!b) return 1;
    int ca = atoi(a->audioChannelCount), cb = atoi(b->audioChannelCount);
    if (ca != cb) return ca > cb;
    return atol(a->bandwidth) > atol(b->bandwidth);
}

// Cleanup functions for parsed data
void free_parsed_data(LlsTable* table);
void free_slt_data(SltData* data);
void free_uct_data(UctData* data);
void free_udst_data(UdstData* data);
void free_fdt_data(FDTInstanceData* data);
void free_mpd_data(MpdData* data);
void free_held_data(HeldData* data);
void free_user_service_description_data(UserServiceDescriptionData* data);
void free_usbd_data(UsdbData* data);
void free_usd_data(UsdData* data);
void free_service_signaling_data(ServiceSignalingData* data);
void free_stsid_data(StsidData* data);
void free_mp_table_data(MpTableData* data);
void free_binary_mp_table_data(BinaryMptData* data);
void free_reassembly_buffers();


/* EAS edition: hand the SLT station details and capture timing to eas.c */
static void eas_collect_and_set_context(const char* input_path) {
    char bsid[32] = "", services[1024] = "", eas_services[512] = "";
    for (int i = 0; i < g_lls_table_count; i++) {
        if (g_lls_tables[i].type != TABLE_TYPE_SLT || !g_lls_tables[i].parsed_data) continue;
        SltData* slt = (SltData*)g_lls_tables[i].parsed_data;
        if (!bsid[0] && slt->bsid[0]) snprintf(bsid, sizeof(bsid), "%s", slt->bsid);
        for (ServiceInfo* sv = slt->head; sv; sv = sv->next) {
            char item[160];
            snprintf(item, sizeof(item), "%s%s%s %s", sv->majorChannelNo,
                     sv->minorChannelNo[0] ? "." : "", sv->minorChannelNo, sv->shortServiceName);
            if (strstr(services, item)) continue;
            size_t L = strlen(services);
            snprintf(services + L, sizeof(services) - L, "%s%s", L ? ", " : "", item);
            if (strcmp(sv->serviceCategory, "5") == 0 && !strstr(eas_services, item)) {
                size_t E = strlen(eas_services);
                snprintf(eas_services + E, sizeof(eas_services) - E, "%s%s", E ? ", " : "", item);
            }
        }
    }
    eas_set_station(bsid, services, eas_services);

    eas_timing_t timing = EAS_TIMING_NONE;
    if (g_pcap_timing_valid) timing = g_timing_estimated ? EAS_TIMING_RELATIVE : EAS_TIMING_ABSOLUTE;
    eas_set_capture(input_path, timing,
                    g_pcap_timing_valid ? &g_first_packet_time : NULL,
                    g_pcap_timing_valid ? &g_last_packet_time : NULL,
                    g_user_duration_s);
}

// --- Main Function ---
int main(int argc, char *argv[]) {
    const char* input_path = NULL;

    g_render_debug = (RENDER_DEBUG[0] == 'Y' || RENDER_DEBUG[0] == 'y');

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--eas-summary") == 0) return eas_summary_main(argc, argv);
    }

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--version") == 0) {
            printf("RENDER - RabbitEars NextGen Data Evaluator and Reporter v%s\n", RENDER_VERSION);
            printf("ATSC 3.0 LLS and ROUTE/DASH Signaling parser\n");
            return 0;
        } else if (strcmp(argv[i], "-d") == 0) {
            g_render_debug = 1;
        } else if (strcmp(argv[i], "-t") == 0) {
            if (i + 1 >= argc || parse_duration_arg(argv[i + 1], &g_user_duration_s) != 0) {
                fprintf(stderr, "Error: -t needs a capture length: <seconds>, <min>:<sec> or <h>:<mm>:<ss> "
                                "(e.g. -t 30, -t 1:30, -t 0:45.5)\n");
                return 1;
            }
            i++;
        } else if (argv[i][0] == '-' && argv[i][1] != '\0') {
            fprintf(stderr, "Error: unknown option %s\n", argv[i]);
            input_path = NULL;
            argc = 0;   // fall through to usage
            break;
        } else if (!input_path) {
            input_path = argv[i];
        } else {
            fprintf(stderr, "Error: more than one input file given\n");
            input_path = NULL;
            argc = 0;
            break;
        }
    }

    if (!input_path) {
        fprintf(stderr, "Usage: %s [-d] [-t <length>] <pcap_file_or_debug_file>\n", argv[0]);
        fprintf(stderr, "       %s --eas-summary <out.html> <capture-dir | file.eas.tsv>...\n", argv[0]);
        fprintf(stderr, "       %s -v|--version\n\n", argv[0]);
        fprintf(stderr, "Options:\n");
        fprintf(stderr, "  -d           Print debug / diagnostic messages to the console.\n");
        fprintf(stderr, "  -t <length>  Capture length, for inputs without timestamps (debug files,\n");
        fprintf(stderr, "               STLTP captures without timestamps). Formats: 30, 30.5, 1:30, 1:02:03.\n");
        fprintf(stderr, "               Without it, bitrates are not shown for those inputs.\n");
        fprintf(stderr, "               Ignored for captures that have their own timestamps.\n\n");
        fprintf(stderr, "Supported file types:\n");
        fprintf(stderr, "  .pcap/.pcapng - Standard PCAP capture files\n");
        fprintf(stderr, "  .dbg - ATSC 3.0 debug files\n");
        fprintf(stderr, "  ALP-PCAP files (link type 289 / DLT_ATSC_ALP)\n");
        fprintf(stderr, "  STLTP files (auto-detected by RTP PT=97 outer tunnel)\n");
        return 1;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = NULL;
    uint8_t *virtual_pcap_data = NULL;
    size_t virtual_pcap_size = 0;
    int input_type = detect_file_type(input_path);
    g_original_input_type = input_type;
    
    if (input_type == INPUT_TYPE_DEBUG) {
        printf("Detected debug file format: %s\n", input_path);
        
        // Convert debug file to virtual PCAP
        if (create_virtual_pcap_from_debug(input_path, &virtual_pcap_data, &virtual_pcap_size) != 0) {
            fprintf(stderr, "Error processing debug file\n");
            return 1;
        }
        
        // Open virtual PCAP from memory
        handle = pcap_open_offline_with_tstamp_precision(
            (char*)virtual_pcap_data, PCAP_TSTAMP_PRECISION_MICRO, errbuf);
        if (handle == NULL) {
            // Try opening as memory buffer (if supported)
            handle = pcap_open_dead(DLT_EN10MB, 65535);
            if (handle == NULL) {
                fprintf(stderr, "Error creating virtual PCAP handle: %s\n", errbuf);
                free(virtual_pcap_data);
                return 1;
            }
        }
        
        DBG_PRINTF("Successfully converted debug file to virtual PCAP\n");
        
        
    } else if (input_type == INPUT_TYPE_STLTP) {
        printf("Detected STLTP file format: %s\n", input_path);
        
        char *l1_basic_b64 = NULL;
        char *l1_detail_b64 = NULL;
        
        // Use input.c function to extract ALP data and L1 signaling from STLTP
        if (create_virtual_alp_pcap_from_stltp(input_path, &virtual_pcap_data, &virtual_pcap_size,
                                               &l1_basic_b64, &l1_detail_b64, &g_stltp_stats) != 0) {
            fprintf(stderr, "Error processing STLTP file\n");
            return 1;
        }
        
        // Parse and store L1 signaling data if present
        // Note: l1_detail_b64 contains the COMBINED L1-Basic + L1-Detail data
        if (l1_detail_b64) {
            DBG_PRINTF("L1 signaling extracted from STLTP preamble\n");
            DBG_PRINTF("  Combined base64 (%zu chars): %.60s%s\n",
                   strlen(l1_detail_b64),
                   l1_detail_b64,
                   strlen(l1_detail_b64) > 60 ? "..." : "");
            
            // Write combined base64 to temp file and use existing L1 parser
#ifdef _WIN32
            char temp_l1_file[MAX_PATH + 32];
            {
                char tdir[MAX_PATH];
                DWORD tl = GetTempPathA(sizeof(tdir), tdir);
                if (tl == 0 || tl >= sizeof(tdir)) strcpy(tdir, ".\\");
                snprintf(temp_l1_file, sizeof(temp_l1_file), "%sstltp_l1_XXXXXX.txt", tdir);
            }
#else
            char temp_l1_file[] = "/tmp/stltp_l1_XXXXXX.txt";
#endif
            int fd = mkstemps(temp_l1_file, 4);
            if (fd >= 0) {
                FILE *l1f = fdopen(fd, "w");
                if (l1f) {
                    // Write combined L1 base64 - matches format parser expects
                    fprintf(l1f, "%s\n", l1_detail_b64);
                    fclose(l1f);
                    
                    DBG_PRINTF("  Wrote L1 base64 to temp file: %s\n", temp_l1_file);
                    
                    // Parse using existing infrastructure
                    void *l1_data = parse_enhanced_l1_signaling_file(temp_l1_file);
                    if (l1_data) {
                        set_enhanced_l1_signaling_data(l1_data);
                        DBG_PRINTF("  L1 signaling parsed successfully!\n");
                        unlink(temp_l1_file);  // Clean up temp file on success
                    } else {
                        printf("  WARNING: L1 parser returned NULL - check base64 format\n");
                        DBG_PRINTF("  Temp file preserved for inspection: %s\n", temp_l1_file);
                    }
                } else {
                    close(fd);
                    printf("  ERROR: Could not write to temp file\n");
                }
            } else {
                printf("  ERROR: Could not create temp file\n");
            }
            
            free(l1_detail_b64);
        }
        
        if (l1_basic_b64) {
            free(l1_basic_b64);
        }
        
        // Check if we got any data
        if (virtual_pcap_size <= 24) {
            fprintf(stderr, "Warning: No ALP data found in STLTP file\n");
        }
        
        // The extracted data is ALP format
        input_type = INPUT_TYPE_ALP_PCAP;
        
        // Create a dead handle for ALP processing
        handle = pcap_open_dead(DLT_ATSC_ALP, 65535);
        if (handle == NULL) {
            fprintf(stderr, "Error creating virtual PCAP handle for STLTP\n");
            free(virtual_pcap_data);
            return 1;
        }
        
    } else {
        printf("Opening %s file: %s\n", 
               (input_type == INPUT_TYPE_ALP_PCAP) ? "ALP-PCAP" : "PCAP", 
               input_path);
        handle = pcap_open_offline(input_path, errbuf);
        if (handle == NULL) {
            fprintf(stderr, "Error opening PCAP file: %s\n", errbuf);
            return 1;
        }
    }
    
    strncpy(g_input_filename, input_path, sizeof(g_input_filename) - 1);
    g_input_filename[sizeof(g_input_filename) - 1] = '\0';
    g_input_type = input_type;
    
    // Check for and parse optional L1 signaling file
    // But skip this if we already have L1 data from STLTP preamble
    if (!get_enhanced_l1_signaling_data()) {
        char* txt_filename = get_txt_filename_from_input(input_path);
        if (txt_filename) {
            set_enhanced_l1_signaling_data(parse_enhanced_l1_signaling_file(txt_filename));
            free(txt_filename);
        }
    }

    // Determine the link-layer header type
    g_link_type = pcap_datalink(handle);
    switch (g_link_type) {
        case DLT_EN10MB:
            DBG_PRINTF("Link-type: Ethernet (DLT_EN10MB)\n\n");
            break;
        case DLT_IPV4:
            DBG_PRINTF("Link-type: Raw IPv4 (DLT_IPV4)\n\n");
            break;
        /* Raw IP: HDHomeRun firmware 20261107 writes IPv4 PCAPs this way
           (LINKTYPE_RAW, 101 in the file; libpcap reports it as DLT_RAW,
           12 on Linux/Windows, 14 on OpenBSD). Same layout as raw IPv4. */
        case 12:
        case 14:
        case 101:
            DBG_PRINTF("Link-type: Raw IP (%d)\n\n", g_link_type);
            g_link_type = DLT_IPV4;
            break;
        case DLT_ATSC_ALP:
            DBG_PRINTF("Link-type: ATSC ALP (DLT_ATSC_ALP)\n\n");
            g_input_type = INPUT_TYPE_ALP_PCAP; // Override input type detection
            break;
        default:
            fprintf(stderr, "Unsupported link-type: %d. Only Ethernet, raw IP, and ATSC ALP are supported.\n", g_link_type);
            pcap_close(handle);
            if (virtual_pcap_data) free(virtual_pcap_data);
            return 1;
    }

    // Initialize the tables array
    for (int i = 0; i < MAX_TABLES; i++) {
        g_lls_tables[i].content_id = NULL;
        g_lls_tables[i].parsed_data = NULL;
        g_lls_tables[i].type = TABLE_TYPE_UNKNOWN;
        g_lls_tables[i].destinationIp[0] = '\0';
        g_lls_tables[i].destinationPort[0] = '\0';
        g_lls_tables[i].is_in_smt = 0;
        g_lls_tables[i].smt_signature_index = -1;
    }
    
    // Initialize libxml2
    LIBXML_TEST_VERSION

    // -t: only for inputs whose virtual pcap has placeholder timestamps
    {
        int lacks_timestamps = (g_original_input_type == INPUT_TYPE_DEBUG);
#ifdef STLTP_HAS_ROBUST_READER
        if (g_original_input_type == INPUT_TYPE_STLTP &&
            !(g_stltp_stats && g_stltp_stats->capture_timing_valid)) {
            lacks_timestamps = 1;
        }
#endif
        if (g_user_duration_s > 0) {
            if (lacks_timestamps && virtual_pcap_data &&
                apply_estimated_timestamps(virtual_pcap_data, virtual_pcap_size, g_user_duration_s) == 0) {
                g_timing_estimated = 1;
                printf("Capture length from -t: %.1f s (packet times estimated by byte position)\n",
                       g_user_duration_s);
            } else if (lacks_timestamps) {
                printf("Warning: -t given but there are too few packets to use it\n");
            } else {
                printf("Note: -t ignored; this capture has its own timestamps\n");
            }
        }
    }

    // For debug/STLTP files, we need to manually process the virtual PCAP data
    if (virtual_pcap_data != NULL) {
        DBG_PRINTF("Processing virtual PCAP data (%zu bytes)...\n", virtual_pcap_size);
        
        // Process the virtual PCAP data manually
        const uint8_t *data = virtual_pcap_data + 24; // Skip global header
        size_t remaining = virtual_pcap_size - 24;
        progress_t prog;
        uint32_t records = 0;
        progress_begin(&prog, g_original_input_type == INPUT_TYPE_STLTP ? "Analyzing ALP packets"
                                                                        : "Analyzing packets",
                       virtual_pcap_size);
        
        while (remaining > 16) { // Need at least record header
            if ((++records & 255) == 0) {
                progress_update(&prog, (uint64_t)(data - virtual_pcap_data));
            }
            // Read record header
            uint32_t ts_sec = *(uint32_t*)data;
            uint32_t ts_usec = *(uint32_t*)(data + 4);
            uint32_t incl_len = *(uint32_t*)(data + 8);
            uint32_t orig_len = *(uint32_t*)(data + 12);
            
            data += 16;
            remaining -= 16;
            
            if (remaining < incl_len) break;
            
            // Create a fake pcap_pkthdr for compatibility
            struct pcap_pkthdr pkthdr;
            pkthdr.ts.tv_sec = ts_sec;
            pkthdr.ts.tv_usec = ts_usec;
            pkthdr.caplen = incl_len;
            pkthdr.len = orig_len;
            
            // Process this packet
            packet_handler(NULL, &pkthdr, data);
            
            data += incl_len;
            remaining -= incl_len;
        }
        progress_end(&prog);
        
    } else {
        // Loop through packets normally for PCAP files
        struct stat in_stat;
        uint64_t in_size = (stat(input_path, &in_stat) == 0 && in_stat.st_size > 0) ? (uint64_t)in_stat.st_size : 0;
        g_loop_progress_file = pcap_file(handle);
        g_loop_progress_count = 0;
        progress_begin(&g_loop_progress, "Analyzing packets", g_loop_progress_file ? in_size : 0);
        pcap_loop(handle, 0, packet_handler_with_progress, NULL);
        progress_end(&g_loop_progress);
        g_loop_progress_file = NULL;
    }

    progress_t finish_prog;
    progress_begin(&finish_prog, "Finishing analysis", 0);

    // --- Process any remaining open (incomplete) ROUTE/MMT objects ---
    DBG_PRINTF("\n--- Processing finished. Processing any remaining open ROUTE/MMT objects. ---\n");

    ReassemblyBuffer* current_buf = g_reassembly_head;
    int buffer_count = 0;
    while(current_buf != NULL) {
        buffer_count++;
        DBG_PRINTF("\n-> Buffer %d: TSI/TOI=%u/%u on %s:%s. Total size: %zu.\n", 
            buffer_count, current_buf->tsi, current_buf->toi, current_buf->destinationIp, 
            current_buf->destinationPort, current_buf->size);
        
        // Skip buffers that are too small (likely just a header fragment)
        if (current_buf->size < 100) {
            //printf("   Skipping - buffer too small (< 100 bytes)\n");
            current_buf = current_buf->next;
            continue;
        }
        
        // Check if buffer looks complete despite missing close flag
        // If it has MIME boundaries and looks complete, skip it
        if (memmem(current_buf->buffer, current_buf->size, "multipart/related", 17) ||
                (current_buf->size > 13 && memcmp(current_buf->buffer, "MIME-Version:", 13) == 0)) {
            // Check if it has final boundary marker
            const char* boundary_marker = "boundary=\"";
            const uint8_t* boundary_loc = memmem(current_buf->buffer, 
                current_buf->size > 500 ? 500 : current_buf->size, 
                boundary_marker, strlen(boundary_marker));
            
            if (boundary_loc) {
                DBG_PRINTF("   Processing complete MIME multipart (close flag was never set)\n");
                
                // Extract boundary string for processing
                const char* boundary_start = (const char*)(boundary_loc + strlen(boundary_marker));
                const char* boundary_end = strchr(boundary_start, '"');
                if (boundary_end) {
                    size_t boundary_len = boundary_end - boundary_start;
                    char boundary_str[256];
                    snprintf(boundary_str, sizeof(boundary_str), "--%.*s", (int)boundary_len, boundary_start);
                    
                    // Process as MIME multipart - this will extract and store the MPD, S-TSID, etc.
                    process_mime_object(current_buf->toi, current_buf->buffer, current_buf->size, 
                                    boundary_str, current_buf->destinationIp, current_buf->destinationPort);
                }
                
                current_buf = current_buf->next;
                continue;
            }
        }
        
        // Skip buffers that don't look like they contain useful data
        // Check if it starts with something recognizable
        int looks_valid = 0;
        if (current_buf->size > 5) {
            if (memcmp(current_buf->buffer, "<?xml", 5) == 0 ||
                memcmp(current_buf->buffer, "<MPD", 4) == 0 ||
                memcmp(current_buf->buffer, "<S-TSID", 7) == 0 ||
                memcmp(current_buf->buffer, "Content-Type:", 13) == 0 ||
                memcmp(current_buf->buffer, "MIME-Version:", 13) == 0 ||
                (current_buf->buffer[0] == 0x1f && current_buf->buffer[1] == 0x8b)) { // gzip
                looks_valid = 1;
            }
        }
        
        if (!looks_valid) {
            DBG_PRINTF("   Skipping - doesn't look like valid content\n");
            current_buf = current_buf->next;
            continue;
        }
        
        DBG_PRINTF("   Force processing incomplete buffer...\n");
        
        int is_route = 0;
        for(int i=0; i< g_service_dest_count; i++) {
            if(strcmp(g_service_dests[i].destinationIpStr, current_buf->destinationIp) == 0 &&
            strcmp(g_service_dests[i].destinationPortStr, current_buf->destinationPort) == 0 &&
            strcmp(g_service_dests[i].protocol, "1") == 0) {
                is_route = 1;
                break;
            }
        }
        
        if (is_route) {
            process_and_store_route_object(current_buf->toi, current_buf->buffer, current_buf->size, 
                                        current_buf->destinationIp, current_buf->destinationPort);
        } else {
            process_mmt_signaling_payload(current_buf->buffer, current_buf->size, 
                                        current_buf->destinationIp, current_buf->destinationPort);
        }
        current_buf = current_buf->next;
    }

    // --- Generate Report Filename ---
    char output_filename[256];
    strncpy(output_filename, input_path, sizeof(output_filename) - 1);
    output_filename[sizeof(output_filename) - 1] = '\0'; // Ensure null termination

    char *dot = strrchr(output_filename, '.');
    if (dot != NULL) {
        strcpy(dot, ".html");
    } else {
        strncat(output_filename, ".html", sizeof(output_filename) - strlen(output_filename) - 1);
    }

    DBG_PRINTF("\nFinished processing %s file.\n", (input_type == INPUT_TYPE_DEBUG) ? "debug" : "PCAP");
    print_packet_id_log();
    print_mmt_message_stats();

    reclassify_data_usage_after_slt();
    
    // ESG processing
    for (int i = 0; i < g_service_dest_count; i++) {
        if (g_service_dests[i].isEsgService) {
            correlate_esg_fragments(g_service_dests[i].destinationIpStr, 
                                g_service_dests[i].destinationPortStr,
                                g_lls_tables, g_lls_table_count);
        }
    }

    remove_functionally_duplicate_tables();
    progress_end(&finish_prog);

    eas_collect_and_set_context(input_path);

    progress_t report_prog;
    progress_begin(&report_prog, "Writing HTML report", 0);
    generate_html_report(output_filename);
    progress_end(&report_prog);
    printf("Generated HTML report: %s\n", output_filename);
    eas_write_sidecar(input_path);
    
    // Free L1 signaling data if it exists
    if (get_l1_signaling_data()) {
        free_l1_signaling_data(get_l1_signaling_data());
        set_l1_signaling_data(NULL);
    }

    // Cleanup
    pcap_close(handle);
    if (virtual_pcap_data) free(virtual_pcap_data);
    cleanup();
    xmlCleanupParser();

    return 0;
}

void record_data_usage(const char* dest_ip, const char* dest_port, uint32_t tsi_or_packet_id, 
                      uint32_t packet_bytes, const char* description, const struct timeval* timestamp,
                      const uint8_t* payload, int payload_len) {
    g_total_capture_bytes += packet_bytes;

    uint32_t rate_idx = 0;
    int have_rate_idx = rate_bin_index(timestamp, &rate_idx);
    if (have_rate_idx) {
        rate_bins_add(&g_total_rate_bins, &g_total_rate_bin_count, &g_total_rate_bin_cap, rate_idx, packet_bytes);
    }
    
    // Find existing entry or create new one
    DataUsageEntry* entry = NULL;
    for (int i = 0; i < g_data_usage_count; i++) {
        if (strcmp(g_data_usage[i].destinationIp, dest_ip) == 0 &&
            strcmp(g_data_usage[i].destinationPort, dest_port) == 0 &&
            g_data_usage[i].tsi_or_packet_id == tsi_or_packet_id) {
            entry = &g_data_usage[i];
            break;
        }
    }
    
    if (!entry && g_data_usage_count < MAX_DATA_STREAMS) {
        entry = &g_data_usage[g_data_usage_count];
        strncpy(entry->destinationIp, dest_ip, sizeof(entry->destinationIp) - 1);
        entry->destinationIp[sizeof(entry->destinationIp) - 1] = '\0';
        strncpy(entry->destinationPort, dest_port, sizeof(entry->destinationPort) - 1);
        entry->destinationPort[sizeof(entry->destinationPort) - 1] = '\0';
        entry->tsi_or_packet_id = tsi_or_packet_id;
        entry->total_bytes = 0;
        entry->packet_count = 0;
        strncpy(entry->description, description, sizeof(entry->description) - 1);
        entry->description[sizeof(entry->description) - 1] = '\0';
        entry->is_lls = (strcmp(dest_ip, "224.0.23.60") == 0 && strcmp(dest_port, "4937") == 0);
        entry->timing_valid = 0;
        entry->sample_payload_len = 0;
        entry->sample_collected = 0;
        entry->rate_bins = NULL;          // slot may hold a stale copy after compaction
        entry->rate_bin_count = 0;
        entry->rate_bin_cap = 0;
        
        // Determine stream type and signaling flag
        if (entry->is_lls) {
            strcpy(entry->stream_type, "LLS");
            entry->is_signaling = 1;
        } else if (strstr(description, "Stuffing") || strstr(description, "Non-UDP")) {
            strcpy(entry->stream_type, "Stuffing");
            entry->is_signaling = 0;
        } else if (strstr(description, "ROUTE")) {
            strcpy(entry->stream_type, "ROUTE");
            entry->is_signaling = (tsi_or_packet_id == 0);
        } else if (strstr(description, "MMT")) {
            strcpy(entry->stream_type, "MMT");
            entry->is_signaling = (strstr(description, "Signaling") != NULL);
        } else if (strstr(description, "RTP/MPEG-TS Null")) {
            strcpy(entry->stream_type, "RTP/MPEG-TS Null");
            entry->is_signaling = 0;
        } else if (strstr(description, "RTP/MPEG-TS")) {
            strcpy(entry->stream_type, "RTP/MPEG-TS");
            entry->is_signaling = 0;
        } else if (strstr(description, "MPEG-TS Null")) {
            strcpy(entry->stream_type, "MPEG-TS Null");
            entry->is_signaling = 0;
        } else if (strstr(description, "MPEG-TS")) {
            strcpy(entry->stream_type, "MPEG-TS");
            entry->is_signaling = 0;
        } else if (strstr(description, "RTP")) {
            strcpy(entry->stream_type, "RTP");
            entry->is_signaling = 0;
        } else if (strstr(description, "BPS") || strstr(description, "Broadcast Positioning")) {
            strcpy(entry->stream_type, "BPS Packet(s)");
            entry->is_signaling = 0;
        } else {
            strcpy(entry->stream_type, "Other UDP");
            entry->is_signaling = 0;
        }
        
        g_data_usage_count++;
    }
    
    if (entry) {
        entry->total_bytes += packet_bytes;
        entry->packet_count++;
        
        // Capture sample payload for unknown services (only once)
        if (!entry->sample_collected && payload && payload_len > 0) {
            // Check if this is an unknown service
            const char* service_name = get_service_name_for_destination(entry->destinationIp, entry->destinationPort);
            if (!service_name && !entry->is_lls && !entry->is_signaling) {
                int copy_len = payload_len > (int)sizeof(entry->sample_payload) ? (int)sizeof(entry->sample_payload) : payload_len;
                memcpy(entry->sample_payload, payload, copy_len);
                entry->sample_payload_len = copy_len;
                entry->sample_collected = 1;
            }
        }
        
        // Also try to capture sample for UDS streams (standalone UDS and inside UDST)
        if (payload && payload_len > 0) {
            for (int i = 0; i < g_lls_table_count; i++) {
                // Check standalone UDS tables
                if (g_lls_tables[i].type == TABLE_TYPE_UDS) {
                    UdsData* uds = (UdsData*)g_lls_tables[i].parsed_data;
                    if (uds && !uds->sample_collected &&
                        strcmp(uds->destIP, dest_ip) == 0 &&
                        strcmp(uds->destPort, dest_port) == 0) {
                        int copy_len = payload_len > (int)sizeof(uds->sample_payload) ? (int)sizeof(uds->sample_payload) : payload_len;
                        memcpy(uds->sample_payload, payload, copy_len);
                        uds->sample_payload_len = copy_len;
                        uds->sample_collected = 1;
                    }
                }
                // Check UDS entries inside UDST tables
                else if (g_lls_tables[i].type == TABLE_TYPE_UDST) {
                    UdstData* udst = (UdstData*)g_lls_tables[i].parsed_data;
                    if (udst) {
                        UdsData* uds = udst->head_uds;
                        while (uds) {
                            if (!uds->sample_collected &&
                                strcmp(uds->destIP, dest_ip) == 0 &&
                                strcmp(uds->destPort, dest_port) == 0) {
                                int copy_len = payload_len > (int)sizeof(uds->sample_payload) ? (int)sizeof(uds->sample_payload) : payload_len;
                                memcpy(uds->sample_payload, payload, copy_len);
                                uds->sample_payload_len = copy_len;
                                uds->sample_collected = 1;
                            }
                            uds = uds->next;
                        }
                    }
                }
            }
            
            // Check for eGPS data - look for Cambium magic bytes (0xBCA1)
            if (is_egps_service(dest_ip, dest_port) && payload_len >= 8) {
                // Check for Cambium packet magic
                if (payload[0] == 0xBC && payload[1] == 0xA1) {
                    // Parse the eGPS packet(s)
                    EgpsData* egps = parse_egps_stream(payload, payload_len, dest_ip, dest_port);
                    if (egps && egps->location_fix_count > 0) {
                        if (store_egps_data(egps)) {
                            DBG_PRINTF("DEBUG: Collected eGPS data for %s:%s (%d fixes)\n",
                                   dest_ip, dest_port, egps->location_fix_count);
                        } else {
                            free_egps_data(egps);
                        }
                    } else if (egps) {
                        free_egps_data(egps);
                    }
                }
            }
        }
        
        if (have_rate_idx) {
            rate_bins_add(&entry->rate_bins, &entry->rate_bin_count, &entry->rate_bin_cap, rate_idx, packet_bytes);
        }

        // Update per-stream timing for ALP-PCAP files
        if (g_input_type == INPUT_TYPE_ALP_PCAP && timestamp) {
            if (!entry->timing_valid) {
                // First packet for this stream
                entry->first_packet_time = *timestamp;
                entry->last_packet_time = *timestamp;
                entry->timing_valid = 1;
            } else {
                // Update last packet time
                entry->last_packet_time = *timestamp;
            }
        }
    }
}

// Function to get description for a stream
const char* get_stream_description(const char* dest_ip, const char* dest_port, uint32_t tsi) {
    // Check if it's LLS
    if (strcmp(dest_ip, "224.0.23.60") == 0 && strcmp(dest_port, "4937") == 0) {
        return "ATSC 3.0 LLS (Low Level Signaling)";
    }
    
    // Check if it's a known service stream
    for (int i = 0; i < g_service_dest_count; i++) {
        if (strcmp(g_service_dests[i].destinationIpStr, dest_ip) == 0 &&
            strcmp(g_service_dests[i].destinationPortStr, dest_port) == 0) {
            
            // Find service name from SLT
            for (int j = 0; j < g_lls_table_count; j++) {
                if (g_lls_tables[j].type == TABLE_TYPE_SLT) {
                    SltData* slt_data = (SltData*)g_lls_tables[j].parsed_data;
                    ServiceInfo* service = slt_data->head;
                    while (service) {
                        if (strcmp(service->slsDestinationIpAddress, dest_ip) == 0 &&
                            strcmp(service->slsDestinationUdpPort, dest_port) == 0) {
                            
                            static char desc[128];
                            if (tsi == 0) {
                                snprintf(desc, sizeof(desc), "%s - Signaling (TSI 0)", 
                                        service->shortServiceName);
                            } else {
                                snprintf(desc, sizeof(desc), "%s - Media (TSI %u)", 
                                        service->shortServiceName, tsi);
                            }
                            return desc;
                        }
                        service = service->next;
                    }
                }
            }
            
            // Fallback description
            static char fallback[128];
            if (tsi == 0) {
                snprintf(fallback, sizeof(fallback), "Service Signaling (TSI 0)");
            } else {
                snprintf(fallback, sizeof(fallback), "Service Media (TSI %u)", tsi);
            }
            return fallback;
        }
    }
    
    // Unknown stream
    static char unknown[128];
    if (tsi == 0) {
        snprintf(unknown, sizeof(unknown), "Unknown Stream - Signaling");
    } else {
        snprintf(unknown, sizeof(unknown), "Unknown Stream - TSI %u", tsi);
    }
    return unknown;
}

void update_packet_timing(const struct pcap_pkthdr *pkthdr) {
#ifdef STLTP_HAS_ROBUST_READER
    // STLTP input is replayed as a virtual ALP pcap. Its timestamps are real only
    // if the STLTP capture had them; otherwise they're synthetic (1 ms/packet), so
    // leave timing invalid and the report shows bitrates as N/A instead of guesses.
    if (g_original_input_type == INPUT_TYPE_STLTP && !g_timing_estimated &&
        (!g_stltp_stats || !g_stltp_stats->capture_timing_valid)) {
        return;
    }
#endif
    // Debug files have only placeholder timestamps; usable only with -t
    if (g_input_type == INPUT_TYPE_PCAP || g_input_type == INPUT_TYPE_ALP_PCAP ||
        (g_input_type == INPUT_TYPE_DEBUG && g_timing_estimated)) {
        if (g_packet_count == 1) {
            // First packet
            g_first_packet_time = pkthdr->ts;
            g_last_packet_time = pkthdr->ts;
            g_pcap_timing_valid = 1;
        } else {
            // Update last packet time
            g_last_packet_time = pkthdr->ts;
        }
    }
}

int lmt_multicast_equals(LmtMulticast* a, LmtMulticast* b) {
    return (a->src_ip == b->src_ip &&
            a->dest_ip == b->dest_ip &&
            a->src_port == b->src_port &&
            a->dest_port == b->dest_port &&
            a->sid_bit == b->sid_bit &&
            a->compression_bit == b->compression_bit);
}

int remove_lmt_duplicates(LmtData* lmt, int* duplicate_count) {
    if (!lmt || !lmt->services) return 0;
    
    *duplicate_count = 0;
    int unique_count = 0;
    
    LmtService* current_service = lmt->services;
    while (current_service) {
        current_service->duplicate_count = 0;  // Initialize per-service counter
        
        LmtMulticast* current_mc = current_service->multicasts;
        LmtMulticast* prev_mc = NULL;
        
        while (current_mc) {
            // Check if this multicast is a duplicate of any previous one in this service
            int is_duplicate = 0;
            LmtMulticast* check_mc = current_service->multicasts;
            
            while (check_mc != current_mc) {
                if (lmt_multicast_equals(check_mc, current_mc)) {
                    is_duplicate = 1;
                    (*duplicate_count)++;
                    current_service->duplicate_count++;  // Increment per-service counter
                    break;
                }
                check_mc = check_mc->next;
            }
            
            if (is_duplicate) {
                // Remove this duplicate entry
                if (prev_mc) {
                    prev_mc->next = current_mc->next;
                } else {
                    current_service->multicasts = current_mc->next;
                }
                LmtMulticast* to_free = current_mc;
                current_mc = current_mc->next;
                free(to_free);
            } else {
                unique_count++;
                prev_mc = current_mc;
                current_mc = current_mc->next;
            }
        }
        
        current_service = current_service->next;
    }
    
    return unique_count;
}

LmtData* parse_lmt(const u_char* data, int len) {
    
    if (!data) {
        DBG_PRINTF("ERROR: NULL data pointer\n");
        return NULL;
    }
    
    if (len < 8) {
        DBG_PRINTF("ERROR: LMT data too short (%d bytes)\n", len);
        return NULL;
    }
    
    // Validate the entire buffer is readable
    for (int test_pos = 0; test_pos < len; test_pos += 1024) {
        volatile uint8_t test_byte = data[test_pos];  // Force read
        (void)test_byte;  // Avoid unused variable warning
    }
    // Test the last byte
    volatile uint8_t last_byte = data[len-1];
    (void)last_byte;
    
    LmtData* lmt = calloc(1, sizeof(LmtData));
    if (!lmt) {
        printf("ERROR: Failed to allocate LmtData\n");
        return NULL;
    }
    
    // Start parsing LMT data at byte 5 (after 5-byte header)
    int pos = 5;
    if (pos >= len) {
        DBG_PRINTF("ERROR: Cannot read service count byte at position %d (len=%d)\n", pos, len);
        free(lmt);
        return NULL;
    }
    
    // Parse number of services (6 bits) + placeholder (2 bits)
    uint8_t svc_byte = data[pos++];
    uint8_t num_svc_minus1 = (svc_byte >> 2) & 0x3F;
    
    lmt->num_services = 0;
    LmtService* service_tail = NULL;
    
    // Parse each service (which corresponds to a PLP)
    for (int svc_idx = 0; svc_idx <= num_svc_minus1; svc_idx++) {
        for (int i = 0; i < 13 && pos + i < len; i++) {
            DBG_PRINTF("%02x ", data[pos + i]);
        }
        DBG_PRINTF("\n");
        
        if (pos >= len - 2) {
            break;
        }
        
        // Parse PLP ID (6 bits) + placeholder (2 bits)
        uint8_t plp_byte = data[pos++];
        uint8_t plp_id = (plp_byte >> 2) & 0x3F;
        
        if (pos >= len) {
            break;
        }
        
        // Parse number of multicast entries for this PLP
        uint8_t num_multicasts = data[pos++];
        
        // Sanity check on multicast count
        /*if (num_multicasts > 40) {  // Reasonable upper limit
            DBG_PRINTF("ERROR: Suspicious multicast count %d for PLP %d\n", num_multicasts, plp_id);
            break;
        }*/
        
        // Check if we have enough data for all multicasts
        size_t needed_bytes = num_multicasts * 13;  // 13 bytes per multicast minimum
        if (pos + needed_bytes > len) {
            DBG_PRINTF("ERROR: Not enough data for %d multicasts (need %zu bytes, have %d)\n", 
                   num_multicasts, needed_bytes, len - pos);
            break;
        }
        
        // Create service entry for this PLP
        LmtService* service = calloc(1, sizeof(LmtService));
        if (!service) {
            printf("ERROR: Failed to allocate service for PLP %d\n", plp_id);
            continue;
        }
        
        service->service_id = lmt->num_services + 1;
        service->service_category = 1;
        service->plp_id = plp_id;
        snprintf(service->service_name, sizeof(service->service_name), "PLP_%d", plp_id);
        service->multicasts = NULL;  // Explicitly initialize
        service->next = NULL;        // Explicitly initialize
        
        LmtMulticast* current_service_multicast_tail = NULL;
        
        // Parse each multicast entry for this PLP
        for (int mc_idx = 0; mc_idx < num_multicasts; mc_idx++) {
            
            if (pos + 13 > len) {  // Need exactly 13 bytes
                DBG_PRINTF("ERROR: Not enough data for multicast %d in PLP %d (need 13 bytes, have %d)\n", 
                       mc_idx, plp_id, len - pos);
                break;
            }
            
            // Create multicast entry
            LmtMulticast* multicast = calloc(1, sizeof(LmtMulticast));
            if (!multicast) {
                printf("ERROR: Failed to allocate multicast %d for PLP %d\n", mc_idx, plp_id);
                continue;
            }
            
            memset(multicast, 0, sizeof(LmtMulticast));  // Ensure everything is zeroed
            
            // Explicitly initialize all fields
            multicast->next = NULL;
            multicast->dest_ip_str[0] = '\0';
            multicast->dest_port_str[0] = '\0';
            
            // Parse multicast entry (13 bytes)
            multicast->src_ip = ntohl(*(uint32_t*)(data + pos));
            pos += 4;
            multicast->dest_ip = ntohl(*(uint32_t*)(data + pos));
            pos += 4;
            multicast->src_port = ntohs(*(uint16_t*)(data + pos));
            pos += 2;
            multicast->dest_port = ntohs(*(uint16_t*)(data + pos));
            pos += 2;
            
            // Parse flags
            uint8_t flags = data[pos++];
            multicast->sid_bit = (flags >> 7) & 0x1;
            multicast->compression_bit = (flags >> 6) & 0x1;
            
            // Convert to string format with bounds checking
            int ip_result = snprintf(multicast->dest_ip_str, sizeof(multicast->dest_ip_str), 
                    "%d.%d.%d.%d",
                    (multicast->dest_ip >> 24) & 0xff,
                    (multicast->dest_ip >> 16) & 0xff,
                    (multicast->dest_ip >> 8) & 0xff,
                    multicast->dest_ip & 0xff);
            
            int port_result = snprintf(multicast->dest_port_str, sizeof(multicast->dest_port_str), 
                    "%u", multicast->dest_port);
            
            if (ip_result <= 0 || port_result <= 0) {
                DBG_PRINTF("ERROR: Failed to format IP/port strings for PLP %d multicast %d\n", plp_id, mc_idx);
                free(multicast);
                continue;
            }
            
            // Handle extra bytes if needed
            int extra_bytes = 0;
            if (multicast->sid_bit && multicast->compression_bit) extra_bytes = 2;
            else if (multicast->sid_bit || multicast->compression_bit) extra_bytes = 1;

            if (extra_bytes > 0) {
                if (pos + extra_bytes > len) {
                    DBG_PRINTF("ERROR: Not enough data for extra bytes (%d needed)\n", extra_bytes);
                    free(multicast);
                    break;
                }
                
                // Actually READ the extra bytes instead of just skipping
                if (extra_bytes == 1) {
                    //uint8_t extra_byte = data[pos];
                    pos += 1;
                } else if (extra_bytes == 2) {
                    //uint16_t extra_word = ntohs(*(uint16_t*)(data + pos));
                    pos += 2;
                }
            }
                    
            // Before adding to linked list, validate the structure:
            if (multicast->dest_ip_str[0] == '\0' || multicast->dest_port_str[0] == '\0') {
                DBG_PRINTF("ERROR: Invalid multicast entry for PLP %d, skipping\n", plp_id);
                free(multicast);
                continue;
            }

            // Double-check the next pointer is still NULL
            if (multicast->next != NULL) {
                DBG_PRINTF("ERROR: multicast->next was corrupted during parsing!\n");
                multicast->next = NULL;
            }
            
            // Add to multicast list for this service
            if (service->multicasts == NULL) {
                service->multicasts = multicast;
                current_service_multicast_tail = multicast;
            } else {
                if (!current_service_multicast_tail) {
                    DBG_PRINTF("ERROR: multicast_tail is NULL but service->multicasts is not\n");
                    free(multicast);
                    break;
                }
                current_service_multicast_tail->next = multicast;
                current_service_multicast_tail = multicast;
            }
        }

        
        // Add service to LMT
        if (lmt->services == NULL) {
            lmt->services = service;
            service_tail = service;
        } else {
            if (!service_tail) {
                DBG_PRINTF("ERROR: service_tail is NULL but lmt->services is not\n");
                free(service);  // This will leak multicasts, but prevents crash
                break;
            }
            service_tail->next = service;
            service_tail = service;
        }
        lmt->num_services++;
    }
    
    DBG_PRINTF("LMT parsing complete: %d PLPs found\n", lmt->num_services);
    
    int duplicate_count = 0;
    int total_entries = 0;
    
    // First count total entries before deduplication
    LmtService* count_svc = lmt->services;
    while (count_svc) {
        LmtMulticast* count_mc = count_svc->multicasts;
        while (count_mc) {
            total_entries++;
            count_mc = count_mc->next;
        }
        count_svc = count_svc->next;
    }
    
    int unique_count = remove_lmt_duplicates(lmt, &duplicate_count);
    
    if (duplicate_count > 0) {
        DBG_PRINTF("WARNING: LMT contains %d duplicate entries (showing %d unique entries)\n", 
               duplicate_count, unique_count);
    }
    
    // Sanity check on unique count instead of raw count
    if (unique_count > 100) {
        DBG_PRINTF("WARNING: Suspiciously high number of unique LMT entries: %d\n", unique_count);
    }
    
    lmt->duplicate_count = duplicate_count;
    lmt->total_entry_count = total_entries;
    
    return lmt;
}

void packet_handler(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    static int alp_packet_count = 0;
    alp_packet_count++;
    
    g_packet_count++;
    
    update_packet_timing(pkthdr);
    eas_note_packet(&pkthdr->ts);

    if (g_link_type == DLT_ATSC_ALP) {
        const u_char* ip_payload;
        const u_char* signaling_payload;
        int ip_len, signaling_len;
        
        int result = parse_alp_packet(packet, pkthdr->caplen, 
                                    &ip_payload, &ip_len, 
                                    &signaling_payload, &signaling_len);
        
        // Suppress Sony manufacturer packets that fail to parse
        if (result < 0 && pkthdr->caplen < 7) {
            return;  // Skip to next packet
        }
        
        if (result == 0 && ip_payload) {
            // Process IP packet using existing logic
            const struct ip *ip_header = (struct ip*)ip_payload;
            if (!ip_header) {
                return;
            }
            
            int ip_header_len = ip_header->ip_hl * 4;

            if (ip_header->ip_p != IPPROTO_UDP) {
                char dest_ip_str[40];
                inet_ntop(AF_INET, &ip_header->ip_dst, dest_ip_str, sizeof(dest_ip_str));
                record_data_usage(dest_ip_str, "N/A", 0, pkthdr->caplen, 
                        "ALP Non-UDP IP (Stuffing)", &pkthdr->ts, NULL, 0);
                return;
            }

            const struct udphdr *udp_header = (struct udphdr*)((u_char*)ip_header + ip_header_len);
            if (!udp_header) {
                return;
            }
            
            const u_char *udp_payload = (u_char*)udp_header + sizeof(struct udphdr);
            int udp_payload_len = ntohs(udp_header->uh_ulen) - sizeof(struct udphdr);
            if (udp_payload_len <= 0) return;

            char dest_ip_str[40];
            char dest_port_str[16];
            inet_ntop(AF_INET, &ip_header->ip_dst, dest_ip_str, sizeof(dest_ip_str));
            snprintf(dest_port_str, sizeof(dest_port_str), "%u", ntohs(udp_header->uh_dport));
            
            // Check if this is a BPS packet
            if (is_bps_service(dest_ip_str, dest_port_str)) {
                const u_char *udp_payload = (u_char*)udp_header + sizeof(struct udphdr);
                int udp_payload_len = ntohs(udp_header->uh_ulen) - sizeof(struct udphdr);
                
                if (udp_payload_len > 0 && !g_bps_data) {
                    g_bps_data = parse_bps_packet(udp_payload, udp_payload_len);
                }
                
                record_data_usage(dest_ip_str, dest_port_str, 0, pkthdr->caplen, 
                                "Broadcast Positioning System (BPS)", &pkthdr->ts, NULL, 0);
                return;  // Don't process as regular ROUTE/MMT
            }
            
            // Check if this is LLS first
            int is_lls = (ntohs(udp_header->uh_dport) == 4937 && 
                        ip_header->ip_dst.s_addr == inet_addr("224.0.23.60"));
            
            if (is_lls) {
                process_lls_payload(udp_payload, udp_payload_len);
                record_data_usage(dest_ip_str, dest_port_str, 0, pkthdr->caplen, 
                                "ATSC 3.0 LLS (Low Level Signaling)", &pkthdr->ts, NULL, 0);
                return;
            }
            
            //printf("DEBUG: Looking up service destination, count=%d\n", g_service_dest_count);
            
            // Find matching service destination from SLT
            ServiceDestination* dest_info = NULL;
            for(int i = 0; i < g_service_dest_count; i++) {
                if(ip_header->ip_dst.s_addr == g_service_dests[i].ip_addr.s_addr &&
                ntohs(udp_header->uh_dport) == g_service_dests[i].port) {
                    dest_info = &g_service_dests[i];
                    //printf("DEBUG: Found service destination at index %d\n", i);
                    break;
                }
            }
            
            if (dest_info) {
                //printf("DEBUG: Using service protocol=%s\n", dest_info->protocol);
                
                // Use SLT configuration to determine protocol
                if (strcmp(dest_info->protocol, "1") == 0) {
                    // ROUTE protocol - extract TSI properly from LCT header
                    uint32_t tsi = get_lct_tsi(udp_payload, udp_payload_len);
                    if (tsi == 0xFFFFFFFF) tsi = 0;
                    
                    const char* description = get_enhanced_stream_description(dest_ip_str, dest_port_str, 
                                                                            tsi, "ROUTE", 0);
                    record_data_usage(dest_ip_str, dest_port_str, tsi, pkthdr->caplen, description, &pkthdr->ts, udp_payload, udp_payload_len);
                    process_route_payload(udp_payload, udp_payload_len, dest_info->destinationIpStr, dest_info->destinationPortStr);
                } else if (strcmp(dest_info->protocol, "2") == 0) {
                    // MMT protocol  
                    uint16_t packet_id = 0;
                    if (udp_payload_len >= 4) {
                        packet_id = ntohs(*(uint16_t*)(udp_payload + 2));
                    }
                    DBG_PRINTF("DEBUG: MMT PID=%u\n", packet_id);
                    
                    const char* description = get_stream_description(dest_ip_str, dest_port_str, packet_id);
                    if (!description) {
                        //printf("DEBUG: NULL description from get_stream_description\n");
                        description = "MMT Stream";
                    }
                    
                    record_data_usage(dest_ip_str, dest_port_str, packet_id, pkthdr->caplen, description, &pkthdr->ts, udp_payload, udp_payload_len);
                    process_enhanced_mmt_payload(udp_payload, udp_payload_len, dest_info);
                }
            } else {
                // No service destination found - need to detect protocol from payload
                
                // Check for raw MPEG-TS (starts with 0x47 sync byte)
                if (udp_payload_len >= 188 && udp_payload[0] == 0x47) {
                    // Raw MPEG-TS over UDP (not ROUTE encapsulated)
                    uint16_t pid = ((udp_payload[1] & 0x1F) << 8) | udp_payload[2];
                    const char* description = (pid == 0x1FFF) ? "MPEG-TS Null" : "MPEG-TS";
                    record_data_usage(dest_ip_str, dest_port_str, pid, pkthdr->caplen, description, &pkthdr->ts, udp_payload, udp_payload_len);
                } 
                // Check for RTP (version 2 in top 2 bits of first byte)
                else if (udp_payload_len >= 12 && ((udp_payload[0] >> 6) & 0x03) == 2) {
                    uint8_t payload_type = udp_payload[1] & 0x7F;
                    // Check if RTP payload is MPEG-TS (starts at byte 12)
                    if (payload_type == 33 && udp_payload_len >= 15 && udp_payload[12] == 0x47) {
                        // RTP carrying MPEG-TS
                        uint16_t pid = ((udp_payload[13] & 0x1F) << 8) | udp_payload[14];
                        const char* description = (pid == 0x1FFF) ? "RTP/MPEG-TS Null" : "RTP/MPEG-TS";
                        record_data_usage(dest_ip_str, dest_port_str, pid, pkthdr->caplen, description, &pkthdr->ts, udp_payload, udp_payload_len);
                    } else {
                        // Other RTP stream
                        char description[64];
                        snprintf(description, sizeof(description), "RTP (PT %d)", payload_type);
                        record_data_usage(dest_ip_str, dest_port_str, payload_type, pkthdr->caplen, description, &pkthdr->ts, udp_payload, udp_payload_len);
                    }
                }
                // IMPORTANT: Check for ROUTE/LCT BEFORE MMT!
                // LCT version=1 means byte[0] = 0x1X, so top 2 bits = 00,
                // which would falsely match the MMT check below.
                else if (udp_payload_len >= 4 && is_likely_route_packet(udp_payload, udp_payload_len)) {
                    uint32_t tsi = get_lct_tsi(udp_payload, udp_payload_len);
                    if (tsi == 0xFFFFFFFF) tsi = 0;
                    
                    const char* description = get_enhanced_stream_description(dest_ip_str, dest_port_str, 
                                                                            tsi, "ROUTE", 0);
                    record_data_usage(dest_ip_str, dest_port_str, tsi, pkthdr->caplen, description, &pkthdr->ts, udp_payload, udp_payload_len);
                    process_route_payload(udp_payload, udp_payload_len, dest_ip_str, dest_port_str);
                }
                // Check for MMT (version 0 in top 2 bits, and reasonable packet structure)
                else if (udp_payload_len >= 12 && ((udp_payload[0] >> 6) & 0x03) == 0) {
                    // MMT packet - extract packet_id from bytes 2-3
                    uint16_t packet_id = ntohs(*(uint16_t*)(udp_payload + 2));
                    const char* description = "MMT";
                    record_data_usage(dest_ip_str, dest_port_str, packet_id, pkthdr->caplen, description, &pkthdr->ts, udp_payload, udp_payload_len);
                }
                else {
                    // Last resort: assume ROUTE/ALC
                    uint32_t tsi = get_lct_tsi(udp_payload, udp_payload_len);
                    if (tsi == 0xFFFFFFFF) tsi = 0;
                    
                    const char* description = get_enhanced_stream_description(dest_ip_str, dest_port_str, 
                                                                            tsi, "ROUTE", 0);
                    record_data_usage(dest_ip_str, dest_port_str, tsi, pkthdr->caplen, description, &pkthdr->ts, udp_payload, udp_payload_len);
                    process_route_payload(udp_payload, udp_payload_len, dest_ip_str, dest_port_str);
                }
            }
            
        } else if (result == 1 && signaling_payload) {
            // Process ALP signaling packet
            //printf("Processing ALP signaling packet (%d bytes)\n", signaling_len);
            
            LmtData* lmt_data = parse_lmt(signaling_payload, signaling_len);
            if (lmt_data) {
                // Store LMT in global tables
                char lmt_content_id[256];
                snprintf(lmt_content_id, sizeof(lmt_content_id), 
                        "LMT_Version_%d_Services_%d", lmt_data->lmt_version, lmt_data->num_services);
                
                store_unique_table(lmt_content_id, strlen(lmt_content_id), 
                                TABLE_TYPE_LMT, lmt_data, "", "", 0, -1);
            }
            
        } else if (result == 2) {
            // ALP Extension/Stuffing packet
            record_data_usage("N/A", "N/A", 0, pkthdr->caplen, 
                            "ALP Stuffing/Extension", &pkthdr->ts, NULL, 0);
        } /*else {
            DBG_PRINTF("DEBUG: Could not parse ALP packet %d (result=%d)\n", g_packet_count, result);
        }*/
        
        return;
    }
    
    const struct ip *ip_header;
    const struct udphdr *udp_header;
    const u_char *payload;
    int ip_header_len;
    int payload_len;

    int offset = 0;
    const u_char* ip_packet_start = packet;  
    
    // Handle different link layer types
    if (g_link_type == DLT_EN10MB) {
        offset = sizeof(struct ether_header);
        ip_packet_start = packet + offset;
    }
    // For DLT_IPV4, no offset needed

    ip_header = (struct ip*)ip_packet_start;
    if (!ip_header) {
        return;
    }
    if (ip_header->ip_v != 4) {
        return;                     /* raw-IP captures can also hold IPv6 */
    }
    
    ip_header_len = ip_header->ip_hl * 4;

    if (ip_header->ip_p != IPPROTO_UDP) {
        char dest_ip_str[40];
        inet_ntop(AF_INET, &ip_header->ip_dst, dest_ip_str, sizeof(dest_ip_str));
        record_data_usage(dest_ip_str, "N/A", 0, pkthdr->caplen, 
                    "ALP Non-UDP IP (Stuffing)", &pkthdr->ts, NULL, 0);
        return;
    }

    udp_header = (struct udphdr*)((u_char*)ip_header + ip_header_len);
    if (!udp_header) {
        return;
    }
    
    payload = (u_char*)udp_header + sizeof(struct udphdr);
    payload_len = ntohs(udp_header->uh_ulen) - sizeof(struct udphdr);
    if (payload_len <= 0) return;

    char dest_ip_str[40];
    char dest_port_str[16];
    inet_ntop(AF_INET, &ip_header->ip_dst, dest_ip_str, sizeof(dest_ip_str));
    snprintf(dest_port_str, sizeof(dest_port_str), "%u", ntohs(udp_header->uh_dport));
    
    //printf("DEBUG: Packet %d - %s:%s, len=%d\n", g_packet_count, dest_ip_str, dest_port_str, payload_len);
    
    // Check if this is LLS first
    int is_lls = (ntohs(udp_header->uh_dport) == 4937 && 
                  ip_header->ip_dst.s_addr == inet_addr("224.0.23.60"));
    
    if (is_lls) {
        process_lls_payload(payload, payload_len);
        record_data_usage(dest_ip_str, dest_port_str, 0, payload_len, 
                         "ATSC 3.0 LLS (Low Level Signaling)", &pkthdr->ts, NULL, 0);
        return;
    }
    
    //printf("DEBUG: Looking up service destination, count=%d\n", g_service_dest_count);
    
    // Find matching service destination from SLT
    ServiceDestination* dest_info = NULL;
    for(int i = 0; i < g_service_dest_count; i++) {
        if(ip_header->ip_dst.s_addr == g_service_dests[i].ip_addr.s_addr &&
           ntohs(udp_header->uh_dport) == g_service_dests[i].port) {
            dest_info = &g_service_dests[i];
            //printf("DEBUG: Found service destination at index %d\n", i);
            break;
        }
    }
    
    if (dest_info) {
        //printf("DEBUG: Using service protocol=%s\n", dest_info->protocol);
        
        // Use SLT configuration to determine protocol
        if (strcmp(dest_info->protocol, "1") == 0) {
            // ROUTE protocol - extract TSI properly from LCT header
            uint32_t tsi = get_lct_tsi(payload, payload_len);
            if (tsi == 0xFFFFFFFF) tsi = 0;
            
            const char* description = get_enhanced_stream_description(dest_ip_str, dest_port_str, 
                                                                    tsi, "ROUTE", 0);
            record_data_usage(dest_ip_str, dest_port_str, tsi, payload_len, description, &pkthdr->ts, payload, payload_len);
            process_route_payload(payload, payload_len, dest_info->destinationIpStr, dest_info->destinationPortStr);
        } else if (strcmp(dest_info->protocol, "2") == 0) {
            // MMT protocol  
            uint16_t packet_id = 0;
            if (payload_len >= 4) {
                packet_id = ntohs(*(uint16_t*)(payload + 2));
            }
            //printf("DEBUG: MMT PID=%u\n", packet_id);
            
            const char* description = get_stream_description(dest_ip_str, dest_port_str, packet_id);
            if (!description) {
                //printf("DEBUG: NULL description from get_stream_description\n");
                description = "MMT Stream";
            }
            
            record_data_usage(dest_ip_str, dest_port_str, packet_id, payload_len, description, &pkthdr->ts, payload, payload_len);
            DBG_PRINTF("DEBUG: About to call process_enhanced_mmt_payload with dest_info=%p\n", dest_info);
            process_enhanced_mmt_payload(payload, payload_len, dest_info);
        }
    } else {
        // No service destination found - need to detect protocol from payload
        
        // Check for raw MPEG-TS (starts with 0x47 sync byte)
        if (payload_len >= 188 && payload[0] == 0x47) {
            // Raw MPEG-TS over UDP (not ROUTE encapsulated)
            uint16_t pid = ((payload[1] & 0x1F) << 8) | payload[2];
            const char* description = (pid == 0x1FFF) ? "MPEG-TS Null" : "MPEG-TS";
            record_data_usage(dest_ip_str, dest_port_str, pid, payload_len, description, &pkthdr->ts, payload, payload_len);
        } 
        // Check for RTP (version 2 in top 2 bits of first byte)
        else if (payload_len >= 12 && ((payload[0] >> 6) & 0x03) == 2) {
            uint8_t payload_type = payload[1] & 0x7F;
            // Check if RTP payload is MPEG-TS (starts at byte 12)
            if (payload_type == 33 && payload_len >= 15 && payload[12] == 0x47) {
                // RTP carrying MPEG-TS
                uint16_t pid = ((payload[13] & 0x1F) << 8) | payload[14];
                const char* description = (pid == 0x1FFF) ? "RTP/MPEG-TS Null" : "RTP/MPEG-TS";
                record_data_usage(dest_ip_str, dest_port_str, pid, payload_len, description, &pkthdr->ts, payload, payload_len);
            } else {
                // Other RTP stream
                char description[64];
                snprintf(description, sizeof(description), "RTP (PT %d)", payload_type);
                record_data_usage(dest_ip_str, dest_port_str, payload_type, payload_len, description, &pkthdr->ts, payload, payload_len);
            }
        }
        // Check ROUTE/LCT BEFORE MMT (LCT version=1 has top 2 bits = 00, same as MMT)
        else if (payload_len >= 4 && is_likely_route_packet(payload, payload_len)) {
            uint32_t tsi = get_lct_tsi(payload, payload_len);
            if (tsi == 0xFFFFFFFF) tsi = 0;
            
            const char* description = get_enhanced_stream_description(dest_ip_str, dest_port_str, 
                                                                      tsi, "ROUTE", 0);
            record_data_usage(dest_ip_str, dest_port_str, tsi, payload_len, description, &pkthdr->ts, payload, payload_len);
            process_route_payload(payload, payload_len, dest_ip_str, dest_port_str);
        }
        // Check for MMT (version 0 in top 2 bits)
        else if (payload_len >= 12 && ((payload[0] >> 6) & 0x03) == 0) {
            // MMT packet - extract packet_id from bytes 2-3
            uint16_t packet_id = ntohs(*(uint16_t*)(payload + 2));
            const char* description = "MMT";
            record_data_usage(dest_ip_str, dest_port_str, packet_id, payload_len, description, &pkthdr->ts, payload, payload_len);
        }
        else {
            // Last resort: assume ROUTE/ALC
            uint32_t tsi = get_lct_tsi(payload, payload_len);
            if (tsi == 0xFFFFFFFF) tsi = 0;
            
            const char* description = get_enhanced_stream_description(dest_ip_str, dest_port_str, 
                                                                      tsi, "ROUTE", 0);
            record_data_usage(dest_ip_str, dest_port_str, tsi, payload_len, description, &pkthdr->ts, payload, payload_len);
            process_route_payload(payload, payload_len, dest_ip_str, dest_port_str);
        }
    }
    
    //printf("DEBUG: Packet %d complete\n", g_packet_count);
}

const char* get_enhanced_stream_description(const char* dest_ip, const char* dest_port, 
                                          uint32_t tsi_or_packet_id, const char* stream_type, int is_lls) {
    static char desc_buffer[256];
    
    if (is_lls) {
        return "ATSC 3.0 LLS (Low Level Signaling)";
    }
    
    if (is_bps_service(dest_ip, dest_port)) {
        return "BPS (Broadcast Positioning System)";
    }
    
    // Get service name from SLT
    const char* service_name = get_service_name_for_destination(dest_ip, dest_port);
    
    // Get detailed media type from signaling tables
    const char* media_type = "Media";
    const char* detailed_info = "";
    
    if (strcmp(stream_type, "ROUTE") == 0) {
        if (tsi_or_packet_id == 0) {
            media_type = "Signaling";
        } else {
            // Look up TSI in S-TSID for detailed info
            //printf("stsid being called  \n");
            media_type = get_media_type_from_stsid(dest_ip, dest_port, tsi_or_packet_id);
            /*for (int i = 0; i < g_lls_table_count; i++) {
                if (g_lls_tables[i].type == TABLE_TYPE_STSID &&
                    strcmp(g_lls_tables[i].destinationIp, dest_ip) == 0 &&
                    strcmp(g_lls_tables[i].destinationPort, dest_port) == 0) {
                    
                    StsidData* stsid_data = (StsidData*)g_lls_tables[i].parsed_data;
                    StsidLogicalStream* ls = stsid_data->head_ls;
                    
                    while (ls) {
                        if (atoi(ls->tsi) == tsi_or_packet_id) {
                            if (strstr(ls->contentType, "video") || strstr(ls->repId, "video")) {
                                media_type = "Video";
                                // Try to extract resolution/quality info from repId
                                if (strstr(ls->repId, "1080")) detailed_info = " (1080p)";
                                else if (strstr(ls->repId, "720")) detailed_info = " (720p)";
                                else if (strstr(ls->repId, "480")) detailed_info = " (480p)";
                            } else if (strstr(ls->contentType, "audio") || strstr(ls->repId, "audio")) {
                                media_type = "Audio";
                                if (strstr(ls->repId, "128k")) detailed_info = " (128k)";
                                else if (strstr(ls->repId, "256k")) detailed_info = " (256k)";
                            } else if (strstr(ls->contentType, "application") || strstr(ls->repId, "cc")) {
                                media_type = "Captions";
                            }
                            break;
                        }
                        ls = ls->next;
                    }
                }
            }*/
        }
    } else if (strcmp(stream_type, "MMT") == 0) {
        // Similar lookup for MMT using MP Table data
        media_type = get_media_type_from_mpt(dest_ip, dest_port, tsi_or_packet_id);
    }
    
    // Build comprehensive description
    if (service_name) {
        if (strcmp(stream_type, "ROUTE") == 0) {
            snprintf(desc_buffer, sizeof(desc_buffer), "%s - ROUTE %s%s (TSI %u)", 
                    service_name, media_type, detailed_info, tsi_or_packet_id);
        } else if (strcmp(stream_type, "MMT") == 0) {
            snprintf(desc_buffer, sizeof(desc_buffer), "%s - MMT %s%s (PID %u)", 
                    service_name, media_type, detailed_info, tsi_or_packet_id);
        } else {
            snprintf(desc_buffer, sizeof(desc_buffer), "%s - %s %s%s", 
                    service_name, stream_type, media_type, detailed_info);
        }
    } else {
        if (strcmp(stream_type, "ROUTE") == 0) {
            snprintf(desc_buffer, sizeof(desc_buffer), "ROUTE %s%s (TSI %u)", 
                    media_type, detailed_info, tsi_or_packet_id);
        } else if (strcmp(stream_type, "MMT") == 0) {
            snprintf(desc_buffer, sizeof(desc_buffer), "MMT %s%s (PID %u)", 
                    media_type, detailed_info, tsi_or_packet_id);
        } else {
            snprintf(desc_buffer, sizeof(desc_buffer), "%s %s Stream%s", 
                    stream_type, media_type, detailed_info);
        }
    }
    
    return desc_buffer;
}

int is_likely_route_packet(const uint8_t* payload, int len) {
    if (len < 8) return 0;
    
    // Check for LCT header patterns
    // LCT version should be 1 (top 4 bits of byte 0)
    uint8_t version = (payload[0] >> 4) & 0x0F;
    uint8_t hdr_len = payload[2]; // Header length in 32-bit words
    
    if (version == 1 && hdr_len >= 2 && hdr_len <= 16) {
        // Check if TSI field looks reasonable (usually 0-255 for signaling/media)
        uint32_t tsi = get_lct_tsi(payload, len);
        if (tsi != 0xFFFFFFFF && tsi <= 1000) { // Reasonable TSI range
            return 1;
        }
    }
    
    return 0;
}

int is_likely_rtp_packet(const uint8_t* payload, int len) {
    if (len < 12) return 0;
    
    // Check for RTP header patterns
    uint8_t version = (payload[0] >> 6) & 0x3;
    uint8_t payload_type = payload[1] & 0x7F;
    
    // RTP version should be 2, payload type should be reasonable
    if (version == 2 && payload_type <= 127) {
        return 1;
    }
    
    return 0;
}

const char* infer_content_type_from_context(const char* dest_ip, const char* dest_port, uint32_t id, const char* stream_type) {
    // Try to infer content type from port numbers and patterns
    int port = atoi(dest_port);
    
    // Common port patterns
    if (port == 5001 || port == 5002) {
        // Check IP pattern for multiple streams on same port (likely different content types)
        struct in_addr addr;
        if (inet_pton(AF_INET, dest_ip, &addr) != 1) addr.s_addr = 0;
        uint32_t ip_int = ntohl(addr.s_addr);
        uint8_t last_octet = ip_int & 0xFF;
        
        // If we see multiple IPs on same port, try to differentiate
        if (port == 5001) {
            // Guess based on last octet or other patterns
            if (last_octet % 4 == 1) return "Video";
            if (last_octet % 4 == 2) return "Audio"; 
            if (last_octet % 4 == 3) return "Data";
            return "Video"; // Default guess for 5001
        }
    }
    
    // Port 5100 often used for signaling
    if (port == 5100) return "Signaling";
    
    // RTP payload type hints
    if (strcmp(stream_type, "RTP") == 0) {
        // Common RTP payload types
        if (id >= 96 && id <= 127) return "Video"; // Dynamic payload types often video
        if (id >= 0 && id <= 23) return "Audio";   // Static audio payload types
        return "Media";
    }
    
    // Default based on stream type
    if (strcmp(stream_type, "ROUTE") == 0 || strcmp(stream_type, "MMT") == 0) {
        if (id == 0) return "Signaling";
        return "Media";
    }
    
    return "Media";
}

const char* get_media_type_from_stsid(const char* dest_ip, const char* dest_port, uint32_t tsi) {
    //printf("ENTERED get_media_type_from_stsid with %s:%s TSI=%u\n", dest_ip, dest_port, tsi);
    //printf("DEBUG S-TSID LOOKUP: Searching for %s:%s TSI=%u\n", dest_ip, dest_port, tsi);
    
    // Search through S-TSID tables to find media type for this TSI
    //printf("DEBUG S-TSID: Starting loop through %d total tables\n", g_lls_table_count);
    for (int i = 0; i < g_lls_table_count; i++) {
        //printf("DEBUG S-TSID: Checking table %d, type=%d\n", i, g_lls_tables[i].type);
        if (g_lls_tables[i].type == TABLE_TYPE_STSID) {
            //printf("DEBUG S-TSID LOOKUP: Checking table %d: IP='%s' vs '%s', Port='%s' vs '%s'\n", 
            //       i, g_lls_tables[i].destinationIp, dest_ip, 
            //       g_lls_tables[i].destinationPort, dest_port);
            
            if (strcmp(g_lls_tables[i].destinationIp, dest_ip) == 0 &&
                strcmp(g_lls_tables[i].destinationPort, dest_port) == 0) {
                
                //printf("DEBUG S-TSID LOOKUP: Found matching S-TSID table for %s:%s\n", dest_ip, dest_port);
                
                StsidData* stsid_data = (StsidData*)g_lls_tables[i].parsed_data;
                StsidLogicalStream* ls = stsid_data->head_ls;
                
                while (ls) {
                    //printf("DEBUG S-TSID LOOKUP: Checking LS TSI=%s against target %u\n", ls->tsi, tsi);
                    if (atoi(ls->tsi) == (int)tsi) {
                        //printf("DEBUG S-TSID LOOKUP: MATCH! TSI=%u contentType=%s repId=%s\n", 
                        //       tsi, ls->contentType, ls->repId);
                        
                        // Try to determine media type from stream-level content type
                        if (strstr(ls->contentType, "video") || strstr(ls->contentType, "Video")) {
                            return "Video";
                        } else if (strstr(ls->contentType, "audio") || strstr(ls->contentType, "Audio")) {
                            return "Audio";  
                        } else if (strstr(ls->contentType, "subtitles") || strstr(ls->contentType, "application/ttml") || 
                                   strstr(ls->contentType, "text")) {
                            return "Captions";
                        }
                        
                        // Check file entries for ESG content types (SGDD/SGDU)
                        // These have MIME types like:
                        //   application/vnd.oma.bcast.sgdd+xml  (Service Guide Delivery Descriptor)
                        //   application/vnd.oma.bcast.sgdu      (Service Guide Delivery Unit)
                        if (ls->head_file) {
                            int has_sgdd = 0, has_sgdu = 0;
                            StsidFileEntry* fe = ls->head_file;
                            while (fe) {
                                if (strstr(fe->content_type, "sgdd")) {
                                    has_sgdd = 1;
                                } else if (strstr(fe->content_type, "sgdu")) {
                                    has_sgdu = 1;
                                }
                                fe = fe->next;
                            }
                            if (has_sgdd && !has_sgdu) return "ESG SGDD";
                            if (has_sgdu && !has_sgdd) return "ESG SGDU";
                            if (has_sgdd && has_sgdu)  return "ESG SGDD+SGDU";
                            
                            // For multipart/related and other generic types,
                            // try to derive a useful label from the filename
                            StsidFileEntry* fe2 = ls->head_file;
                            while (fe2) {
                                // Check content_type for multipart/related packages
                                if (strstr(fe2->content_type, "multipart/related")) {
                                    // Use filename to identify the package
                                    static char pkg_label[64];
                                    if (strcasestr(fe2->content_location, "weather")) {
                                        return "App (Weather)";
                                    } else if (strcasestr(fe2->content_location, "app") || 
                                               strcasestr(fe2->content_location, "App")) {
                                        return "App (Interactive)";
                                    } else if (strcasestr(fe2->content_location, "alert")) {
                                        return "App (Alerts)";
                                    } else if (strcasestr(fe2->content_location, "news")) {
                                        return "App (News)";
                                    } else if (strcasestr(fe2->content_location, "score")) {
                                        return "App (Scores)";
                                    } else if (fe2->content_location[0]) {
                                        // Use the filename itself as the label
                                        // Extract just the filename (strip path)
                                        const char* basename = strrchr(fe2->content_location, '/');
                                        basename = basename ? basename + 1 : fe2->content_location;
                                        // Strip extension
                                        snprintf(pkg_label, sizeof(pkg_label), "App (%.50s)", basename);
                                        char* dot = strrchr(pkg_label, '.');
                                        if (dot && dot > pkg_label + 5) {
                                            *dot = ')';
                                            *(dot + 1) = '\0';
                                        }
                                        return pkg_label;
                                    }
                                    return "App Package";
                                }
                                fe2 = fe2->next;
                            }
                        }
                        
                        // Fall back to stream-level contentType if set
                        if (strlen(ls->contentType) > 0) {
                            // Check for generic application types that might be ESG
                            if (strstr(ls->contentType, "application")) {
                                return "Captions";
                            }
                            return ls->contentType;
                        }
                    }
                    ls = ls->next;
                }
                //printf("DEBUG S-TSID LOOKUP: No matching TSI found in S-TSID table\n");
            }
        }
    }
    
    //printf("DEBUG S-TSID LOOKUP: No S-TSID table found for %s:%s\n", dest_ip, dest_port);
    return "Media";
}

const char* get_extended_stream_description(const char* dest_ip, const char* dest_port, uint32_t id, const char* stream_type) {
    static char ext_desc_buffer[256];
    
    // Check if this IP:port appears in any signaling table, even if not in main service list
    for (int i = 0; i < g_lls_table_count; i++) {
        if (strlen(g_lls_tables[i].destinationIp) > 0 &&
            strcmp(g_lls_tables[i].destinationIp, dest_ip) == 0 &&
            strcmp(g_lls_tables[i].destinationPort, dest_port) == 0) {
            
            // Found signaling for this IP:port - try to get service name
            const char* service_name = get_service_name_for_destination(dest_ip, dest_port);
            const char* media_type = "Media";
            
            if (strcmp(stream_type, "ROUTE") == 0) {
                media_type = get_media_type_from_stsid(dest_ip, dest_port, id);
            } else if (strcmp(stream_type, "MMT") == 0) {
                media_type = get_media_type_from_mpt(dest_ip, dest_port, id);
            }
            
            if (service_name) {
                snprintf(ext_desc_buffer, sizeof(ext_desc_buffer), "%s - %s %s", 
                        service_name, stream_type, media_type);
            } else {
                snprintf(ext_desc_buffer, sizeof(ext_desc_buffer), "%s %s Stream", stream_type, media_type);
            }
            return ext_desc_buffer;
        }
    }
    
    return NULL; // Not found
}

const char* get_service_name_for_destination(const char* dest_ip, const char* dest_port) {
    static char udst_name_buffer[128];
    
    // Special case for LLS
    if (strcmp(dest_ip, "224.0.23.60") == 0 && strcmp(dest_port, "4937") == 0) {
        return "LLS Signaling";
    }
    
    // Special case for BPS
    if (is_bps_service(dest_ip, dest_port)) {
        return "BPS Packet(s)";
    }
    
    // Look through all SLT entries to find service name
    for (int i = 0; i < g_lls_table_count; i++) {
        if (g_lls_tables[i].type == TABLE_TYPE_SLT) {
            SltData* slt_data = (SltData*)g_lls_tables[i].parsed_data;
            ServiceInfo* service = slt_data->head;
            while (service) {
                if (strcmp(service->slsDestinationIpAddress, dest_ip) == 0 &&
                    strcmp(service->slsDestinationUdpPort, dest_port) == 0) {
                    return service->shortServiceName;
                }
                service = service->next;
            }
        }
    }
    
    // Look through UDST entries for BroadSpan services and simple UDS
    for (int i = 0; i < g_lls_table_count; i++) {
        if (g_lls_tables[i].type == TABLE_TYPE_UDST) {
            UdstData* udst_data = (UdstData*)g_lls_tables[i].parsed_data;
            if (!udst_data) continue;
            
            // Check simple UDS entries
            UdsData* uds = udst_data->head_uds;
            while (uds) {
                if (strcmp(uds->destIP, dest_ip) == 0 && strcmp(uds->destPort, dest_port) == 0) {
                    if (uds->name[0]) {
                        return uds->name;
                    } else if (uds->contextId[0]) {
                        return uds->contextId;
                    }
                }
                uds = uds->next;
            }
            
            // Check BroadSpan services
            BroadSpanServiceInfo* bss = udst_data->head_service;
            while (bss) {
                RsrvInfo* rsrv = bss->head_rsrv;
                if (rsrv && strcmp(rsrv->destIP, dest_ip) == 0 && strcmp(rsrv->destPort, dest_port) == 0) {
                    // Return a shortened version of the service name
                    if (bss->name[0]) {
                        // Extract just the meaningful part (e.g., "RTK" from the full gsid)
                        const char* type_start = strstr(bss->name, "(");
                        if (type_start) {
                            // Name already has type appended like "tag:... (RTK)"
                            snprintf(udst_name_buffer, sizeof(udst_name_buffer), "BroadSpan %s", type_start);
                        } else {
                            snprintf(udst_name_buffer, sizeof(udst_name_buffer), "BroadSpan: %.100s", bss->name);
                        }
                        return udst_name_buffer;
                    }
                }
                bss = bss->next;
            }
        }
    }
    
    // Look through standalone UDS tables
    for (int i = 0; i < g_lls_table_count; i++) {
        if (g_lls_tables[i].type == TABLE_TYPE_UDS) {
            UdsData* uds = (UdsData*)g_lls_tables[i].parsed_data;
            if (uds && strcmp(uds->destIP, dest_ip) == 0 && strcmp(uds->destPort, dest_port) == 0) {
                if (uds->name[0]) {
                    return uds->name;
                } else if (uds->contextId[0]) {
                    return uds->contextId;
                }
            }
        }
    }
    
    return NULL;
}

/**
 * @brief Extracts the TSI from an LCT header per RFC 5651.
 *
 * The LCT header layout depends on flag bits in bytes 0-1:
 *   Byte 0: V(4) | C(2) | r(2)
 *   Byte 1: S(1) | O(2) | H(1) | T(1) | R(1) | A(1) | B(1)
 *   Byte 2: HDR_LEN (total header length in 32-bit words)
 *   Byte 3: CP (codepoint)
 *   Then: CCI  = 4*(C+1) bytes
 *   Then: TSI  = 4*S + 2*H bytes
 *   Then: TOI  = 4*O + 2*H bytes
 *
 * @return TSI value, or 0xFFFFFFFF on error
 */
uint32_t get_lct_tsi(const u_char* payload, int len) {
    if (len < 4) return 0xFFFFFFFF;
    
    uint8_t version = (payload[0] >> 4) & 0x0F;
    if (version != 1) return 0xFFFFFFFF;
    
    uint8_t c_flag = (payload[0] >> 2) & 0x03;
    uint8_t s_flag = (payload[1] >> 7) & 0x01;
    uint8_t o_flag = (payload[1] >> 5) & 0x03;
    uint8_t h_flag = (payload[1] >> 4) & 0x01;
    
    uint8_t hdr_len_words = payload[2];
    if (hdr_len_words < 2 || hdr_len_words > 30) return 0xFFFFFFFF;
    
    size_t cci_len = 4 * (c_flag + 1);
    size_t tsi_len = 4 * s_flag + 2 * h_flag;
    size_t toi_len = 4 * o_flag + 2 * h_flag;
    size_t min_hdr_bytes = 4 + cci_len + tsi_len + toi_len;
    size_t hdr_bytes = (size_t)hdr_len_words * 4;
    
    if (hdr_bytes < min_hdr_bytes) return 0xFFFFFFFF;
    if (tsi_len == 0) return 0xFFFFFFFF;
    
    size_t tsi_offset = 4 + cci_len;
    if ((int)(tsi_offset + tsi_len) > len) return 0xFFFFFFFF;
    
    const uint8_t* tsi_ptr = (const uint8_t*)payload + tsi_offset;
    uint32_t tsi;
    if (tsi_len == 2) tsi = (tsi_ptr[0] << 8) | tsi_ptr[1];
    else if (tsi_len == 4) tsi = ntohl(*(uint32_t*)tsi_ptr);
    else if (tsi_len == 6) tsi = ntohl(*(uint32_t*)(tsi_ptr + 2));
    else return 0xFFFFFFFF;
    
    // Debug dump for suspected bogus TSIs
    if (tsi == 1004 || tsi == 1006 || tsi == 1283) {
        int dump_len = (int)hdr_bytes + 8;
        if (dump_len > 48) dump_len = 48;
        if (dump_len > len) dump_len = len;
        
        DBG_PRINTF("SUSPECT_TSI %u (0x%x): V=%u C=%u S=%u O=%u H=%u | HDR_LEN=%u (%zu bytes) | CP=%u\n",
               tsi, tsi, version, c_flag, s_flag, o_flag, h_flag,
               hdr_len_words, hdr_bytes, (unsigned)payload[3]);
        DBG_PRINTF("  CCI=%zu bytes @4, TSI=%zu bytes @%zu, TOI=%zu bytes @%zu | min_hdr=%zu actual=%zu\n",
               cci_len, tsi_len, tsi_offset, toi_len, 4 + cci_len + tsi_len, min_hdr_bytes, hdr_bytes);
        DBG_PRINTF("  Raw %d bytes:", dump_len);
        for (int i = 0; i < dump_len; i++) {
            if (i == 4) DBG_PRINTF(" |CCI:");
            if (i == (int)(4 + cci_len)) DBG_PRINTF(" |TSI:");
            if (i == (int)(4 + cci_len + tsi_len)) DBG_PRINTF(" |TOI:");
            if (i == (int)hdr_bytes) DBG_PRINTF(" |PAYLOAD:");
            DBG_PRINTF(" %02x", (unsigned char)payload[i]);
        }
        DBG_PRINTF("\n");
    }
    
    return tsi;
}

/**
 * @brief Extracts the TOI from an LCT header per RFC 5651.
 * @return TOI value, or 0xFFFFFFFF on error
 */
uint32_t get_lct_toi(const u_char* payload, int len) {
    if (len < 4) return 0xFFFFFFFF;
    
    uint8_t version = (payload[0] >> 4) & 0x0F;
    if (version != 1) return 0xFFFFFFFF;
    
    uint8_t c_flag = (payload[0] >> 2) & 0x03;
    uint8_t s_flag = (payload[1] >> 7) & 0x01;
    uint8_t o_flag = (payload[1] >> 5) & 0x03;
    uint8_t h_flag = (payload[1] >> 4) & 0x01;
    
    uint8_t hdr_len_words = payload[2];
    if (hdr_len_words < 2 || hdr_len_words > 30) return 0xFFFFFFFF;
    
    size_t cci_len = 4 * (c_flag + 1);
    size_t tsi_len = 4 * s_flag + 2 * h_flag;
    size_t toi_len = 4 * o_flag + 2 * h_flag;
    size_t min_hdr_bytes = 4 + cci_len + tsi_len + toi_len;
    size_t hdr_bytes = (size_t)hdr_len_words * 4;
    
    if (hdr_bytes < min_hdr_bytes) return 0xFFFFFFFF;
    if (toi_len == 0) return 0xFFFFFFFF;
    
    size_t toi_offset = 4 + cci_len + tsi_len;
    if ((int)(toi_offset + toi_len) > len) return 0xFFFFFFFF;
    
    const uint8_t* toi_ptr = (const uint8_t*)payload + toi_offset;
    if (toi_len == 2) return (toi_ptr[0] << 8) | toi_ptr[1];
    else if (toi_len == 4) return ntohl(*(uint32_t*)toi_ptr);
    else if (toi_len >= 6) return ntohl(*(uint32_t*)(toi_ptr + toi_len - 4));
    return 0xFFFFFFFF;
}

/**
 * @brief Calculates the total length of an LCT header based on the HDR_LEN field.
 */
uint16_t get_route_header_length(const u_char* payload, int len) {
    // The LCT header requires at least 4 bytes to read HDR_LEN.
    if (len < 4) return 0;
    
    // Read the HDR_LEN field from the 3rd byte (index 2).
    // HDR_LEN is the total header length in 32-bit words.
    uint8_t hdr_len_words = payload[2];
    uint16_t total_header_len = hdr_len_words * 4;

    // Sanity check: The header length cannot be smaller than the minimum LCT header
    // that contains the length field itself, and it cannot exceed the total packet payload length.
    if (total_header_len < 4 || total_header_len > len) {
        return 0;
    }

    return total_header_len;
}

/**
 * @brief Calculates the offset to the ROUTE payload by accounting for both the
 * LCT header and the FEC Payload ID.
 * @return The calculated offset in bytes, or 0 on failure.
 */
uint16_t get_route_payload_offset(const u_char* payload, int len) {
    uint16_t lct_header_len = get_route_header_length(payload, len);
    if (lct_header_len == 0) return 0;

    // The FEC Payload ID is only present for ROUTE/ALC. For TSI=0 (signaling),
    // it consists of a 4-byte field.
    /*uint16_t fec_payload_id_len = 0;
    uint32_t tsi = get_lct_tsi(payload, len);
    if (tsi == 0) {
        fec_payload_id_len = 4;
    }*/
    uint16_t fec_payload_id_len = 4;

    uint16_t total_offset = lct_header_len + fec_payload_id_len;
    
    // Final sanity check
    if (total_offset > len) {
        return 0;
    }

    return total_offset;
}

int is_esg_service(const char* destIp, const char* destPort) {
    //printf("DEBUG ESG CHECK: Checking if %s:%s is ESG service\n", destIp, destPort);
    for(int i = 0; i < g_service_dest_count; i++) {
        if(strcmp(g_service_dests[i].destinationIpStr, destIp) == 0 &&
           strcmp(g_service_dests[i].destinationPortStr, destPort) == 0) {
            //printf("DEBUG ESG CHECK: Found service, category=%s, isEsgService=%d\n", 
            //       g_service_dests[i].serviceCategory, g_service_dests[i].isEsgService);
            return g_service_dests[i].isEsgService;
        }
    }
    //printf("DEBUG ESG CHECK: Service not found in g_service_dests\n");
    return 0;
}

/**
 * @brief Check if a destination is an eGPS service
 */
int is_egps_service(const char* destIp, const char* destPort) {
    for(int i = 0; i < g_service_dest_count; i++) {
        if(strcmp(g_service_dests[i].destinationIpStr, destIp) == 0 &&
           strcmp(g_service_dests[i].destinationPortStr, destPort) == 0) {
            return g_service_dests[i].isEgpsService;
        }
    }
    return 0;
}

/**
 * @brief Enhanced function to detect truncated/corrupted duplicates
 */
int is_truncated_duplicate(const char* content1, const char* content2) {
    if (!content1 || !content2) return 0;
    
    size_t len1 = strlen(content1);
    size_t len2 = strlen(content2);
    
    // If lengths are identical, do exact comparison
    if (len1 == len2) {
        return strcmp(content1, content2) == 0;
    }
    
    // Must be substantial content to consider for duplicate detection
    if (len1 < 200 || len2 < 200) return 0;
    
    // Extract root element names for both documents
    char root1[64] = "";
    char root2[64] = "";
    
    // Find first root element in content1
    const char* start1 = strstr(content1, "<");
    if (start1) {
        start1 = strstr(start1, "<S-TSID") ? strstr(start1, "<S-TSID") : 
                 strstr(start1, "<MPD") ? strstr(start1, "<MPD") :
                 strstr(start1, "<FDT-Instance") ? strstr(start1, "<FDT-Instance") : NULL;
        if (start1) {
            const char* end1 = strchr(start1 + 1, ' ');
            if (!end1) end1 = strchr(start1 + 1, '>');
            if (end1) {
                int root_len = (end1 - start1 - 1) < 63 ? (end1 - start1 - 1) : 63;
                strncpy(root1, start1 + 1, root_len);
                root1[root_len] = '\0';
            }
        }
    }
    
    // Find first root element in content2
    const char* start2 = strstr(content2, "<");
    if (start2) {
        start2 = strstr(start2, "<S-TSID") ? strstr(start2, "<S-TSID") : 
                 strstr(start2, "<MPD") ? strstr(start2, "<MPD") :
                 strstr(start2, "<FDT-Instance") ? strstr(start2, "<FDT-Instance") : NULL;
        if (start2) {
            const char* end2 = strchr(start2 + 1, ' ');
            if (!end2) end2 = strchr(start2 + 1, '>');
            if (end2) {
                int root_len = (end2 - start2 - 1) < 63 ? (end2 - start2 - 1) : 63;
                strncpy(root2, start2 + 1, root_len);
                root2[root_len] = '\0';
            }
        }
    }
    
    // Only compare documents with the same root element
    if (strlen(root1) == 0 || strlen(root2) == 0 || strcmp(root1, root2) != 0) {
        return 0;
    }
    
    // Find the main content portion of each document (after XML declaration)
    const char* main1 = strstr(content1, root1);
    const char* main2 = strstr(content2, root2);
    
    if (!main1 || !main2) return 0;
    
    // Compare the beginnings - look for substantial overlap
    size_t compare_len = (len1 < len2) ? len1 / 2 : len2 / 2;  // Compare first half of shorter doc
    if (compare_len < 500) compare_len = 500;  // Minimum comparison length
    
    if (main1 - content1 + compare_len > len1) compare_len = len1 - (main1 - content1);
    if (main2 - content2 + compare_len > len2) compare_len = len2 - (main2 - content2);
    
    // Check if the main portions match for the comparison length
    if (memcmp(main1, main2, compare_len) == 0) {
        // They start the same - now check if one is truncated/corrupted
        
        // Look for proper closing tag in both
        char closing_tag[70];
        snprintf(closing_tag, sizeof(closing_tag), "</%s>", root1);
        
        const char* close1 = strstr(content1, closing_tag);
        const char* close2 = strstr(content2, closing_tag);
        
        // If one has proper closing and the other doesn't, it's likely a truncated duplicate
        if (close1 && !close2) {
            return 1;  // content1 is complete, content2 is truncated
        }
        if (!close1 && close2) {
            return 1;  // content2 is complete, content1 is truncated
        }
        
        // If both have closing tags, check if one is clearly shorter/incomplete
        if (close1 && close2) {
            size_t doc1_end = (close1 - content1) + strlen(closing_tag);
            size_t doc2_end = (close2 - content2) + strlen(closing_tag);
            
            // If there's significant length difference and substantial content match,
            // consider it a duplicate where one has extra content appended
            if (abs((int)(doc1_end - doc2_end)) > 100 && compare_len > 1000) {
                return 1;
            }
        }
        
        // Additional check: if one document has corrupted content after the main portion
        // (like XML declarations in the middle), it's likely corrupted
        const char* xml_decl_mid1 = strstr(main1 + 100, "<?xml");
        const char* xml_decl_mid2 = strstr(main2 + 100, "<?xml");
        
        if ((xml_decl_mid1 && !xml_decl_mid2) || (!xml_decl_mid1 && xml_decl_mid2)) {
            return 1;  // One has corrupted content
        }
    }
    
    return 0;
}

char* normalize_xml_declaration(const char* xml_content) {
    if (!xml_content) return NULL;
    
    // Skip XML declaration if present
    const char* content_start = xml_content;
    if (strncmp(xml_content, "<?xml", 5) == 0) {
        const char* decl_end = strstr(xml_content, "?>");
        if (decl_end) {
            content_start = decl_end + 2;
            // Skip any whitespace after declaration
            while (*content_start && isspace(*content_start)) {
                content_start++;
            }
        }
    }
    
    return strdup(content_start);
}

/**
 * @brief Normalizes XML content by removing/standardizing commonly changing values
 * @param xml_content Original XML content
 * @param normalized_buffer Output buffer for normalized content
 * @param buffer_size Size of output buffer
 * @return 0 on success, -1 on failure
 */
int normalize_xml_content(const char* xml_content, char* normalized_buffer, size_t buffer_size) {
    if (!xml_content || !normalized_buffer || buffer_size == 0) return -1;
    
    strncpy(normalized_buffer, xml_content, buffer_size - 1);
    normalized_buffer[buffer_size - 1] = '\0';
    
    // For metadataEnvelope: normalize version numbers to a placeholder
    if (strstr(normalized_buffer, "<metadataEnvelope")) {
        char* version_start = strstr(normalized_buffer, "version=\"");
        while (version_start) {
            version_start += 9; // Skip 'version="'
            char* version_end = strchr(version_start, '"');
            if (version_end) {
                // Replace version number with placeholder
                memmove(version_start + 9, version_end, strlen(version_end) + 1);
                memcpy(version_start, "XXXXXXXXX", 9);
            }
            version_start = strstr(version_end ? version_end : normalized_buffer, "version=\"");
        }
    }
    
    // Normalize afdt:efdtVersion attribute
    char* pos = normalized_buffer;
    while ((pos = strstr(pos, "afdt:efdtVersion=\"")) != NULL) {
        pos += 18; // Skip 'afdt:efdtVersion="'
        char* end_quote = strchr(pos, '"');
        if (end_quote) {
            // Replace version number with X's
            while (pos < end_quote) {
                *pos = 'X';
                pos++;
            }
        } else {
            break;
        }
    }
    
    // For S-TSID: normalize startTime attribute (changes every second)
    if (strstr(normalized_buffer, "<S-TSID") || strstr(normalized_buffer, "<RS ")) {
        pos = normalized_buffer;
        while ((pos = strstr(pos, "startTime=\"")) != NULL) {
            pos += 11; // Skip 'startTime="'
            char* end_quote = strchr(pos, '"');
            if (end_quote) {
                // Replace timestamp with X's
                while (pos < end_quote) {
                    *pos = 'X';
                    pos++;
                }
            } else {
                break;
            }
        }
    }
    
    // For MPD: normalize publishTime and timeline t values
    if (strstr(normalized_buffer, "<MPD")) {
        
        // Normalize publishTime
        char* publish_start = strstr(normalized_buffer, "publishTime=\"");
        if (publish_start) {
            publish_start += 13; // Skip 'publishTime="'
            char* publish_end = strchr(publish_start, '"');
            if (publish_end && publish_end > publish_start) { // Make sure we found a different quote
                size_t time_len = publish_end - publish_start;
                
                // Replace each character with 'X'
                for (size_t i = 0; i < time_len; i++) {
                    publish_start[i] = 'X';
                }
                
            } 
        } 
        
        // Normalize SegmentTimeline t values - CONSISTENT WITH PUBLISHTIME
        // Normalize ALL t attributes anywhere in the document
        char* pos = normalized_buffer;
        while ((pos = strstr(pos, " t=\"")) != NULL) {
            pos += 4; // Skip ' t="'
            char* end_quote = strchr(pos, '"');
            if (end_quote) {
                while (pos < end_quote) {
                    *pos = 'X';
                    pos++;
                }
            } else {
                break;
            }
        }
        
    }
    
    return 0;
}

/**
 * @brief Checks if two XML documents are functionally equivalent (ignoring version/timestamp changes)
 * @param content1 First XML document
 * @param content2 Second XML document
 * @return 1 if functionally equivalent, 0 if different
 */
int is_functionally_equivalent(const char* content1, const char* content2) {
    if (!content1 || !content2) return 0;
    
    // Quick exact match check first
    if (strcmp(content1, content2) == 0) return 1;
    
    // Normalize XML declarations FIRST
    char* normalized1 = normalize_xml_declaration(content1);
    char* normalized2 = normalize_xml_declaration(content2);
    
    if (!normalized1 || !normalized2) {
        free(normalized1);
        free(normalized2);
        return 0;
    }
    
    // Check if they match after removing declarations
    int match = (strcmp(normalized1, normalized2) == 0);
    
    free(normalized1);
    free(normalized2);
    
    if (match) return 1;
    
    // Check if both are same document type
    char doc_type1[64] = "";
    char doc_type2[64] = "";
    
    // Extract root element names
    const char* start1 = strchr(content1, '<');
    const char* start2 = strchr(content2, '<');
    
    if (start1 && start2) {
        // Skip XML declaration if present
        if (strncmp(start1, "<?xml", 5) == 0) {
            start1 = strstr(start1, "<") + 1;
            start1 = strchr(start1, '<');
        }
        if (strncmp(start2, "<?xml", 5) == 0) {
            start2 = strstr(start2, "<") + 1;
            start2 = strchr(start2, '<');
        }
        
        if (start1 && start2) {
            const char* end1 = strpbrk(start1 + 1, " >");
            const char* end2 = strpbrk(start2 + 1, " >");
            
            if (end1 && end2) {
                size_t len1 = end1 - start1 - 1;
                size_t len2 = end2 - start2 - 1;
                
                if (len1 < sizeof(doc_type1) && len2 < sizeof(doc_type2)) {
                    strncpy(doc_type1, start1 + 1, len1);
                    doc_type1[len1] = '\0';
                    strncpy(doc_type2, start2 + 1, len2);
                    doc_type2[len2] = '\0';
                }
            }
        }
    }
    
    // Only compare documents of the same type
    if (strlen(doc_type1) == 0 || strlen(doc_type2) == 0 || strcmp(doc_type1, doc_type2) != 0) {
        return 0;
    }
    
    // Normalize both documents and compare (for timestamp/version differences)
    char normalized_content1[65536];
    char normalized_content2[65536];
    
    if (normalize_xml_content(content1, normalized_content1, sizeof(normalized_content1)) != 0 ||
        normalize_xml_content(content2, normalized_content2, sizeof(normalized_content2)) != 0) {
        return 0;
    }
    
    match = (strcmp(normalized_content1, normalized_content2) == 0);

    return match;
}

/**
 * @brief Enhanced duplicate removal that handles functional equivalence
 */
void remove_functionally_duplicate_tables() {
    int removed_count = 0;
    
    DBG_PRINTF("Starting enhanced deduplication...\n");
    
    for (int i = 0; i < g_lls_table_count; i++) {
        if (!g_lls_tables[i].content_id) continue;
        
        for (int j = i + 1; j < g_lls_table_count; j++) {
            if (!g_lls_tables[j].content_id) continue;
            
            // Only check tables of same type and destination
            if (g_lls_tables[i].type != g_lls_tables[j].type) continue;
            if (strcmp(g_lls_tables[i].destinationIp, g_lls_tables[j].destinationIp) != 0) continue;
            if (strcmp(g_lls_tables[i].destinationPort, g_lls_tables[j].destinationPort) != 0) continue;
            
            size_t len_i = strlen(g_lls_tables[i].content_id);
            size_t len_j = strlen(g_lls_tables[j].content_id);
            
            // Check for exact duplicates
            if (len_i == len_j && strcmp(g_lls_tables[i].content_id, g_lls_tables[j].content_id) == 0) {
                DBG_PRINTF("Found exact duplicate: type=%d, removing entry %d\n", g_lls_tables[i].type, j);
                free(g_lls_tables[j].content_id);
                free_parsed_data(&g_lls_tables[j]);
                g_lls_tables[j].content_id = NULL;
                removed_count++;
                continue;
            }
            
            // NEW: Check if one is a truncated/corrupted version of the other
            // If one is much shorter and is a prefix of the longer one, it's corrupted
            size_t min_len = (len_i < len_j) ? len_i : len_j;
            size_t max_len = (len_i > len_j) ? len_i : len_j;
            
            // If lengths differ by more than 20% and the shorter one matches the start of the longer
            if (max_len > min_len * 1.1) {
                int is_prefix = (memcmp(g_lls_tables[i].content_id, g_lls_tables[j].content_id, min_len) == 0);
                
                if (is_prefix) {
                    // Keep the longer (more complete) one
                    int remove_index = (len_i < len_j) ? i : j;
                    int keep_index = (len_i >= len_j) ? i : j;
                    
                    DBG_PRINTF("Found truncated duplicate: type=%d, keeping longer version (len=%zu), removing shorter (len=%zu)\n", 
                           g_lls_tables[i].type, 
                           strlen(g_lls_tables[keep_index].content_id),
                           strlen(g_lls_tables[remove_index].content_id));
                    
                    free(g_lls_tables[remove_index].content_id);
                    free_parsed_data(&g_lls_tables[remove_index]);
                    g_lls_tables[remove_index].content_id = NULL;
                    removed_count++;
                    
                    if (remove_index == i) {
                        break; // i was removed, move to next i
                    }
                    continue;
                }
            }
            
            if (is_functionally_equivalent(g_lls_tables[i].content_id, g_lls_tables[j].content_id)) {
                // Determine which one to keep (prefer more recent timestamp if available)
                int remove_index = i; // Default: keep the NEWER one (j), remove the older (i)
                
                // For MPD documents, keep the one with more recent publishTime
                if (g_lls_tables[i].type == TABLE_TYPE_MPD) {
                    char* pub1 = strstr(g_lls_tables[i].content_id, "publishTime=\"");
                    char* pub2 = strstr(g_lls_tables[j].content_id, "publishTime=\"");
                    
                    if (pub1 && pub2) {
                        // Simple string comparison works for ISO timestamps
                        if (strncmp(pub1 + 13, pub2 + 13, 19) > 0) {
                            // i is NEWER, keep i, remove j
                            remove_index = j;
                        }
                        // else: j is newer or equal, remove i (already set)
                    }
                }
                
                // For S-TSID documents, keep the one with higher efdtVersion
                if (g_lls_tables[i].type == TABLE_TYPE_STSID) {
                    char* ver1 = strstr(g_lls_tables[i].content_id, "afdt:efdtVersion=\"");
                    char* ver2 = strstr(g_lls_tables[j].content_id, "afdt:efdtVersion=\"");
                    
                    if (ver1 && ver2) {
                        int version1 = atoi(ver1 + 18);
                        int version2 = atoi(ver2 + 18);
                        
                        if (version1 > version2) {
                            remove_index = j;
                        }
                    }
                }
                
                // For metadataEnvelope, try to keep the one with higher version
                if (g_lls_tables[i].type == TABLE_TYPE_SERVICE_SIGNALING) {
                    char* ver1 = strstr(g_lls_tables[i].content_id, "version=\"");
                    char* ver2 = strstr(g_lls_tables[j].content_id, "version=\"");
                    
                    if (ver1 && ver2) {
                        int version1 = atoi(ver1 + 9);
                        int version2 = atoi(ver2 + 9);
                        
                        if (version1 > version2) {
                            // i has higher version, keep i
                            remove_index = j;
                        } else {
                            // j has higher version, keep j
                            remove_index = i;
                        }
                    }
                }
                
                // Free the duplicate entry
                free(g_lls_tables[remove_index].content_id);
                free_parsed_data(&g_lls_tables[remove_index]);
                g_lls_tables[remove_index].content_id = NULL;
                g_lls_tables[remove_index].parsed_data = NULL;
                
                // Shift remaining entries down
                for (int k = remove_index; k < g_lls_table_count - 1; k++) {
                    g_lls_tables[k] = g_lls_tables[k + 1];
                }
                g_lls_table_count--;
                removed_count++;
                
                // Adjust loop indices since we removed an entry
                if (remove_index <= i) i--;
                if (remove_index < j) j--;
                
                break; // Found duplicate, move to next i
            }
        }
    }
    
    // Compact the array by removing NULL entries
    int write_idx = 0;
    for (int read_idx = 0; read_idx < g_lls_table_count; read_idx++) {
        if (g_lls_tables[read_idx].content_id != NULL) {
            if (write_idx != read_idx) {
                g_lls_tables[write_idx] = g_lls_tables[read_idx];
            }
            write_idx++;
        }
    }
    g_lls_table_count = write_idx;
    
    DBG_PRINTF("Deduplication complete: removed %d duplicates, %d tables remaining\n", 
           removed_count, g_lls_table_count);
}

/**
 * @brief Processes ROUTE packets. Buffers fragments based on a unique key of
 * IP, Port, and TOI. This ensures streams don't get mixed.
 */
void process_route_payload(const u_char* payload, int len, const char* destIp, const char* destPort) {
    if (len < 16) return; 

    uint32_t tsi = get_lct_tsi(payload, len);
    uint32_t toi = get_lct_toi(payload, len);
    
    // Handle extraction errors
    if (tsi == 0xFFFFFFFF) tsi = 0;
    if (toi == 0xFFFFFFFF) toi = 0;
    
    const char* description = get_stream_description(destIp, destPort, tsi);
    (void)description;  // May be unused
    
    // ADD THIS DEBUG - shows ALL packets before filtering:
    if (tsi == 2) {
        int close_obj = (payload[1] & 0x01);
        int close_sess = (payload[1] & 0x02) >> 1;
        DBG_PRINTF("DEBUG TSI2 PACKET: TOI=%u, close_obj=%d, close_sess=%d, len=%d\n", 
               toi, close_obj, close_sess, len);
        uint16_t hdr_len = payload[2] * 4;
        uint32_t b_off = 0;
        if (len > hdr_len + 4) {
            b_off = ntohl(*(uint32_t*)(payload + hdr_len));
        }
        DBG_PRINTF("DEBUG TSI2 PACKET: TOI=%u, close_obj=%d, byte_offset=%u, pkt_len=%d\n", 
            toi, close_obj, b_off, len);
    }
    
    if (tsi != 0 && !is_esg_service(destIp, destPort) && !is_egps_service(destIp, destPort)) {
        // Allow reassembly for streams not matched to a known service,
        // but only if they're small enough to be signaling/metadata/images
        // (not media streams which would be huge).
        const char* svc_name = get_service_name_for_destination(destIp, destPort);
        if (svc_name) {
            // Known service, non-zero TSI, not ESG/eGPS - skip (it's media)
            return;
        }
        // Unknown service - allow reassembly so we can identify the content
        // (e.g., broadcaster logos delivered as BMP via ROUTE)
    }

    int close_object_flag = (payload[1] & 0x01);
    int close_session_flag = (payload[1] & 0x02) >> 1;
    
    uint16_t header_len = payload[2] * 4;
    uint16_t payload_offset = get_route_payload_offset(payload, len);
    
    if (payload_offset == 0 || len <= payload_offset) {
        return;
    }

    // Extract byte offset from FEC Payload ID
    // For ESG and other data streams, FEC Payload ID is also present
    uint32_t byte_offset = 0;
    if (len > header_len + 4) {
        byte_offset = ntohl(*(uint32_t*)(payload + header_len));
        
        // Sanity check - signaling objects shouldn't be > 10MB
        if (byte_offset > 10 * 1024 * 1024) {
            return;
        }
    }

    // Reassembly logic - find or create buffer
    ReassemblyBuffer *current_buf = NULL;
    for (current_buf = g_reassembly_head; current_buf != NULL; current_buf = current_buf->next) {
        if (current_buf->toi == toi && 
            current_buf->tsi == tsi &&
            strcmp(current_buf->destinationIp, destIp) == 0 &&
            strcmp(current_buf->destinationPort, destPort) == 0) 
        {
            break;
        }
    }

    if (current_buf == NULL) {
        current_buf = calloc(1, sizeof(ReassemblyBuffer));
        if (!current_buf) return;
        current_buf->toi = toi;
        current_buf->tsi = tsi;
        current_buf->mmt_header_len = -1;
        strncpy(current_buf->destinationIp, destIp, sizeof(current_buf->destinationIp) - 1);
        current_buf->destinationIp[sizeof(current_buf->destinationIp) - 1] = '\0';
        strncpy(current_buf->destinationPort, destPort, sizeof(current_buf->destinationPort) - 1);
        current_buf->destinationPort[sizeof(current_buf->destinationPort) - 1] = '\0';
        current_buf->next = g_reassembly_head;
        g_reassembly_head = current_buf;
    }

    const u_char* data_to_copy = payload + payload_offset;
    int len_to_copy = len - payload_offset;
    
    // Calculate required buffer size
    size_t required_size = byte_offset + len_to_copy;
    
    // Resize buffer if needed
    if (required_size > current_buf->size) {
        uint8_t* new_buffer = realloc(current_buf->buffer, required_size);
        if (!new_buffer) {
            fprintf(stderr, "Failed to realloc reassembly buffer!\n");
            return;
        }
        
        // Zero-fill any gaps
        if (byte_offset > current_buf->size) {
            memset(new_buffer + current_buf->size, 0, byte_offset - current_buf->size);
        }
        
        current_buf->buffer = new_buffer;
        current_buf->size = required_size;
    }
    
    // Write data at the specified byte offset
    memcpy(current_buf->buffer + byte_offset, data_to_copy, len_to_copy);
    
    // Add detailed logging for ESG reassembly
    if (is_esg_service(destIp, destPort) && toi >= 5290 && toi <= 5300) {
        DBG_PRINTF("DEBUG REASSEMBLY DETAIL: TOI=%u, wrote %d bytes at offset %u, buffer now %zu bytes\n",
               toi, len_to_copy, byte_offset, current_buf->size);
        DBG_PRINTF("  Close flags: object=%d session=%d\n", close_object_flag, close_session_flag);
        DBG_PRINTF("  First 8 bytes at write position: ");
        for (int i = 0; i < 8 && i < len_to_copy; i++) {
            DBG_PRINTF("%02x ", data_to_copy[i]);
        }
        DBG_PRINTF("\n");
        DBG_PRINTF("  Buffer start (first 16 bytes): ");
        for (int i = 0; i < 16 && i < (int)current_buf->size; i++) {
            DBG_PRINTF("%02x ", current_buf->buffer[i]);
        }
        DBG_PRINTF("\n");
    }

if (close_object_flag || close_session_flag) {
        // Don't complete if buffer appears incomplete (starts with zeros and we expect more)
        int looks_incomplete = 0;
        if (current_buf->size > 100) {
            // Check if first 16 bytes are all zeros (missed start of object)
            int all_zeros = 1;
            for (int i = 0; i < 16 && i < (int)current_buf->size; i++) {
                if (current_buf->buffer[i] != 0) {
                    all_zeros = 0;
                    break;
                }
            }
            if (all_zeros && byte_offset > 0) {
                looks_incomplete = 1;
                DBG_PRINTF("DEBUG: Skipping incomplete TOI=%u (missed start, first data at offset %u)\n", 
                    toi, byte_offset);
            }
        }
        
        if (looks_incomplete) {
            // Don't process or free - wait for next carousel cycle to fill in the start
            return;
        }
        
        if (is_esg_service(destIp, destPort)) {
            DBG_PRINTF("DEBUG ESG REASSEMBLY: TOI=%u complete, size=%zu\n", toi, current_buf->size);
            DBG_PRINTF("First 16 bytes: ");
            for (int i = 0; i < 16 && i < (int)current_buf->size; i++) {
                DBG_PRINTF("%02x ", current_buf->buffer[i]);
            }
            DBG_PRINTF("\n");
            
            // Check for GZIP signature
            if (current_buf->size >= 2) {
                if (current_buf->buffer[0] == 0x1f && current_buf->buffer[1] == 0x8b) {
                    DBG_PRINTF("DEBUG ESG REASSEMBLY: Valid GZIP header found at start\n");
                } else {
                    // Search for GZIP header in first 100 bytes
                    int found_gzip = 0;
                    for (size_t i = 0; i < 100 && i < current_buf->size - 1; i++) {
                        if (current_buf->buffer[i] == 0x1f && current_buf->buffer[i+1] == 0x8b) {
                            DBG_PRINTF("DEBUG ESG REASSEMBLY: GZIP header found at offset %zu (NOT at start!)\n", i);
                            found_gzip = 1;
                            
                            // Create new buffer starting from GZIP header
                            size_t new_size = current_buf->size - i;
                            uint8_t* new_buffer = malloc(new_size);
                            if (new_buffer) {
                                memcpy(new_buffer, current_buf->buffer + i, new_size);
                                free(current_buf->buffer);
                                current_buf->buffer = new_buffer;
                                current_buf->size = new_size;
                                DBG_PRINTF("DEBUG ESG REASSEMBLY: Trimmed buffer to start at GZIP header, new size=%zu\n", new_size);
                            }
                            break;
                        }
                    }
                    
                    if (!found_gzip) {
                        DBG_PRINTF("DEBUG ESG REASSEMBLY: WARNING - No GZIP header found in reassembled object!\n");
                    }
                }
            }
        }
        
        // Debug logging for eGPS service
        if (is_egps_service(destIp, destPort)) {
            DBG_PRINTF("DEBUG eGPS REASSEMBLY: TOI=%u complete at %s:%s, size=%zu\n", 
                   toi, destIp, destPort, current_buf->size);
            DBG_PRINTF("First 16 bytes: ");
            for (int i = 0; i < 16 && i < (int)current_buf->size; i++) {
                DBG_PRINTF("%02x ", current_buf->buffer[i]);
            }
            DBG_PRINTF("\n");
            
            // Check for Cambium magic
            if (current_buf->size >= 2 && 
                current_buf->buffer[0] == 0xBC && current_buf->buffer[1] == 0xA1) {
                DBG_PRINTF("DEBUG eGPS: Found Cambium 0xBCA1 magic in reassembled object!\n");
            }
        }
        
        if (current_buf->size < 10) {
            // Buffer too small, discard silently
        } else {
            // Check for image formats in completed ROUTE objects
            if (current_buf->size >= 54 && 
                current_buf->buffer[0] == 'B' && current_buf->buffer[1] == 'M') {
                // BMP image detected
                uint32_t bmp_file_size = current_buf->buffer[2] | (current_buf->buffer[3] << 8) |
                                         (current_buf->buffer[4] << 16) | (current_buf->buffer[5] << 24);
                int32_t bmp_width = current_buf->buffer[18] | (current_buf->buffer[19] << 8) |
                                    (current_buf->buffer[20] << 16) | (current_buf->buffer[21] << 24);
                int32_t bmp_height = current_buf->buffer[22] | (current_buf->buffer[23] << 8) |
                                     (current_buf->buffer[24] << 16) | (current_buf->buffer[25] << 24);
                uint16_t bmp_bpp = current_buf->buffer[28] | (current_buf->buffer[29] << 8);
                
                // Use declared file size or buffer size, whichever is smaller
                size_t image_len = (bmp_file_size <= current_buf->size) ? bmp_file_size : current_buf->size;
                
                if (bmp_width > 0 && bmp_width <= 4096 && 
                    bmp_height != 0 && bmp_height >= -4096 && bmp_height <= 4096 &&
                    image_len <= MAX_ROUTE_IMAGE_SIZE) {
                    int abs_height = bmp_height < 0 ? -bmp_height : bmp_height;
                    store_route_image(destIp, destPort, tsi,
                                     current_buf->buffer, image_len,
                                     bmp_width, abs_height, bmp_bpp, "BMP");
                }
            }
            // Could add PNG (89 50 4E 47) and JPEG (FF D8 FF) detection here too
            else if (current_buf->size >= 8 &&
                     current_buf->buffer[0] == 0x89 && current_buf->buffer[1] == 0x50 &&
                     current_buf->buffer[2] == 0x4E && current_buf->buffer[3] == 0x47) {
                // PNG detected - store as-is (we can embed PNG directly)
                if (current_buf->size <= MAX_ROUTE_IMAGE_SIZE) {
                    store_route_image(destIp, destPort, tsi,
                                     current_buf->buffer, current_buf->size,
                                     0, 0, 0, "PNG");
                }
            }
            else if (current_buf->size >= 3 &&
                     current_buf->buffer[0] == 0xFF && current_buf->buffer[1] == 0xD8 &&
                     current_buf->buffer[2] == 0xFF) {
                // JPEG detected
                if (current_buf->size <= MAX_ROUTE_IMAGE_SIZE) {
                    store_route_image(destIp, destPort, tsi,
                                     current_buf->buffer, current_buf->size,
                                     0, 0, 0, "JPEG");
                }
            }
            
            process_and_store_route_object(current_buf->toi, current_buf->buffer, current_buf->size, 
                                        current_buf->destinationIp, current_buf->destinationPort);
        }
        
        // Remove from linked list
        if (g_reassembly_head == current_buf) {
            g_reassembly_head = current_buf->next;
        } else {
            ReassemblyBuffer* temp = g_reassembly_head;
            while(temp && temp->next != current_buf) {
                temp = temp->next;
            }
            if (temp) {
                temp->next = current_buf->next;
            }
        }
        
        free(current_buf->buffer);
        free(current_buf);
    }
}

/**
 * @brief Enhanced GZIP completion check with better debugging
 */
int is_gzip_complete(const uint8_t* buffer, size_t size) {
    if (size < 10) {
        #if DEBUG_MMT
        fprintf(stderr, "GZIP: Too small (%zu bytes)\n", size);
        #endif
        return 0;
    }
    
    // Find GZIP header within the buffer (it might not be at offset 0)
    const uint8_t gzip_magic[] = {0x1f, 0x8b};
    const uint8_t* gzip_start = NULL;
    
    for (size_t i = 0; i <= size - 10; i++) {
        if (memcmp(buffer + i, gzip_magic, 2) == 0) {
            gzip_start = buffer + i;
            #if DEBUG_MMT
            fprintf(stderr, "GZIP: Found header at offset %zu\n", i);
            #endif
            break;
        }
    }
    
    if (!gzip_start) {
        #if DEBUG_MMT
        fprintf(stderr, "GZIP: No header found in %zu bytes\n", size);
        #endif
        return 0;
    }
    
    size_t gzip_size = size - (gzip_start - buffer);
    
    #if DEBUG_MMT
    fprintf(stderr, "GZIP: Checking %zu bytes starting at offset %ld\n", 
            gzip_size, gzip_start - buffer);
    fprintf(stderr, "GZIP: First 16 bytes: ");
    for (int i = 0; i < 16 && i < gzip_size; i++) {
        fprintf(stderr, "%02x ", gzip_start[i]);
    }
    fprintf(stderr, "\n");
    fprintf(stderr, "GZIP: Last 16 bytes: ");
    for (int i = gzip_size - 16; i < gzip_size && i >= 0; i++) {
        fprintf(stderr, "%02x ", gzip_start[i]);
    }
    fprintf(stderr, "\n");
    #endif
    
    // Try to decompress to check completeness
    z_stream strm;
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;
    strm.avail_in = gzip_size;
    strm.next_in = (Bytef *)gzip_start;
    
    if (inflateInit2(&strm, 16 + MAX_WBITS) != Z_OK) {
        #if DEBUG_MMT
        fprintf(stderr, "GZIP: inflateInit2 failed\n");
        #endif
        return 0;
    }
    
    uint8_t temp_buf[4096];
    strm.avail_out = sizeof(temp_buf);
    strm.next_out = temp_buf;
    
    int ret = inflate(&strm, Z_SYNC_FLUSH);
    size_t bytes_produced = sizeof(temp_buf) - strm.avail_out;
    size_t bytes_consumed = gzip_size - strm.avail_in;
    
    #if DEBUG_MMT
    fprintf(stderr, "GZIP: inflate returned %d, consumed %zu/%zu bytes, produced %zu bytes\n", 
            ret, bytes_consumed, gzip_size, bytes_produced);
    #endif
    
    int complete = 0;
    if (ret == Z_STREAM_END) {
        complete = 1;
        #if DEBUG_MMT
        fprintf(stderr, "GZIP: Stream complete!\n");
        #endif
    } else if (ret == Z_OK && bytes_produced > 0) {
        // Partial success - check if we're close to complete
        if (bytes_consumed == gzip_size && gzip_size > 200) {
            complete = 1;  // Consumed all input and produced output
            #if DEBUG_MMT
            fprintf(stderr, "GZIP: Assuming complete (consumed all input)\n");
            #endif
        }
    } else {
        #if DEBUG_MMT
        fprintf(stderr, "GZIP: inflate failed or no progress\n");
        #endif
    }
    
    inflateEnd(&strm);
    
    // Fallback: if we have a lot of data and it starts with valid GZIP, assume complete
    if (!complete && gzip_size > 500) {
        complete = 1;
        #if DEBUG_MMT
        fprintf(stderr, "GZIP: Force complete due to size (%zu bytes)\n", gzip_size);
        #endif
    }
    
    return complete;
}

/**
 * @brief Helper function to check if an XML document is complete
 */
int is_xml_complete(const char* buffer, size_t size) {
    // Simple check: look for common closing tags
    const char* closing_tags[] = {
        "</MP_Table>", "</BundleDescriptionMMT>", "</DWD>",
        "</metadataEnvelope>", "</FDT-Instance>", NULL
    };
    
    for (int i = 0; closing_tags[i] != NULL; i++) {
        if (memmem(buffer, size, closing_tags[i], strlen(closing_tags[i]))) {
            return 1;
        }
    }
    
    // Fallback: count opening and closing angle brackets
    int open_count = 0, close_count = 0;
    int in_tag = 0;
    for (size_t i = 0; i < size; i++) {
        if (buffer[i] == '<' && i + 1 < size && buffer[i+1] != '/') {
            open_count++;
            in_tag = 1;
        } else if (buffer[i] == '<' && i + 1 < size && buffer[i+1] == '/') {
            close_count++;
            in_tag = 1;
        } else if (buffer[i] == '>' && in_tag) {
            in_tag = 0;
        }
    }
    
    // If we have balanced tags and reasonable data, consider it complete
    return (open_count > 0 && open_count == close_count);
}

/**
 * @brief Enhanced terminal payload processor with better ESG handling
 */
void process_terminal_payload(uint32_t toi, const uint8_t* buffer, size_t size, const char* destIp, const char* destPort, int is_mmt, uint16_t packet_id) {
    // Check for eGPS binary data (Cambium-style packets with 0xBCA1 magic)
    if (size >= 8 && buffer[0] == 0xBC && buffer[1] == 0xA1) {
        DBG_PRINTF("DEBUG eGPS: Found Cambium magic 0xBCA1 in TOI=%u at %s:%s, size=%zu\n", 
               toi, destIp, destPort, size);
        
        // Parse the eGPS packet(s)
        EgpsData* egps = parse_egps_stream(buffer, size, destIp, destPort);
        if (egps && egps->location_fix_count > 0) {
            DBG_PRINTF("DEBUG eGPS: Parsed %d location fix(es)\n", egps->location_fix_count);
            
            if (store_egps_data(egps)) {
                DBG_PRINTF("DEBUG eGPS: Stored eGPS data for %s:%s\n", destIp, destPort);
            } else {
                DBG_PRINTF("DEBUG eGPS: No space for more eGPS streams\n");
                free_egps_data(egps);
            }
        } else if (egps) {
            DBG_PRINTF("DEBUG eGPS: No valid fixes parsed from packet\n");
            free_egps_data(egps);
        }
        return;  // Don't process as XML
    }
    
    if (is_esg_service(destIp, destPort) && toi > 0) {
        DBG_PRINTF("DEBUG ESG TERMINAL: Processing TOI=%u payload, size=%zu\n", toi, size);
        
        // Check if it looks like XML
        if(size > 5 && memcmp(buffer, "<?xml", 5) == 0) {
            DBG_PRINTF("DEBUG ESG: Found XML content in TOI=%u\n", toi);
        } else if(size > 2 && buffer[0] == 0x1f && buffer[1] == 0x8b) {
            DBG_PRINTF("DEBUG ESG: Found GZIP content in TOI=%u\n", toi);
        } else {
            DBG_PRINTF("DEBUG ESG: Unknown content type in TOI=%u (first bytes: %02x %02x %02x %02x)\n", 
                   toi, 
                   size > 0 ? buffer[0] : 0x00,
                   size > 1 ? buffer[1] : 0x00, 
                   size > 2 ? buffer[2] : 0x00, 
                   size > 3 ? buffer[3] : 0x00);
            
            // For non-GZIP, non-XML data that's too small or looks corrupted, skip it
            if (size < 100 || (size > 0 && buffer[0] > 0x7F && buffer[0] != 0x1f)) {
                DBG_PRINTF("DEBUG ESG: Skipping likely corrupted or incomplete fragment\n");
                return;
            }
        }
    }
    
    // Skip leading whitespace (but not for binary data!)
    if (size > 0 && buffer[0] < 0x80) {  // Only skip whitespace for ASCII-range data
        while (size > 0 && isspace(*buffer)) {
            buffer++;
            size--;
        }
    }
    if (size == 0) return;

    char source_id[512];
    snprintf(source_id, sizeof(source_id), "TOI=%u on %s:%s", toi, destIp, destPort);

    const uint8_t gzip_magic[] = {0x1f, 0x8b};
    if (size > 2 && memcmp(buffer, gzip_magic, 2) == 0) {
        DBG_PRINTF("--> Found GZIP stream in TOI=%u. Decompressing...\n", toi);
        int decompressed_size = 0, consumed_size = 0;
        char* decompressed_xml = decompress_gzip(buffer, size, &decompressed_size, &consumed_size);
        
        if (decompressed_xml && decompressed_size > 0) {
            // For ESG, find and skip garbage before XML
            if (is_esg_service(destIp, destPort)) {
                DBG_PRINTF("DEBUG ESG: Searching for XML declaration in %d bytes\n", decompressed_size);
                
                // Manually search for "<?xml" pattern (don't use strstr - it stops at null bytes)
                const char* xml_pattern = "<?xml";
                const char* xml_start = NULL;
                
                for (size_t i = 0; i < decompressed_size - 5; i++) {
                    if (memcmp(decompressed_xml + i, xml_pattern, 5) == 0) {
                        xml_start = decompressed_xml + i;
                        break;
                    }
                }
                
                // If no "<?xml", try finding "<Content"
                if (!xml_start) {
                    const char* content_pattern = "<Content";
                    for (size_t i = 0; i < decompressed_size - 8; i++) {
                        if (memcmp(decompressed_xml + i, content_pattern, 8) == 0) {
                            xml_start = decompressed_xml + i;
                            break;
                        }
                    }
                }
                
                if (xml_start && xml_start != decompressed_xml) {
                    size_t garbage_bytes = xml_start - decompressed_xml;
                    DBG_PRINTF("DEBUG ESG: Found XML at offset %zu, removing %zu bytes of garbage\n", 
                        (size_t)(xml_start - decompressed_xml), garbage_bytes);
                    
                    // Create clean buffer
                    size_t clean_size = decompressed_size - garbage_bytes;
                    char* clean_xml = malloc(clean_size + 1);
                    if (clean_xml) {
                        memcpy(clean_xml, xml_start, clean_size);
                        clean_xml[clean_size] = '\0';
                        
                        // Replace the old buffer
                        free(decompressed_xml);
                        decompressed_xml = clean_xml;
                        decompressed_size = clean_size;
                        
                        DBG_PRINTF("DEBUG ESG: Cleaned buffer, new size=%zu\n", clean_size);
                        DBG_PRINTF("DEBUG ESG: First 100 clean chars: %.100s\n", decompressed_xml);
                    }
                } else if (xml_start) {
                    DBG_PRINTF("DEBUG ESG: XML starts at beginning, no garbage to remove\n");
                } else {
                    DBG_PRINTF("DEBUG ESG: ERROR - No XML found in decompressed data!\n");
                }
            
                // Show first 500 characters of decompressed content
                int show_len = (decompressed_size > 500) ? 500 : decompressed_size;
                DBG_PRINTF("DEBUG ESG CONTENT: %.*s%s\n", show_len, decompressed_xml, 
                    (decompressed_size > 500) ? "..." : "");
                
                // CRITICAL FIX: Check if there are multiple XML documents
                int xml_count = 0;
                const char* search_pos = decompressed_xml;
                const char* end_pos = decompressed_xml + decompressed_size;
                while (search_pos < end_pos) {
                    const char* found = memmem(search_pos, end_pos - search_pos, "<?xml", 5);
                    if (!found) break;
                    xml_count++;
                    search_pos = found + 5;
                }
                
                DBG_PRINTF("DEBUG ESG: Found %d XML declarations in decompressed data\n", xml_count);
                
                if (xml_count > 1) {
                    // Multiple documents - use the multi-document parser
                    DBG_PRINTF("DEBUG ESG: Processing as multi-document XML\n");
                    process_multi_document_xml(decompressed_xml, decompressed_size, destIp, destPort, source_id);
                } else {
                    // Single document - parse normally
                    TableType type = TABLE_TYPE_UNKNOWN;
                    void* parsed_data = NULL;
                    
                    if (parse_xml(decompressed_xml, decompressed_size, &type, &parsed_data, source_id) == 0 && parsed_data) {
                        DBG_PRINTF("DEBUG ESG STORE: Parsed XML type=%d, is_esg_service=%d\n", type, is_esg_service(destIp, destPort));
                        if (type == TABLE_TYPE_ESG_FRAGMENT) {
                            DBG_PRINTF("DEBUG ESG STORE: Storing ESG fragment for %s:%s\n", destIp, destPort);
                        }
                        store_unique_table(decompressed_xml, decompressed_size, type, parsed_data, destIp, destPort, 0, -1);
                        
                        DBG_PRINTF("DEBUG ESG SUCCESS: Successfully parsed TOI=%u as XML type %d\n", toi, type);
                    } else {
                        DBG_PRINTF("DEBUG ESG PARSE FAIL: Failed to parse decompressed content from TOI=%u\n", toi);
                        
                        // Try to identify why parsing failed
                        if (decompressed_size < 10) {
                            DBG_PRINTF("DEBUG ESG: Content too short (%d bytes)\n", decompressed_size);
                        } else if (memmem(decompressed_xml, decompressed_size, "<?xml", 5) == NULL) {
                            DBG_PRINTF("DEBUG ESG: No XML declaration found\n");
                        } else if (memmem(decompressed_xml, decompressed_size, "<", 1) == NULL) {
                            DBG_PRINTF("DEBUG ESG: No XML tags found\n");
                        } else {
                            DBG_PRINTF("DEBUG ESG: XML structure issue - check saved file\n");
                        }
                    }
                }
            } else {
                // Non-ESG service processing
                TableType type = TABLE_TYPE_UNKNOWN;
                void* parsed_data = NULL;
                
                if (parse_xml(decompressed_xml, decompressed_size, &type, &parsed_data, source_id) == 0 && parsed_data) {
                    store_unique_table(decompressed_xml, decompressed_size, type, parsed_data, destIp, destPort, 0, -1);
                }
            }
            
            free(decompressed_xml);
        } else {
            if (is_esg_service(destIp, destPort)) {
                DBG_PRINTF("DEBUG ESG GZIP FAIL: Failed to decompress TOI=%u, consumed=%d bytes\n", toi, consumed_size);
                
                // Dump raw GZIP data for analysis
                char gzip_filename[256];
                snprintf(gzip_filename, sizeof(gzip_filename), "esg_toi_%u_gzip_raw.bin", toi);
                FILE* f_gzip = fopen(gzip_filename, "wb");
                if (f_gzip) {
                    fwrite(buffer, 1, size, f_gzip);
                    fclose(f_gzip);
                    DBG_PRINTF("DEBUG ESG: Saved raw GZIP data to %s for analysis\n", gzip_filename);
                }
            }
        }
    } else if (size > 20) {
        DBG_PRINTF("--> Processing as plain text/XML in TOI=%u, size %zu\n", toi, size);

        int looks_incomplete = 0;
        if (size > 7) {
            // Check if it starts with a closing tag
            if (memcmp(buffer, "</", 2) == 0) {
                DBG_PRINTF("--> WARNING: XML fragment starts with closing tag, likely incomplete\n");
                looks_incomplete = 1;
            }
            // Check if there's an opening tag without a matching closing tag
            const char* opening_tags[] = {"<EFDT", "<FDT-Instance", "<S-TSID", "<MPD", NULL};
            for (int i = 0; opening_tags[i]; i++) {
                if (memmem(buffer, size > 100 ? 100 : size, opening_tags[i], strlen(opening_tags[i]))) {
                    // Found opening tag, look for closing tag
                    char closing_tag[64];
                    if (strcmp(opening_tags[i], "<FDT-Instance") == 0) {
                        strcpy(closing_tag, "</FDT-Instance>");
                    } else {
                        // Strip the '<' and add '</' and '>'
                        snprintf(closing_tag, sizeof(closing_tag), "</%s>", opening_tags[i] + 1);
                    }
                    
                    if (!memmem(buffer, size, closing_tag, strlen(closing_tag))) {
                        DBG_PRINTF("--> WARNING: Found %s but no matching closing tag, likely incomplete\n", opening_tags[i]);
                        looks_incomplete = 1;
                    }
                    break;
                }
            }
        }
        
        if (looks_incomplete) {
            DBG_PRINTF("--> Skipping incomplete XML fragment\n");
            return;  // Don't try to parse incomplete fragments
        }
        
        if (is_esg_service(destIp, destPort)) {
            DBG_PRINTF("DEBUG ESG PLAIN: Processing plain content from TOI=%u\n", toi);
            
            // Show first 200 chars
            int show_len = (size > 200) ? 200 : size;
            DBG_PRINTF("DEBUG ESG PLAIN CONTENT: %.*s%s\n", show_len, (char*)buffer, 
                   (size > 200) ? "..." : "");
        }
        
        TableType type = TABLE_TYPE_UNKNOWN;
        void* parsed_data = NULL;
        if (parse_xml((const char*)buffer, size, &type, &parsed_data, source_id) == 0) {
            if(parsed_data) {
                store_unique_table((const char*)buffer, size, type, parsed_data, destIp, destPort, 0, -1);
                
                if (is_esg_service(destIp, destPort)) {
                    DBG_PRINTF("DEBUG ESG SUCCESS: Successfully parsed plain TOI=%u as XML type %d\n", toi, type);
                }
            }
        } else {
            DBG_PRINTF("--> XML parsing failed for object in TOI=%u.\n", toi);
            
            if (is_esg_service(destIp, destPort)) {
                DBG_PRINTF("DEBUG ESG PLAIN FAIL: Failed to parse plain content from TOI=%u\n", toi);
            }
        }
    }
}

/**
 * @brief Parses a reassembled MIME object.
 * Updated to handle nested MIME structures (e.g. multipart/signed containing multipart/related).
 */
void process_mime_object(uint32_t toi, const uint8_t* buffer, size_t size, const char* boundary_str, const char* destIp, const char* destPort) {
    if (is_esg_service(destIp, destPort)) {
        DBG_PRINTF("DEBUG ESG MIME: Processing multipart ESG with boundary: %s\n", boundary_str);
    }
    size_t boundary_len = strlen(boundary_str);
    
    // Validate we have a complete MIME structure
    char final_boundary[300];
    snprintf(final_boundary, sizeof(final_boundary), "%s--", boundary_str);
    
    const uint8_t* final_marker = memmem(buffer, size, final_boundary, strlen(final_boundary));
    if (!final_marker) {
        DBG_PRINTF("WARN: MIME object missing final boundary marker, may be incomplete\n");
    }
    
    const uint8_t* current_pos = buffer;
    size_t remaining_size = size;
    
    // Skip to the first boundary
    const uint8_t* first_boundary = memmem(current_pos, remaining_size, boundary_str, boundary_len);
    if (!first_boundary) {
        DBG_PRINTF("ERROR: Could not find first boundary in MIME message\n");
        return;
    }
    
    current_pos = first_boundary;
    remaining_size = size - (current_pos - buffer);
    
    int part_count = 0;
    int max_parts = 100; // Safety limit
    
    while(part_count < max_parts) {
        const uint8_t* boundary_loc = memmem(current_pos, remaining_size, boundary_str, boundary_len);
        if(!boundary_loc) break;
        
        // Move past the boundary line (boundary + CRLF)
        const uint8_t* headers_start = boundary_loc + boundary_len;
        while (headers_start < buffer + size && (*headers_start == '\r' || *headers_start == '\n' || *headers_start == '-')) {
            headers_start++;
        }

        // Find the next boundary
        const uint8_t* next_boundary_loc = memmem(headers_start, size - (headers_start - buffer), boundary_str, boundary_len);
        if(!next_boundary_loc) {
            DBG_PRINTF("DEBUG MIME: No more boundaries found after part %d\n", part_count + 1);
            break;
        }

        // The part ends just before the next boundary (trim trailing CRLF)
        const uint8_t* part_end = next_boundary_loc;
        while (part_end > headers_start && (*(part_end - 1) == '\r' || *(part_end - 1) == '\n')) {
            part_end--;
        }

        if (part_end <= headers_start) {
            current_pos = next_boundary_loc;
            remaining_size = size - (current_pos - buffer);
            continue;
        }
        
        size_t part_len = part_end - headers_start;
        
        // Find the blank line that separates headers from content
        // Try standard CRLF first, then handle \r\r\n variant  
        const uint8_t* payload_start = memmem(headers_start, part_len, "\r\n\r\n", 4);
        size_t header_sep_len = 4;

        if (!payload_start) {
            payload_start = memmem(headers_start, part_len, "\r\r\n\r\r\n", 6);
            header_sep_len = 6;
        }

        if(payload_start) {
            // Calculate header length before advancing payload pointer
            size_t headers_len = payload_start - headers_start;

            payload_start += header_sep_len;
            size_t payload_len = part_end - payload_start;
            
            if (payload_len > 0) {
                part_count++;
                
                // --- NEW: Check headers for nested multipart ---
                int is_nested = 0;
                char nested_boundary[256] = "";

                // Make a temporary null-terminated copy of headers for easier string searching
                char* headers_copy = malloc(headers_len + 1);
                if (headers_copy) {
                    memcpy(headers_copy, headers_start, headers_len);
                    headers_copy[headers_len] = '\0';
                    
                    // Check for Content-Type: multipart/...
                    if (strcasestr(headers_copy, "Content-Type") && strcasestr(headers_copy, "multipart/")) {
                        char* b_ptr = strcasestr(headers_copy, "boundary=");
                        if (b_ptr) {
                            b_ptr += 9; // skip "boundary="
                            if (*b_ptr == '"') b_ptr++; // skip quote if present
                            
                            char* b_end = strpbrk(b_ptr, "\";\r\n"); // Find end of token
                            if (b_end && b_end > b_ptr) {
                                size_t b_len = b_end - b_ptr;
                                if (b_len < 200) {
                                    // MIME boundaries used in the body must be prefixed with "--"
                                    snprintf(nested_boundary, sizeof(nested_boundary), "--%.*s", (int)b_len, b_ptr);
                                    is_nested = 1;
                                }
                            }
                        }
                    }
                    free(headers_copy);
                }

                if (is_nested) {
                    DBG_PRINTF("DEBUG MIME: Found nested multipart in part %d, recursing with boundary: %s\n", part_count, nested_boundary);
                    process_mime_object(toi, payload_start, payload_len, nested_boundary, destIp, destPort);
                } else {
                    // Standard leaf processing (XML, etc.)
                    // Validate this looks like valid XML before processing
                    int looks_valid = 0;
                    if (payload_len > 5) {
                        if (memcmp(payload_start, "<?xml", 5) == 0 ||
                            memcmp(payload_start, "<S-TSID", 7) == 0 ||
                            memcmp(payload_start, "<MPD", 4) == 0 ||
                            memcmp(payload_start, "<FDT-", 5) == 0 ||
                            memcmp(payload_start, "<HELD", 5) == 0 ||
                            // Also accept if it has Content- headers (sometimes stripped but good safety)
                            memcmp(payload_start, "Content-", 8) == 0) {
                            looks_valid = 1;
                        }
                    }
                    
                    if (!looks_valid) {
                        DBG_PRINTF("WARN MIME: Part %d doesn't look like valid XML, skipping\n", part_count);
                        // Fall through to update current_pos
                    } else {
                        process_terminal_payload(toi, payload_start, payload_len, destIp, destPort, 0, 0);
                    }
                }
            }
        } else {
            DBG_PRINTF("WARNING MIME: Could not find header separator for part %d\n", part_count + 1);
        }

        current_pos = next_boundary_loc;
        remaining_size = size - (current_pos - buffer);
    }
    
    if (part_count >= max_parts) {
        DBG_PRINTF("WARN: Hit maximum part limit (%d), stopping MIME processing\n", max_parts);
    }
    
    DBG_PRINTF("DEBUG MIME: Processed %d valid parts total\n", part_count);
}

/**
 * @brief FINAL: Top-level object processor. Scans a buffer for concatenated objects.
 */
void process_and_store_route_object(uint32_t toi, const uint8_t* buffer, size_t size, const char* destIp, const char* destPort) {
    if (size == 0) return;
    
    // Check for XML declarations
    int xml_count = 0;
    for (size_t i = 0; i < size - 5; i++) {
        if (memcmp(&buffer[i], "<?xml", 5) == 0) {
            xml_count++;
        }
    }

    // FIRST: Check for multipart MIME (but only if it looks like valid MIME)
    // MIME must start with either "Content-Type:" or have "multipart/related" near the beginning
    int looks_like_mime = 0;
    if (size > 20) {
        // Check if it starts with typical MIME headers
        if (memcmp(buffer, "Content-Type:", 13) == 0 ||
            memcmp(buffer, "Content-", 8) == 0 ||
            memcmp(buffer, "MIME-Version:", 13) == 0 ||
            (size > 100 && memmem(buffer, 100, "multipart/", 10) != NULL)) {
            looks_like_mime = 1;
        }
    }
    
    if (looks_like_mime) {
        const char* multipart_marker = "multipart/related";
        const uint8_t* multipart_loc = memmem(buffer, size > 500 ? 500 : size, multipart_marker, strlen(multipart_marker));
        
        if (multipart_loc) {
            
            const char* boundary_marker = "boundary=\"";
            const uint8_t* boundary_loc = memmem(multipart_loc, size - (multipart_loc - buffer), boundary_marker, strlen(boundary_marker));
            
            if (boundary_loc) {
                const char* boundary_val_start = (char*)boundary_loc + strlen(boundary_marker);
                const char* boundary_val_end = strchr(boundary_val_start, '"');
                
                if (boundary_val_end) {
                    char boundary_str[256];
                    size_t boundary_len = boundary_val_end - boundary_val_start;
                    snprintf(boundary_str, sizeof(boundary_str), "--%.*s", (int)boundary_len, boundary_val_start);
                    
                    // Count how many times this boundary appears
                    int boundary_count = 0;
                    const uint8_t* search_pos = buffer;
                    size_t search_remaining = size;
                    while (search_remaining > 0) {
                        const uint8_t* found = memmem(search_pos, search_remaining, boundary_str, strlen(boundary_str));
                        if (!found) break;
                        boundary_count++;
                        search_pos = found + strlen(boundary_str);
                        search_remaining = size - (search_pos - buffer);
                    }
                    
                    // Only process as MIME if we found at least 2 boundaries
                    if (boundary_count >= 2) {
                        process_mime_object(toi, buffer, size, boundary_str, destIp, destPort);
                        return;
                    }
                }
            }
        }
    }
    
    // Scanner logic with detailed logging
    const uint8_t* scan_pos = buffer;
    size_t remaining_size = size;
    int iteration = 0;

    while (remaining_size > 50) {
        iteration++;
        
        const char* fdt_marker = "<FDT-Instance";
        const char* efdt_marker = "<EFDT";
        const char* stsid_marker = "<S-TSID";
        const char* mpd_marker = "<MPD";
        const char* held_marker = "<HELD";
        const char* usd_marker = "<BundleDescriptionROUTE";  // ADD THIS
        const char* meta_marker = "<metadataEnvelope";       // ADD THIS

        const uint8_t* fdt_start = memmem(scan_pos, remaining_size, fdt_marker, strlen(fdt_marker));
        const uint8_t* efdt_start = memmem(scan_pos, remaining_size, efdt_marker, strlen(efdt_marker));
        const uint8_t* stsid_start = memmem(scan_pos, remaining_size, stsid_marker, strlen(stsid_marker));
        const uint8_t* mpd_start = memmem(scan_pos, remaining_size, mpd_marker, strlen(mpd_marker));
        const uint8_t* held_start = memmem(scan_pos, remaining_size, held_marker, strlen(held_marker));
        const uint8_t* usd_start = memmem(scan_pos, remaining_size, usd_marker, strlen(usd_marker));      // ADD THIS
        const uint8_t* meta_start = memmem(scan_pos, remaining_size, meta_marker, strlen(meta_marker));   // ADD THIS
        
        const uint8_t* next_obj_start = NULL;
        int next_obj_type = -1;
        
        if (fdt_start) { next_obj_start = fdt_start; next_obj_type = 1; }
        if (efdt_start && (!next_obj_start || efdt_start < next_obj_start)) {
            next_obj_start = efdt_start; next_obj_type = 8;
        }
        if (stsid_start && (!next_obj_start || stsid_start < next_obj_start)) { 
            next_obj_start = stsid_start; next_obj_type = 2;
        }
        if (mpd_start && (!next_obj_start || mpd_start < next_obj_start)) { 
            next_obj_start = mpd_start; next_obj_type = 3;
        }
        if (held_start && (!next_obj_start || held_start < next_obj_start)) { 
            next_obj_start = held_start; next_obj_type = 4;
        }
        if (usd_start && (!next_obj_start || usd_start < next_obj_start)) {   // ADD THIS
            next_obj_start = usd_start; next_obj_type = 5;
        }
        if (meta_start && (!next_obj_start || meta_start < next_obj_start)) { // ADD THIS
            next_obj_start = meta_start; next_obj_type = 6;
        }

        if (!next_obj_start) {
            if (scan_pos == buffer && remaining_size > 0) {
                process_terminal_payload(toi, scan_pos, remaining_size, destIp, destPort, 0, 0);
            }
            break;
        }
        
        // Check gap before next object
        if (next_obj_start > scan_pos) {
            size_t gap_len = next_obj_start - scan_pos;
            
            int is_mime_artifact = 0;
            if (gap_len > 6 && memmem(scan_pos, gap_len, "------", 6) != NULL) {
                is_mime_artifact = 1;
            }
            if (gap_len > 13 && memmem(scan_pos, gap_len, "Content-Type:", 13) != NULL) {
                is_mime_artifact = 1;
            }
            
            int is_xml_declaration = 0;
            if (gap_len > 5 && memcmp(scan_pos, "<?xml", 5) == 0) {
                const uint8_t* decl_end = memmem(scan_pos, gap_len, "?>", 2);
                if (decl_end) {
                    decl_end += 2;
                    while (decl_end < scan_pos + gap_len && 
                           (*decl_end == '\r' || *decl_end == '\n' || *decl_end == ' ' || *decl_end == '\t')) {
                        decl_end++;
                    }
                    if (decl_end >= scan_pos + gap_len) {
                        is_xml_declaration = 1;
                    }
                }
            }
            
            if (is_mime_artifact || is_xml_declaration) {
                // Skip this gap, don't process it
            } else if (gap_len > 20) {
                process_terminal_payload(toi, scan_pos, gap_len, destIp, destPort, 0, 0);
            }
        }
        
        scan_pos = next_obj_start;
        remaining_size = size - (scan_pos - buffer);
        
        scan_pos = next_obj_start;
        remaining_size = size - (scan_pos - buffer);

        // Find end marker for this object type
        const char* end_marker = NULL;
        
        if (next_obj_type == 1) { 
            end_marker = "</FDT-Instance>";
        } else if (next_obj_type == 8) {
            end_marker = "</EFDT>";
        } else if (next_obj_type == 2) { 
            end_marker = "</S-TSID>";
        } else if (next_obj_type == 3) { 
            end_marker = "</MPD>";
        } else if (next_obj_type == 4) { 
            end_marker = "</HELD>";
        } else if (next_obj_type == 5) {
            end_marker = "</BundleDescriptionROUTE>";
        } else if (next_obj_type == 6) {
            end_marker = "</metadataEnvelope>";
        }
        
        if (end_marker) {
            const uint8_t* obj_end = memmem(scan_pos, remaining_size, end_marker, strlen(end_marker));
            if (obj_end) {
                obj_end += strlen(end_marker);
                size_t obj_len = obj_end - scan_pos;
                
                // Validate it starts with <?xml or proper tag
                if (obj_len > 5) {
                    if (memcmp(scan_pos, "<?xml", 5) == 0 || memcmp(scan_pos, "<", 1) == 0) {
                        process_terminal_payload(toi, scan_pos, obj_len, destIp, destPort, 0, 0);
                    }
                }
                
                scan_pos = obj_end;
                remaining_size = size - (scan_pos - buffer);
                continue;
            }
        }
        
        process_terminal_payload(toi, scan_pos, remaining_size, destIp, destPort, 0, 0);
        break;
    }
}

void reclassify_data_usage_after_slt() {
    for (int i = 0; i < g_data_usage_count; i++) {
        DataUsageEntry* entry = &g_data_usage[i];
        
        // Skip LLS entries
        if (entry->is_lls) continue;
        
        // Find matching service destination
        ServiceDestination* dest_info = NULL;
        for (int j = 0; j < g_service_dest_count; j++) {
            if (strcmp(g_service_dests[j].destinationIpStr, entry->destinationIp) == 0 &&
                strcmp(g_service_dests[j].destinationPortStr, entry->destinationPort) == 0) {
                dest_info = &g_service_dests[j];
                break;
            }
        }
        
        if (dest_info) {
            // Update stream type and signaling flag based on SLT info
            if (strcmp(dest_info->protocol, "1") == 0) {
                // If switching from MMT to ROUTE, the tsi_or_packet_id was
                // extracted as an MMT packet_id (bytes 2-3) which is wrong
                // for ROUTE. Re-extract the TSI from the sample payload.
                if (strcmp(entry->stream_type, "MMT") == 0 || 
                    strcmp(entry->stream_type, "Other UDP") == 0) {
                    if (entry->sample_collected && entry->sample_payload_len >= 4) {
                        uint32_t real_tsi = get_lct_tsi(entry->sample_payload, entry->sample_payload_len);
                        if (real_tsi != 0xFFFFFFFF) {
                            DBG_PRINTF("RECLASSIFY: %s:%s was %s PID %u -> ROUTE TSI %u\n",
                                   entry->destinationIp, entry->destinationPort,
                                   entry->stream_type, entry->tsi_or_packet_id, real_tsi);
                            entry->tsi_or_packet_id = real_tsi;
                        }
                    }
                }
                strcpy(entry->stream_type, "ROUTE");
                entry->is_signaling = (entry->tsi_or_packet_id == 0);
            } else if (strcmp(dest_info->protocol, "2") == 0) {
                strcpy(entry->stream_type, "MMT");
                entry->is_signaling = (entry->tsi_or_packet_id == 0);
            }
            
            // Now generate enhanced description with full signaling table access
            const char* new_description = get_enhanced_stream_description(
                entry->destinationIp, entry->destinationPort, 
                entry->tsi_or_packet_id, entry->stream_type, entry->is_lls);
            
            strncpy(entry->description, new_description, sizeof(entry->description) - 1);
            entry->description[sizeof(entry->description) - 1] = '\0';
        }
    }
}

/**
 * @brief Detects signature algorithm from CMS signature block
 * @return SignatureAlgorithm enum value
 */
static SignatureAlgorithm detect_signature_algorithm(const uint8_t* data, size_t len) {
    // Combined signature algorithm OIDs (preferred)
    // RSA-SHA256 OID: 1.2.840.113549.1.1.11 = 2A 86 48 86 F7 0D 01 01 0B
    static const uint8_t RSA_SHA256[] = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B};
    // RSA-SHA384 OID: 1.2.840.113549.1.1.12
    static const uint8_t RSA_SHA384[] = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0C};
    // RSA-SHA512 OID: 1.2.840.113549.1.1.13
    static const uint8_t RSA_SHA512[] = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0D};
    // ECDSA-SHA256 OID: 1.2.840.10045.4.3.2 = 2A 86 48 CE 3D 04 03 02
    static const uint8_t ECDSA_SHA256[] = {0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02};
    // ECDSA-SHA384 OID: 1.2.840.10045.4.3.3
    static const uint8_t ECDSA_SHA384[] = {0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03};
    
    // Digest algorithm OIDs (used when signature and digest are specified separately)
    // SHA-256 OID: 2.16.840.1.101.3.4.2.1 = 60 86 48 01 65 03 04 02 01
    static const uint8_t SHA256_DIGEST[] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01};
    // SHA-384 OID: 2.16.840.1.101.3.4.2.2
    static const uint8_t SHA384_DIGEST[] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02};
    // rsaEncryption OID: 1.2.840.113549.1.1.1 = 2A 86 48 86 F7 0D 01 01 01
    static const uint8_t RSA_ENCRYPTION[] = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01};
    
    // Search for OIDs in first 500 bytes (signature algorithms appear early in CMS)
    size_t search_len = len > 500 ? 500 : len;
    
    int found_sha256 = 0, found_sha384 = 0, found_rsa = 0, found_ecdsa = 0;
    
    for (size_t i = 0; i < search_len - 10; i++) {
        // OID tag is 0x06, followed by length byte
        if (data[i] == 0x06) {
            uint8_t oid_len = data[i + 1];
            if (i + 2 + oid_len <= search_len) {
                // Check combined signature+hash OIDs first (most specific)
                if (oid_len == 9 && memcmp(&data[i + 2], RSA_SHA256, 9) == 0) return SIG_ALG_RSA_SHA256;
                if (oid_len == 9 && memcmp(&data[i + 2], RSA_SHA384, 9) == 0) return SIG_ALG_RSA_SHA384;
                if (oid_len == 9 && memcmp(&data[i + 2], RSA_SHA512, 9) == 0) return SIG_ALG_RSA_SHA512;
                if (oid_len == 8 && memcmp(&data[i + 2], ECDSA_SHA256, 8) == 0) return SIG_ALG_ECDSA_SHA256;
                if (oid_len == 8 && memcmp(&data[i + 2], ECDSA_SHA384, 8) == 0) return SIG_ALG_ECDSA_SHA384;
                
                // Check separate digest and encryption OIDs
                if (oid_len == 9 && memcmp(&data[i + 2], SHA256_DIGEST, 9) == 0) found_sha256 = 1;
                if (oid_len == 9 && memcmp(&data[i + 2], SHA384_DIGEST, 9) == 0) found_sha384 = 1;
                if (oid_len == 9 && memcmp(&data[i + 2], RSA_ENCRYPTION, 9) == 0) found_rsa = 1;
                // ecPublicKey OID: 1.2.840.10045.2.1 = 2A 86 48 CE 3D 02 01
                if (oid_len == 7 && data[i + 2] == 0x2A && data[i + 3] == 0x86 && 
                    data[i + 4] == 0x48 && data[i + 5] == 0xCE && data[i + 6] == 0x3D) found_ecdsa = 1;
            }
        }
    }
    
    // Infer algorithm from separate OIDs
    if (found_rsa && found_sha256) return SIG_ALG_RSA_SHA256;
    if (found_rsa && found_sha384) return SIG_ALG_RSA_SHA384;
    if (found_ecdsa && found_sha256) return SIG_ALG_ECDSA_SHA256;
    if (found_ecdsa && found_sha384) return SIG_ALG_ECDSA_SHA384;
    
    // If we found RSA but no specific hash, assume SHA-256 (most common)
    if (found_rsa) return SIG_ALG_RSA_SHA256;
    if (found_ecdsa) return SIG_ALG_ECDSA_SHA256;
    
    return SIG_ALG_UNKNOWN;
}

/**
 * @brief Gets human-readable name for signature algorithm
 */
static const char* get_signature_algorithm_name(SignatureAlgorithm alg) {
    switch (alg) {
        case SIG_ALG_RSA_SHA256:   return "RSA-SHA256";
        case SIG_ALG_RSA_SHA384:   return "RSA-SHA384";
        case SIG_ALG_RSA_SHA512:   return "RSA-SHA512";
        case SIG_ALG_ECDSA_SHA256: return "ECDSA-SHA256";
        case SIG_ALG_ECDSA_SHA384: return "ECDSA-SHA384";
        default:                   return "Unknown";
    }
}

/**
 * @brief Processes the UDP payload of an LLS packet.
 * Enhanced to track Signed Multi-Table (SMT) containment.
 */
void process_lls_payload(const u_char *payload, int len) {
    const u_char *payload_start = payload;
    const u_char *current_pos = payload;
    int remaining_len = len;
    int fragments_found = 0;
    
    // Track tables extracted from this LLS payload for SMT association
    int first_table_index = g_lls_table_count;  // Remember where we started
    int tables_in_this_payload = 0;

    while (remaining_len > 10) { 
        const u_char *gzip_header = NULL;
        for (int i = 0; i < remaining_len - 1; ++i) {
            if (current_pos[i] == 0x1f && current_pos[i+1] == 0x8b) {
                gzip_header = current_pos + i;
                break;
            }
        }

        if (gzip_header) {
            fragments_found++;
            
            int decompressed_size = 0;
            int consumed_size = 0;
            char *xml_content = decompress_gzip(gzip_header, remaining_len - (gzip_header - current_pos), &decompressed_size, &consumed_size);

            if (xml_content && consumed_size > 0) {
                TableType type = TABLE_TYPE_UNKNOWN;
                void* parsed_data = NULL;
                if(parse_xml(xml_content, decompressed_size, &type, &parsed_data, "LLS Global") == 0 && parsed_data) {
                    if(type == TABLE_TYPE_SLT) {
                        store_slt_destinations((SltData*)parsed_data);
                    }
                    // Store with is_in_smt=0 for now - we'll update after checking for signature
                    store_unique_table(xml_content, decompressed_size, type, parsed_data, NULL, NULL, 0, -1);
                    tables_in_this_payload++;
                }
                free(xml_content);
                
                current_pos = gzip_header + consumed_size;
                remaining_len = len - (current_pos - payload_start);

            } else {
                break;
            }
        } else {
            break;
        }
    }

    // Handle signature block - if present, this was a Signed Multi-Table (SMT)
    if (fragments_found > 0 && remaining_len > 10) {
        SignatureData* sig_data = calloc(1, sizeof(SignatureData));
        if(sig_data) {
            sig_data->signature_len = remaining_len;
            sig_data->tables_covered = tables_in_this_payload;
            
            // Check if this looks like valid CMS (starts with SEQUENCE tag 0x30)
            sig_data->is_cms_valid = (current_pos[0] == 0x30) ? 1 : 0;
            
            // Detect signature algorithm
            sig_data->algorithm = detect_signature_algorithm(current_pos, remaining_len);
            strncpy(sig_data->algorithm_name, get_signature_algorithm_name(sig_data->algorithm),
                    sizeof(sig_data->algorithm_name) - 1);
            sig_data->algorithm_name[sizeof(sig_data->algorithm_name) - 1] = '\0';
            
            char sig_id[256];
            snprintf(sig_id, sizeof(sig_id), "<Signature len=\"%d\" alg=\"%s\" tables=\"%d\"/>", 
                     remaining_len, sig_data->algorithm_name, tables_in_this_payload);
            
            // Store signature and get its index
            int sig_index = g_lls_table_count;
            store_unique_table(sig_id, strlen(sig_id), TABLE_TYPE_SIGNATURE, sig_data, NULL, NULL, 0, -1);
            
            // Go back and mark all tables from this SMT as signed
            for (int i = first_table_index; i < sig_index; i++) {
                g_lls_tables[i].is_in_smt = 1;
                g_lls_tables[i].smt_signature_index = sig_index;
            }
            
            DBG_PRINTF("DEBUG SMT: Marked %d tables as signed (sig index %d, alg=%s)\n", 
                   tables_in_this_payload, sig_index, sig_data->algorithm_name);
        }
    }

    if (fragments_found == 0) {
        TableType type = TABLE_TYPE_UNKNOWN;
        void* parsed_data = NULL;
        if(parse_xml((const char*)payload, len, &type, &parsed_data, "LLS Global") == 0 && parsed_data) {
             if(type == TABLE_TYPE_SLT) {
                store_slt_destinations((SltData*)parsed_data);
            }
            store_unique_table((const char*)payload, len, type, parsed_data, NULL, NULL, 0, -1);
        }
    }
}

/* NULL-safe view of an optional SLT string field */
static const char *nz(const char *s) { return s ? s : ""; }

void store_slt_destinations(SltData* slt_data) {
    if(!slt_data) {
        return;
    }

    ServiceInfo* service = slt_data->head;
    int services_processed = 0;
    while(service) {
        services_processed++;
        const char *dst   = nz(service->slsDestinationIpAddress);
        const char *port  = nz(service->slsDestinationUdpPort);
        const char *proto = nz(service->slsProtocol);
        const char *pktid = nz(service->slsMmtpPacketId);
        const char *cat   = nz(service->serviceCategory);
        const char *sname = nz(service->shortServiceName);
        const char *gsid  = nz(service->globalServiceID);
        
        // Store destinations for services that have SLS streams OR are ESG services
        if((dst[0] || strcmp(cat, "4") == 0) && 
           g_service_dest_count < MAX_SERVICES) {
            
            struct in_addr dest_ip;
            if (inet_pton(AF_INET, dst, &dest_ip) != 1) {
                service = service->next;
                continue;
            }
            
            uint16_t dest_port = atoi(port);
            if (dest_port == 0) {
                service = service->next;
                continue;
            }

            int found = 0;
            for(int i = 0; i < g_service_dest_count; i++) {
                if(g_service_dests[i].ip_addr.s_addr == dest_ip.s_addr && g_service_dests[i].port == dest_port) {
                    found = 1;
                    break;
                }
            }

            if(!found) {
                
                g_service_dests[g_service_dest_count].ip_addr = dest_ip;
                g_service_dests[g_service_dest_count].port = dest_port;
                strncpy(g_service_dests[g_service_dest_count].destinationIpStr, dst, sizeof(g_service_dests[0].destinationIpStr) - 1);
                g_service_dests[g_service_dest_count].destinationIpStr[sizeof(g_service_dests[0].destinationIpStr) - 1] = '\0';
                strncpy(g_service_dests[g_service_dest_count].destinationPortStr, port, sizeof(g_service_dests[0].destinationPortStr) - 1);
                g_service_dests[g_service_dest_count].destinationPortStr[sizeof(g_service_dests[0].destinationPortStr) - 1] = '\0';
                strncpy(g_service_dests[g_service_dest_count].protocol, proto, sizeof(g_service_dests[0].protocol) - 1);
                g_service_dests[g_service_dest_count].protocol[sizeof(g_service_dests[0].protocol) - 1] = '\0';
                g_service_dests[g_service_dest_count].mmtSignalingPacketId = atoi(pktid);
                DBG_PRINTF("DEBUG: Configured MMT service %s:%s with signaling PacketID=%u\n",
                       dst, port,
                       g_service_dests[g_service_dest_count].mmtSignalingPacketId);
                
                strncpy(g_service_dests[g_service_dest_count].serviceCategory, cat, sizeof(g_service_dests[0].serviceCategory) - 1);
                g_service_dests[g_service_dest_count].serviceCategory[sizeof(g_service_dests[0].serviceCategory) - 1] = '\0';
                g_service_dests[g_service_dest_count].isEsgService = (strcmp(cat, "4") == 0) ? 1 : 0;
                
                // Check for eGPS service - typically App-Based Service (category 3) with eGPS indicators
                // Can be identified by shortServiceName, globalServiceID, or other signaling
                int is_egps = 0;
                if (sname[0]) {
                    // Check for common eGPS service names (case-insensitive)
                    char name_lower[64];
                    strncpy(name_lower, sname, sizeof(name_lower) - 1);
                    name_lower[sizeof(name_lower) - 1] = '\0';
                    for (int c = 0; name_lower[c]; c++) {
                        if (name_lower[c] >= 'A' && name_lower[c] <= 'Z') {
                            name_lower[c] += 32;
                        }
                    }
                    if (strstr(name_lower, "egps") || strstr(name_lower, "gps") || 
                        strstr(name_lower, "gnss") || strstr(name_lower, "location") ||
                        strstr(name_lower, "position")) {
                        is_egps = 1;
                        DBG_PRINTF("DEBUG: Detected eGPS service by name: %s at %s:%s\n",
                               sname, dst, port);
                    }
                }
                if (!is_egps && gsid[0]) {
                    char gsid_lower[128];
                    strncpy(gsid_lower, gsid, sizeof(gsid_lower) - 1);
                    gsid_lower[sizeof(gsid_lower) - 1] = '\0';
                    for (int c = 0; gsid_lower[c]; c++) {
                        if (gsid_lower[c] >= 'A' && gsid_lower[c] <= 'Z') {
                            gsid_lower[c] += 32;
                        }
                    }
                    if (strstr(gsid_lower, "egps") || strstr(gsid_lower, "gps:") ||
                        strstr(gsid_lower, "gnss") || strstr(gsid_lower, "location")) {
                        is_egps = 1;
                        DBG_PRINTF("DEBUG: Detected eGPS service by globalServiceID: %s at %s:%s\n",
                               gsid, dst, port);
                    }
                }
                g_service_dests[g_service_dest_count].isEgpsService = is_egps;
                g_service_dests[g_service_dest_count].egpsContextId[0] = '\0';
                
                g_service_dest_count++;
            }
        }
        service = service->next;
    }
}

/**
 * @brief Checks if a table is unique and stores it if so.
 */
void store_unique_table(const char* content, int len, TableType type, void* parsed_data, const char* destIp, const char* destPort, int is_in_smt, int smt_sig_index) {
    // Validate completeness for critical table types
    if (type == TABLE_TYPE_MPD || type == TABLE_TYPE_STSID) {
        // Check if content ends properly
        const char* last_200 = content + (len > 200 ? len - 200 : 0);
        size_t check_len = len > 200 ? 200 : len;
        
        if (type == TABLE_TYPE_MPD && !memmem(last_200, check_len, "</MPD>", 6)) {
            DBG_PRINTF("WARN: Rejecting incomplete MPD (no closing tag), len=%d\n", len);
            DBG_PRINTF("Last 200 chars: %.*s\n", (int)check_len, last_200);
            free_parsed_data(&(LlsTable){ .type = type, .parsed_data = parsed_data });
            return;
        }
        
        if (type == TABLE_TYPE_STSID && !memmem(last_200, check_len, "</S-TSID>", 9)) {
            DBG_PRINTF("WARN: Rejecting incomplete S-TSID (no closing tag), len=%d, dest=%s:%s\n", 
                   len, destIp ? destIp : "N/A", destPort ? destPort : "N/A");
            DBG_PRINTF("Last 200 chars: %.*s\n", (int)check_len, last_200);
            free_parsed_data(&(LlsTable){ .type = type, .parsed_data = parsed_data });
            return;
        }
    }
    
    if (type == TABLE_TYPE_ESG_FRAGMENT) {
        DBG_PRINTF("DEBUG ESG STORE TABLE: Storing ESG type=%d, destIp='%s', destPort='%s', parsed_data=%p\n",
               type, destIp ? destIp : "NULL", destPort ? destPort : "NULL", parsed_data);
    }
    
    if (g_lls_table_count >= MAX_TABLES) {
        fprintf(stderr, "Warning: Maximum number of unique tables reached.\n");
        free_parsed_data(&(LlsTable){ .type = type, .parsed_data = parsed_data });
        return;
    }

    for (int i = 0; i < g_lls_table_count; i++) {
         if (g_lls_tables[i].type == type) {
            int ip_match = (destIp && strlen(destIp) > 0) ? 
                           (strcmp(g_lls_tables[i].destinationIp, destIp) == 0) : 
                           (strlen(g_lls_tables[i].destinationIp) == 0);
            int port_match = (destPort && strlen(destPort) > 0) ? 
                             (strcmp(g_lls_tables[i].destinationPort, destPort) == 0) : 
                             (strlen(g_lls_tables[i].destinationPort) == 0);

            if (ip_match && port_match && strncmp(g_lls_tables[i].content_id, content, len) == 0 && strlen(g_lls_tables[i].content_id) == len) {
                free_parsed_data(&(LlsTable){ .type = type, .parsed_data = parsed_data });
                return; 
            }
        }
    }

    LlsTable* new_table = &g_lls_tables[g_lls_table_count];
    new_table->content_id = strndup(content, len);
    if (!new_table->content_id) {
        perror("Failed to allocate memory for content ID");
        free_parsed_data(&(LlsTable){ .type = type, .parsed_data = parsed_data });
        return;
    }
    new_table->parsed_data = parsed_data;
    new_table->type = type;
    new_table->is_in_smt = is_in_smt;
    new_table->smt_signature_index = smt_sig_index;
    if (destIp) {
        strncpy(new_table->destinationIp, destIp, sizeof(new_table->destinationIp) - 1);
        new_table->destinationIp[sizeof(new_table->destinationIp) - 1] = '\0';
    } else {
        new_table->destinationIp[0] = '\0';
    }
    if (destPort) {
        strncpy(new_table->destinationPort, destPort, sizeof(new_table->destinationPort) - 1);
        new_table->destinationPort[sizeof(new_table->destinationPort) - 1] = '\0';
    } else {
        new_table->destinationPort[0] = '\0';
    }

    g_lls_table_count++;
    if (type == TABLE_TYPE_SLT) {
        DBG_PRINTF("Stored new SLT table (total count: %d)%s\n", g_lls_table_count, is_in_smt ? " [SIGNED]" : "");
    }
}

void process_multi_document_xml(const char* xml_data, size_t size, const char* destIp, const char* destPort, const char* source_id) {
    const char* current_pos = xml_data;
    size_t remaining = size;
    int doc_count = 0;
    const char* xml_marker = "<?xml";
    
    while (remaining > 10) {
        // Find next XML declaration using memmem (handles null bytes)
        const char* next_doc = memmem(current_pos, remaining, xml_marker, 5);
        if (!next_doc) break;
        
        // Find the end of this document (start of next one, or end of buffer)
        const char* doc_end;
        size_t search_size = remaining - (next_doc - current_pos + 5);
        const char* next_xml = memmem(next_doc + 5, search_size, xml_marker, 5);
        
        if (next_xml) {
            doc_end = next_xml;
        } else {
            doc_end = xml_data + size;
        }
        
        size_t doc_len = doc_end - next_doc;
        if (doc_len > 10) {
            doc_count++;
            
            TableType type = TABLE_TYPE_UNKNOWN;
            void* parsed_data = NULL;
            if (parse_xml(next_doc, doc_len, &type, &parsed_data, source_id) == 0 && parsed_data) {
                store_unique_table(next_doc, doc_len, type, parsed_data, destIp, destPort, 0, -1);
            }
        }
        
        current_pos = doc_end;
        remaining = size - (current_pos - xml_data);
    }
}

/**
 * @brief Parses XML content and routes to the correct specific parser.
 * @return 0 on success (even if no data is extracted), -1 on a true parsing failure.
 */
int parse_xml(const char* xml_content, int len, TableType* type, void** parsed_data_out, const char* source_identifier) {
    *parsed_data_out = NULL;
    *type = TABLE_TYPE_UNKNOWN;
    
    DBG_PRINTF("DEBUG: parse_xml called with len=%d, source=%s\n", len, source_identifier);
    DBG_PRINTF("DEBUG: First 100 chars: %.100s\n", xml_content);

    xmlDocPtr doc = xmlReadMemory(xml_content, len, "noname.xml", NULL, XML_PARSE_RECOVER | XML_PARSE_NOWARNING | XML_PARSE_NOERROR);

    if (doc == NULL) {
        DBG_PRINTF("XML document could not be parsed (from %s).\n", source_identifier);
        return -1; // True failure
    }
    
    DBG_PRINTF("DEBUG: XML doc created successfully at %p\n", doc);

    xmlNodePtr root = xmlDocGetRootElement(doc);
    if (root == NULL) {
        DBG_PRINTF("XML document is empty or malformed (from %s).\n", source_identifier);
        xmlFreeDoc(doc);
        return -1; // True failure
    }
    
    DBG_PRINTF("DEBUG: Found XML root element: '%s' from %s\n", root->name, source_identifier);
    eas_note_xml((const char*)root->name, xml_content, len);
    
    if (xmlStrcmp(root->name, (const xmlChar *)"SLT") == 0) {
        *type = TABLE_TYPE_SLT;
        *parsed_data_out = parse_slt(doc);
        DBG_PRINTF("DEBUG: SLT parsing returned %p\n", *parsed_data_out);
    } else if (xmlStrcmp(root->name, (const xmlChar *)"SystemTime") == 0) {
        *type = TABLE_TYPE_SYSTEM_TIME;
        *parsed_data_out = parse_system_time(doc);
    } else if (xmlStrcmp(root->name, (const xmlChar *)"RatingRegionTables") == 0 ||
               xmlStrcmp(root->name, (const xmlChar *)"RRT") == 0) {
        *type = TABLE_TYPE_RRT;
        *parsed_data_out = parse_rrt(doc);
    } else if (xmlStrcmp(root->name, (const xmlChar *)"UCT") == 0) {
        *type = TABLE_TYPE_UCT;
        *parsed_data_out = parse_uct(doc);
    } else if (xmlStrcmp(root->name, (const xmlChar *)"CertificationData") == 0) {
        DBG_PRINTF("DEBUG: Detected CertificationData (CDT) XML document\n");
        *type = TABLE_TYPE_CDT;
        *parsed_data_out = parse_cdt(doc);
        if (*parsed_data_out) {
            DBG_PRINTF("DEBUG: CDT parsing successful\n");
        } else {
            DBG_PRINTF("DEBUG: CDT parsing failed\n");
        }
    } else if (xmlStrcmp(root->name, (const xmlChar *)"UDST") == 0) {
        *type = TABLE_TYPE_UDST;
        *parsed_data_out = parse_udst(doc);
    } else if (xmlStrcmp(root->name, (const xmlChar *)"FDT-Instance") == 0) {
        *type = TABLE_TYPE_FDT;
        *parsed_data_out = parse_fdt(doc);
        
    } else if (xmlStrcmp(root->name, (const xmlChar *)"EFDT") == 0) {
        *type = TABLE_TYPE_EFDT;
        *parsed_data_out = parse_fdt_from_node(root); // Reuse FDT parser
    } else if (xmlStrcmp(root->name, (const xmlChar *)"EFDT-Instance") == 0) {
        *type = TABLE_TYPE_EFDT;
        *parsed_data_out = parse_fdt_from_node(root);
    } else if (xmlStrcmp(root->name, (const xmlChar *)"S-TSID") == 0) {
        *type = TABLE_TYPE_STSID;
        *parsed_data_out = parse_stsid(doc);
    } else if (xmlStrcmp(root->name, (const xmlChar *)"MPD") == 0) {
        *type = TABLE_TYPE_MPD;
        *parsed_data_out = parse_mpd(doc);
    } else if (xmlStrcmp(root->name, (const xmlChar *)"HELD") == 0) {
        *type = TABLE_TYPE_HELD;
        *parsed_data_out = parse_held(doc);
    } else if (xmlStrcmp(root->name, (const xmlChar *)"Service") == 0) {
        *type = TABLE_TYPE_ESG_FRAGMENT;
        *parsed_data_out = parse_esg_service_fragment(doc);
        DBG_PRINTF("DEBUG ESG PARSE: parse_esg_service_fragment returned %p\n", *parsed_data_out);
    } else if (xmlStrcmp(root->name, (const xmlChar *)"Program") == 0) {
        *type = TABLE_TYPE_ESG_FRAGMENT;
        *parsed_data_out = parse_esg_service_fragment(doc);
    }
    else if (xmlStrcmp(root->name, (const xmlChar *)"ServiceGuideDeliveryDescriptor") == 0) {
        *type = TABLE_TYPE_SGDD;
        *parsed_data_out = parse_sgdd(doc);
    }
    else if (xmlStrcmp(root->name, (const xmlChar *)"Schedule") == 0) {
        *type = TABLE_TYPE_ESG_FRAGMENT;
        *parsed_data_out = parse_esg_service_fragment(doc);
    }
    else if (xmlStrcmp(root->name, (const xmlChar *)"ServiceBundle") == 0) {
        *type = TABLE_TYPE_ESG_FRAGMENT;
        *parsed_data_out = parse_esg_service_fragment(doc);
    }
    else if (xmlStrcmp(root->name, (const xmlChar *)"ESG") == 0) {
        *type = TABLE_TYPE_ESG_FRAGMENT;
        *parsed_data_out = parse_esg_service_fragment(doc);
    }
    else if (xmlStrcmp(root->name, (const xmlChar *)"Content") == 0) {
        *type = TABLE_TYPE_ESG_FRAGMENT;
        *parsed_data_out = parse_esg_service_fragment(doc);
    }
    else if (xmlStrcmp(root->name, (const xmlChar *)"BundleDescriptionROUTE") == 0) {
        *type = TABLE_TYPE_USER_SERVICE_DESCRIPTION;
        *parsed_data_out = parse_user_service_description(doc);
    }
    else if (xmlStrcmp(root->name, (const xmlChar *)"BundleDescriptionMMT") == 0) {
        *type = TABLE_TYPE_USBD;
        *parsed_data_out = parse_usbd(doc);
    }
    else if (xmlStrcmp(root->name, (const xmlChar *)"UserServiceDescription") == 0) {
        *type = TABLE_TYPE_USD;
        *parsed_data_out = parse_usd(doc);
    }
    else if (xmlStrcmp(root->name, (const xmlChar *)"USD") == 0) {
        *type = TABLE_TYPE_USD;
        *parsed_data_out = parse_usd(doc);
    }
    else if (xmlStrcmp(root->name, (const xmlChar *)"DWD") == 0) {
        *type = TABLE_TYPE_DWD;
        *parsed_data_out = parse_dwd(doc);
    }
    else if (xmlStrcmp(root->name, (const xmlChar *)"UDS") == 0) {
        *type = TABLE_TYPE_UDS;
        *parsed_data_out = parse_uds(doc);
    }
    else if (xmlStrcmp(root->name, (const xmlChar *)"AEAT") == 0) {
        *type = TABLE_TYPE_AEAT;
        *parsed_data_out = parse_aeat(doc);
        eas_note_aeat((AeatData*)*parsed_data_out);
    }
    else if (xmlStrcmp(root->name, (const xmlChar *)"metadataEnvelope") == 0) {
        *type = TABLE_TYPE_SERVICE_SIGNALING;
        *parsed_data_out = parse_service_signaling(doc);
    }
    else if (xmlStrcmp(root->name, (const xmlChar *)"MP_Table") == 0) {
        *type = TABLE_TYPE_MP_TABLE_XML;
        *parsed_data_out = parse_mp_table(doc);
    }
    else {
        // Store unrecognized table types so they can be displayed
        DBG_PRINTF("--> INFO: Encountered unrecognized XML root element: '%s'\n", root->name);
        
        UnhandledTableData* unhandled = calloc(1, sizeof(UnhandledTableData));
        if (unhandled) {
            strncpy(unhandled->root_element, (const char*)root->name, sizeof(unhandled->root_element) - 1);
            
            // Try to get namespace
            if (root->ns && root->ns->href) {
                strncpy(unhandled->namespace_uri, (const char*)root->ns->href, sizeof(unhandled->namespace_uri) - 1);
            }
            
            *type = TABLE_TYPE_UNHANDLED;
            *parsed_data_out = unhandled;
        }
    }

    DBG_PRINTF("DEBUG: About to free XML doc\n");
    xmlFreeDoc(doc);
    DBG_PRINTF("DEBUG: XML doc freed successfully\n");
    return 0; // Success
}

/**
 * @brief Parses an FDT-Instance from a given XML node.
 * This was refactored from parse_fdt to allow parsing of embedded FDTs.
 */
FDTInstanceData* parse_fdt_from_node(xmlNodePtr fdt_node) {
    if (!fdt_node) return NULL;

    FDTInstanceData* fdt_data = calloc(1, sizeof(FDTInstanceData));
    if (!fdt_data) return NULL;

    xmlChar* prop = xmlGetProp(fdt_node, (const xmlChar *)"Expires");
    if(prop) { 
        strncpy(fdt_data->expires, (char*)prop, sizeof(fdt_data->expires)-1); 
        xmlFree(prop); 
    }

    xmlNodePtr cur_node = fdt_node->children;
    FDTFileInfo* current_file_tail = NULL;
    int file_count = 0;

    while (cur_node != NULL) {
        if (cur_node->type == XML_ELEMENT_NODE) {
            if (xmlStrcmp(cur_node->name, (const xmlChar *)"File") == 0 ||
                xmlStrcmp(cur_node->name, (const xmlChar *)"fdt:File") == 0) {
                
                FDTFileInfo* file_info = calloc(1, sizeof(FDTFileInfo));
                if (!file_info) continue;
                
                prop = xmlGetProp(cur_node, (const xmlChar *)"Content-Location");
                if(prop) { strncpy(file_info->contentLocation, (char*)prop, sizeof(file_info->contentLocation)-1); xmlFree(prop); }
                
                prop = xmlGetProp(cur_node, (const xmlChar *)"TOI");
                if(prop) { strncpy(file_info->toi, (char*)prop, sizeof(file_info->toi)-1); xmlFree(prop); }

                prop = xmlGetProp(cur_node, (const xmlChar *)"Content-Length");
                if(prop) { strncpy(file_info->contentLength, (char*)prop, sizeof(file_info->contentLength)-1); xmlFree(prop); }
                
                prop = xmlGetProp(cur_node, (const xmlChar *)"Content-Type");
                if(prop) { strncpy(file_info->contentType, (char*)prop, sizeof(file_info->contentType)-1); xmlFree(prop); }

                if (fdt_data->head == NULL) {
                    fdt_data->head = file_info;
                    current_file_tail = file_info;
                } else {
                    current_file_tail->next = file_info;
                    current_file_tail = file_info;
                }
                file_count++;
            }
        }
        cur_node = cur_node->next;
    }
    
    if (file_count > 0) {
        DBG_PRINTF("--> FDT parsed with %d files.\n", file_count);
    } else {
        free(fdt_data);
        fdt_data = NULL;
    }

    return fdt_data;
}


/**
 * @brief Wrapper for parse_fdt_from_node to parse a whole document where FDT is the root.
 */
FDTInstanceData* parse_fdt(xmlDocPtr doc) {
    xmlNodePtr root = xmlDocGetRootElement(doc);
    if (!root) return NULL;
    if (xmlStrcmp(root->name, (const xmlChar *)"FDT-Instance") == 0) {
        return parse_fdt_from_node(root);
    }
    return NULL;
}


/**
 * @brief Iterates through the children of a node and attempts to parse them
 * as known standalone table types (like FDT-Instance).
 */
void parse_embedded_children(xmlNodePtr parent_node, const char* destIp, const char* destPort) {
    xmlNodePtr cur_node = NULL;
    for (cur_node = parent_node; cur_node; cur_node = cur_node->next) {
        if (cur_node->type == XML_ELEMENT_NODE) {
            if (xmlStrcmp(cur_node->name, (const xmlChar *)"FDT-Instance") == 0) {
                FDTInstanceData* fdt_data = parse_fdt_from_node(cur_node);
                if (fdt_data) {
                    xmlBufferPtr buf = xmlBufferCreate();
                    xmlNodeDump(buf, cur_node->doc, cur_node, 0, 1);
                    store_unique_table((const char*)xmlBufferContent(buf), xmlBufferLength(buf), TABLE_TYPE_FDT, fdt_data, destIp, destPort, 0, -1);
                    xmlBufferFree(buf);
                }
            }
            // Future: Add checks for other embedded types like MPD here if needed
        }
        parse_embedded_children(cur_node->children, destIp, destPort);
    }
}

/**
 * @brief Parses a DASH MPD XML document into MpdData struct.
 */
MpdData* parse_mpd(xmlDocPtr doc) {
    MpdData* mpd_data = calloc(1, sizeof(MpdData));
    if (!mpd_data) return NULL;

    xmlNodePtr root = xmlDocGetRootElement(doc);
    if (!root) {
        free(mpd_data);
        return NULL;
    }
    xmlChar* prop;
    
    prop = xmlGetProp(root, (const xmlChar *)"publishTime");
    if(prop) { strncpy(mpd_data->publishTime, (char*)prop, sizeof(mpd_data->publishTime)-1); xmlFree(prop); }
    prop = xmlGetProp(root, (const xmlChar *)"profiles");
    if(prop) { strncpy(mpd_data->profiles, (char*)prop, sizeof(mpd_data->profiles)-1); xmlFree(prop); }
    prop = xmlGetProp(root, (const xmlChar *)"type");
    if(prop) { strncpy(mpd_data->type, (char*)prop, sizeof(mpd_data->type)-1); xmlFree(prop); }
    prop = xmlGetProp(root, (const xmlChar *)"minBufferTime");
    if(prop) { strncpy(mpd_data->minBufferTime, (char*)prop, sizeof(mpd_data->minBufferTime)-1); xmlFree(prop); }


    xmlNodePtr period_node = root->children;
    MpdAdaptationSet* current_as_tail = NULL;

    // Find the first Period node
    while(period_node != NULL && (period_node->type != XML_ELEMENT_NODE || xmlStrcmp(period_node->name, (const xmlChar *)"Period") != 0)) {
        period_node = period_node->next;
    }
    if(!period_node) { free(mpd_data); return NULL; }

// Iterate through AdaptationSet nodes within the Period
    xmlNodePtr as_node = period_node->children;
    while(as_node != NULL) {
        if(as_node->type == XML_ELEMENT_NODE && xmlStrcmp(as_node->name, (const xmlChar *)"AdaptationSet") == 0) {
            MpdAdaptationSet* as = calloc(1, sizeof(MpdAdaptationSet));
            if(!as) continue;

            prop = xmlGetProp(as_node, (const xmlChar *)"contentType");
            if(prop) { strncpy(as->contentType, (char*)prop, sizeof(as->contentType)-1); xmlFree(prop); }
            prop = xmlGetProp(as_node, (const xmlChar *)"lang");
            if(prop) { strncpy(as->lang, (char*)prop, sizeof(as->lang)-1); xmlFree(prop); }
            prop = xmlGetProp(as_node, (const xmlChar *)"mimeType");
            if(prop) { strncpy(as->mimeType, (char*)prop, sizeof(as->mimeType)-1); xmlFree(prop); }
            prop = xmlGetProp(as_node, (const xmlChar *)"par");
            if(prop) { strncpy(as->par, (char*)prop, sizeof(as->par)-1); xmlFree(prop); }

            // NEW: Parse AdaptationSet-level attributes that should be inherited by Representations
            char as_codecs[128] = "";
            char as_width[16] = "";
            char as_height[16] = "";
            char as_frameRate[16] = "";
            char as_audioSamplingRate[16] = "";
            
            prop = xmlGetProp(as_node, (const xmlChar *)"codecs");
            if(prop) { strncpy(as_codecs, (char*)prop, sizeof(as_codecs)-1); xmlFree(prop); }
            prop = xmlGetProp(as_node, (const xmlChar *)"width");
            if(prop) { strncpy(as_width, (char*)prop, sizeof(as_width)-1); xmlFree(prop); }
            prop = xmlGetProp(as_node, (const xmlChar *)"height");
            if(prop) { strncpy(as_height, (char*)prop, sizeof(as_height)-1); xmlFree(prop); }
            prop = xmlGetProp(as_node, (const xmlChar *)"frameRate");
            if(prop) { strncpy(as_frameRate, (char*)prop, sizeof(as_frameRate)-1); xmlFree(prop); }
            prop = xmlGetProp(as_node, (const xmlChar *)"audioSamplingRate");
            if(prop) { strncpy(as_audioSamplingRate, (char*)prop, sizeof(as_audioSamplingRate)-1); xmlFree(prop); }

            // Find SegmentTemplate at the AdaptationSet level
            SegmentTemplateData as_template = {0};
            xmlNodePtr temp_node = as_node->children;
            while(temp_node != NULL) {
                 if(temp_node->type == XML_ELEMENT_NODE && xmlStrcmp(temp_node->name, (const xmlChar *)"SegmentTemplate") == 0) {
                    prop = xmlGetProp(temp_node, (const xmlChar *)"initialization");
                    if(prop) { strncpy(as_template.initialization, (char*)prop, sizeof(as_template.initialization)-1); xmlFree(prop); }
                    prop = xmlGetProp(temp_node, (const xmlChar *)"media");
                    if(prop) { strncpy(as_template.media, (char*)prop, sizeof(as_template.media)-1); xmlFree(prop); }
                    prop = xmlGetProp(temp_node, (const xmlChar *)"timescale");
                    if(prop) { strncpy(as_template.timescale, (char*)prop, sizeof(as_template.timescale)-1); xmlFree(prop); }
                    prop = xmlGetProp(temp_node, (const xmlChar *)"startNumber");
                    if(prop) { strncpy(as_template.startNumber, (char*)prop, sizeof(as_template.startNumber)-1); xmlFree(prop); }
                    prop = xmlGetProp(temp_node, (const xmlChar *)"duration");
                    if(prop) { strncpy(as_template.duration, (char*)prop, sizeof(as_template.duration)-1); xmlFree(prop); }
                    
                    xmlNodePtr timeline_node = temp_node->children;
                    SegmentTimelineS* current_s_tail = NULL;
                     while(timeline_node != NULL) {
                        if(timeline_node->type == XML_ELEMENT_NODE && xmlStrcmp(timeline_node->name, (const xmlChar*)"SegmentTimeline") == 0) {
                            xmlNodePtr s_node = timeline_node->children;
                            while(s_node != NULL) {
                                if(s_node->type == XML_ELEMENT_NODE && xmlStrcmp(s_node->name, (const xmlChar*)"S") == 0) {
                                    SegmentTimelineS* s_elem = calloc(1, sizeof(SegmentTimelineS));
                                    if(s_elem) {
                                        prop = xmlGetProp(s_node, (const xmlChar*)"t");
                                        if(prop) { strncpy(s_elem->t, (char*)prop, sizeof(s_elem->t)-1); xmlFree(prop); }
                                        prop = xmlGetProp(s_node, (const xmlChar*)"d");
                                        if(prop) { strncpy(s_elem->d, (char*)prop, sizeof(s_elem->d)-1); xmlFree(prop); }
                                        prop = xmlGetProp(s_node, (const xmlChar*)"r");
                                        if(prop) { strncpy(s_elem->r, (char*)prop, sizeof(s_elem->r)-1); xmlFree(prop); }
                                        
                                        if(as_template.timeline == NULL) {
                                            as_template.timeline = s_elem;
                                            current_s_tail = s_elem;
                                        } else {
                                            current_s_tail->next = s_elem;
                                            current_s_tail = s_elem;
                                        }
                                    }
                                }
                                s_node = s_node->next;
                            }
                            break;
                        }
                        timeline_node = timeline_node->next;
                     }
                    break;
                 }
                 temp_node = temp_node->next;
            }

            // Parse ContentProtection elements for DRM
            DrmInfo* adaptationset_drm = NULL;
            DrmInfo* as_drm_tail = NULL;

            xmlNodePtr as_child = as_node->children;
            while(as_child != NULL) {
                if(as_child->type == XML_ELEMENT_NODE && 
                xmlStrcmp(as_child->name, (const xmlChar*)"ContentProtection") == 0) {
                    
                    DrmInfo* drm = parse_drm_content_protection(as_child);
                    if (drm) {
                        if (adaptationset_drm == NULL) {
                            adaptationset_drm = drm;
                            as_drm_tail = drm;
                        } else {
                            as_drm_tail->next = drm;
                            as_drm_tail = drm;
                        }
                    }
                }
                as_child = as_child->next;
            }

            // Parse Representation nodes
            xmlNodePtr rep_node = as_node->children;
            MpdRepresentation* current_rep_tail = NULL;
            while(rep_node != NULL) {
                if(rep_node->type == XML_ELEMENT_NODE && xmlStrcmp(rep_node->name, (const xmlChar *)"Representation") == 0) {
                    MpdRepresentation* rep = calloc(1, sizeof(MpdRepresentation));
                    if(!rep) continue;
                    
                    memcpy(&rep->segmentTemplate, &as_template, sizeof(SegmentTemplateData));

                    // Parse Representation-level attributes with inheritance from AdaptationSet
                    prop = xmlGetProp(rep_node, (const xmlChar *)"id");
                    if(prop) { strncpy(rep->id, (char*)prop, sizeof(rep->id)-1); xmlFree(prop); }
                    
                    prop = xmlGetProp(rep_node, (const xmlChar *)"codecs");
                    if(prop) { 
                        strncpy(rep->codecs, (char*)prop, sizeof(rep->codecs)-1); 
                        xmlFree(prop); 
                    } else if(strlen(as_codecs) > 0) {
                        strncpy(rep->codecs, as_codecs, sizeof(rep->codecs)-1);
                    }
                    
                    prop = xmlGetProp(rep_node, (const xmlChar *)"bandwidth");
                    if(prop) { strncpy(rep->bandwidth, (char*)prop, sizeof(rep->bandwidth)-1); xmlFree(prop); }
                    
                    prop = xmlGetProp(rep_node, (const xmlChar *)"width");
                    if(prop) { 
                        strncpy(rep->width, (char*)prop, sizeof(rep->width)-1); 
                        xmlFree(prop); 
                    } else if(strlen(as_width) > 0) {
                        strncpy(rep->width, as_width, sizeof(rep->width)-1);
                    }
                    
                    prop = xmlGetProp(rep_node, (const xmlChar *)"height");
                    if(prop) { 
                        strncpy(rep->height, (char*)prop, sizeof(rep->height)-1); 
                        xmlFree(prop); 
                    } else if(strlen(as_height) > 0) {
                        strncpy(rep->height, as_height, sizeof(rep->height)-1);
                    }
                    
                    prop = xmlGetProp(rep_node, (const xmlChar *)"frameRate");
                    if(prop) { 
                        strncpy(rep->frameRate, (char*)prop, sizeof(rep->frameRate)-1); 
                        xmlFree(prop); 
                    } else if(strlen(as_frameRate) > 0) {
                        strncpy(rep->frameRate, as_frameRate, sizeof(rep->frameRate)-1);
                    }
                    
                    prop = xmlGetProp(rep_node, (const xmlChar *)"audioSamplingRate");
                    if(prop) { 
                        strncpy(rep->audioSamplingRate, (char*)prop, sizeof(rep->audioSamplingRate)-1); 
                        xmlFree(prop); 
                    } else if(strlen(as_audioSamplingRate) > 0) {
                        strncpy(rep->audioSamplingRate, as_audioSamplingRate, sizeof(rep->audioSamplingRate)-1);
                    }
                    
                    prop = xmlGetProp(rep_node, (const xmlChar *)"sar");
                    if(prop) { strncpy(rep->sar, (char*)prop, sizeof(rep->sar)-1); xmlFree(prop); }
                    
                    prop = xmlGetProp(rep_node, (const xmlChar *)"scanType");
                    if(prop) { strncpy(rep->scanType, (char*)prop, sizeof(rep->scanType)-1); xmlFree(prop); }

                    prop = xmlGetProp(rep_node, (const xmlChar *)"audioChannelCount");
                    if(prop) { strncpy(rep->audioChannelCount, (char*)prop, sizeof(rep->audioChannelCount)-1); xmlFree(prop); }

                    // mimeType may be given per Representation instead of on the AdaptationSet
                    if (as->mimeType[0] == '\0') {
                        prop = xmlGetProp(rep_node, (const xmlChar *)"mimeType");
                        if(prop) { strncpy(as->mimeType, (char*)prop, sizeof(as->mimeType)-1); xmlFree(prop); }
                    }
                    
                    // Always check for AudioChannelConfiguration elements (both in Representation and AdaptationSet)
                    if (strlen(rep->audioChannelCount) == 0) {
                        // First check within the Representation
                        xmlNodePtr audio_config_node = rep_node->children;
                        while(audio_config_node != NULL) {
                            if(audio_config_node->type == XML_ELEMENT_NODE && 
                               xmlStrcmp(audio_config_node->name, (const xmlChar*)"AudioChannelConfiguration") == 0) {
                                if (parse_audio_channel_config(audio_config_node, rep->audioChannelCount, sizeof(rep->audioChannelCount))) {
                                    break;
                                }
                            }
                            audio_config_node = audio_config_node->next;
                        }
                        
                        // If still not found, check in the parent AdaptationSet
                        if (strlen(rep->audioChannelCount) == 0) {
                            xmlNodePtr as_audio_config = as_node->children;
                            while(as_audio_config != NULL) {
                                if(as_audio_config->type == XML_ELEMENT_NODE && 
                                   xmlStrcmp(as_audio_config->name, (const xmlChar*)"AudioChannelConfiguration") == 0) {
                                    if (parse_audio_channel_config(as_audio_config, rep->audioChannelCount, sizeof(rep->audioChannelCount))) {
                                        break;
                                    }
                                }
                                as_audio_config = as_audio_config->next;
                            }
                        }
                    }
                    
                    // Calculate display aspect ratio
                    if(strlen(rep->width) > 0 && strlen(rep->height) > 0) {
                        int width = atoi(rep->width);
                        int height = atoi(rep->height);
                        double par = 1.0;
                        
                        if(strlen(rep->sar) > 0) {
                            char* colon = strchr(rep->sar, ':');
                            if(colon) {
                                int sar_w = atoi(rep->sar);
                                int sar_h = atoi(colon + 1);
                                if(sar_h > 0) par = (double)sar_w / sar_h;
                            }
                        }
                        
                        double display_ar = ((double)width * par) / height;
                        if(fabs(display_ar - 16.0/9.0) < 0.1) {
                            strcpy(rep->displayAspectRatio, "16:9");
                        } else if(fabs(display_ar - 4.0/3.0) < 0.1) {
                            strcpy(rep->displayAspectRatio, "4:3");
                        } else {
                            snprintf(rep->displayAspectRatio, sizeof(rep->displayAspectRatio), "%.2f:1", display_ar);
                        }
                    }
                    
                    // Parse Representation-level SegmentTemplate if present
                    xmlNodePtr rep_temp_node = rep_node->children;
                    while(rep_temp_node != NULL) {
                        if(rep_temp_node->type == XML_ELEMENT_NODE && xmlStrcmp(rep_temp_node->name, (const xmlChar *)"SegmentTemplate") == 0) {
                            prop = xmlGetProp(rep_temp_node, (const xmlChar *)"initialization");
                            if(prop) { strncpy(rep->segmentTemplate.initialization, (char*)prop, sizeof(rep->segmentTemplate.initialization)-1); xmlFree(prop); }
                            prop = xmlGetProp(rep_temp_node, (const xmlChar *)"media");
                            if(prop) { strncpy(rep->segmentTemplate.media, (char*)prop, sizeof(rep->segmentTemplate.media)-1); xmlFree(prop); }
                            prop = xmlGetProp(rep_temp_node, (const xmlChar *)"timescale");
                            if(prop) { strncpy(rep->segmentTemplate.timescale, (char*)prop, sizeof(rep->segmentTemplate.timescale)-1); xmlFree(prop); }
                            prop = xmlGetProp(rep_temp_node, (const xmlChar *)"startNumber");
                            if(prop) { strncpy(rep->segmentTemplate.startNumber, (char*)prop, sizeof(rep->segmentTemplate.startNumber)-1); xmlFree(prop); }
                            prop = xmlGetProp(rep_temp_node, (const xmlChar *)"duration");
                            if(prop) { strncpy(rep->segmentTemplate.duration, (char*)prop, sizeof(rep->segmentTemplate.duration)-1); xmlFree(prop); }
                            
                            // Parse SegmentTimeline if present
                            xmlNodePtr timeline_node = rep_temp_node->children;
                            SegmentTimelineS* current_s_tail = NULL;
                            while(timeline_node != NULL) {
                                if(timeline_node->type == XML_ELEMENT_NODE && xmlStrcmp(timeline_node->name, (const xmlChar*)"SegmentTimeline") == 0) {
                                    xmlNodePtr s_node = timeline_node->children;
                                    while(s_node != NULL) {
                                        if(s_node->type == XML_ELEMENT_NODE && xmlStrcmp(s_node->name, (const xmlChar*)"S") == 0) {
                                            SegmentTimelineS* s_elem = calloc(1, sizeof(SegmentTimelineS));
                                            if(s_elem) {
                                                prop = xmlGetProp(s_node, (const xmlChar*)"t");
                                                if(prop) { strncpy(s_elem->t, (char*)prop, sizeof(s_elem->t)-1); xmlFree(prop); }
                                                prop = xmlGetProp(s_node, (const xmlChar*)"d");
                                                if(prop) { strncpy(s_elem->d, (char*)prop, sizeof(s_elem->d)-1); xmlFree(prop); }
                                                prop = xmlGetProp(s_node, (const xmlChar*)"r");
                                                if(prop) { strncpy(s_elem->r, (char*)prop, sizeof(s_elem->r)-1); xmlFree(prop); }
                                                
                                                if(rep->segmentTemplate.timeline == NULL) {
                                                    rep->segmentTemplate.timeline = s_elem;
                                                    current_s_tail = s_elem;
                                                } else {
                                                    current_s_tail->next = s_elem;
                                                    current_s_tail = s_elem;
                                                }
                                            }
                                        }
                                        s_node = s_node->next;
                                    }
                                    break;
                                }
                                timeline_node = timeline_node->next;
                            }
                            break;
                        }
                        rep_temp_node = rep_temp_node->next;
                    }

                    // Copy DRM from AdaptationSet to Representation
                    if (adaptationset_drm) {
                        DrmInfo* src_drm = adaptationset_drm;
                        DrmInfo* rep_tail = NULL;
                        
                        while (src_drm) {
                            DrmInfo* copy = calloc(1, sizeof(DrmInfo));
                            if (copy) {
                                strcpy(copy->schemeIdUri, src_drm->schemeIdUri);
                                strcpy(copy->systemName, src_drm->systemName);
                                strcpy(copy->contentId, src_drm->contentId);
                                strcpy(copy->licenseUrl, src_drm->licenseUrl);
                                strcpy(copy->groupLicenseUrl, src_drm->groupLicenseUrl);
                                strcpy(copy->psshData, src_drm->psshData);
                                
                                if (rep->drmInfo == NULL) {
                                    rep->drmInfo = copy;
                                    rep_tail = copy;
                                } else {
                                    rep_tail->next = copy;
                                    rep_tail = copy;
                                }
                            }
                            src_drm = src_drm->next;
                        }
                    }

                    // Add to linked list
                    if (as->head_rep == NULL) {
                        as->head_rep = rep;
                        current_rep_tail = rep;
                    } else {
                        current_rep_tail->next = rep;
                        current_rep_tail = rep;
                    }
                }
                rep_node = rep_node->next;
            }

            // Clean up AdaptationSet DRM
            DrmInfo* cleanup_drm = adaptationset_drm;
            while (cleanup_drm != NULL) {
                DrmInfo* next = cleanup_drm->next;
                free(cleanup_drm);
                cleanup_drm = next;
            }

            // Add AdaptationSet to linked list
            if(mpd_data->head_as == NULL) {
                mpd_data->head_as = as;
                current_as_tail = as;
            } else {
                current_as_tail->next = as;
                current_as_tail = as;
            }
        }
        as_node = as_node->next;
    }
    
    return mpd_data;
}

/**
 * @brief Parses an HELD XML document into HeldData struct.
 */
HeldData* parse_held(xmlDocPtr doc) {
    HeldData* held_data = calloc(1, sizeof(HeldData));
    if (!held_data) return NULL;

    xmlNodePtr root = xmlDocGetRootElement(doc);
    if (!root) {
        free(held_data);
        return NULL;
    }
    xmlNodePtr cur_node = root->children;

    while(cur_node != NULL) {
        if(cur_node->type == XML_ELEMENT_NODE && xmlStrcmp(cur_node->name, (const xmlChar *)"HTMLEntryPackage") == 0) {
            xmlChar* prop;
            prop = xmlGetProp(cur_node, (const xmlChar *)"bbandEntryPageUrl");
            if(prop) { strncpy(held_data->bbandEntryPageUrl, (char*)prop, sizeof(held_data->bbandEntryPageUrl)-1); xmlFree(prop); }
            
            prop = xmlGetProp(cur_node, (const xmlChar *)"clearBbandEntryPageUrl");
            if(prop) { strncpy(held_data->clearBbandEntryPageUrl, (char*)prop, sizeof(held_data->clearBbandEntryPageUrl)-1); xmlFree(prop); }

            prop = xmlGetProp(cur_node, (const xmlChar *)"coupledServices");
            if(prop) { strncpy(held_data->coupledServices, (char*)prop, sizeof(held_data->coupledServices)-1); xmlFree(prop); }
            break; 
        }
        cur_node = cur_node->next;
    }
    return held_data;
}


/**
 * @brief Parses an SLT XML document into SltData struct.
 */
SltData* parse_slt(xmlDocPtr doc) {
    SltData* slt_data = calloc(1, sizeof(SltData));
    if (!slt_data) return NULL;

    xmlNodePtr root = xmlDocGetRootElement(doc);
    if (!root) {
        free(slt_data);
        return NULL;
    }
    
    xmlChar* prop = xmlGetProp(root, (const xmlChar *)"bsid");
    if(prop) { strncpy(slt_data->bsid, (char*)prop, sizeof(slt_data->bsid)-1); xmlFree(prop); }

    xmlNodePtr cur_node = root->children;
    ServiceInfo* current_service_tail = NULL;

    while (cur_node != NULL) {
        if (cur_node->type == XML_ELEMENT_NODE && xmlStrcmp(cur_node->name, (const xmlChar *)"Service") == 0) {
            ServiceInfo* service = calloc(1, sizeof(ServiceInfo));
            if (!service) continue;

            prop = xmlGetProp(cur_node, (const xmlChar *)"serviceId");
            if(prop) { strncpy(service->serviceId, (char*)prop, sizeof(service->serviceId)-1); xmlFree(prop); }
            
            prop = xmlGetProp(cur_node, (const xmlChar *)"majorChannelNo");
            if(prop) { strncpy(service->majorChannelNo, (char*)prop, sizeof(service->majorChannelNo)-1); xmlFree(prop); }

            prop = xmlGetProp(cur_node, (const xmlChar *)"minorChannelNo");
            if(prop) { strncpy(service->minorChannelNo, (char*)prop, sizeof(service->minorChannelNo)-1); xmlFree(prop); }

            prop = xmlGetProp(cur_node, (const xmlChar *)"shortServiceName");
            if(prop) { strncpy(service->shortServiceName, (char*)prop, sizeof(service->shortServiceName)-1); xmlFree(prop); }
            
            prop = xmlGetProp(cur_node, (const xmlChar *)"globalServiceID");
            if(prop) { strncpy(service->globalServiceID, (char*)prop, sizeof(service->globalServiceID)-1); xmlFree(prop); }

            prop = xmlGetProp(cur_node, (const xmlChar *)"serviceCategory");
            if(prop) { strncpy(service->serviceCategory, (char*)prop, sizeof(service->serviceCategory)-1); xmlFree(prop); }

            prop = xmlGetProp(cur_node, (const xmlChar *)"sltSvcSeqNum");
            if(prop) { strncpy(service->sltSvcSeqNum, (char*)prop, sizeof(service->sltSvcSeqNum)-1); xmlFree(prop); }

            prop = xmlGetProp(cur_node, (const xmlChar *)"protected");
            if(prop) { service->protected = (strcmp((char*)prop, "true") == 0 || strcmp((char*)prop, "1") == 0); xmlFree(prop); }

            prop = xmlGetProp(cur_node, (const xmlChar *)"broadbandAccessRequired");
            if(prop) { service->broadbandAccessRequired = (strcmp((char*)prop, "true") == 0 || strcmp((char*)prop, "1") == 0); xmlFree(prop); }

            prop = xmlGetProp(cur_node, (const xmlChar *)"hidden");
            if(prop) { service->hidden = (strcmp((char*)prop, "true") == 0 || strcmp((char*)prop, "1") == 0); xmlFree(prop); }

            prop = xmlGetProp(cur_node, (const xmlChar *)"hideInGuide");
            if(prop) { service->hideInGuide = (strcmp((char*)prop, "true") == 0 || strcmp((char*)prop, "1") == 0); xmlFree(prop); }


            xmlNodePtr sig_node = cur_node->children;
            while(sig_node != NULL) {
                if(sig_node->type == XML_ELEMENT_NODE && xmlStrcmp(sig_node->name, (const xmlChar*)"BroadcastSvcSignaling") == 0) {
                    prop = xmlGetProp(sig_node, (const xmlChar *)"slsDestinationIpAddress");
                    if(prop) { strncpy(service->slsDestinationIpAddress, (char*)prop, sizeof(service->slsDestinationIpAddress)-1); xmlFree(prop); }
                    
                    prop = xmlGetProp(sig_node, (const xmlChar *)"slsDestinationUdpPort");
                    if(prop) { strncpy(service->slsDestinationUdpPort, (char*)prop, sizeof(service->slsDestinationUdpPort)-1); xmlFree(prop); }

                    prop = xmlGetProp(sig_node, (const xmlChar *)"slsSourceIpAddress");
                    if(prop) { strncpy(service->slsSourceIpAddress, (char*)prop, sizeof(service->slsSourceIpAddress)-1); xmlFree(prop); }

                    prop = xmlGetProp(sig_node, (const xmlChar *)"slsProtocol");
                    if(prop) { strncpy(service->slsProtocol, (char*)prop, sizeof(service->slsProtocol)-1); xmlFree(prop); }
                    
                    prop = xmlGetProp(sig_node, (const xmlChar *)"slsMmtpPacketId");
                    if(prop) { strncpy(service->slsMmtpPacketId, (char*)prop, sizeof(service->slsMmtpPacketId)-1); xmlFree(prop); }

                    prop = xmlGetProp(sig_node, (const xmlChar *)"slsMajorProtocolVersion");
                    if(prop) { strncpy(service->slsMajorProtocolVersion, (char*)prop, sizeof(service->slsMajorProtocolVersion)-1); xmlFree(prop); }

                    prop = xmlGetProp(sig_node, (const xmlChar *)"slsMinorProtocolVersion");
                    if(prop) { strncpy(service->slsMinorProtocolVersion, (char*)prop, sizeof(service->slsMinorProtocolVersion)-1); xmlFree(prop); }

                    break;
                }
                sig_node = sig_node->next;
            }
            
            if (slt_data->head == NULL) {
                slt_data->head = service;
                current_service_tail = service;
            } else {
                current_service_tail->next = service;
                current_service_tail = service;
            }
        }
        cur_node = cur_node->next;
    }
    return slt_data;
}

/**
 * @brief Parses a SystemTime XML document into SystemTimeData struct.
 */
SystemTimeData* parse_system_time(xmlDocPtr doc) {
    // Allocate and zero-out memory for the struct.
    // Using calloc ensures any un-found attributes will be empty strings.
    SystemTimeData* time_data = calloc(1, sizeof(SystemTimeData));
    if (!time_data) {
        // Failed to allocate memory
        return NULL;
    }

    xmlNodePtr root = xmlDocGetRootElement(doc);
    if (!root) {
        free(time_data);
        return NULL;
    }
    
    xmlChar* prop; // Re-usable pointer for attributes

    prop = xmlGetProp(root, (const xmlChar *)"currentUtcOffset");
    if (prop) { strncpy(time_data->currentUtcOffset, (char*)prop, sizeof(time_data->currentUtcOffset)-1); xmlFree(prop); }

    prop = xmlGetProp(root, (const xmlChar *)"ptpPrepend");
    if (prop) { strncpy(time_data->ptpPrepend, (char*)prop, sizeof(time_data->ptpPrepend)-1); xmlFree(prop); }

    prop = xmlGetProp(root, (const xmlChar *)"leap59");
    if (prop) { strncpy(time_data->leap59, (char*)prop, sizeof(time_data->leap59)-1); xmlFree(prop); }

    prop = xmlGetProp(root, (const xmlChar *)"leap61");
    if (prop) { strncpy(time_data->leap61, (char*)prop, sizeof(time_data->leap61)-1); xmlFree(prop); }

    prop = xmlGetProp(root, (const xmlChar *)"utcLocalOffset");
    if (prop) { strncpy(time_data->utcLocalOffset, (char*)prop, sizeof(time_data->utcLocalOffset)-1); xmlFree(prop); }
    
    prop = xmlGetProp(root, (const xmlChar *)"dsStatus");
    if (prop) { strncpy(time_data->dsStatus, (char*)prop, sizeof(time_data->dsStatus)-1); xmlFree(prop); }
    
    prop = xmlGetProp(root, (const xmlChar *)"dsDayOfMonth");
    if (prop) { strncpy(time_data->dsDayOfMonth, (char*)prop, sizeof(time_data->dsDayOfMonth)-1); xmlFree(prop); }

    prop = xmlGetProp(root, (const xmlChar *)"dsHour");
    if (prop) { strncpy(time_data->dsHour, (char*)prop, sizeof(time_data->dsHour)-1); xmlFree(prop); }
    
    return time_data;
}

/**
 * @brief Parses an RRT (Rating Region Table) XML document.
 * Handles <RatingRegionTables> with <RatingRegionTable> children per A/331.
 */
RrtData* parse_rrt(xmlDocPtr doc) {
    RrtData* rrt_data = calloc(1, sizeof(RrtData));
    if (!rrt_data) return NULL;

    xmlNodePtr root = xmlDocGetRootElement(doc);
    if (!root) {
        free(rrt_data);
        return NULL;
    }

    RrtRegion* region_tail = NULL;

    // Find RatingRegionTable elements (children of RatingRegionTables)
    xmlNodePtr region_node = root->children;
    
    // If root is RatingRegionTable directly, process it
    if (xmlStrcmp(root->name, (const xmlChar *)"RatingRegionTable") == 0) {
        region_node = root;
    }

    while (region_node) {
        if (region_node->type == XML_ELEMENT_NODE && 
            xmlStrcmp(region_node->name, (const xmlChar *)"RatingRegionTable") == 0) {
            
            RrtRegion* region = calloc(1, sizeof(RrtRegion));
            if (!region) {
                region_node = region_node->next;
                continue;
            }

            // Get region identifier attribute
            xmlChar* prop = xmlGetProp(region_node, (const xmlChar *)"regionIdentifier");
            if (prop) {
                region->region_id = atoi((char*)prop);
                xmlFree(prop);
            }

            // Look for RegionIdText child element for region name
            xmlNodePtr child = region_node->children;
            while (child) {
                if (child->type == XML_ELEMENT_NODE && 
                    xmlStrcmp(child->name, (const xmlChar *)"RegionIdText") == 0) {
                    xmlChar* content = xmlNodeGetContent(child);
                    if (content) {
                        strncpy(region->region_name, (char*)content, sizeof(region->region_name) - 1);
                        xmlFree(content);
                    }
                    break;
                }
                child = child->next;
            }

            // Parse Dimension elements
            RrtDimension* dim_tail = NULL;
            xmlNodePtr dim_node = region_node->children;
            
            while (dim_node) {
                if (dim_node->type == XML_ELEMENT_NODE && 
                    xmlStrcmp(dim_node->name, (const xmlChar *)"Dimension") == 0) {
                    
                    RrtDimension* dim = calloc(1, sizeof(RrtDimension));
                    if (!dim) {
                        dim_node = dim_node->next;
                        continue;
                    }

                    // Get dimensionGraduated attribute
                    prop = xmlGetProp(dim_node, (const xmlChar *)"dimensionGraduated");
                    if (prop) {
                        dim->graduated_scale = (strcmp((char*)prop, "true") == 0 || 
                                                strcmp((char*)prop, "1") == 0) ? 1 : 0;
                        xmlFree(prop);
                    }

                    // Look for DimensionTitle child element
                    xmlNodePtr dim_child = dim_node->children;
                    while (dim_child) {
                        if (dim_child->type == XML_ELEMENT_NODE && 
                            xmlStrcmp(dim_child->name, (const xmlChar *)"DimensionTitle") == 0) {
                            xmlChar* content = xmlNodeGetContent(dim_child);
                            if (content) {
                                strncpy(dim->dimension_name, (char*)content, sizeof(dim->dimension_name) - 1);
                                xmlFree(content);
                            }
                            break;
                        }
                        dim_child = dim_child->next;
                    }

                    // Parse Rating elements
                    RrtRatingValue* val_tail = NULL;
                    xmlNodePtr val_node = dim_node->children;
                    
                    while (val_node) {
                        if (val_node->type == XML_ELEMENT_NODE && 
                            xmlStrcmp(val_node->name, (const xmlChar *)"Rating") == 0) {
                            
                            RrtRatingValue* val = calloc(1, sizeof(RrtRatingValue));
                            if (!val) {
                                val_node = val_node->next;
                                continue;
                            }

                            // Look for RatingValueAbbrev and RatingValueString child elements
                            xmlNodePtr rating_child = val_node->children;
                            while (rating_child) {
                                if (rating_child->type == XML_ELEMENT_NODE) {
                                    xmlChar* content = xmlNodeGetContent(rating_child);
                                    if (content && content[0] != '\0') {
                                        if (xmlStrcmp(rating_child->name, (const xmlChar *)"RatingValueAbbrev") == 0) {
                                            strncpy(val->abbrev_name, (char*)content, sizeof(val->abbrev_name) - 1);
                                        } else if (xmlStrcmp(rating_child->name, (const xmlChar *)"RatingValueString") == 0) {
                                            strncpy(val->full_name, (char*)content, sizeof(val->full_name) - 1);
                                        }
                                        xmlFree(content);
                                    } else if (content) {
                                        xmlFree(content);
                                    }
                                }
                                rating_child = rating_child->next;
                            }

                            // Only add if we got at least an abbreviation or full name
                            if (val->abbrev_name[0] != '\0' || val->full_name[0] != '\0') {
                                if (dim->values == NULL) {
                                    dim->values = val;
                                } else {
                                    val_tail->next = val;
                                }
                                val_tail = val;
                                dim->num_values++;
                            } else {
                                free(val);
                            }
                        }
                        val_node = val_node->next;
                    }

                    // Only add dimension if it has a name
                    if (dim->dimension_name[0] != '\0') {
                        if (region->dimensions == NULL) {
                            region->dimensions = dim;
                        } else {
                            dim_tail->next = dim;
                        }
                        dim_tail = dim;
                        region->num_dimensions++;
                    } else {
                        // Free empty dimension
                        RrtRatingValue* v = dim->values;
                        while (v) {
                            RrtRatingValue* next = v->next;
                            free(v);
                            v = next;
                        }
                        free(dim);
                    }
                }
                dim_node = dim_node->next;
            }

            // Add region to RRT data
            if (rrt_data->regions == NULL) {
                rrt_data->regions = region;
            } else {
                region_tail->next = region;
            }
            region_tail = region;
            rrt_data->num_regions++;
        }
        
        // If we started at root (RatingRegionTable), don't iterate siblings
        if (region_node == root) break;
        region_node = region_node->next;
    }

    DBG_PRINTF("DEBUG RRT: Parsed %d regions\n", rrt_data->num_regions);
    return rrt_data;
}

/**
 * @brief Parses a UCT XML document into UctData struct.
 */
UctData* parse_uct(xmlDocPtr doc) {
    UctData* uct_data = calloc(1, sizeof(UctData));
    if (!uct_data) return NULL;
    
    xmlNodePtr root = xmlDocGetRootElement(doc);
    if (!root) {
        free(uct_data);
        return NULL;
    }
    xmlNodePtr ndp_node = root->children;
    NdPackage* current_package_tail = NULL;

    while(ndp_node != NULL && (ndp_node->type != XML_ELEMENT_NODE || xmlStrcmp(ndp_node->name, (const xmlChar *)"NDP") != 0)) {
        ndp_node = ndp_node->next;
    }
    if(ndp_node == NULL) { free(uct_data); return NULL; }

    xmlNodePtr package_node = ndp_node->children;
    while(package_node != NULL) {
        if(package_node->type == XML_ELEMENT_NODE && xmlStrcmp(package_node->name, (const xmlChar *)"NDPackage") == 0) {
            NdPackage* package = calloc(1, sizeof(NdPackage));
            if(!package) continue;

            xmlChar* prop = xmlGetProp(package_node, (const xmlChar*)"name");
            if(prop) { strncpy(package->name, (char*)prop, sizeof(package->name)-1); xmlFree(prop); }

            prop = xmlGetProp(package_node, (const xmlChar*)"dstIP");
            if(prop) { strncpy(package->dstIP, (char*)prop, sizeof(package->dstIP)-1); xmlFree(prop); }
            
            prop = xmlGetProp(package_node, (const xmlChar*)"dstPort");
            if(prop) { strncpy(package->dstPort, (char*)prop, sizeof(package->dstPort)-1); xmlFree(prop); }

            xmlNodePtr element_node = package_node->children;
            NdElement* current_element_tail = NULL;
            while(element_node != NULL) {
                if(element_node->type == XML_ELEMENT_NODE && xmlStrcmp(element_node->name, (const xmlChar*)"NDElement") == 0) {
                     NdElement* element = calloc(1, sizeof(NdElement));
                     if(!element) continue;

                    prop = xmlGetProp(element_node, (const xmlChar*)"name");
                    if(prop) { strncpy(element->name, (char*)prop, sizeof(element->name)-1); xmlFree(prop); }

                    prop = xmlGetProp(element_node, (const xmlChar*)"tsi");
                    if(prop) { strncpy(element->tsi, (char*)prop, sizeof(element->tsi)-1); xmlFree(prop); }

                    if(package->head_element == NULL) {
                        package->head_element = element;
                        current_element_tail = element;
                    } else {
                        current_element_tail->next = element;
                        current_element_tail = element;
                    }
                }
                element_node = element_node->next;
            }

            if (uct_data->head_package == NULL) {
                uct_data->head_package = package;
                current_package_tail = package;
            } else {
                current_package_tail->next = package;
                current_package_tail = package;
            }
        }
        package_node = package_node->next;
    }
    return uct_data;
}

/**
 * @brief Parses a UDST XML document into UdstData struct.
 */
UdstData* parse_udst(xmlDocPtr doc) {
    UdstData* udst_data = calloc(1, sizeof(UdstData));
    if (!udst_data) return NULL;
    
    xmlNodePtr root = xmlDocGetRootElement(doc);
    if (!root) {
        free(udst_data);
        return NULL;
    }
    xmlChar* prop = xmlGetProp(root, (const xmlChar*)"version");
    if(prop) { strncpy(udst_data->version, (char*)prop, sizeof(udst_data->version)-1); xmlFree(prop); }

    UdsData* uds_tail = NULL;
    BroadSpanServiceInfo* current_service_tail = NULL;  // Track tail across all loop iterations
    
    xmlNodePtr uds_node = root->children;
    while(uds_node != NULL) {
        if(uds_node->type == XML_ELEMENT_NODE && xmlStrcmp(uds_node->name, (const xmlChar*)"UDS") == 0) {
            // Check if this is a simple UDS (has destIP attribute) or complex UDS (has children)
            xmlChar* dest_ip_attr = xmlGetProp(uds_node, (const xmlChar*)"destIP");
            
            if (dest_ip_attr) {
                xmlFree(dest_ip_attr);
                // Simple UDS format: use shared parser
                UdsData* uds = parse_uds_from_node(uds_node);
                if (uds) {
                    if (udst_data->head_uds == NULL) {
                        udst_data->head_uds = uds;
                        uds_tail = uds;
                    } else {
                        uds_tail->next = uds;
                        uds_tail = uds;
                    }
                }
            } else {
                // Complex UDS format with broadSpanServices children
                xmlNodePtr bss_node = uds_node->children;
                while(bss_node != NULL) {
                    if(bss_node->type == XML_ELEMENT_NODE && xmlStrcmp(bss_node->name, (const xmlChar*)"broadSpanServices") == 0) {
                        
                        xmlNodePtr service_node = bss_node->children;
                        while(service_node != NULL) {
                            if(service_node->type == XML_ELEMENT_NODE && xmlStrcmp(service_node->name, (const xmlChar*)"broadSpanService") == 0) {
                                BroadSpanServiceInfo* service = calloc(1, sizeof(BroadSpanServiceInfo));
                                if(!service) continue;

                                // Try name first, then gsid, then type for service name
                                prop = xmlGetProp(service_node, (const xmlChar*)"name");
                                if(prop) { strncpy(service->name, (char*)prop, sizeof(service->name)-1); xmlFree(prop); }
                                else {
                                    prop = xmlGetProp(service_node, (const xmlChar*)"gsid");
                                    if(prop) { strncpy(service->name, (char*)prop, sizeof(service->name)-1); xmlFree(prop); }
                                }
                                // Also get type attribute
                                prop = xmlGetProp(service_node, (const xmlChar*)"type");
                                if(prop) { 
                                    // Append type to name if we have both
                                    if (service->name[0] && strlen(service->name) < sizeof(service->name) - 10) {
                                        strcat(service->name, " (");
                                        strncat(service->name, (char*)prop, sizeof(service->name) - strlen(service->name) - 2);
                                        strcat(service->name, ")");
                                    }
                                    xmlFree(prop); 
                                }

                                xmlNodePtr child_node = service_node->children;
                                while(child_node != NULL) {
                                    // Handle <rsrv> elements (reservation format)
                                    if(child_node->type == XML_ELEMENT_NODE && 
                                       xmlStrcmp(child_node->name, (const xmlChar*)"rsrv") == 0) {
                                        RsrvInfo* rsrv = calloc(1, sizeof(RsrvInfo));
                                        if(rsrv) {
                                            rsrv->is_session = 0;
                                            prop = xmlGetProp(child_node, (const xmlChar*)"name");
                                            if(prop) { strncpy(rsrv->name, (char*)prop, sizeof(rsrv->name)-1); xmlFree(prop); }
                                            prop = xmlGetProp(child_node, (const xmlChar*)"srvid");
                                            if(prop) { strncpy(rsrv->srvid, (char*)prop, sizeof(rsrv->srvid)-1); xmlFree(prop); }
                                            prop = xmlGetProp(child_node, (const xmlChar*)"destIP");
                                            if(prop) { strncpy(rsrv->destIP, (char*)prop, sizeof(rsrv->destIP)-1); xmlFree(prop); }
                                            prop = xmlGetProp(child_node, (const xmlChar*)"destPort");
                                            if(prop) { strncpy(rsrv->destPort, (char*)prop, sizeof(rsrv->destPort)-1); xmlFree(prop); }
                                            prop = xmlGetProp(child_node, (const xmlChar*)"orderId");
                                            if(prop) { strncpy(rsrv->orderId, (char*)prop, sizeof(rsrv->orderId)-1); xmlFree(prop); }
                                            prop = xmlGetProp(child_node, (const xmlChar*)"fileName");
                                            if(prop) { strncpy(rsrv->fileName, (char*)prop, sizeof(rsrv->fileName)-1); xmlFree(prop); }
                                            service->head_rsrv = rsrv;
                                        }
                                    }
                                    // Handle <session> elements (session format with <dsrv> children)
                                    else if(child_node->type == XML_ELEMENT_NODE && 
                                            xmlStrcmp(child_node->name, (const xmlChar*)"session") == 0) {
                                        RsrvInfo* rsrv = calloc(1, sizeof(RsrvInfo));
                                        if(rsrv) {
                                            rsrv->is_session = 1;
                                            prop = xmlGetProp(child_node, (const xmlChar*)"sessionId");
                                            if(prop) { strncpy(rsrv->sessionId, (char*)prop, sizeof(rsrv->sessionId)-1); xmlFree(prop); }
                                            prop = xmlGetProp(child_node, (const xmlChar*)"destIP");
                                            if(prop) { strncpy(rsrv->destIP, (char*)prop, sizeof(rsrv->destIP)-1); xmlFree(prop); }
                                            prop = xmlGetProp(child_node, (const xmlChar*)"destPort");
                                            if(prop) { strncpy(rsrv->destPort, (char*)prop, sizeof(rsrv->destPort)-1); xmlFree(prop); }
                                            prop = xmlGetProp(child_node, (const xmlChar*)"orderId");
                                            if(prop) { strncpy(rsrv->orderId, (char*)prop, sizeof(rsrv->orderId)-1); xmlFree(prop); }
                                            prop = xmlGetProp(child_node, (const xmlChar*)"apiKey");
                                            if(prop) { xmlFree(prop); } // Acknowledge but don't store apiKey
                                            
                                            // Parse <dsrv> child element for fileName and endsAt
                                            xmlNodePtr dsrv_node = child_node->children;
                                            while(dsrv_node != NULL) {
                                                if(dsrv_node->type == XML_ELEMENT_NODE && 
                                                   xmlStrcmp(dsrv_node->name, (const xmlChar*)"dsrv") == 0) {
                                                    prop = xmlGetProp(dsrv_node, (const xmlChar*)"fileName");
                                                    if(prop) { strncpy(rsrv->fileName, (char*)prop, sizeof(rsrv->fileName)-1); xmlFree(prop); }
                                                    prop = xmlGetProp(dsrv_node, (const xmlChar*)"endsAt");
                                                    if(prop) { strncpy(rsrv->endsAt, (char*)prop, sizeof(rsrv->endsAt)-1); xmlFree(prop); }
                                                    break; // Only process first <dsrv>
                                                }
                                                dsrv_node = dsrv_node->next;
                                            }
                                            service->head_rsrv = rsrv;
                                        }
                                    }
                                    child_node = child_node->next;
                                }

                                 if (udst_data->head_service == NULL) {
                                    udst_data->head_service = service;
                                    current_service_tail = service;
                                } else {
                                    current_service_tail->next = service;
                                    current_service_tail = service;
                                }
                            }
                            service_node = service_node->next;
                        }
                    }
                    bss_node = bss_node->next;
                }
            }
        }
        uds_node = uds_node->next;
    }
    return udst_data;
}

/**
 * @brief Parses a BundleDescriptionROUTE (User Service Description) XML document.
 */
UserServiceDescriptionData* parse_user_service_description(xmlDocPtr doc) {
    UserServiceDescriptionData* usd_data = calloc(1, sizeof(UserServiceDescriptionData));
    if (!usd_data) return NULL;

    xmlNodePtr root = xmlDocGetRootElement(doc);
    if (!root) {
        free(usd_data);
        return NULL;
    }
    xmlNodePtr cur_node = root->children;
    UsdEntry* current_entry_tail = NULL;
    xmlChar* prop;

    while (cur_node != NULL) {
        if (cur_node->type == XML_ELEMENT_NODE && xmlStrcmp(cur_node->name, (const xmlChar *)"item") == 0) {
            UsdEntry* entry = calloc(1, sizeof(UsdEntry));
            if (!entry) continue;

            prop = xmlGetProp(cur_node, (const xmlChar *)"contentType");
            if(prop) { strncpy(entry->contentType, (char*)prop, sizeof(entry->contentType)-1); xmlFree(prop); }

            prop = xmlGetProp(cur_node, (const xmlChar *)"version");
            if(prop) { strncpy(entry->version, (char*)prop, sizeof(entry->version)-1); xmlFree(prop); }
            
            prop = xmlGetProp(cur_node, (const xmlChar *)"userAgent");
            if(prop) { strncpy(entry->userAgent, (char*)prop, sizeof(entry->userAgent)-1); xmlFree(prop); }

            prop = xmlGetProp(cur_node, (const xmlChar *)"filterCodes");
            if(prop) { strncpy(entry->filterCodes, (char*)prop, sizeof(entry->filterCodes)-1); xmlFree(prop); }
            
            if (usd_data->head == NULL) {
                usd_data->head = entry;
                current_entry_tail = entry;
            } else {
                current_entry_tail->next = entry;
                current_entry_tail = entry;
            }
        }
        cur_node = cur_node->next;
    }

    return usd_data;
}

char* extract_node_as_xml(xmlNodePtr node) {
    if (!node) return NULL;
    
    xmlBufferPtr buf = xmlBufferCreate();
    if (!buf) return NULL;
    
    // Create a complete XML document with declaration
    xmlBufferAdd(buf, (const xmlChar*)"<?xml version=\"1.0\" encoding=\"UTF-8\"?>", -1);
    xmlNodeDump(buf, node->doc, node, 0, 1);
    
    char* result = strdup((const char*)xmlBufferContent(buf));
    xmlBufferFree(buf);
    
    return result;
}

/**
 * @brief NEW: Parses a BundleDescriptionMMT XML document.
 */
UsdbData* parse_usbd(xmlDocPtr doc) {
    UsdbData* usbd_data = calloc(1, sizeof(UsdbData));
    if (!usbd_data) return NULL;

    xmlNodePtr root = xmlDocGetRootElement(doc);
    if (!root) {
        free(usbd_data);
        return NULL;
    }
    xmlNodePtr cur_node = root->children;
    UsdEntryMmt* entry_tail = NULL;

    while (cur_node != NULL) {
        if (cur_node->type == XML_ELEMENT_NODE && 
            xmlStrcmp(cur_node->name, (const xmlChar *)"UserServiceDescription") == 0) {
            
            // Found a USD - parse it and also store it as a separate table
            char* usd_xml = extract_node_as_xml(cur_node);
            if (usd_xml) {
                TableType type = TABLE_TYPE_USD;
                void* usd_parsed_data = NULL;
                if (parse_xml(usd_xml, strlen(usd_xml), &type, &usd_parsed_data, "Nested USD") == 0 && usd_parsed_data) {
                    store_unique_table(usd_xml, strlen(usd_xml), TABLE_TYPE_USD, usd_parsed_data, "", "", 0, -1);
                }
                free(usd_xml);
            }
            
            // Also store basic info in USBD structure
            UsdEntryMmt* entry = calloc(1, sizeof(UsdEntryMmt));
            if (entry) {
                xmlChar* prop = xmlGetProp(cur_node, (const xmlChar *)"serviceId");
                if(prop) { strncpy(entry->id, (char*)prop, sizeof(entry->id)-1); xmlFree(prop); }
                
                strcpy(entry->contentType, "UserServiceDescription");
                strcpy(entry->version, "1.0");
                
                if (usbd_data->head == NULL) {
                    usbd_data->head = entry;
                    entry_tail = entry;
                } else {
                    entry_tail->next = entry;
                    entry_tail = entry;
                }
            }
        }
        cur_node = cur_node->next;
    }

    return usbd_data;
}

UsdData* parse_usd(xmlDocPtr doc) {
    UsdData* usd_data = calloc(1, sizeof(UsdData));
    if (!usd_data) return NULL;

    xmlNodePtr root = xmlDocGetRootElement(doc);
    if (!root) {
        free(usd_data);
        return NULL;
    }
    xmlChar* prop;
    
    // Parse USD attributes
    prop = xmlGetProp(root, (const xmlChar *)"serviceId");
    if(prop) { strncpy(usd_data->serviceId, (char*)prop, sizeof(usd_data->serviceId)-1); xmlFree(prop); }

    xmlNodePtr cur_node = root->children;
    
    while (cur_node != NULL) {
        if (cur_node->type == XML_ELEMENT_NODE) {
            if (xmlStrcmp(cur_node->name, (const xmlChar *)"Name") == 0) {
                xmlChar* content = xmlNodeGetContent(cur_node);
                if(content) {
                    strncpy(usd_data->serviceName, (char*)content, sizeof(usd_data->serviceName)-1);
                    xmlFree(content);
                }
            } else if (xmlStrcmp(cur_node->name, (const xmlChar *)"MPUComponent") == 0) {
                prop = xmlGetProp(cur_node, (const xmlChar *)"mmtPackageId");
                if(prop) { 
                    strncpy(usd_data->mmtPackageId, (char*)prop, sizeof(usd_data->mmtPackageId)-1); 
                    xmlFree(prop); 
                }
            } else if (xmlStrcmp(cur_node->name, (const xmlChar *)"ComponentInfo") == 0) {
                UsdComponent* component = calloc(1, sizeof(UsdComponent));
                if (component) {
                    prop = xmlGetProp(cur_node, (const xmlChar *)"componentId");
                    if(prop) { 
                        strncpy(component->componentId, (char*)prop, sizeof(component->componentId)-1); 
                        xmlFree(prop); 
                    }
                    
                    prop = xmlGetProp(cur_node, (const xmlChar *)"componentType");
                    if(prop) { 
                        component->componentType = atoi((char*)prop);
                        xmlFree(prop); 
                    }
                    
                    prop = xmlGetProp(cur_node, (const xmlChar *)"componentRole");
                    if(prop) { 
                        component->componentRole = atoi((char*)prop);
                        xmlFree(prop); 
                    }
                    
                    // Generate description
                    const char* type_str = (component->componentType == 0) ? "Audio" :
                                          (component->componentType == 1) ? "Video" :
                                          (component->componentType == 2) ? "Data/Captions" : "Unknown";
                    const char* role_str = (component->componentRole == 0) ? "Main" : "Alternate";
                    snprintf(component->description, sizeof(component->description), 
                            "%s %s", role_str, type_str);
                    
                    // Add to component list
                    if (usd_data->components == NULL) {
                        usd_data->components = component;
                    } else {
                        UsdComponent* tail = usd_data->components;
                        while (tail->next) tail = tail->next;
                        tail->next = component;
                    }
                }
            }
        }
        cur_node = cur_node->next;
    }

    return usd_data;
}

/**
 * @brief NEW: Parses a DWD (placeholder).
 */
DwdData* parse_dwd(xmlDocPtr doc) {
    DwdData* dwd_data = calloc(1, sizeof(DwdData));
    if (!dwd_data) return NULL;
    strncpy(dwd_data->placeholder, "Parsed", sizeof(dwd_data->placeholder)-1);
    return dwd_data;
}

/**
 * @brief Parses a UDS (User Defined Stream) XML document.
 */
/**
 * @brief Parses UDS attributes from an XML node into a UdsData struct.
 * Can be used for standalone UDS tables or UDS elements inside UDST.
 */
UdsData* parse_uds_from_node(xmlNodePtr node) {
    if (!node) return NULL;
    
    UdsData* uds_data = calloc(1, sizeof(UdsData));
    if (!uds_data) return NULL;

    xmlChar* prop;
    
    prop = xmlGetProp(node, (const xmlChar *)"contextId");
    if (prop) { strncpy(uds_data->contextId, (char*)prop, sizeof(uds_data->contextId)-1); xmlFree(prop); }
    
    prop = xmlGetProp(node, (const xmlChar *)"destIP");
    if (prop) { strncpy(uds_data->destIP, (char*)prop, sizeof(uds_data->destIP)-1); xmlFree(prop); }
    
    prop = xmlGetProp(node, (const xmlChar *)"destPort");
    if (prop) { strncpy(uds_data->destPort, (char*)prop, sizeof(uds_data->destPort)-1); xmlFree(prop); }
    
    prop = xmlGetProp(node, (const xmlChar *)"maxBitrate");
    if (prop) { strncpy(uds_data->maxBitrate, (char*)prop, sizeof(uds_data->maxBitrate)-1); xmlFree(prop); }
    
    prop = xmlGetProp(node, (const xmlChar *)"name");
    if (prop) { strncpy(uds_data->name, (char*)prop, sizeof(uds_data->name)-1); xmlFree(prop); }

    uds_data->sample_collected = 0;
    uds_data->sample_payload_len = 0;

    return uds_data;
}

UdsData* parse_uds(xmlDocPtr doc) {
    xmlNodePtr root = xmlDocGetRootElement(doc);
    return parse_uds_from_node(root);
}

/**
 * @brief Parses an AEAT (Advanced Emergency Alert Table) XML document.
 */
AeatData* parse_aeat(xmlDocPtr doc) {
    AeatData* aeat_data = calloc(1, sizeof(AeatData));
    if (!aeat_data) return NULL;

    xmlNodePtr root = xmlDocGetRootElement(doc);
    if (!root) {
        free(aeat_data);
        return NULL;
    }

    xmlChar* prop;
    AeaEntry* current_aea_tail = NULL;
    
    // Iterate through AEA elements
    for (xmlNodePtr aea_node = root->children; aea_node; aea_node = aea_node->next) {
        if (aea_node->type != XML_ELEMENT_NODE) continue;
        if (xmlStrcmp(aea_node->name, (const xmlChar *)"AEA") != 0) continue;
        
        AeaEntry* aea = calloc(1, sizeof(AeaEntry));
        if (!aea) continue;
        
        // Parse AEA attributes
        prop = xmlGetProp(aea_node, (const xmlChar *)"aeaId");
        if (prop) { strncpy(aea->aeaId, (char*)prop, sizeof(aea->aeaId)-1); xmlFree(prop); }
        
        prop = xmlGetProp(aea_node, (const xmlChar *)"aeaType");
        if (prop) { strncpy(aea->aeaType, (char*)prop, sizeof(aea->aeaType)-1); xmlFree(prop); }
        
        prop = xmlGetProp(aea_node, (const xmlChar *)"audience");
        if (prop) { strncpy(aea->audience, (char*)prop, sizeof(aea->audience)-1); xmlFree(prop); }
        
        prop = xmlGetProp(aea_node, (const xmlChar *)"category");
        if (prop) { strncpy(aea->category, (char*)prop, sizeof(aea->category)-1); xmlFree(prop); }
        
        prop = xmlGetProp(aea_node, (const xmlChar *)"issuer");
        if (prop) { strncpy(aea->issuer, (char*)prop, sizeof(aea->issuer)-1); xmlFree(prop); }
        
        prop = xmlGetProp(aea_node, (const xmlChar *)"priority");
        if (prop) { strncpy(aea->priority, (char*)prop, sizeof(aea->priority)-1); xmlFree(prop); }
        
        prop = xmlGetProp(aea_node, (const xmlChar *)"wakeup");
        if (prop) { strncpy(aea->wakeup, (char*)prop, sizeof(aea->wakeup)-1); xmlFree(prop); }
        
        // Parse child elements
        AeatMedia* current_media_tail = NULL;
        for (xmlNodePtr child = aea_node->children; child; child = child->next) {
            if (child->type != XML_ELEMENT_NODE) continue;
            
            if (xmlStrcmp(child->name, (const xmlChar *)"Header") == 0) {
                prop = xmlGetProp(child, (const xmlChar *)"effective");
                if (prop) { strncpy(aea->effective, (char*)prop, sizeof(aea->effective)-1); xmlFree(prop); }
                
                prop = xmlGetProp(child, (const xmlChar *)"expires");
                if (prop) { strncpy(aea->expires, (char*)prop, sizeof(aea->expires)-1); xmlFree(prop); }
                
                // Parse Header children (EventCode, EventDesc, Location)
                for (xmlNodePtr hdr_child = child->children; hdr_child; hdr_child = hdr_child->next) {
                    if (hdr_child->type != XML_ELEMENT_NODE) continue;
                    
                    if (xmlStrcmp(hdr_child->name, (const xmlChar *)"EventCode") == 0) {
                        prop = xmlGetProp(hdr_child, (const xmlChar *)"type");
                        if (prop) { strncpy(aea->eventCodeType, (char*)prop, sizeof(aea->eventCodeType)-1); xmlFree(prop); }
                        
                        xmlChar* content = xmlNodeGetContent(hdr_child);
                        if (content) { strncpy(aea->eventCode, (char*)content, sizeof(aea->eventCode)-1); xmlFree(content); }
                    }
                    else if (xmlStrcmp(hdr_child->name, (const xmlChar *)"EventDesc") == 0) {
                        prop = xmlGetProp(hdr_child, (const xmlChar *)"lang");
                        if (!prop) prop = xmlGetNsProp(hdr_child, (const xmlChar *)"lang", (const xmlChar *)"http://www.w3.org/XML/1998/namespace");
                        if (prop) { strncpy(aea->eventDescLang, (char*)prop, sizeof(aea->eventDescLang)-1); xmlFree(prop); }
                        
                        xmlChar* content = xmlNodeGetContent(hdr_child);
                        if (content) { strncpy(aea->eventDesc, (char*)content, sizeof(aea->eventDesc)-1); xmlFree(content); }
                    }
                    else if (xmlStrcmp(hdr_child->name, (const xmlChar *)"Location") == 0) {
                        prop = xmlGetProp(hdr_child, (const xmlChar *)"type");
                        if (prop) { strncpy(aea->locationType, (char*)prop, sizeof(aea->locationType)-1); xmlFree(prop); }
                        
                        xmlChar* content = xmlNodeGetContent(hdr_child);
                        if (content) { strncpy(aea->location, (char*)content, sizeof(aea->location)-1); xmlFree(content); }
                    }
                }
            }
            else if (xmlStrcmp(child->name, (const xmlChar *)"AEAText") == 0) {
                prop = xmlGetProp(child, (const xmlChar *)"lang");
                if (!prop) prop = xmlGetNsProp(child, (const xmlChar *)"lang", (const xmlChar *)"http://www.w3.org/XML/1998/namespace");
                if (prop) { strncpy(aea->aeaTextLang, (char*)prop, sizeof(aea->aeaTextLang)-1); xmlFree(prop); }
                
                xmlChar* content = xmlNodeGetContent(child);
                if (content) { strncpy(aea->aeaText, (char*)content, sizeof(aea->aeaText)-1); xmlFree(content); }
            }
            else if (xmlStrcmp(child->name, (const xmlChar *)"Media") == 0) {
                AeatMedia* media = calloc(1, sizeof(AeatMedia));
                if (!media) continue;
                
                prop = xmlGetProp(child, (const xmlChar *)"url");
                if (prop) { strncpy(media->url, (char*)prop, sizeof(media->url)-1); xmlFree(prop); }
                
                prop = xmlGetProp(child, (const xmlChar *)"contentType");
                if (prop) { strncpy(media->contentType, (char*)prop, sizeof(media->contentType)-1); xmlFree(prop); }
                
                prop = xmlGetProp(child, (const xmlChar *)"contentLength");
                if (prop) { strncpy(media->contentLength, (char*)prop, sizeof(media->contentLength)-1); xmlFree(prop); }
                
                prop = xmlGetProp(child, (const xmlChar *)"mediaType");
                if (prop) { strncpy(media->mediaType, (char*)prop, sizeof(media->mediaType)-1); xmlFree(prop); }
                
                prop = xmlGetProp(child, (const xmlChar *)"mediaDesc");
                if (prop) { strncpy(media->mediaDesc, (char*)prop, sizeof(media->mediaDesc)-1); xmlFree(prop); }
                
                prop = xmlGetProp(child, (const xmlChar *)"lang");
                if (!prop) prop = xmlGetNsProp(child, (const xmlChar *)"lang", (const xmlChar *)"http://www.w3.org/XML/1998/namespace");
                if (prop) { strncpy(media->lang, (char*)prop, sizeof(media->lang)-1); xmlFree(prop); }
                
                // Add to media list
                if (aea->head_media == NULL) {
                    aea->head_media = media;
                    current_media_tail = media;
                } else {
                    current_media_tail->next = media;
                    current_media_tail = media;
                }
            }
        }
        
        // Add AEA to list
        if (aeat_data->head_aea == NULL) {
            aeat_data->head_aea = aea;
            current_aea_tail = aea;
        } else {
            current_aea_tail->next = aea;
            current_aea_tail = aea;
        }
        aeat_data->aea_count++;
    }

    return aeat_data;
}


/**
 * @brief Parses a metadataEnvelope (Service Signaling) XML document.
 */
ServiceSignalingData* parse_service_signaling(xmlDocPtr doc) {
    ServiceSignalingData* signaling_data = calloc(1, sizeof(ServiceSignalingData));
    if (!signaling_data) return NULL;

    xmlNodePtr root = xmlDocGetRootElement(doc);
    if (!root) {
        free(signaling_data);
        return NULL;
    }
    xmlNodePtr cur_node = root->children;
    ServiceSignalingFragment* current_frag_tail = NULL;
    xmlChar* prop;

    while (cur_node != NULL) {
        if (cur_node->type == XML_ELEMENT_NODE && xmlStrcmp(cur_node->name, (const xmlChar *)"metadataFragment") == 0) {
            ServiceSignalingFragment* frag = calloc(1, sizeof(ServiceSignalingFragment));
            if (!frag) continue;

            prop = xmlGetProp(cur_node, (const xmlChar *)"contentType");
            if(prop) { strncpy(frag->contentType, (char*)prop, sizeof(frag->contentType)-1); xmlFree(prop); }

            prop = xmlGetProp(cur_node, (const xmlChar *)"version");
            if(prop) { strncpy(frag->version, (char*)prop, sizeof(frag->version)-1); xmlFree(prop); }
            
            if (signaling_data->head == NULL) {
                signaling_data->head = frag;
                current_frag_tail = frag;
            } else {
                current_frag_tail->next = frag;
                current_frag_tail = frag;
            }
        }
        cur_node = cur_node->next;
    }

    return signaling_data;
}

/**
 * @brief Parses an S-TSID XML document into an StsidData struct.
 * Also triggers parsing of embedded FDT-Instances.
 */
StsidData* parse_stsid(xmlDocPtr doc) {
    StsidData* stsid_data = calloc(1, sizeof(StsidData));
    if (!stsid_data) return NULL;

    xmlNodePtr root = xmlDocGetRootElement(doc);
    if (!root) {
        free(stsid_data);
        return NULL;
    }
    xmlNodePtr rs_node = root->children;
    StsidLogicalStream* current_ls_tail = NULL;
    xmlChar* prop;

    // Find the RS node
    while (rs_node != NULL && (rs_node->type != XML_ELEMENT_NODE || xmlStrcmp(rs_node->name, (const xmlChar *)"RS") != 0)) {
        rs_node = rs_node->next;
    }
    if (!rs_node) {
        free(stsid_data);
        return NULL;
    }

    prop = xmlGetProp(rs_node, (const xmlChar*)"dIpAddr");
    if(prop) { strncpy(stsid_data->dIpAddr, (char*)prop, sizeof(stsid_data->dIpAddr)-1); xmlFree(prop); }
    else {
        // Try sIpAddr as fallback (source IP)
        prop = xmlGetProp(rs_node, (const xmlChar*)"sIpAddr");
        if(prop) { strncpy(stsid_data->dIpAddr, (char*)prop, sizeof(stsid_data->dIpAddr)-1); xmlFree(prop); }
    }
    prop = xmlGetProp(rs_node, (const xmlChar*)"dPort");
    if(prop) { strncpy(stsid_data->dPort, (char*)prop, sizeof(stsid_data->dPort)-1); xmlFree(prop); }
    else {
        // Try sPort as fallback
        prop = xmlGetProp(rs_node, (const xmlChar*)"sPort");
        if(prop) { strncpy(stsid_data->dPort, (char*)prop, sizeof(stsid_data->dPort)-1); xmlFree(prop); }
    }

    // Iterate through LS nodes
    xmlNodePtr ls_node = rs_node->children;
    int ls_count = 0;
    while(ls_node != NULL) {
        if(ls_node->type == XML_ELEMENT_NODE && xmlStrcmp(ls_node->name, (const xmlChar *)"LS") == 0) {
            StsidLogicalStream* ls = calloc(1, sizeof(StsidLogicalStream));
            if(!ls) continue;

            prop = xmlGetProp(ls_node, (const xmlChar*)"tsi");
            if(prop) { 
                strncpy(ls->tsi, (char*)prop, sizeof(ls->tsi)-1); 
                xmlFree(prop); 
            }

            // MOVE THE LINKED LIST ADDITION HERE, BEFORE MediaInfo parsing
            if (stsid_data->head_ls == NULL) {
                stsid_data->head_ls = ls;
                current_ls_tail = ls;
            } else {
                current_ls_tail->next = ls;
                current_ls_tail = ls;
            }
            ls_count++;

            // Now try to find MediaInfo (this might fail, but stream is already added)
            xmlNodePtr srcflow_node = ls_node->children;
            while(srcflow_node != NULL && (srcflow_node->type != XML_ELEMENT_NODE || xmlStrcmp(srcflow_node->name, (const xmlChar*)"SrcFlow") != 0)) {
                srcflow_node = srcflow_node->next;
            }
            if(srcflow_node) {
                xmlNodePtr contentinfo_node = srcflow_node->children;
                 while(contentinfo_node != NULL && (contentinfo_node->type != XML_ELEMENT_NODE || xmlStrcmp(contentinfo_node->name, (const xmlChar*)"ContentInfo") != 0)) {
                    contentinfo_node = contentinfo_node->next;
                }
                if(contentinfo_node) {
                    xmlNodePtr mediainfo_node = contentinfo_node->children;
                     while(mediainfo_node != NULL && (mediainfo_node->type != XML_ELEMENT_NODE || xmlStrcmp(mediainfo_node->name, (const xmlChar*)"MediaInfo") != 0)) {
                        mediainfo_node = mediainfo_node->next;
                    }
                    if(mediainfo_node) {
                        prop = xmlGetProp(mediainfo_node, (const xmlChar*)"repId");
                        if(prop) { 
                            strncpy(ls->repId, (char*)prop, sizeof(ls->repId)-1); 
                            xmlFree(prop); 
                        }
                        prop = xmlGetProp(mediainfo_node, (const xmlChar*)"contentType");
                        if(prop) { 
                            strncpy(ls->contentType, (char*)prop, sizeof(ls->contentType)-1); 
                            xmlFree(prop); 
                        }
                        
                        // Parse ContentRatings
                        xmlNodePtr rating_node = mediainfo_node->children;
                        ContentRatingInfo* current_rating_tail = NULL;
                        while(rating_node != NULL) {
                            if(rating_node->type == XML_ELEMENT_NODE && xmlStrcmp(rating_node->name, (const xmlChar*)"ContentRating") == 0) {
                                ContentRatingInfo* rating = calloc(1, sizeof(ContentRatingInfo));
                                if(rating) {
                                    prop = xmlGetProp(rating_node, (const xmlChar*)"value");
                                    if(prop) { strncpy(rating->value, (char*)prop, sizeof(rating->value)-1); xmlFree(prop); }
                                    
                                    if(ls->head_rating == NULL) {
                                        ls->head_rating = rating;
                                        current_rating_tail = rating;
                                    } else {
                                        current_rating_tail->next = rating;
                                        current_rating_tail = rating;
                                    }
                                }
                            }
                            rating_node = rating_node->next;
                        }
                    }
                }
                
                // Parse embedded EFDT for file manifest
                xmlNodePtr efdt_node = srcflow_node->children;
                while (efdt_node != NULL) {
                    if (efdt_node->type == XML_ELEMENT_NODE && xmlStrcmp(efdt_node->name, (const xmlChar*)"EFDT") == 0) {
                        // Look for FDT-Instance inside EFDT
                        xmlNodePtr fdt_instance = efdt_node->children;
                        while (fdt_instance != NULL) {
                            if (fdt_instance->type == XML_ELEMENT_NODE && 
                                xmlStrcmp(fdt_instance->name, (const xmlChar*)"FDT-Instance") == 0) {
                                // Parse File entries (may be namespaced as fdt:File)
                                xmlNodePtr file_node = fdt_instance->children;
                                StsidFileEntry* file_tail = NULL;
                                while (file_node != NULL) {
                                    // Check for "File" element
                                    if (file_node->type == XML_ELEMENT_NODE && 
                                        xmlStrcmp(file_node->name, (const xmlChar*)"File") == 0) {
                                        StsidFileEntry* file_entry = calloc(1, sizeof(StsidFileEntry));
                                        if (file_entry) {
                                            prop = xmlGetProp(file_node, (const xmlChar*)"TOI");
                                            if (prop) {
                                                file_entry->toi = (uint32_t)strtoul((char*)prop, NULL, 10);
                                                xmlFree(prop);
                                            }
                                            prop = xmlGetProp(file_node, (const xmlChar*)"Content-Location");
                                            if (prop) {
                                                strncpy(file_entry->content_location, (char*)prop, sizeof(file_entry->content_location) - 1);
                                                xmlFree(prop);
                                            }
                                            prop = xmlGetProp(file_node, (const xmlChar*)"Content-Length");
                                            if (prop) {
                                                file_entry->content_length = strtoull((char*)prop, NULL, 10);
                                                xmlFree(prop);
                                            }
                                            prop = xmlGetProp(file_node, (const xmlChar*)"Content-Type");
                                            if (prop) {
                                                strncpy(file_entry->content_type, (char*)prop, sizeof(file_entry->content_type) - 1);
                                                xmlFree(prop);
                                            }
                                            
                                            // Add to list
                                            if (ls->head_file == NULL) {
                                                ls->head_file = file_entry;
                                            } else {
                                                file_tail->next = file_entry;
                                            }
                                            file_tail = file_entry;
                                            ls->file_count++;
                                        }
                                    }
                                    file_node = file_node->next;
                                }
                            }
                            fdt_instance = fdt_instance->next;
                        }
                    }
                    efdt_node = efdt_node->next;
                }
                
                // Also parse any embedded tables like FDT within the SrcFlow
                parse_embedded_children(srcflow_node, stsid_data->dIpAddr, stsid_data->dPort);
            }
        }
        ls_node = ls_node->next;
    }
    return stsid_data;
}

/**
 * @brief Enhanced GZIP decompression with better error reporting
 */
char* decompress_gzip(const uint8_t* compressed_data, int compressed_size, int* decompressed_size_out, int* consumed_size_out) {
    *decompressed_size_out = 0;
    *consumed_size_out = 0;

    if (compressed_size < 10) {
        DBG_PRINTF("DEBUG GZIP: Input too small (%d bytes)\n", compressed_size);
        return NULL;
    }

    // Verify GZIP header
    if (compressed_data[0] != 0x1f || compressed_data[1] != 0x8b) {
        DBG_PRINTF("DEBUG GZIP: Invalid magic bytes: %02x %02x\n", compressed_data[0], compressed_data[1]);
        return NULL;
    }

    z_stream stream = {0};
    if (inflateInit2(&stream, 16 + MAX_WBITS) != Z_OK) {
        DBG_PRINTF("DEBUG GZIP: inflateInit2 failed\n");
        return NULL;
    }

    // Start with 64KB output buffer, expand if needed
    int output_buffer_size = 65536;
    char* output_buffer = malloc(output_buffer_size);
    if (!output_buffer) {
        inflateEnd(&stream);
        return NULL;
    }

    stream.next_in = (Bytef*)compressed_data;
    stream.avail_in = compressed_size;
    stream.next_out = (Bytef*)output_buffer;
    stream.avail_out = output_buffer_size;
    
    int ret;

    do {
        ret = inflate(&stream, Z_NO_FLUSH);

        if (ret == Z_STREAM_ERROR || ret == Z_MEM_ERROR) {
            DBG_PRINTF("DEBUG GZIP: inflate error %d\n", ret);
            free(output_buffer);
            inflateEnd(&stream);
            return NULL;
        }

        // For Z_DATA_ERROR, if we got significant output, use it anyway
        if (ret == Z_DATA_ERROR) {
            if (stream.total_out > 100) {  // We got at least some useful data
                DBG_PRINTF("DEBUG GZIP: Z_DATA_ERROR but recovered %lu bytes\n", stream.total_out);
                *decompressed_size_out = stream.total_out;
                *consumed_size_out = compressed_size - stream.avail_in;
                inflateEnd(&stream);
                if (*decompressed_size_out < output_buffer_size) {
                    output_buffer[*decompressed_size_out] = '\0';
                }
                return output_buffer;
            }
            DBG_PRINTF("DEBUG GZIP: inflate error %d\n", ret);
            free(output_buffer);
            inflateEnd(&stream);
            return NULL;
        }

        // If output buffer is full, expand it
        if (stream.avail_out == 0 && ret != Z_STREAM_END) {
            int current_size = output_buffer_size - stream.avail_out;
            output_buffer_size *= 2;
            char* new_buffer = realloc(output_buffer, output_buffer_size);
            if (!new_buffer) {
                free(output_buffer);
                inflateEnd(&stream);
                return NULL;
            }
            output_buffer = new_buffer;
            stream.next_out = (Bytef*)(output_buffer + current_size);
            stream.avail_out = output_buffer_size - current_size;
        }

    } while (ret != Z_STREAM_END && stream.avail_in > 0);

    *decompressed_size_out = stream.total_out;
    *consumed_size_out = compressed_size - stream.avail_in;

    if (ret == Z_STREAM_END) {
        DBG_PRINTF("DEBUG GZIP SUCCESS: Decompressed %lu bytes\n", stream.total_out);
    } else {
        DBG_PRINTF("DEBUG GZIP: Incomplete decompression, ret=%d\n", ret);
    }

    inflateEnd(&stream);

    // Null-terminate for safety when treating as string
    if (*decompressed_size_out < output_buffer_size) {
        output_buffer[*decompressed_size_out] = '\0';
    }

    return output_buffer;
}



// Comparison function for sorting data usage by bytes (descending)
int compare_data_usage(const void *a, const void *b) {
    const DataUsageEntry *entry_a = (const DataUsageEntry *)a;
    const DataUsageEntry *entry_b = (const DataUsageEntry *)b;
    
    // First compare by IP address
    int ip_cmp = strcmp(entry_a->destinationIp, entry_b->destinationIp);
    if (ip_cmp != 0) return ip_cmp;
    
    // If IPs are the same, compare by port
    int port_cmp = strcmp(entry_a->destinationPort, entry_b->destinationPort);
    if (port_cmp != 0) return port_cmp;
    
    // If IPs and ports are the same, compare by TSI/Packet ID
    if (entry_a->tsi_or_packet_id < entry_b->tsi_or_packet_id) return -1;
    if (entry_a->tsi_or_packet_id > entry_b->tsi_or_packet_id) return 1;
    return 0;
}

int compare_data_usage_by_bytes(const void *a, const void *b) {
    DataUsageEntry *entry_a = (DataUsageEntry *)a;
    DataUsageEntry *entry_b = (DataUsageEntry *)b;
    
    // Always sort stuffing to the end
    int a_is_stuffing = (strcmp(entry_a->stream_type, "Stuffing") == 0);
    int b_is_stuffing = (strcmp(entry_b->stream_type, "Stuffing") == 0);
    
    if (a_is_stuffing && !b_is_stuffing) return 1;   // a goes after b
    if (!a_is_stuffing && b_is_stuffing) return -1;  // a goes before b
    
    // Both stuffing or both not stuffing - sort by bytes descending
    if (entry_b->total_bytes > entry_a->total_bytes) return 1;
    if (entry_b->total_bytes < entry_a->total_bytes) return -1;
    return 0;
}

void consolidate_data_usage_entries() {
    
    // First: merge exact duplicates (same IP:port:TSI/PID and stream_type)
    // These arise when reclassify_data_usage_after_slt corrects a misclassified
    // entry's TSI, creating a duplicate of an already-correct entry.
    for (int i = 0; i < g_data_usage_count; i++) {
        DataUsageEntry* entry_i = &g_data_usage[i];
        if (entry_i->total_bytes == 0) continue;
        
        for (int j = i + 1; j < g_data_usage_count; j++) {
            DataUsageEntry* entry_j = &g_data_usage[j];
            if (entry_j->total_bytes == 0) continue;
            
            if (strcmp(entry_i->destinationIp, entry_j->destinationIp) == 0 &&
                strcmp(entry_i->destinationPort, entry_j->destinationPort) == 0 &&
                strcmp(entry_i->stream_type, entry_j->stream_type) == 0 &&
                entry_i->tsi_or_packet_id == entry_j->tsi_or_packet_id) {
                
                // Exact duplicate - merge j into i
                entry_i->total_bytes += entry_j->total_bytes;
                entry_i->packet_count += entry_j->packet_count;
                merge_rate_bins(entry_i, entry_j);
                
                // Keep the better description (longer = more detailed)
                if (strlen(entry_j->description) > strlen(entry_i->description)) {
                    strncpy(entry_i->description, entry_j->description, sizeof(entry_i->description) - 1);
                }
                
                // Keep sample if i doesn't have one
                if (!entry_i->sample_collected && entry_j->sample_collected) {
                    memcpy(entry_i->sample_payload, entry_j->sample_payload, entry_j->sample_payload_len);
                    entry_i->sample_payload_len = entry_j->sample_payload_len;
                    entry_i->sample_collected = 1;
                }
                
                // Mark j as consolidated
                entry_j->total_bytes = 0;
                entry_j->packet_count = 0;
            }
        }
    }
    
    // Second: consolidate MMT entries with same media type (existing logic)
    for (int i = 0; i < g_data_usage_count; i++) {
        DataUsageEntry* entry_i = &g_data_usage[i];
        if (entry_i->total_bytes == 0) continue; // Already consolidated
        
        // Look for other entries with same IP:port and media type
        for (int j = i + 1; j < g_data_usage_count; j++) {
            DataUsageEntry* entry_j = &g_data_usage[j];
            if (entry_j->total_bytes == 0) continue; // Already consolidated
            
            // Same service and protocol?
            if (strcmp(entry_i->destinationIp, entry_j->destinationIp) == 0 &&
                strcmp(entry_i->destinationPort, entry_j->destinationPort) == 0 &&
                strcmp(entry_i->stream_type, entry_j->stream_type) == 0) {
                
                // Both are MMT and have similar media types?
                if (strcmp(entry_i->stream_type, "MMT") == 0) {
                    const char* type_i = get_media_type_from_mpt(entry_i->destinationIp, entry_i->destinationPort, entry_i->tsi_or_packet_id);
                    const char* type_j = get_media_type_from_mpt(entry_j->destinationIp, entry_j->destinationPort, entry_j->tsi_or_packet_id);
                    
                    // Consolidate if same media type (e.g., all "Data/Captions" entries)
                    if (strcmp(type_i, type_j) == 0 && 
                        (strcmp(type_i, "Data/Captions") == 0 || strcmp(type_i, "caption") == 0)) {
                        
                        // Merge j into i
                        entry_i->total_bytes += entry_j->total_bytes;
                        entry_i->packet_count += entry_j->packet_count;
                        merge_rate_bins(entry_i, entry_j);
                        
                        // Update description to show consolidation
                        snprintf(entry_i->description, sizeof(entry_i->description), 
                                "%s - MMT %s (Multiple PIDs)", 
                                get_service_name_for_destination(entry_i->destinationIp, entry_i->destinationPort),
                                type_i);
                        
                        // Mark j as consolidated
                        entry_j->total_bytes = 0;
                        entry_j->packet_count = 0;
                    }
                }
            }
        }
    }
    
    // Remove consolidated (empty) entries
    int write_idx = 0;
    for (int read_idx = 0; read_idx < g_data_usage_count; read_idx++) {
        if (g_data_usage[read_idx].total_bytes > 0) {
            if (write_idx != read_idx) {
                g_data_usage[write_idx] = g_data_usage[read_idx];
            }
            write_idx++;
        }
    }
    
    //int removed = g_data_usage_count - write_idx;
    g_data_usage_count = write_idx;
}

void generate_data_usage_chart(FILE *f) {
    if (g_data_usage_count == 0 || g_total_capture_bytes == 0) {
        return;
    }
    
    // Sort entries by total bytes (descending)
    qsort(g_data_usage, g_data_usage_count, sizeof(DataUsageEntry), compare_data_usage_by_bytes);
    
    fprintf(f, "<h2>ATSC 3.0 Data Usage Analysis</h2>\n");
    fprintf(f, "<script>\n");
    fprintf(f, "function sortTable(n) {\n");
    fprintf(f, "  var table = document.getElementById('usageTable');\n");
    fprintf(f, "  var rows = Array.from(table.rows).slice(1);\n");
    fprintf(f, "  var dir = table.getAttribute('data-sort-dir') === 'asc' ? 'desc' : 'asc';\n");
    fprintf(f, "  \n");
    fprintf(f, "  rows.sort(function(a, b) {\n");
    fprintf(f, "    var aVal = a.cells[n].textContent.trim();\n");
    fprintf(f, "    var bVal = b.cells[n].textContent.trim();\n");
    fprintf(f, "    \n");
    fprintf(f, "    // Handle percentage and data size columns\n");
    fprintf(f, "    if (n === 1) { // Usage column - extract percentage\n");
    fprintf(f, "      aVal = parseFloat(aVal.match(/([0-9.]+)%%/)[1]);\n");
    fprintf(f, "      bVal = parseFloat(bVal.match(/([0-9.]+)%%/)[1]);\n");
    fprintf(f, "    } else if (n === 4) { // Packet Count - integer (NEW)\n");
    fprintf(f, "      aVal = parseInt(aVal.replace(/,/g, ''));\n");
    fprintf(f, "      bVal = parseInt(bVal.replace(/,/g, ''));\n");
    fprintf(f, "    } else if (n === 5) { // Total Data column - convert to bytes (Shifted from 4)\n");
    fprintf(f, "      aVal = parseDataSize(aVal);\n");
    fprintf(f, "      bVal = parseDataSize(bVal);\n");
    fprintf(f, "    } else if (n === 6) { // Bitrate column - convert to bps (Shifted from 5)\n");
    fprintf(f, "      aVal = parseBitrate(aVal);\n");
    fprintf(f, "      bVal = parseBitrate(bVal);\n");
    fprintf(f, "    }\n");
    fprintf(f, "    \n");
    fprintf(f, "    if (typeof aVal === 'number' && typeof bVal === 'number') {\n");
    fprintf(f, "      return dir === 'asc' ? aVal - bVal : bVal - aVal;\n");
    fprintf(f, "    } else {\n");
    fprintf(f, "      return dir === 'asc' ? aVal.localeCompare(bVal) : bVal.localeCompare(aVal);\n");
    fprintf(f, "    }\n");
    fprintf(f, "  });\n");
    fprintf(f, "  \n");
    fprintf(f, "  // Clear existing rows and add sorted ones\n");
    fprintf(f, "  while(table.rows.length > 1) table.deleteRow(1);\n");
    fprintf(f, "  rows.forEach(function(row) { table.appendChild(row); });\n");
    fprintf(f, "  \n");
    fprintf(f, "  table.setAttribute('data-sort-dir', dir);\n");
    fprintf(f, "  \n");
    fprintf(f, "  // Update header arrows\n");
    fprintf(f, "  var headers = table.querySelectorAll('th');\n");
    fprintf(f, "  headers.forEach(function(th, i) {\n");
    fprintf(f, "    th.style.cursor = 'pointer';\n");
    fprintf(f, "    if (i === n) {\n");
    fprintf(f, "      th.innerHTML = th.innerHTML.replace(/ [↑↓]/g, '') + (dir === 'asc' ? ' ↑' : ' ↓');\n");
    fprintf(f, "    } else {\n");
    fprintf(f, "      th.innerHTML = th.innerHTML.replace(/ [↑↓]/g, '');\n");
    fprintf(f, "    }\n");
    fprintf(f, "  });\n");
    fprintf(f, "}\n");
    fprintf(f, "\n");
    fprintf(f, "function parseDataSize(str) {\n");
    fprintf(f, "  var match = str.match(/([0-9.]+)\\s*(MB|KB|bytes)/i);\n");
    fprintf(f, "  if (!match) return 0;\n");
    fprintf(f, "  var val = parseFloat(match[1]);\n");
    fprintf(f, "  var unit = match[2].toUpperCase();\n");
    fprintf(f, "  if (unit === 'MB') return val * 1000000;\n");
    fprintf(f, "  if (unit === 'KB') return val * 1000;\n");
    fprintf(f, "  return val;\n");
    fprintf(f, "}\n");
    fprintf(f, "\n");
    fprintf(f, "function parseBitrate(str) {\n");
    fprintf(f, "  if (str === 'N/A') return 0;\n");
    fprintf(f, "  var match = str.match(/([0-9.]+)\\s*(Mbps|Kbps|bps)/i);\n");
    fprintf(f, "  if (!match) return 0;\n");
    fprintf(f, "  var val = parseFloat(match[1]);\n");
    fprintf(f, "  var unit = match[2].toLowerCase();\n");
    fprintf(f, "  if (unit === 'mbps') return val * 1000000;\n");
    fprintf(f, "  if (unit === 'kbps') return val * 1000;\n");
    fprintf(f, "  return val;\n");
    fprintf(f, "}\n");
    fprintf(f, "</script>\n");
    fprintf(f, "<table id='usageTable' style='width:100%%;margin:0;border-collapse:collapse;' data-sort-dir='desc'>\n");
    fprintf(f, "<thead><tr>");
    fprintf(f, "<th onclick='sortTable(0)' style='cursor:pointer;'>IP:Port (ID)</th>");
    fprintf(f, "<th onclick='sortTable(1)' style='cursor:pointer;'>Usage ↓</th>");
    fprintf(f, "<th onclick='sortTable(2)' style='cursor:pointer;'>Service</th>");
    fprintf(f, "<th onclick='sortTable(3)' style='cursor:pointer;'>Type</th>");
    fprintf(f, "<th onclick='sortTable(4)' style='cursor:pointer;'>Packets</th>"); // NEW
    fprintf(f, "<th onclick='sortTable(5)' style='cursor:pointer;'>Total Data</th>");
    fprintf(f, "<th onclick='sortTable(6)' style='cursor:pointer;'>Bitrate</th>");
    fprintf(f, "</tr></thead>\n");
    
    // Count junk entries for summary
    int junk_entry_count = 0;
    uint64_t junk_total_bytes = 0;
    uint32_t rate_windows = rate_full_windows();   // complete windows for min/max bitrate
    
    for (int i = 0; i < g_data_usage_count; i++) {
        DataUsageEntry* entry = &g_data_usage[i];
        double percentage = (double)entry->total_bytes / g_total_capture_bytes * 100.0;
        
        // Skip likely junk entries from signal dropouts
        if (is_junk_entry(entry)) {
            junk_entry_count++;
            junk_total_bytes += entry->total_bytes;
            continue;
        }
        
        // Determine bar color based on stream type and media content
        const char* bar_color;
        
        // First check if this is a known service
        const char* service_name_check = get_service_name_for_destination(entry->destinationIp, entry->destinationPort);
        int is_known_service = (service_name_check != NULL);
        
        if (entry->is_lls) {
            bar_color = "#00aa00"; // Green for LLS
        } else if (entry->is_signaling) {
            bar_color = "#ff6600"; // Orange for all signaling
        } else if (!is_known_service) {
            bar_color = "#000000"; // Black for unknown/unidentified services
        } else if (strcmp(entry->stream_type, "ROUTE") == 0) {
            // Get specific media type for ROUTE streams (known service)
            const char* route_media_type = get_media_type_from_stsid(entry->destinationIp, entry->destinationPort, entry->tsi_or_packet_id);
            if (strstr(route_media_type, "video") || strstr(route_media_type, "Video")) {
                bar_color = "#0066cc"; // Blue for ROUTE video
            } else if (strstr(route_media_type, "audio") || strstr(route_media_type, "Audio")) {
                bar_color = "#00cc00"; // Green for ROUTE audio
            } else if (strstr(route_media_type, "caption") || strstr(route_media_type, "Caption") || strstr(route_media_type, "subtitles")) {
                bar_color = "#cc00cc"; // Pink for ROUTE captions
            } else {
                bar_color = "#9933ff"; // Purple for other identified ROUTE media (known service)
            }
        } else if (strcmp(entry->stream_type, "MMT") == 0) {
            // Get specific media type for MMT streams (known service)
            const char* mmt_media_type = get_media_type_from_mpt(entry->destinationIp, entry->destinationPort, entry->tsi_or_packet_id);
            if (strstr(mmt_media_type, "video") || strstr(mmt_media_type, "Video")) {
                bar_color = "#0066cc"; // Blue for MMT video
            } else if (strstr(mmt_media_type, "audio") || strstr(mmt_media_type, "Audio")) {
                bar_color = "#00cc00"; // Green for MMT audio
            } else if (strstr(mmt_media_type, "caption") || strstr(mmt_media_type, "Caption") || 
                       strstr(mmt_media_type, "subtitles") || strcmp(mmt_media_type, "stpp") == 0) {
                bar_color = "#cc00cc"; // Pink for MMT captions
            } else {
                bar_color = "#9933ff"; // Purple for other identified MMT media (known service)
            }
        } else {
            bar_color = "#9933ff"; // Purple for other known service types
        }
        
        // Calculate bandwidth if timing available
        char bandwidth_str[64] = "N/A";
        
        // For ALP-PCAP, use global timing so bitrates sum correctly to channel bandwidth
        if (g_input_type == INPUT_TYPE_ALP_PCAP && g_pcap_timing_valid && g_packet_count > 1) {
            double duration_seconds = (double)(g_last_packet_time.tv_sec - g_first_packet_time.tv_sec) + 
                                    (double)(g_last_packet_time.tv_usec - g_first_packet_time.tv_usec) / 1000000.0;
            if (duration_seconds > 0) {
                double bps = entry->total_bytes * 8.0 / duration_seconds;
                if (bps >= 1000000) {
                    snprintf(bandwidth_str, sizeof(bandwidth_str), "%.2f Mbps", bps / 1000000.0);
                } else if (bps >= 1000) {
                    snprintf(bandwidth_str, sizeof(bandwidth_str), "%.1f Kbps", bps / 1000.0);
                } else {
                    snprintf(bandwidth_str, sizeof(bandwidth_str), "%.0f bps", bps);
                }
            }
        } else if ((g_input_type == INPUT_TYPE_PCAP ||
                    (g_input_type == INPUT_TYPE_DEBUG && g_timing_estimated)) &&
                   g_pcap_timing_valid && g_packet_count > 1) {
            // Regular PCAP (and debug files given -t) use global timing
            double duration_seconds = (double)(g_last_packet_time.tv_sec - g_first_packet_time.tv_sec) + 
                                     (double)(g_last_packet_time.tv_usec - g_first_packet_time.tv_usec) / 1000000.0;
            if (duration_seconds > 0) {
                double bps = entry->total_bytes * 8.0 / duration_seconds;
                if (bps >= 1000000) {
                    snprintf(bandwidth_str, sizeof(bandwidth_str), "%.2f Mbps", bps / 1000000.0);
                } else if (bps >= 1000) {
                    snprintf(bandwidth_str, sizeof(bandwidth_str), "%.1f Kbps", bps / 1000.0);
                } else {
                    snprintf(bandwidth_str, sizeof(bandwidth_str), "%.0f bps", bps);
                }
            }
        }
        
        // Format total data size
        char data_size_str[64];
        if (entry->total_bytes >= 1000000) {
            snprintf(data_size_str, sizeof(data_size_str), "%.2f MB", entry->total_bytes / 1000000.0);
        } else if (entry->total_bytes >= 1000) {
            snprintf(data_size_str, sizeof(data_size_str), "%.1f KB", entry->total_bytes / 1000.0);
        } else {
            snprintf(data_size_str, sizeof(data_size_str), "%llu bytes", (unsigned long long)entry->total_bytes);
        }
        
        // Extract service name and media type from description
        const char* service_name = get_service_name_for_destination(entry->destinationIp, entry->destinationPort);
        if (!service_name) {
            service_name = "Unknown Service";
        }
        
        // Determine media type based on stream analysis
        const char* media_type = "Unknown";
        if (entry->is_lls) {
            media_type = "LLS Signaling";
        } else if (entry->is_signaling) {
            media_type = "Service Signaling";
        } else if (strcmp(entry->stream_type, "ROUTE") == 0) {
            media_type = get_media_type_from_stsid(entry->destinationIp, entry->destinationPort, entry->tsi_or_packet_id);
            if (strcmp(media_type, "Media") == 0) {
                // Check S-TSID repId for "file delivery" hint before falling back to generic
                int is_file_delivery = 0;
                for (int t = 0; t < g_lls_table_count; t++) {
                    if (g_lls_tables[t].type == TABLE_TYPE_STSID &&
                        strcmp(g_lls_tables[t].destinationIp, entry->destinationIp) == 0 &&
                        strcmp(g_lls_tables[t].destinationPort, entry->destinationPort) == 0) {
                        StsidData* sd = (StsidData*)g_lls_tables[t].parsed_data;
                        StsidLogicalStream* ls = sd->head_ls;
                        while (ls) {
                            if (atoi(ls->tsi) == (int)entry->tsi_or_packet_id) {
                                if (ls->head_file && ls->file_count > 0) {
                                    is_file_delivery = 1;
                                }
                                break;
                            }
                            ls = ls->next;
                        }
                        break;
                    }
                }
                media_type = is_file_delivery ? "File Delivery" : "ROUTE Media";
            }
        } else if (strcmp(entry->stream_type, "MMT") == 0) {
            media_type = get_media_type_from_mpt(entry->destinationIp, entry->destinationPort, entry->tsi_or_packet_id);
            if (strcmp(media_type, "Media") == 0) {
                media_type = "MMT Media";
            }
            // Normalize raw codec names to friendly labels
            if (strcmp(media_type, "stpp") == 0 || strcmp(media_type, "Data/Captions") == 0 ||
                strcmp(media_type, "caption") == 0) {
                media_type = "Captions";
            }
        } else if (strcmp(entry->stream_type, "BPS Packet(s)") == 0) {
            media_type = "BPS Packet(s)";
        } else {
            // Check if this is a UDST/UDS service with a known type (e.g., RTK)
            int found_udst_type = 0;
            for (int t = 0; t < g_lls_table_count && !found_udst_type; t++) {
                if (g_lls_tables[t].type == TABLE_TYPE_UDST) {
                    UdstData* udst = (UdstData*)g_lls_tables[t].parsed_data;
                    if (!udst) continue;
                    // Check UDS entries
                    UdsData* uds = udst->head_uds;
                    while (uds) {
                        if (strcmp(uds->destIP, entry->destinationIp) == 0 &&
                            strcmp(uds->destPort, entry->destinationPort) == 0) {
                            if (strcasestr(uds->name, "RTK") || strcasestr(uds->contextId, "RTK") ||
                                strcasestr(uds->contextId, "rtk")) {
                                media_type = "RTK";
                                found_udst_type = 1;
                            } else if (strcasestr(uds->name, "GNSS") || strcasestr(uds->contextId, "gnss")) {
                                media_type = "GNSS Data";
                                found_udst_type = 1;
                            } else if (uds->name[0]) {
                                media_type = uds->name;
                                found_udst_type = 1;
                            }
                            break;
                        }
                        uds = uds->next;
                    }
                    // Check BroadSpan services
                    if (!found_udst_type) {
                        BroadSpanServiceInfo* bss = udst->head_service;
                        while (bss) {
                            RsrvInfo* rsrv = bss->head_rsrv;
                            if (rsrv && strcmp(rsrv->destIP, entry->destinationIp) == 0 &&
                                strcmp(rsrv->destPort, entry->destinationPort) == 0) {
                                if (strcasestr(bss->name, "RTK") || strcasestr(bss->name, "rtk")) {
                                    media_type = "RTK";
                                    found_udst_type = 1;
                                } else if (strcasestr(bss->name, "GNSS") || strcasestr(bss->name, "gnss")) {
                                    media_type = "GNSS Data";
                                    found_udst_type = 1;
                                }
                                break;
                            }
                            bss = bss->next;
                        }
                    }
                } else if (g_lls_tables[t].type == TABLE_TYPE_UDS) {
                    UdsData* uds = (UdsData*)g_lls_tables[t].parsed_data;
                    if (uds && strcmp(uds->destIP, entry->destinationIp) == 0 &&
                        strcmp(uds->destPort, entry->destinationPort) == 0) {
                        if (strcasestr(uds->name, "RTK") || strcasestr(uds->contextId, "RTK") ||
                            strcasestr(uds->contextId, "rtk")) {
                            media_type = "RTK";
                            found_udst_type = 1;
                        } else if (uds->name[0]) {
                            media_type = uds->name;
                            found_udst_type = 1;
                        }
                    }
                }
            }
            if (!found_udst_type) {
                media_type = entry->stream_type;
            }
        }
        
        fprintf(f, "<tr>\n");
        
        // Column 1: IP:Port (ID)
        fprintf(f, "  <td style='font-size:small;'>%s:%s", entry->destinationIp, entry->destinationPort);
        if (strcmp(entry->stream_type, "ROUTE") == 0) {
            fprintf(f, " (TSI %u)", entry->tsi_or_packet_id);
        } else if (strcmp(entry->stream_type, "MMT") == 0) {
            if (entry->tsi_or_packet_id == 0) {
                fprintf(f, " (PID 0)");
            } else {
                fprintf(f, " (PID %u)", entry->tsi_or_packet_id);
            }
        } else if (strcmp(entry->stream_type, "MPEG-TS") == 0 || strcmp(entry->stream_type, "MPEG-TS Null") == 0) {
            fprintf(f, " (PID 0x%04X)", entry->tsi_or_packet_id);
        } else if (strcmp(entry->stream_type, "RTP/MPEG-TS") == 0 || strcmp(entry->stream_type, "RTP/MPEG-TS Null") == 0) {
            fprintf(f, " (PID 0x%04X)", entry->tsi_or_packet_id);
        } else if (strcmp(entry->stream_type, "RTP") == 0) {
            fprintf(f, " (PT %u)", entry->tsi_or_packet_id);
        } else if (entry->is_lls) {
            fprintf(f, " (LLS)");
        } else if (is_bps_service(entry->destinationIp, entry->destinationPort)) {
            fprintf(f, " (BPS)");
        }
        fprintf(f, "</td>\n");
        
        // Bitrate over fixed windows: range goes in the Bitrate column,
        // the sparkline under the usage bar
        RateRange rr = {0};
        if (strcmp(bandwidth_str, "N/A") != 0) {
            rr = rate_range(entry->rate_bins, entry->rate_bin_count, rate_windows);
        }

        // Column 2: Usage (bar + percentage, sparkline beneath)
        fprintf(f, "  <td style='width:30%%;'>");
        fprintf(f, "<div style='background-color:%s;width:%.1f%%;height:16px;display:inline-block;'></div> %.2f%%", 
                bar_color, percentage > 50.0 ? 50.0 : percentage, percentage);
        if (rr.valid) {
            write_rate_sparkline(f, entry->rate_bins, entry->rate_bin_count, rate_windows, bar_color, &rr);
        }
        fprintf(f, "</td>\n");
        
        // Column 3: Service
        fprintf(f, "  <td style='font-size:small;'>%s</td>\n", service_name);
        
        // Column 4: Type
        fprintf(f, "  <td style='font-size:small;'>%s</td>\n", media_type);
        
        // Column 5: Packets (NEW)
        fprintf(f, "  <td style='font-size:small;'>%u</td>\n", entry->packet_count);

        // Column 6: Total Data
        fprintf(f, "  <td style='font-size:small;'>%s</td>\n", data_size_str);
        
        // Column 7: Bitrate (average first, so column sorting still uses it),
        // then the range over fixed windows
        fprintf(f, "  <td style='font-size:small;white-space:nowrap;'>%s", bandwidth_str);
        if (rr.valid) {
            char range_str[96];
            format_rate_range(&rr, range_str, sizeof(range_str));
            fprintf(f, "<br><span style='color:#888;font-size:x-small;'>%s</span>", range_str);
        }
        fprintf(f, "</td>\n");
        
        fprintf(f, "</tr>\n");
    }
    
    fprintf(f, "</table>\n");
    
    // Add summary stats
    uint64_t signaling_bytes = 0, media_bytes = 0, other_bytes = 0;
    for (int i = 0; i < g_data_usage_count; i++) {
        if (g_data_usage[i].is_signaling || g_data_usage[i].is_lls) {
            signaling_bytes += g_data_usage[i].total_bytes;
        } else if (strcmp(g_data_usage[i].stream_type, "Other UDP") == 0) {
            other_bytes += g_data_usage[i].total_bytes;
        } else {
            media_bytes += g_data_usage[i].total_bytes;
        }
    }
    
    fprintf(f, "<p style='font-size:small;margin-top:10px;'>\n");
    
    // Calculate overall bitrate if timing is available
    char overall_bitrate_str[64] = "N/A";
    double summary_duration_s = 0.0;   // also used for the per-PLP bitrates below
    if (g_pcap_timing_valid && g_packet_count > 1) {
        double duration_seconds = (double)(g_last_packet_time.tv_sec - g_first_packet_time.tv_sec) + 
                                 (double)(g_last_packet_time.tv_usec - g_first_packet_time.tv_usec) / 1000000.0;
        summary_duration_s = duration_seconds;
        if (duration_seconds > 0) {
            double bps = g_total_capture_bytes * 8.0 / duration_seconds;
            if (bps >= 1000000) {
                snprintf(overall_bitrate_str, sizeof(overall_bitrate_str), "%.2f Mbps", bps / 1000000.0);
            } else if (bps >= 1000) {
                snprintf(overall_bitrate_str, sizeof(overall_bitrate_str), "%.1f Kbps", bps / 1000.0);
            } else {
                snprintf(overall_bitrate_str, sizeof(overall_bitrate_str), "%.0f bps", bps);
            }
        }
    }
    
    char overall_range_str[112] = "";
    {
        RateRange tr = rate_range(g_total_rate_bins, g_total_rate_bin_count, rate_full_windows());
        if (tr.valid && strcmp(overall_bitrate_str, "N/A") != 0) {
            char rs[96];
            format_rate_range(&tr, rs, sizeof(rs));
            snprintf(overall_range_str, sizeof(overall_range_str), " (%s)", rs);
        }
    }
    fprintf(f, "Total: %.2f MB | Packets: %d | Bitrate: %s%s<br>\n", 
            g_total_capture_bytes / 1000000.0,
            g_packet_count,
            overall_bitrate_str, overall_range_str);
    if (rate_full_windows() >= 2) {
        fprintf(f, "<span style='color:#888;'>Bitrate ranges are the lowest and highest rate over %u complete %g-second windows "
                   "(set A3_RATE_WINDOW to change); the sparkline shows the rate across the capture. "
                   "Hover a sparkline for the 5th/50th/95th percentiles.%s</span><br>\n",
                rate_full_windows(), rate_window_s(),
                g_timing_estimated ?
                    " This capture has no timestamps, so packet times were estimated by spreading the -t length"
                    " over the data by byte position: averages use the -t length directly, but ranges (marked"
                    " est.) assume an even arrival rate and are approximate." : "");
    }
    fprintf(f, "Signaling: %.2f%% | Media: %.2f%% | Other: %.2f%%\n", 
            (double)signaling_bytes / g_total_capture_bytes * 100.0,
            (double)media_bytes / g_total_capture_bytes * 100.0,
            (double)other_bytes / g_total_capture_bytes * 100.0);
    
    // Note about filtered junk entries
    if (junk_entry_count > 0) {
        fprintf(f, "<br><span style='color:#888;'>%d single-packet entr%s omitted (likely signal dropout artifacts, %.1f KB total)</span>\n",
                junk_entry_count, junk_entry_count == 1 ? "y" : "ies",
                junk_total_bytes / 1000.0);
    }
    
    // PLP breakdown if LMT data is available
    if (has_lmt_data()) {
        // Find LMT table
        LmtData* lmt = NULL;
        for (int t = 0; t < g_lls_table_count; t++) {
            if (g_lls_tables[t].type == TABLE_TYPE_LMT) {
                lmt = (LmtData*)g_lls_tables[t].parsed_data;
                break;
            }
        }
        
        if (lmt) {
            // Collect per-PLP totals
            // Use a simple array indexed by PLP ID (max 64)
            uint64_t plp_bytes[64] = {0};
            uint32_t plp_packets[64] = {0};
            int plp_seen[64] = {0};
            uint64_t unknown_plp_bytes = 0;
            uint32_t unknown_plp_packets = 0;
            int has_unknown_plp = 0;

            // Per-PLP bytes per window (index 64 = unknown PLP), for the range
            uint32_t plp_windows = rate_full_windows();
            uint32_t* plp_bins[65] = {0};
            #define PLP_ADD_BINS(slot, e_) do { \
                if (plp_windows >= 2 && (e_)->rate_bins) { \
                    if (!plp_bins[slot]) plp_bins[slot] = calloc(plp_windows, sizeof(uint32_t)); \
                    if (plp_bins[slot]) { \
                        for (uint32_t w_ = 0; w_ < plp_windows && w_ < (e_)->rate_bin_count; w_++) \
                            plp_bins[slot][w_] += (e_)->rate_bins[w_]; \
                    } \
                } } while (0)
            
            for (int i = 0; i < g_data_usage_count; i++) {
                DataUsageEntry* e = &g_data_usage[i];
                
                // Skip junk entries
                if (is_junk_entry(e)) continue;
                
                // Find this entry's PLP from LMT
                int found_plp = 0;
                LmtService* svc = lmt->services;
                while (svc) {
                    LmtMulticast* mc = svc->multicasts;
                    while (mc) {
                        if (strcmp(mc->dest_ip_str, e->destinationIp) == 0 &&
                            strcmp(mc->dest_port_str, e->destinationPort) == 0) {
                            int plp = svc->plp_id;
                            if (plp >= 0 && plp < 64) {
                                plp_bytes[plp] += e->total_bytes;
                                plp_packets[plp] += e->packet_count;
                                plp_seen[plp] = 1;
                                PLP_ADD_BINS(plp, e);
                                found_plp = 1;
                            }
                            break;
                        }
                        mc = mc->next;
                    }
                    if (found_plp) break;
                    svc = svc->next;
                }
                
                // Special case: LLS is always on PLP 0
                if (!found_plp && e->is_lls) {
                    plp_bytes[0] += e->total_bytes;
                    plp_packets[0] += e->packet_count;
                    plp_seen[0] = 1;
                    PLP_ADD_BINS(0, e);
                    found_plp = 1;
                }
                
                if (!found_plp) {
                    unknown_plp_bytes += e->total_bytes;
                    unknown_plp_packets += e->packet_count;
                    has_unknown_plp = 1;
                    PLP_ADD_BINS(64, e);
                }
            }
            
            // Count how many PLPs we have
            int plp_count = 0;
            for (int p = 0; p < 64; p++) {
                if (plp_seen[p]) plp_count++;
            }
            
            if (plp_count > 1 || has_unknown_plp) {
                fprintf(f, "<br><strong>By PLP:</strong> ");
                int first = 1;
                for (int p = 0; p < 64 + 1; p++) {
                    // p == 64 is the "Unknown PLP" bucket
                    int is_unknown = (p == 64);
                    if (is_unknown ? !has_unknown_plp : !plp_seen[p]) continue;
                    uint64_t bytes = is_unknown ? unknown_plp_bytes : plp_bytes[p];

                    // Bitrate over the same capture duration as the overall bitrate,
                    // so the per-PLP figures add up to the total
                    char plp_rate[160] = "";
                    if (summary_duration_s > 0) {
                        char avg[32];
                        format_bps(bytes * 8.0 / summary_duration_s, avg, sizeof(avg));
                        snprintf(plp_rate, sizeof(plp_rate), ", %s", avg);
                        RateRange pr = rate_range(plp_bins[p], plp_windows, plp_windows);
                        if (pr.valid && plp_bins[p]) {
                            char rs[96];
                            format_rate_range(&pr, rs, sizeof(rs));
                            size_t l = strlen(plp_rate);
                            snprintf(plp_rate + l, sizeof(plp_rate) - l, ", %s", rs);
                        }
                    }

                    if (!first) fprintf(f, " | ");
                    if (is_unknown) {
                        fprintf(f, "Unknown PLP: ");
                    } else {
                        fprintf(f, "PLP %d: ", p);
                    }
                    fprintf(f, "%.2f MB (%.1f%%%s)", bytes / 1000000.0,
                            (double)bytes / g_total_capture_bytes * 100.0, plp_rate);
                    first = 0;
                }
                fprintf(f, "\n");
            }
            for (int p = 0; p < 65; p++) free(plp_bins[p]);
            #undef PLP_ADD_BINS
        }
    }
    fprintf(f, "</p>\n");
}

// Helper: detect likely junk entries from signal dropouts
// Returns 1 if the entry looks like junk (single packet, unknown service, unknown IP)
static int is_junk_entry(DataUsageEntry* entry) {
    if (entry->packet_count > 1) return 0;
    if (entry->is_lls) return 0;
    
    const char* svc = get_service_name_for_destination(entry->destinationIp, entry->destinationPort);
    if (svc) return 0;
    
    for (int j = 0; j < g_service_dest_count; j++) {
        if (strcmp(g_service_dests[j].destinationIpStr, entry->destinationIp) == 0) {
            return 0;  // Known IP, keep it
        }
    }
    
    return 1;  // Single packet, unknown service, unknown IP = junk
}

// Generate Unknown Service Analysis section
void generate_unknown_service_analysis(FILE *f) {
    // Count unknown services (excluding junk)
    int unknown_count = 0;
    for (int i = 0; i < g_data_usage_count; i++) {
        if (is_junk_entry(&g_data_usage[i])) continue;
        
        const char* svc_name = get_service_name_for_destination(g_data_usage[i].destinationIp, g_data_usage[i].destinationPort);
        if (!svc_name && !g_data_usage[i].is_lls && !g_data_usage[i].is_signaling && 
            strcmp(g_data_usage[i].stream_type, "Stuffing") != 0 &&
            strcmp(g_data_usage[i].stream_type, "BPS Packet(s)") != 0) {
            unknown_count++;
        }
    }
    
    if (unknown_count == 0) {
        return;
    }
    
    fprintf(f, "<details><summary>Unknown Service Analysis (%d streams)</summary>\n", unknown_count);
    fprintf(f, "<div class='details-content'>\n");
    fprintf(f, "<table>\n<thead><tr><th>Destination</th><th>Stream Type</th><th>Payload Analysis</th></tr></thead>\n<tbody>\n");
    
    for (int i = 0; i < g_data_usage_count; i++) {
        DataUsageEntry* entry = &g_data_usage[i];
        const char* svc_name = get_service_name_for_destination(entry->destinationIp, entry->destinationPort);
        
        if (svc_name || entry->is_lls || entry->is_signaling || 
            strcmp(entry->stream_type, "Stuffing") == 0 ||
            strcmp(entry->stream_type, "BPS Packet(s)") == 0) {
            continue;
        }
        
        // Skip junk entries (same filter as usage chart)
        if (is_junk_entry(entry)) {
            continue;
        }
        
        fprintf(f, "<tr><td style='font-family:monospace;'>%s:%s", entry->destinationIp, entry->destinationPort);
        if (strcmp(entry->stream_type, "ROUTE") == 0) {
            fprintf(f, "<br>(TSI %u)", entry->tsi_or_packet_id);
        } else if (strcmp(entry->stream_type, "MMT") == 0) {
            fprintf(f, "<br>(PID %u)", entry->tsi_or_packet_id);
        } else if (strcmp(entry->stream_type, "MPEG-TS") == 0 || strcmp(entry->stream_type, "MPEG-TS Null") == 0) {
            fprintf(f, "<br>(PID 0x%04X)", entry->tsi_or_packet_id);
        } else if (strcmp(entry->stream_type, "RTP/MPEG-TS") == 0 || strcmp(entry->stream_type, "RTP/MPEG-TS Null") == 0) {
            fprintf(f, "<br>(PID 0x%04X)", entry->tsi_or_packet_id);
        } else if (strcmp(entry->stream_type, "RTP") == 0) {
            fprintf(f, "<br>(PT %u)", entry->tsi_or_packet_id);
        }
        fprintf(f, "</td>\n");
        
        fprintf(f, "<td>%s</td>\n", entry->stream_type);
        
        // Analyze sample payload
        fprintf(f, "<td style='font-family:monospace;font-size:11px;'>");
        if (entry->sample_collected && entry->sample_payload_len > 0) {
            // Try to identify payload type
            int is_gzip = (entry->sample_payload_len >= 2 && 
                          entry->sample_payload[0] == 0x1f && entry->sample_payload[1] == 0x8b);
            int is_xml = (entry->sample_payload_len >= 5 && 
                         memcmp(entry->sample_payload, "<?xml", 5) == 0);
            int is_mpeg_ts = (entry->sample_payload_len >= 1 && entry->sample_payload[0] == 0x47);
            int looks_like_text = 1;
            for (int j = 0; j < entry->sample_payload_len && j < 32; j++) {
                if (entry->sample_payload[j] < 0x20 && entry->sample_payload[j] != '\n' && 
                    entry->sample_payload[j] != '\r' && entry->sample_payload[j] != '\t') {
                    looks_like_text = 0;
                    break;
                }
            }
            
            if (is_gzip) {
                fprintf(f, "<strong>GZIP compressed</strong><br>");
                // Try to decompress and show preview
                int decomp_size = 0;
                int consumed = 0;
                char* decomp = decompress_gzip(entry->sample_payload, entry->sample_payload_len, &decomp_size, &consumed);
                if (decomp && decomp_size > 0) {
                    // Check if decompressed content is XML
                    if (decomp_size >= 5 && memcmp(decomp, "<?xml", 5) == 0) {
                        fprintf(f, "Contains XML: ");
                        
                        // Find root element
                        char* root_start = strstr(decomp, "?>");
                        if (root_start && root_start < decomp + decomp_size - 2) {
                            root_start += 2;
                            while (root_start < decomp + decomp_size && (*root_start == ' ' || *root_start == '\n' || *root_start == '\r' || *root_start == '\t')) {
                                root_start++;
                            }
                            if (*root_start == '<') {
                                root_start++;
                                char root_element[64] = {0};
                                int k = 0;
                                while (root_start < decomp + decomp_size && k < 63 && 
                                       *root_start != ' ' && *root_start != '>' && *root_start != '\n' && *root_start != '/') {
                                    root_element[k++] = *root_start++;
                                }
                                root_element[k] = '\0';
                                
                                if (strlen(root_element) > 0) {
                                    fprintf(f, "<strong>&lt;%s&gt;</strong>", root_element);
                                    
                                    // Identify known table types
                                    if (strcmp(root_element, "SLT") == 0) {
                                        fprintf(f, " (Service List Table)");
                                    } else if (strcmp(root_element, "S-TSID") == 0) {
                                        fprintf(f, " (ROUTE Stream Description)");
                                    } else if (strcmp(root_element, "MPD") == 0) {
                                        fprintf(f, " (DASH Manifest)");
                                    } else if (strcmp(root_element, "USBD") == 0 || strcmp(root_element, "BundleDescriptionROUTE") == 0) {
                                        fprintf(f, " (User Service Bundle Description)");
                                    } else if (strcmp(root_element, "USD") == 0) {
                                        fprintf(f, " (User Service Description)");
                                    } else if (strcmp(root_element, "HELD") == 0) {
                                        fprintf(f, " (HTML Entry Locations)");
                                    } else if (strcmp(root_element, "RRT") == 0) {
                                        fprintf(f, " (Rating Region Table)");
                                    } else if (strcmp(root_element, "SystemTime") == 0) {
                                        fprintf(f, " (System Time)");
                                    } else if (strcmp(root_element, "AEAT") == 0) {
                                        fprintf(f, " (Advanced Emergency Alert)");
                                    } else if (strcmp(root_element, "OnscreenMessageNotification") == 0) {
                                        fprintf(f, " (Onscreen Message)");
                                    } else if (strcmp(root_element, "CAP") == 0 || strcmp(root_element, "alert") == 0) {
                                        fprintf(f, " (Common Alerting Protocol)");
                                    } else if (strcmp(root_element, "metadataEnvelope") == 0) {
                                        fprintf(f, " (Service Signaling)");
                                    } else if (strcmp(root_element, "MMTPackageTable") == 0) {
                                        fprintf(f, " (MMT Package Table)");
                                    } else if (strcmp(root_element, "ESGData") == 0 || strcmp(root_element, "ESGMain") == 0) {
                                        fprintf(f, " (Electronic Service Guide)");
                                    } else if (strcmp(root_element, "ContentAdvisoryTable") == 0) {
                                        fprintf(f, " (Content Advisory)");
                                    }
                                    fprintf(f, "<br>");
                                }
                            }
                        }
                    }
                    
                    int preview_len = decomp_size > 100 ? 100 : decomp_size;
                    fprintf(f, "Preview:<br><code>");
                    for (int j = 0; j < preview_len; j++) {
                        char c = decomp[j];
                        if (c == '<') fprintf(f, "&lt;");
                        else if (c == '>') fprintf(f, "&gt;");
                        else if (c == '&') fprintf(f, "&amp;");
                        else if (c >= 0x20 || c == '\n' || c == '\r' || c == '\t') fputc(c, f);
                        else fprintf(f, ".");
                    }
                    if (decomp_size > 100) fprintf(f, "...");
                    fprintf(f, "</code>");
                    free(decomp);
                } else {
                    fprintf(f, "(decompression failed or incomplete)");
                }
            } else if (is_mpeg_ts) {
                // Parse MPEG-TS header
                uint16_t pid = ((entry->sample_payload[1] & 0x1F) << 8) | entry->sample_payload[2];
                fprintf(f, "<strong>MPEG-TS</strong> (PID 0x%04X", pid);
                if (pid == 0x1FFF) {
                    fprintf(f, " - Null/Stuffing");
                } else if (pid == 0x0000) {
                    fprintf(f, " - PAT");
                } else if (pid == 0x0001) {
                    fprintf(f, " - CAT");
                } else if (pid < 0x0010) {
                    fprintf(f, " - Reserved");
                }
                fprintf(f, ")<br>");
                
                // Scan for embedded XML
                char* xml_start = NULL;
                for (int j = 0; j < entry->sample_payload_len - 5; j++) {
                    if (memcmp(entry->sample_payload + j, "<?xml", 5) == 0) {
                        xml_start = (char*)(entry->sample_payload + j);
                        break;
                    }
                }
                
                if (xml_start) {
                    int xml_remaining = entry->sample_payload_len - (xml_start - (char*)entry->sample_payload);
                    fprintf(f, "Contains embedded XML: ");
                    
                    // Find root element
                    char* root_start = strstr(xml_start, "?>");
                    if (root_start && root_start < xml_start + xml_remaining - 2) {
                        root_start += 2;
                        while (root_start < xml_start + xml_remaining && (*root_start == ' ' || *root_start == '\n' || *root_start == '\r' || *root_start == '\t')) {
                            root_start++;
                        }
                        if (*root_start == '<') {
                            root_start++;
                            char root_element[64] = {0};
                            int k = 0;
                            while (root_start < xml_start + xml_remaining && k < 63 && 
                                   *root_start != ' ' && *root_start != '>' && *root_start != '\n' && *root_start != '/') {
                                root_element[k++] = *root_start++;
                            }
                            root_element[k] = '\0';
                            
                            if (strlen(root_element) > 0) {
                                fprintf(f, "<strong>&lt;%s&gt;</strong>", root_element);
                                
                                // Identify known table types
                                if (strcmp(root_element, "SLT") == 0) {
                                    fprintf(f, " (Service List Table)");
                                } else if (strcmp(root_element, "S-TSID") == 0) {
                                    fprintf(f, " (ROUTE Stream Description)");
                                } else if (strcmp(root_element, "MPD") == 0) {
                                    fprintf(f, " (DASH Manifest)");
                                } else if (strcmp(root_element, "USBD") == 0 || strcmp(root_element, "BundleDescriptionROUTE") == 0) {
                                    fprintf(f, " (User Service Bundle Description)");
                                } else if (strcmp(root_element, "USD") == 0) {
                                    fprintf(f, " (User Service Description)");
                                } else if (strcmp(root_element, "HELD") == 0) {
                                    fprintf(f, " (HTML Entry Locations)");
                                } else if (strcmp(root_element, "RRT") == 0) {
                                    fprintf(f, " (Rating Region Table)");
                                } else if (strcmp(root_element, "SystemTime") == 0) {
                                    fprintf(f, " (System Time)");
                                } else if (strcmp(root_element, "AEAT") == 0) {
                                    fprintf(f, " (Advanced Emergency Alert)");
                                } else if (strcmp(root_element, "OnscreenMessageNotification") == 0) {
                                    fprintf(f, " (Onscreen Message)");
                                } else if (strcmp(root_element, "CAP") == 0 || strcmp(root_element, "alert") == 0) {
                                    fprintf(f, " (Common Alerting Protocol)");
                                } else if (strcmp(root_element, "metadataEnvelope") == 0) {
                                    fprintf(f, " (Service Signaling)");
                                } else if (strcmp(root_element, "MMTPackageTable") == 0) {
                                    fprintf(f, " (MMT Package Table)");
                                } else if (strcmp(root_element, "ESGData") == 0 || strcmp(root_element, "ESGMain") == 0) {
                                    fprintf(f, " (Electronic Service Guide)");
                                } else if (strcmp(root_element, "ContentAdvisoryTable") == 0) {
                                    fprintf(f, " (Content Advisory)");
                                }
                            }
                        }
                    }
                    fprintf(f, "<br>");
                }
                
                fprintf(f, "Hex: ");
                int hex_len = entry->sample_payload_len > 24 ? 24 : entry->sample_payload_len;
                for (int j = 0; j < hex_len; j++) {
                    fprintf(f, "%02X ", entry->sample_payload[j]);
                }
                if (entry->sample_payload_len > 24) fprintf(f, "...");
            } else if (is_xml) {
                fprintf(f, "<strong>XML data</strong><br>");
                
                // Try to identify the XML root element and table type
                char* xml_str = (char*)entry->sample_payload;
                int xml_len = entry->sample_payload_len;
                
                // Find the root element (skip past <?xml ...?>)
                char* root_start = strstr(xml_str, "?>");
                if (root_start && root_start < xml_str + xml_len - 2) {
                    root_start += 2;
                    // Skip whitespace
                    while (root_start < xml_str + xml_len && (*root_start == ' ' || *root_start == '\n' || *root_start == '\r' || *root_start == '\t')) {
                        root_start++;
                    }
                    if (*root_start == '<') {
                        root_start++;
                        // Extract element name (up to space, >, or end)
                        char root_element[64] = {0};
                        int k = 0;
                        while (root_start < xml_str + xml_len && k < 63 && 
                               *root_start != ' ' && *root_start != '>' && *root_start != '\n' && *root_start != '/') {
                            root_element[k++] = *root_start++;
                        }
                        root_element[k] = '\0';
                        
                        if (strlen(root_element) > 0) {
                            fprintf(f, "Root: <strong>&lt;%s&gt;</strong>", root_element);
                            
                            // Identify known table types
                            if (strcmp(root_element, "SLT") == 0) {
                                fprintf(f, " (Service List Table)");
                            } else if (strcmp(root_element, "S-TSID") == 0) {
                                fprintf(f, " (ROUTE Stream Description)");
                            } else if (strcmp(root_element, "MPD") == 0) {
                                fprintf(f, " (DASH Manifest)");
                            } else if (strcmp(root_element, "USBD") == 0 || strcmp(root_element, "BundleDescriptionROUTE") == 0) {
                                fprintf(f, " (User Service Bundle Description)");
                            } else if (strcmp(root_element, "USD") == 0) {
                                fprintf(f, " (User Service Description)");
                            } else if (strcmp(root_element, "HELD") == 0) {
                                fprintf(f, " (HTML Entry Locations)");
                            } else if (strcmp(root_element, "RRT") == 0) {
                                fprintf(f, " (Rating Region Table)");
                            } else if (strcmp(root_element, "SystemTime") == 0) {
                                fprintf(f, " (System Time)");
                            } else if (strcmp(root_element, "AEAT") == 0) {
                                fprintf(f, " (Advanced Emergency Alert)");
                            } else if (strcmp(root_element, "OnscreenMessageNotification") == 0) {
                                fprintf(f, " (Onscreen Message)");
                            } else if (strcmp(root_element, "CAP") == 0 || strcmp(root_element, "alert") == 0) {
                                fprintf(f, " (Common Alerting Protocol)");
                            } else if (strcmp(root_element, "metadataEnvelope") == 0) {
                                fprintf(f, " (Service Signaling)");
                            } else if (strcmp(root_element, "MMTPackageTable") == 0) {
                                fprintf(f, " (MMT Package Table)");
                            } else if (strcmp(root_element, "ESGData") == 0 || strcmp(root_element, "ESGMain") == 0) {
                                fprintf(f, " (Electronic Service Guide)");
                            } else if (strcmp(root_element, "ContentAdvisoryTable") == 0) {
                                fprintf(f, " (Content Advisory)");
                            } else if (strcmp(root_element, "CDT") == 0) {
                                fprintf(f, " (Caption Distribution Table)");
                            } else if (strcmp(root_element, "DCT") == 0) {
                                fprintf(f, " (Dedicated Channel Table)");
                            }
                            fprintf(f, "<br>");
                        }
                    }
                }
                
                // Show preview
                fprintf(f, "<code>");
                int preview_len = entry->sample_payload_len > 100 ? 100 : entry->sample_payload_len;
                for (int j = 0; j < preview_len; j++) {
                    char c = entry->sample_payload[j];
                    if (c == '<') fprintf(f, "&lt;");
                    else if (c == '>') fprintf(f, "&gt;");
                    else if (c == '&') fprintf(f, "&amp;");
                    else if (c >= 0x20 || c == '\n') fputc(c, f);
                }
                if (entry->sample_payload_len > 100) fprintf(f, "...");
                fprintf(f, "</code>");
            } else if (looks_like_text) {
                fprintf(f, "<strong>Text data</strong><br><code>");
                int preview_len = entry->sample_payload_len > 80 ? 80 : entry->sample_payload_len;
                for (int j = 0; j < preview_len; j++) {
                    char c = entry->sample_payload[j];
                    if (c == '<') fprintf(f, "&lt;");
                    else if (c == '>') fprintf(f, "&gt;");
                    else if (c == '&') fprintf(f, "&amp;");
                    else fputc(c, f);
                }
                if (entry->sample_payload_len > 80) fprintf(f, "...");
                fprintf(f, "</code>");
            } else {
                // Binary data - try to identify specific formats
                
                // Check if we have a reassembled image for this stream
                RouteImageEntry* img = find_route_image(entry->destinationIp, entry->destinationPort, 
                                                        entry->tsi_or_packet_id);
                if (img && img->data && img->data_len > 0) {
                    // Determine MIME type
                    const char* mime_type = "image/bmp";
                    if (strcmp(img->format, "PNG") == 0) mime_type = "image/png";
                    else if (strcmp(img->format, "JPEG") == 0) mime_type = "image/jpeg";
                    
                    fprintf(f, "<strong>%s Image</strong> ", img->format);
                    if (img->width > 0 && img->height > 0) {
                        fprintf(f, "(%dx%d, %d-bit", img->width, img->height, img->bpp);
                    } else {
                        fprintf(f, "(%zu bytes", img->data_len);
                    }
                    fprintf(f, ")<br>");
                    
                    // Base64 encode and embed as <img>
                    size_t b64_len = 0;
                    char* b64 = base64_encode(img->data, img->data_len, &b64_len);
                    if (b64) {
                        // Scale for display: show at 2x-4x for tiny images
                        int display_width = img->width > 0 ? img->width : 72;
                        if (display_width < 100) display_width *= 3;
                        else if (display_width < 200) display_width *= 2;
                        if (display_width > 400) display_width = 400;
                        
                        fprintf(f, "<img src='data:%s;base64,%s' "
                                   "style='max-width:%dpx; border:1px solid #ccc; "
                                   "background:#fff; padding:4px; margin:4px 0;' "
                                   "alt='ROUTE image TSI %u'><br>",
                                mime_type, b64, display_width, entry->tsi_or_packet_id);
                        free(b64);
                    }
                } else {
                    fprintf(f, "<strong>Binary data</strong><br>");
                }
                
                // Check for LCT header (ROUTE/ALC)
                if (entry->sample_payload_len >= 4) {
                    uint8_t lct_version = (entry->sample_payload[0] >> 4) & 0x0F;
                    uint8_t header_len = (entry->sample_payload[2] >> 4) * 4; // In 32-bit words
                    uint8_t codepoint = entry->sample_payload[3];
                    
                    if (lct_version == 1 && header_len >= 8 && header_len <= 64) {
                        fprintf(f, "<em>Possible LCT Header:</em> Version=%d, HDR_LEN=%d bytes, Codepoint=%d<br>", 
                                lct_version, header_len, codepoint);
                    }
                }
                
                // Check for RTP header
                if (entry->sample_payload_len >= 12) {
                    uint8_t rtp_version = (entry->sample_payload[0] >> 6) & 0x03;
                    uint8_t rtp_pt = entry->sample_payload[1] & 0x7F;
                    if (rtp_version == 2) {
                        fprintf(f, "<em>Possible RTP:</em> Payload Type=%d", rtp_pt);
                        if (rtp_pt == 33) {
                            fprintf(f, " (MP2T/MPEG-TS)");
                            // Check if RTP payload is MPEG-TS null packets
                            if (entry->sample_payload_len >= 15) {
                                uint8_t ts_sync = entry->sample_payload[12];
                                uint16_t ts_pid = ((entry->sample_payload[13] & 0x1F) << 8) | entry->sample_payload[14];
                                if (ts_sync == 0x47 && ts_pid == 0x1FFF) {
                                    fprintf(f, "<br><span style='color:#856404;'>⚠️ RTP carrying MPEG-TS Null/Stuffing packets</span>");
                                }
                            }
                        }
                        else if (rtp_pt == 96) fprintf(f, " (Dynamic)");
                        fprintf(f, "<br>");
                    }
                }
                
                // Check for Scoreboard (1B F4 Signature)
                if (entry->sample_payload_len >= 5) {
                    // Check for the specific header bytes: 0x1B (ESC) and 0xF4
                    if (entry->sample_payload[0] == 0x1B && entry->sample_payload[1] == 0xF4) {
                        
                        fprintf(f, "<em>Possible Scoreboard Data:</em> Signature=0x1BF4");

                        // Based on your logs, Byte 4 contains the payload length
                        if (entry->sample_payload_len >= 5) {
                            uint8_t internal_len = entry->sample_payload[4];
                            uint8_t cmd_id = entry->sample_payload[2];
                            fprintf(f, " Cmd=0x%02X InternalLen=%d", cmd_id, internal_len);
                        }

                        // Optional: Heuristic to detect ASCII time (e.g., "12:00") inside the packet
                        // This checks if the payload contains a colon character
                        int has_time = 0;
                        for (size_t i = 5; i < entry->sample_payload_len; i++) {
                            if (entry->sample_payload[i] == 0x3A) { // Hex for ':'
                                has_time = 1;
                                break;
                            }
                        }
                        if (has_time) fprintf(f, " <span style='color:#28a745;'>(Contains Clock/Time)</span>");
                        
                        fprintf(f, "<br>");
                    }
                }
                
                // Scan for embedded XML anywhere in payload
                char* xml_start = NULL;
                for (int j = 0; j < entry->sample_payload_len - 5; j++) {
                    if (memcmp(entry->sample_payload + j, "<?xml", 5) == 0) {
                        xml_start = (char*)(entry->sample_payload + j);
                        break;
                    }
                }
                
                if (xml_start) {
                    int xml_remaining = entry->sample_payload_len - (xml_start - (char*)entry->sample_payload);
                    fprintf(f, "Contains embedded XML: ");
                    
                    // Find root element
                    char* root_start = strstr(xml_start, "?>");
                    if (root_start && root_start < xml_start + xml_remaining - 2) {
                        root_start += 2;
                        while (root_start < xml_start + xml_remaining && (*root_start == ' ' || *root_start == '\n' || *root_start == '\r' || *root_start == '\t')) {
                            root_start++;
                        }
                        if (*root_start == '<') {
                            root_start++;
                            char root_element[64] = {0};
                            int k = 0;
                            while (root_start < xml_start + xml_remaining && k < 63 && 
                                   *root_start != ' ' && *root_start != '>' && *root_start != '\n' && *root_start != '/') {
                                root_element[k++] = *root_start++;
                            }
                            root_element[k] = '\0';
                            
                            if (strlen(root_element) > 0) {
                                fprintf(f, "<strong>&lt;%s&gt;</strong>", root_element);
                                
                                // Identify known table types
                                if (strcmp(root_element, "SLT") == 0) {
                                    fprintf(f, " (Service List Table)");
                                } else if (strcmp(root_element, "S-TSID") == 0) {
                                    fprintf(f, " (ROUTE Stream Description)");
                                } else if (strcmp(root_element, "MPD") == 0) {
                                    fprintf(f, " (DASH Manifest)");
                                } else if (strcmp(root_element, "USBD") == 0 || strcmp(root_element, "BundleDescriptionROUTE") == 0) {
                                    fprintf(f, " (User Service Bundle Description)");
                                } else if (strcmp(root_element, "USD") == 0) {
                                    fprintf(f, " (User Service Description)");
                                } else if (strcmp(root_element, "HELD") == 0) {
                                    fprintf(f, " (HTML Entry Locations)");
                                } else if (strcmp(root_element, "RRT") == 0) {
                                    fprintf(f, " (Rating Region Table)");
                                } else if (strcmp(root_element, "SystemTime") == 0) {
                                    fprintf(f, " (System Time)");
                                } else if (strcmp(root_element, "AEAT") == 0) {
                                    fprintf(f, " (Advanced Emergency Alert)");
                                } else if (strcmp(root_element, "CAP") == 0 || strcmp(root_element, "alert") == 0) {
                                    fprintf(f, " (Common Alerting Protocol)");
                                } else if (strcmp(root_element, "metadataEnvelope") == 0) {
                                    fprintf(f, " (Service Signaling)");
                                } else if (strcmp(root_element, "MMTPackageTable") == 0) {
                                    fprintf(f, " (MMT Package Table)");
                                } else if (strcmp(root_element, "ESGData") == 0 || strcmp(root_element, "ESGMain") == 0) {
                                    fprintf(f, " (Electronic Service Guide)");
                                }
                            }
                        }
                    }
                    fprintf(f, "<br>");
                }
                
                fprintf(f, "Hex: ");
                int hex_len = entry->sample_payload_len > 32 ? 32 : entry->sample_payload_len;
                for (int j = 0; j < hex_len; j++) {
                    fprintf(f, "%02X ", entry->sample_payload[j]);
                }
                if (entry->sample_payload_len > 32) fprintf(f, "...");
            }
        } else {
            fprintf(f, "<em>No sample captured</em>");
        }
        
        // Add notes inline if applicable
        if (entry->tsi_or_packet_id == 0xFFFFFFFF) {
            fprintf(f, "<br><span style='color:#856404;'>⚠️ TSI 0xFFFFFFFF (reserved/special value)</span>");
        } else if (entry->tsi_or_packet_id == 0) {
            fprintf(f, "<br><span style='color:#856404;'>ℹ️ TSI 0 typically indicates signaling</span>");
        }
        
        fprintf(f, "</td></tr>\n");
    }
    
    fprintf(f, "</tbody></table>\n");
    fprintf(f, "</div></details>\n");
}

// Helper function to find highest resolution video representation
MpdRepresentation* find_highest_resolution_video(MpdAdaptationSet* as) {
    if (!as || !mpd_as_is_video(as)) {
        return NULL;
    }
    
    MpdRepresentation* best_rep = NULL;
    int best_pixels = 0;
    
    MpdRepresentation* rep = as->head_rep;
    while (rep) {
        if (strlen(rep->width) > 0 && strlen(rep->height) > 0) {
            int width = atoi(rep->width);
            int height = atoi(rep->height);
            int pixels = width * height;
            
            if (pixels > best_pixels) {
                best_pixels = pixels;
                best_rep = rep;
            }
        }
        rep = rep->next;
    }
    
    return best_rep;
}

// Helper function to format bandwidth
void format_bandwidth(const char* bandwidth_str, char* output, size_t output_size) {
    if (strlen(bandwidth_str) == 0) {
        strcpy(output, "Unknown");
        return;
    }
    
    int bw = atoi(bandwidth_str);
    if (bw >= 1000000) {
        snprintf(output, output_size, "%.1f Mbps", bw / 1000000.0);
    } else if (bw >= 1000) {
        snprintf(output, output_size, "%.0f kbps", bw / 1000.0);
    } else {
        snprintf(output, output_size, "%d bps", bw);
    }
}

// Helper function to format audio sample rate
void format_sample_rate(const char* sample_rate_str, char* output, size_t output_size) {
    if (strlen(sample_rate_str) == 0) {
        strcpy(output, "Unknown");
        return;
    }
    
    int sample_rate = atoi(sample_rate_str);
    if (sample_rate >= 1000) {
        snprintf(output, output_size, "%.0f kHz", sample_rate / 1000.0);
    } else {
        snprintf(output, output_size, "%s Hz", sample_rate_str);
    }
}

// Helper function to determine app type from HELD data
const char* determine_app_type(HeldData* held_data) {
    if (!held_data) return "No";
    
    // Check bbandEntryPageUrl for known patterns
    if (strlen(held_data->bbandEntryPageUrl) > 0) {
        if (strstr(held_data->bbandEntryPageUrl, "gameloop") || strstr(held_data->bbandEntryPageUrl, "GameLoop")) {
            return "<a href='https://gameloop.tv/' target='_blank'>GameLoop</a>";
        }
        if (strstr(held_data->bbandEntryPageUrl, "roxi") || strstr(held_data->bbandEntryPageUrl, "Roxi")) {
            return "<a href='https://roxi.tv/' target='_blank'>ROXi</a>";
        }
        if (strstr(held_data->bbandEntryPageUrl, "run3tv") || strstr(held_data->bbandEntryPageUrl, "Run3TV") || strstr(held_data->bbandEntryPageUrl, "A3FA") || strstr(held_data->bbandEntryPageUrl, "a3fa")) {
            return "<a href='https://run3tv.com/' target='_blank'>Run3TV</a>";
        }
    }
    
    // Check clearBbandEntryPageUrl as well
    if (strlen(held_data->clearBbandEntryPageUrl) > 0) {
        if (strstr(held_data->clearBbandEntryPageUrl, "gameloop") || strstr(held_data->clearBbandEntryPageUrl, "GameLoop")) {
            return "<a href='https://gameloop.tv/' target='_blank'>GameLoop</a>";
        }
        if (strstr(held_data->clearBbandEntryPageUrl, "roxi") || strstr(held_data->clearBbandEntryPageUrl, "Roxi")) {
            return "<a href='https://roxi.tv/' target='_blank'>ROXi</a>";
        }
        if (strstr(held_data->clearBbandEntryPageUrl, "run3tv") || strstr(held_data->clearBbandEntryPageUrl, "Run3TV") || strstr(held_data->clearBbandEntryPageUrl, "A3FA") || strstr(held_data->bbandEntryPageUrl, "a3fa")) {
            return "<a href='https://run3tv.com/' target='_blank'>Run3TV</a>";
        }
    }
    
    // If HELD data exists but doesn't match known patterns
    return "Yes";
}

// Add this function to generate the KEYDATA section
void generate_keydata_section(FILE *f) {
    // Get current time in the required format
    time_t current_time = time(NULL);
    char time_str[32];
    struct tm *current_tm = gmtime(&current_time);  // Use GMT like the example
    strftime(time_str, sizeof(time_str), "%d-%b-%Y %H:%M:%S", current_tm);
    
    // Find BSID from SLT data
    char bsid[16] = "Unknown";
    for (int i = 0; i < g_lls_table_count; i++) {
        if (g_lls_tables[i].type == TABLE_TYPE_SLT) {
            SltData* slt_data = (SltData*)g_lls_tables[i].parsed_data;
            if (strlen(slt_data->bsid) > 0) {
                strncpy(bsid, slt_data->bsid, sizeof(bsid) - 1);
                bsid[sizeof(bsid) - 1] = '\0';
                break;
            }
        }
    }
    
    // Count programs in categories 1 and 2
    int program_count = 0;
    for (int i = 0; i < g_lls_table_count; i++) {
        if (g_lls_tables[i].type == TABLE_TYPE_SLT) {
            SltData* slt_data = (SltData*)g_lls_tables[i].parsed_data;
            ServiceInfo* service = slt_data->head;
            while(service) {
                int category = atoi(service->serviceCategory);
                if (category == 1 || category == 2) {
                    program_count++;
                }
                service = service->next;
            }
        }
    }
    
    fprintf(f, "<!--KEYDATA>\n");
    fprintf(f, "Channel: Unknown\n");
    fprintf(f, "BSID: %s\n", bsid);
    fprintf(f, "TEI: 0\n");
    fprintf(f, "Time: %s\n", time_str);
    fprintf(f, "Programs: %d\n", program_count);
    
    // Generate program entries for categories 1 and 2 only
    for (int i = 0; i < g_lls_table_count; i++) {
        if (g_lls_tables[i].type == TABLE_TYPE_SLT) {
            SltData* slt_data = (SltData*)g_lls_tables[i].parsed_data;
            ServiceInfo* service = slt_data->head;
            while(service) {
                int category = atoi(service->serviceCategory);
                if (category == 1 || category == 2) {
                    // Find MPD data for this service to get technical details
                    MpdData* service_mpd = NULL;
                    MpdRepresentation* video_rep = NULL;
                    MpdRepresentation* audio_rep = NULL;
                    
                    for (int j = 0; j < g_lls_table_count; j++) {
                        if (strcmp(g_lls_tables[j].destinationIp, service->slsDestinationIpAddress) == 0 &&
                            strcmp(g_lls_tables[j].destinationPort, service->slsDestinationUdpPort) == 0 &&
                            g_lls_tables[j].type == TABLE_TYPE_MPD) {
                            service_mpd = (MpdData*)g_lls_tables[j].parsed_data;
                            break;
                        }
                    }
                    
                    // Find video and audio representations
                    if (service_mpd) {
                        MpdAdaptationSet* as = service_mpd->head_as;
                        while (as) {
                            if (mpd_as_is_video(as) && !video_rep) {
                                video_rep = find_highest_resolution_video(as);
                            } else if (mpd_as_is_audio(as) && !audio_rep) {
                                // Most channels, then highest bandwidth (channel count may be absent)
                                MpdRepresentation* rep = as->head_rep;
                                while (rep) {
                                    if (mpd_audio_rep_better(rep, audio_rep)) {
                                        audio_rep = rep;
                                    }
                                    rep = rep->next;
                                }
                            }
                            as = as->next;
                        }
                    }
                    
                    // Format channel number
                    char channel_str[32] = "";
                    if (strlen(service->majorChannelNo) > 0 && strlen(service->minorChannelNo) > 0) {
                        snprintf(channel_str, sizeof(channel_str), "%s.%s", service->majorChannelNo, service->minorChannelNo);
                    } else {
                        strcpy(channel_str, "0.0");
                    }
                    
                    // Format IP:Port as service identifier
                    char ip_port[64];
                    snprintf(ip_port, sizeof(ip_port), "%s:%s", service->slsDestinationIpAddress, service->slsDestinationUdpPort);
                    
                    // Start building the program line
                    fprintf(f, "%s|%s|%s|%s|", 
                           service->serviceId, 
                           channel_str, 
                           ip_port, 
                           service->shortServiceName);
                    
                    // Video information
                    if (video_rep && strlen(video_rep->width) > 0 && strlen(video_rep->height) > 0) {
                        char scan_type = (strlen(video_rep->scanType) > 0 && strcmp(video_rep->scanType, "progressive") == 0) ? 'p' : 'i';
                        fprintf(f, "0|0|%s|%s%c|%sx%s|", 
                               video_rep->codecs, 
                               video_rep->height, scan_type,
                               video_rep->width, video_rep->height);
                        
                        // Display aspect ratio
                        if (strlen(video_rep->displayAspectRatio) > 0) {
                            fprintf(f, "%s|", video_rep->displayAspectRatio);
                        } else {
                            fprintf(f, "16:9|");  // Default assumption
                        }
                        
                        // Video bitrates (placeholder zeros for now)
                        fprintf(f, "0|0|0|");
                    } else {
                        // No video data available
                        fprintf(f, "0|0|Unknown|Unknown|Unknown|Unknown|0|0|0|");
                    }
                    
                    // Audio information  
                    if (audio_rep) {
                        fprintf(f, "0|0|%s|", audio_rep->codecs);
                        
                        // Audio channels
                        if (strlen(audio_rep->audioChannelCount) > 0) {
                            int channels = atoi(audio_rep->audioChannelCount);
                            if (channels == 1) {
                                fprintf(f, "1.0|");
                            } else if (channels == 2) {
                                fprintf(f, "2.0|");
                            } else if (channels == 6) {
                                fprintf(f, "5.1|");
                            } else {
                                fprintf(f, "%d.0|", channels);
                            }
                        } else {
                            fprintf(f, "Unknown|");
                        }
                        
                        // Audio bitrate
                        if (strlen(audio_rep->bandwidth) > 0) {
                            int bw_bps = atoi(audio_rep->bandwidth);
                            int bw_kbps = bw_bps / 1000;
                            fprintf(f, "%d|", bw_kbps);
                        } else {
                            fprintf(f, "0|");
                        }
                    } else {
                        // No audio data available
                        fprintf(f, "0|0|Unknown|Unknown|0|");
                    }
                    
                    // End with language count and terminator
                    fprintf(f, "1|^|\n");
                }
                service = service->next;
            }
        }
    }
    
    fprintf(f, "-->\n");
}

int get_plps_for_service_enhanced(const char* dest_ip, const char* dest_port, char* plp_list, size_t plp_list_size) {
    if (!dest_ip || !dest_port || !plp_list || plp_list_size == 0) {
        return 0;
    }
    
    plp_list[0] = '\0';
    int plp_count = 0;
    int plps_found[64] = {0};
    
    // Search through all LMT tables
    for (int i = 0; i < g_lls_table_count; i++) {
        if (g_lls_tables[i].type == TABLE_TYPE_LMT) {
            LmtData* lmt_data = (LmtData*)g_lls_tables[i].parsed_data;
            LmtService* service = lmt_data->services;
            
            while (service) {
                LmtMulticast* multicast = service->multicasts;
                while (multicast) {
                    // Check if this multicast destination matches the service
                    if (strcmp(multicast->dest_ip_str, dest_ip) == 0 && 
                        strcmp(multicast->dest_port_str, dest_port) == 0) {
                        
                        if (!plps_found[service->plp_id]) {
                            plps_found[service->plp_id] = 1;
                            plp_count++;
                        }
                    }
                    multicast = multicast->next;
                }
                service = service->next;
            }
        }
    }
    
    // Build the PLP list string
    int first = 1;
    for (int plp = 0; plp < 64; plp++) {
        if (plps_found[plp]) {
            if (!first) {
                strncat(plp_list, "+", plp_list_size - strlen(plp_list) - 1);
            }
            char plp_str[8];
            snprintf(plp_str, sizeof(plp_str), "%d", plp);
            strncat(plp_list, plp_str, plp_list_size - strlen(plp_list) - 1);
            first = 0;
        }
    }
    
    return plp_count;
}

/**
 * @brief Check if any LMT tables are present in the parsed data
 */
int has_lmt_data(void) {
    for (int i = 0; i < g_lls_table_count; i++) {
        if (g_lls_tables[i].type == TABLE_TYPE_LMT) {
            return 1;
        }
    }
    return 0;
}

void generate_html_report(const char* filename) {
    FILE *f = fopen(filename, "w");
    if (f == NULL) {
        perror("Error opening HTML report file");
        return;
    }

    fprintf(f, "<!DOCTYPE html>\n<html lang='en'>\n<head>\n<meta charset='UTF-8'>\n");
    fprintf(f, "<meta name='viewport' content='width=device-width, initial-scale=1.0'>\n");
    fprintf(f, "<title>RENDER - RabbitEars NextGen Data Evaluator Report - v%s</title>\n", RENDER_VERSION);
    
    generate_keydata_section(f);
    
    fprintf(f, "<style>\n"
           "body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif, 'Apple Color Emoji', 'Segoe UI Emoji'; font-size: 14px; line-height: 1.4; margin: 1em; background-color: #f8f9fa; color: #212529; }\n"
           "h1, h2, h3, h4, h5 { margin-top: 0.4em; margin-bottom: 0.6em; color: #343a40; }\n"
           "h1 { font-size: 2em; border-bottom: 2px solid #007bff; padding-bottom: 0.3em; }\n"
           "h2 { font-size: 1.6em; border-bottom: 1px solid #dee2e6; padding-bottom: 0.2em; margin-top: 1.0em;}\n"
           "h3 { font-size: 1.3em; }\n"
           "h4 { font-size: 1.1em; color: #495057; }\n"
           "table { border-collapse: collapse; width: 100%%; margin-top: 0.8em; box-shadow: 0 1px 2px rgba(0,0,0,0.05); }\n"
           "th, td { border: 1px solid #dee2e6; padding: 6px 10px; text-align: left; vertical-align: top; word-break: break-word; }\n"
           "th { background-color: #e9ecef; color: #495057; font-weight: 600; }\n"
           "tr:nth-child(even) { background-color: #f8f9fa; }\n"
           "ul { list-style-type: none; padding-left: 0; }\n"
           "li { background-color: #ffffff; border-left: 3px solid #007bff; margin-bottom: 5px; padding: 8px 12px; }\n"
           "li strong { color: #0056b3; }\n"
           ".container { background-color: white; padding: 1.5em; border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.1); max-width: 1200px; margin: auto; }\n"
           ".service-container { border: 2px solid #007bff; border-radius: 8px; padding: 1em; margin-top: 1em; background: #f8f9fa;}\n"
           ".not-found { color: #6c757d; }\n"
           ".mpd-summary { background-color: #e7f3ff; border: 1px solid #b3d7ff; padding: 12px; border-radius: 5px; margin-bottom: 0.8em; }\n"
           ".segment-list { padding-left: 20px; list-style-type: disc; }\n"
           ".segment-list li { border: none; background-color: transparent; padding: 2px; margin-bottom: 2px; }\n"
           ".smt-badge { background: #28a745; color: white; padding: 2px 8px; border-radius: 4px; font-size: 0.85em; font-weight: normal; margin-left: 8px; }\n"
           ".signature-info { background: #f8f9fa; border: 1px solid #28a745; border-radius: 5px; padding: 12px; margin: 10px 0; }\n"
           ".signature-info h4 { margin: 0 0 10px 0; color: #28a745; }\n"
           "details { border: 1px solid #dee2e6; border-radius: 5px; margin: 1em 0; background-color: #fff; }\n"
           "summary { font-weight: bold; padding: 8px 12px; background-color: #f8f9fa; cursor: pointer; border-bottom: 1px solid #dee2e6; }\n"
           "details[open] > summary { border-bottom: 1px solid #dee2e6; }\n"
           ".details-content { padding: 0.5em 1em 1em 1em; }\n"
           "pre { background-color: #e9ecef; padding: 12px; margin: 0; border-radius: 4px; white-space: pre-wrap; word-wrap: break-word; font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, Courier, monospace; font-size: 13px; color: #333; max-height: 300px; overflow-y: auto; }\n"
           "details:not([open]) pre { display: none; }\n"
           "</style>\n</head>\n<body>\n<div class='container'>\n");
    fprintf(f, "<h1>RENDER - RabbitEars NextGen Data Evaluator Report - v%s</h1>\n", RENDER_VERSION);
    eas_write_html_section(f);
    
    // Extract SLT BSID for comparison with L1 BSID
    char slt_bsid_for_compare[16] = "";
    for (int i = 0; i < g_lls_table_count; i++) {
        if (g_lls_tables[i].type == TABLE_TYPE_SLT) {
            SltData* slt_data = (SltData*)g_lls_tables[i].parsed_data;
            if (slt_data && strlen(slt_data->bsid) > 0) {
                strncpy(slt_bsid_for_compare, slt_data->bsid, sizeof(slt_bsid_for_compare) - 1);
                slt_bsid_for_compare[sizeof(slt_bsid_for_compare) - 1] = '\0';
                break;
            }
        }
    }
    
    // --- L1 Information Section ---
    if (get_enhanced_l1_signaling_data()) {
        generate_enhanced_l1_section(f, get_enhanced_l1_signaling_data(), slt_bsid_for_compare);
    } else if (get_l1_signaling_data()) {
        // Add a function to generate basic L1 section or convert the data
        generate_basic_l1_section(f, get_l1_signaling_data(), slt_bsid_for_compare);
    } else {
        // If no L1 data is available, show the red message similar to CDT
        fprintf(f, "<div class='details-content' style='margin-top: 1em; padding: 10px; border-radius: 5px; background-color: #f8d7da; border: 1px solid #f5c6cb; color: #721c24;'>\n");
        fprintf(f, "<strong>PLP/L1 Information Not Available</strong>\n");
        fprintf(f, "</div>\n");
    }
    
    // LMT Tables
    int lmt_count = 0;
    for (int i = 0; i < g_lls_table_count; i++) {
        if (g_lls_tables[i].type == TABLE_TYPE_LMT) {
            lmt_count++;
            LmtData* lmt_data = (LmtData*)g_lls_tables[i].parsed_data;
            
            // Count total multicast entries and check if any service has duplicates
            int total_multicast_count = 0;
            int has_any_duplicates = 0;
            
            LmtService* count_service = lmt_data->services;
            while (count_service) {
                if (count_service->duplicate_count > 0) {
                    has_any_duplicates = 1;
                }
                LmtMulticast* count_multicast = count_service->multicasts;
                while (count_multicast) {
                    total_multicast_count++;
                    count_multicast = count_multicast->next;
                }
                count_service = count_service->next;
            }

            fprintf(f, "<details><summary>Link Mapping Table (LMT) Version %d - %d Service(s)", 
                    lmt_data->lmt_version, total_multicast_count);
            
            if (lmt_data->duplicate_count > 0) {
                fprintf(f, " - <span style='color: #ff6600;'>⚠ %d duplicate%s detected and removed</span>", 
                        lmt_data->duplicate_count,
                        lmt_data->duplicate_count == 1 ? "" : "s");
            }
            
            fprintf(f, "</summary>\n");
            fprintf(f, "<div class='details-content'>\n");
            
            // Conditional header based on whether duplicates exist
            fprintf(f, "<table><thead><tr><th>PLP ID</th><th>Source IP:Port</th><th>Destination IP:Port</th><th>Service ID</th><th>Service Name</th><th>Flags</th>");
            if (has_any_duplicates) {
                fprintf(f, "<th>Duplicates Removed</th>");
            }
            fprintf(f, "</tr></thead><tbody>\n");
            
            LmtService* service = lmt_data->services;
            while (service) {
                LmtMulticast* multicast = service->multicasts;
                
                // Track if we've already printed the duplicate count for this service
                int first_row_for_service = 1;
                int service_row_count = 0;
                
                // Count rows for this service first (for rowspan)
                LmtMulticast* count_mc = service->multicasts;
                while (count_mc) {
                    service_row_count++;
                    count_mc = count_mc->next;
                }
                
                while (multicast) {
                    // Build flags string
                    char flags_str[32] = "";
                    if (multicast->sid_bit || multicast->compression_bit) {
                        snprintf(flags_str, sizeof(flags_str), "SID:%d COMP:%d", 
                                multicast->sid_bit, multicast->compression_bit);
                    } else {
                        strcpy(flags_str, "None");
                    }
                    
                    // Try to find matching service from SLT
                    char service_id_str[16] = "";
                    char service_name_str[128] = "";
                    
                    // Search through SLT data to find matching service
                    for (int j = 0; j < g_lls_table_count; j++) {
                        if (g_lls_tables[j].type == TABLE_TYPE_SLT) {
                            SltData* slt_data = (SltData*)g_lls_tables[j].parsed_data;
                            ServiceInfo* slt_service = slt_data->head;
                            while (slt_service) {
                                if (strcmp(slt_service->slsDestinationIpAddress, multicast->dest_ip_str) == 0 &&
                                    strcmp(slt_service->slsDestinationUdpPort, multicast->dest_port_str) == 0) {
                                    strncpy(service_id_str, slt_service->serviceId, sizeof(service_id_str) - 1);
                                    service_id_str[sizeof(service_id_str) - 1] = '\0';
                                    strncpy(service_name_str, slt_service->shortServiceName, sizeof(service_name_str) - 1);
                                    service_name_str[sizeof(service_name_str) - 1] = '\0';
                                    break;
                                }
                                slt_service = slt_service->next;
                            }
                            if (strlen(service_id_str) > 0) break;
                        }
                    }
                    
                    fprintf(f, "<tr><td>%d</td><td>%d.%d.%d.%d:%d</td><td>%s:%s</td><td>%s</td><td>%s</td><td>%s</td>",
                        service->plp_id,
                        (multicast->src_ip >> 24) & 0xff, (multicast->src_ip >> 16) & 0xff,
                        (multicast->src_ip >> 8) & 0xff, multicast->src_ip & 0xff,
                        multicast->src_port,
                        multicast->dest_ip_str, multicast->dest_port_str,
                        service_id_str, service_name_str,
                        flags_str);
                    
                    // Add duplicate count column if needed
                    if (has_any_duplicates) {
                        if (first_row_for_service && service->duplicate_count > 0) {
                            // Use rowspan to show duplicate count across all rows for this service
                            fprintf(f, "<td rowspan='%d' style='background-color: #fff3cd; text-align: center; vertical-align: middle;'><strong>%d</strong></td>",
                                    service_row_count, service->duplicate_count);
                        } else if (first_row_for_service) {
                            // No duplicates for this service
                            fprintf(f, "<td rowspan='%d' style='text-align: center; vertical-align: middle;'>-</td>",
                                    service_row_count);
                        }
                        // else: subsequent rows for this service don't get a cell (covered by rowspan)
                    }
                    
                    fprintf(f, "</tr>\n");
                    
                    first_row_for_service = 0;
                    multicast = multicast->next;
                }
                service = service->next;
            }
            
            fprintf(f, "</tbody></table>");
            fprintf(f, "</div></details>\n");
        } 
    }
    if (lmt_count == 0) {
        // If LMT is not present, show the red message where the table would have been.
        fprintf(f, "<div class='details-content' style='margin-top: 1em; padding: 10px; border-radius: 5px; background-color: #f8d7da; border: 1px solid #f5c6cb; color: #721c24;'>\n");
        fprintf(f, "<strong>Link Mapping Table Data Not Available</strong>\n");
        fprintf(f, "</div>\n");
    }

    // Check if CDT is present for later use
    /*int cdt_present = 0;
    for (int i = 0; i < g_lls_table_count; i++) {
        if (g_lls_tables[i].type == TABLE_TYPE_CDT) {
            cdt_present = 1;
            break;
        }
    }*/

    // --- Create a list of unique services found ---
    #define MAX_UNIQUE_SERVICES 1000
    ServiceInfo* unique_services[MAX_UNIQUE_SERVICES];
    int unique_service_count = 0;
    int udst_linked_flags[MAX_TABLES] = {0}; // Track linked UDSTs

    for (int i = 0; i < g_lls_table_count; i++) {
        if (g_lls_tables[i].type == TABLE_TYPE_SLT) {
            SltData* slt_data = (SltData*)g_lls_tables[i].parsed_data;
            ServiceInfo* service = slt_data->head;
            while(service) {
                int service_found = 0;
                for (int j = 0; j < unique_service_count; j++) {
                    if (strcmp(unique_services[j]->serviceId, service->serviceId) == 0) {
                        service_found = 1;
                        break;
                    }
                }
                if (!service_found && unique_service_count < MAX_UNIQUE_SERVICES) {
                    unique_services[unique_service_count++] = service;
                }
                service = service->next;
            }
        }
    }

    // --- Service Summary Section (moved to top) ---
    if (unique_service_count > 0) {
        // Extract BSID from SLT data for the header
        char slt_bsid[16] = "";
        for (int i = 0; i < g_lls_table_count; i++) {
            if (g_lls_tables[i].type == TABLE_TYPE_SLT) {
                SltData* slt_data = (SltData*)g_lls_tables[i].parsed_data;
                if (strlen(slt_data->bsid) > 0) {
                    strncpy(slt_bsid, slt_data->bsid, sizeof(slt_bsid) - 1);
                    slt_bsid[sizeof(slt_bsid) - 1] = '\0';
                    break;
                }
            }
        }
        
        // Get L1 BSID for comparison - also track if L1 data exists at all
        const char* l1_bsid = NULL;
        int l1_data_exists = 0;
        if (get_enhanced_l1_signaling_data()) {
            l1_data_exists = 1;
            if (strlen(get_enhanced_l1_signaling_data()->l1_bsid) > 0) {
                l1_bsid = get_enhanced_l1_signaling_data()->l1_bsid;
            }
        } else if (get_l1_signaling_data()) {
            l1_data_exists = 1;
            if (strlen(get_l1_signaling_data()->l1_bsid) > 0) {
                l1_bsid = get_l1_signaling_data()->l1_bsid;
            }
        }
        
        // Check if we have LMT data to show PLP column
        int show_plp_column = has_lmt_data();
        
        fprintf(f, "<h2>Service Summary");
        if (strlen(slt_bsid) > 0) {
            // Highlight yellow if L1 data exists and either:
            // 1. L1 BSID differs from SLT BSID, or
            // 2. L1 BSID is not set (empty)
            int bsid_mismatch = l1_data_exists && (!l1_bsid || strcmp(slt_bsid, l1_bsid) != 0);
            if (bsid_mismatch) {
                fprintf(f, " <span style='background:#ffff00;' title='SLT BSID does not match L1 BSID (%s)'>(SLT BSID: %s)</span>", 
                        l1_bsid ? l1_bsid : "Not Set", slt_bsid);
            } else {
                fprintf(f, " (SLT BSID: %s)", slt_bsid);
            }
        }
        fprintf(f, "</h2>\n");
        
        // Table header - conditionally include PLP column
        fprintf(f, "<table><thead><tr><th>Service Name</th><th>ID</th><th>Channel</th>");
        if (show_plp_column) {
            fprintf(f, "<th>PLP</th>");
        }
        fprintf(f, "<th>Protocol / Category</th><th>SLS Destination</th></tr></thead><tbody>\n");
        
        for(int i = 0; i < unique_service_count; i++) {
            ServiceInfo* service = unique_services[i];
            
            // Get protocol string
            const char* protocol_str = strcmp(service->slsProtocol, "1") == 0 ? "ROUTE" : (strcmp(service->slsProtocol, "2") == 0 ? "MMT" : service->slsProtocol);
            
            // Get category description
            const char* category_desc = "Unknown";
            int category_num = atoi(service->serviceCategory);
            switch(category_num) {
                case 1: category_desc = "Linear A/V Service"; break;
                case 2: category_desc = "Linear Audio Only Service"; break;
                case 3: category_desc = "App-Based Service"; break;
                case 4: category_desc = "ESG Service"; break;
                case 5: category_desc = "EAS Service"; break;
                case 6: category_desc = "DRM Data Service"; break;
            }
            
            // Format channel number (only show if both major and minor are present)
            char channel_str[32] = "";
            if (strlen(service->majorChannelNo) > 0 && strlen(service->minorChannelNo) > 0) {
                snprintf(channel_str, sizeof(channel_str), "%s.%s", service->majorChannelNo, service->minorChannelNo);
            }
            
            // Build service name with icons
            char service_name_with_icons[2048];
            snprintf(service_name_with_icons, sizeof(service_name_with_icons), "<a href=\"#service_%s\">%s</a>", service->serviceId, service->shortServiceName);
            
            if (service->protected) {
                strncat(service_name_with_icons, " <svg width='16' height='16' viewBox='0 0 24 24' fill='none' style='display:inline;vertical-align:middle;margin-left:2px;'><path d='M18 8h-1V6c0-2.76-2.24-5-5-5S7 3.24 7 6v2H6c-1.1 0-2 .9-2 2v10c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V10c0-1.1-.9-2-2-2zM12 17c-1.1 0-2-.9-2-2s.9-2 2-2 2 .9 2 2-.9 2-2 2zM15.1 8H8.9V6c0-1.71 1.39-3.1 3.1-3.1s3.1 1.39 3.1 3.1v2z' fill='#f57c00'/><title>Encrypted</title></svg>", sizeof(service_name_with_icons) - strlen(service_name_with_icons) - 1);
            }
            if (service->broadbandAccessRequired) {
                strncat(service_name_with_icons, " <svg width='16' height='16' viewBox='0 0 24 24' fill='none' style='display:inline;vertical-align:middle;margin-left:2px;'><circle cx='12' cy='12' r='10' stroke='#1976d2' stroke-width='2' fill='none'/><ellipse cx='12' cy='12' rx='5' ry='10' stroke='#1976d2' stroke-width='1.5' fill='none'/><ellipse cx='12' cy='12' rx='10' ry='5' stroke='#1976d2' stroke-width='1.5' fill='none'/><line x1='2' y1='12' x2='22' y2='12' stroke='#1976d2' stroke-width='1.5'/><line x1='12' y1='2' x2='12' y2='22' stroke='#1976d2' stroke-width='1.5'/><title>Internet Required</title></svg>", sizeof(service_name_with_icons) - strlen(service_name_with_icons) - 1);
            }
            if (service->hidden) {
                strncat(service_name_with_icons, " <svg width='16' height='16' viewBox='0 0 24 24' fill='none' style='display:inline;vertical-align:middle;margin-left:2px;'><path d='M12 4.5C7 4.5 2.73 7.61 1 12c1.73 4.39 6 7.5 11 7.5s9.27-3.11 11-7.5c-1.73-4.39-6-7.5-11-7.5zM12 17c-2.76 0-5-2.24-5-5s2.24-5 5-5 5 2.24 5 5-2.24 5-5 5zm0-8c-1.66 0-3 1.34-3 3s1.34 3 3 3 3-1.34 3-3-1.34-3-3-3z' fill='gray'/><line x1='4' y1='4' x2='20' y2='20' stroke='red' stroke-width='2'/><circle cx='12' cy='12' r='10' fill='none' stroke='red' stroke-width='2'/><title>Hidden</title></svg>", sizeof(service_name_with_icons) - strlen(service_name_with_icons) - 1);
            }
            
            // Get PLP information if LMT is available
            char plp_list[64] = "";
            if (show_plp_column) {
                get_plps_for_service_enhanced(service->slsDestinationIpAddress, service->slsDestinationUdpPort, plp_list, sizeof(plp_list));
                if (strlen(plp_list) == 0) {
                    strcpy(plp_list, "?"); // Unknown PLP mapping
                }
            }
            
            fprintf(f, "<tr><td>%s</td><td>%s</td><td>%s</td>", service_name_with_icons, service->serviceId, channel_str);
            
            // Conditionally add PLP column
            if (show_plp_column) {
                fprintf(f, "<td>%s</td>", plp_list);
            }
            
            fprintf(f, "<td>%s / %s</td><td>%s:%s</td></tr>\n",
                protocol_str, category_desc, service->slsDestinationIpAddress, service->slsDestinationUdpPort);
        }
        fprintf(f, "</tbody></table>\n");
    }

    // --- Core Signaling Tables Section ---
    
    if (g_bps_data) {
        generate_bps_html_section(f, g_bps_data);
    }

    // CDT Table - Conditionally displayed based on presence
    generate_cdt_html_section(f, g_lls_table_count, g_lls_tables);
    
    // SLT Tables (raw XML only)
    int slt_instance_count = 0;
    int found_slt = 0;
    for (int i = 0; i < g_lls_table_count; i++) {
        if (g_lls_tables[i].type == TABLE_TYPE_SLT) {
            found_slt = 1;
            slt_instance_count++;
            //SltData* slt_data = (SltData*)g_lls_tables[i].parsed_data;
            fprintf(f, "<details><summary>Service List Table (SLT) Instance %d", slt_instance_count);
            if (g_lls_tables[i].is_in_smt) {
                fprintf(f, " <span class='smt-badge' title='This table was delivered in a Signed Multi-Table (SMT)'>🔒 Signed</span>");
            }
            fprintf(f, " - Raw XML</summary>\n");
            fprintf(f, "<div class='details-content'><pre>"); // <h4>Raw XML</h4>
            fprintf_escaped_xml(f, g_lls_tables[i].content_id);
            fprintf(f, "</pre></div></details>\n");
        }
    }
    if (!found_slt) {
        fprintf(f, "<details><summary>Service List Table (SLT) - Not Found</summary>\n");
        fprintf(f, "<div class='details-content'><p class='not-found'>No SLT tables found in this capture.</p></div></details>\n");
    }

    // --- Per-Service Details Section ---
    for (int i = 0; i < unique_service_count; i++) {
        ServiceInfo* service = unique_services[i];
        
        // Build service header with icons
        char service_header[4096];
        if (strlen(service->majorChannelNo) > 0 && strlen(service->minorChannelNo) > 0) {
            snprintf(service_header, sizeof(service_header), "Service %s: %s (%s.%s)", 
            service->serviceId, service->shortServiceName, service->majorChannelNo, service->minorChannelNo);
        } else {
            snprintf(service_header, sizeof(service_header), "Service %s: %s", 
            service->serviceId, service->shortServiceName);
        }
        
        if (service->protected) {
            strncat(service_header, " <svg width='20' height='20' viewBox='0 0 24 24' fill='none' style='display:inline;vertical-align:middle;margin-left:4px;'><path d='M18 8h-1V6c0-2.76-2.24-5-5-5S7 3.24 7 6v2H6c-1.1 0-2 .9-2 2v10c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V10c0-1.1-.9-2-2-2zM12 17c-1.1 0-2-.9-2-2s.9-2 2-2 2 .9 2 2-.9 2-2 2zM15.1 8H8.9V6c0-1.71 1.39-3.1 3.1-3.1s3.1 1.39 3.1 3.1v2z' fill='#f57c00'/><title>Encrypted</title></svg>", sizeof(service_header) - strlen(service_header) - 1);
        }
        if (service->broadbandAccessRequired) {
            strncat(service_header, " <svg width='20' height='20' viewBox='0 0 24 24' fill='none' style='display:inline;vertical-align:middle;margin-left:4px;'><circle cx='12' cy='12' r='10' stroke='#1976d2' stroke-width='2' fill='none'/><ellipse cx='12' cy='12' rx='5' ry='10' stroke='#1976d2' stroke-width='1.5' fill='none'/><ellipse cx='12' cy='12' rx='10' ry='5' stroke='#1976d2' stroke-width='1.5' fill='none'/><line x1='2' y1='12' x2='22' y2='12' stroke='#1976d2' stroke-width='1.5'/><line x1='12' y1='2' x2='12' y2='22' stroke='#1976d2' stroke-width='1.5'/><title>Internet Required</title></svg>", sizeof(service_header) - strlen(service_header) - 1);
        }
        if (service->hidden) {
            strncat(service_header, " <svg width='20' height='20' viewBox='0 0 24 24' fill='none' style='display:inline;vertical-align:middle;margin-left:4px;'><path d='M12 4.5C7 4.5 2.73 7.61 1 12c1.73 4.39 6 7.5 11 7.5s9.27-3.11 11-7.5c-1.73-4.39-6-7.5-11-7.5zM12 17c-2.76 0-5-2.24-5-5s2.24-5 5-5 5 2.24 5 5-2.24 5-5 5zm0-8c-1.66 0-3 1.34-3 3s1.34 3 3 3 3-1.34 3-3-1.34-3-3-3z' fill='gray'/><line x1='4' y1='4' x2='20' y2='20' stroke='red' stroke-width='2'/><circle cx='12' cy='12' r='10' fill='none' stroke='red' stroke-width='2'/><title>Hidden</title></svg>", sizeof(service_header) - strlen(service_header) - 1);
        }
        
        fprintf(f, "<h2 id=\"service_%s\">%s</h2>\n", service->serviceId, service_header);
        
        fprintf(f, "<div class='service-container'>\n");

        // NEW: Enhanced Service Summary Section
        fprintf(f, "<div class='service-summary' style='background-color: #e3f2fd; border: 1px solid #2196f3; padding: 15px; border-radius: 8px; margin-bottom: 15px;'>\n");
        fprintf(f, "<div style='display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 10px;'>\n");
        
        // Basic service info
        const char* summary_category_desc = "Unknown";
        int summary_category_num = atoi(service->serviceCategory);
        switch(summary_category_num) {
            case 1: summary_category_desc = "Linear A/V Service"; break;
            case 2: summary_category_desc = "Linear Audio Only Service"; break;
            case 3: summary_category_desc = "App-Based Service"; break;
            case 4: summary_category_desc = "ESG Service"; break;
            case 5: summary_category_desc = "EAS Service"; break;
            case 6: summary_category_desc = "DRM Data Service"; break;
        }
        const char* summary_protocol_str = strcmp(service->slsProtocol, "1") == 0 ? "ROUTE" : (strcmp(service->slsProtocol, "2") == 0 ? "MMT" : service->slsProtocol);
        
        fprintf(f, "<div><strong>Protocol:</strong> %s<br />\n", summary_protocol_str);
        fprintf(f, "<strong>Category:</strong> %s</div>\n", summary_category_desc);
        fprintf(f, "<div><strong>Source:</strong> %s<br />\n", service->slsSourceIpAddress);
        fprintf(f, "<strong>Destination:</strong> %s:%s</div>\n", service->slsDestinationIpAddress, service->slsDestinationUdpPort);
        
        // Check for MPD data to show video/audio info (using highest resolution) for ROUTE
        MpdData* service_mpd = NULL;
        for (int j = 0; j < g_lls_table_count; j++) {
            if (strcmp(g_lls_tables[j].destinationIp, service->slsDestinationIpAddress) == 0 &&
                strcmp(g_lls_tables[j].destinationPort, service->slsDestinationUdpPort) == 0 &&
                g_lls_tables[j].type == TABLE_TYPE_MPD) {
                service_mpd = (MpdData*)g_lls_tables[j].parsed_data;
                break;
            }
        }
        
        // Display ROUTE stream parameters (from MPD)
        if (service_mpd) {
            // Find video and audio info (prefer highest resolution for video, most channels for audio)
            MpdAdaptationSet* as = service_mpd->head_as;
            int found_video = 0, found_audio = 0;
            MpdRepresentation* best_audio_rep = NULL;
            int total_audio_streams = 0;
            
            // First pass: count audio streams and find the best one
            as = service_mpd->head_as;
            while (as) {
                if (mpd_as_is_audio(as)) {
                    total_audio_streams++;
                    MpdRepresentation* rep = as->head_rep;
                    while (rep) {
                        // Most channels, then highest bandwidth: still picks a stream when
                        // no channel count is signaled (common with AC-3 / E-AC-3)
                        if (mpd_audio_rep_better(rep, best_audio_rep)) {
                            best_audio_rep = rep;
                        }
                        rep = rep->next;
                    }
                }
                as = as->next;
            }
            
            // Second pass: display video and best audio
            as = service_mpd->head_as;
            while (as && (!found_video || !found_audio)) {
                if (mpd_as_is_video(as) && !found_video) {
                    // Find the highest resolution representation
                    MpdRepresentation* rep = find_highest_resolution_video(as);
                    if (rep && strlen(rep->width) > 0 && strlen(rep->height) > 0) {
                        fprintf(f, "<div><strong>Video:</strong> %sx%s", rep->width, rep->height);
                        if (strlen(rep->scanType) > 0) {
                            fprintf(f, "%c", (strcmp(rep->scanType, "progressive") == 0) ? 'p' : 'i');
                        }
                        if (strlen(rep->frameRate) > 0) {
                            // Parse fractional frame rates like "60000/1001"
                            if (strchr(rep->frameRate, '/')) {
                                char* slash = strchr(rep->frameRate, '/');
                                int numerator = atoi(rep->frameRate);
                                int denominator = atoi(slash + 1);
                                if (denominator > 0) {
                                    double fps = (double)numerator / denominator;
                                    fprintf(f, " (%.2f fps)", fps);
                                }
                            } else {
                                fprintf(f, " (%s fps)", rep->frameRate);
                            }
                        }
                        if (strlen(rep->codecs) > 0) {
                            fprintf(f, "<br />\n<strong>Codec:</strong> %s", rep->codecs);
                        }
                        fprintf(f, "</div>\n");
                        found_video = 1;
                    }
                } else if (mpd_as_is_audio(as) && !found_audio) {
                    // Use the best audio representation we found
                    if (best_audio_rep) {
                        fprintf(f, "<div><strong>Audio:</strong> ");
                        if (strlen(best_audio_rep->audioChannelCount) > 0) {
                            fprintf(f, "%s ch", best_audio_rep->audioChannelCount);
                        }
                        if (strlen(best_audio_rep->bandwidth) > 0) {
                            if (strlen(best_audio_rep->audioChannelCount) > 0) fprintf(f, " @ ");
                            char formatted_bandwidth[32];
                            format_bandwidth(best_audio_rep->bandwidth, formatted_bandwidth, sizeof(formatted_bandwidth));
                            fprintf(f, "%s", formatted_bandwidth);
                        }
                        
                        // Add green plus sign if there are additional audio streams
                        if (total_audio_streams > 1) {
                            fprintf(f, " <svg width='16' height='16' viewBox='0 0 24 24' fill='none' style='display:inline;vertical-align:middle;margin-left:4px;'><circle cx='12' cy='12' r='10' fill='#4CAF50'/><path d='M12 6v12M6 12h12' stroke='white' stroke-width='2' stroke-linecap='round'/><title>+%d additional audio stream%s</title></svg>", 
                                   total_audio_streams - 1, 
                                   (total_audio_streams - 1) == 1 ? "" : "s");
                        }
                        
                        if (strlen(best_audio_rep->codecs) > 0) {
                            fprintf(f, "<br />\n<strong>Codec:</strong> %s", best_audio_rep->codecs);
                        }
                        fprintf(f, "</div>\n");
                        found_audio = 1;
                    }
                }
                as = as->next;
            }
        } else {
            int mmt_audio_streams = 0;
            display_mmt_stream_parameters(f, service, &mmt_audio_streams);
        }
        
        fprintf(f, "<div><strong>Hidden:</strong> ");
        if (service->hidden || service->hideInGuide) {
            if (service->hidden && service->hideInGuide) {
                fprintf(f, "Service & Guide");
            } else if (service->hidden) {
                fprintf(f, "Service");
            } else {
                fprintf(f, "Guide");
            }
        } else {
            fprintf(f, "No");
        }
        fprintf(f, "<br />\n");
        
        // Check for HELD data for this service
        HeldData* service_held = NULL;
        for (int j = 0; j < g_lls_table_count; j++) {
            if (strcmp(g_lls_tables[j].destinationIp, service->slsDestinationIpAddress) == 0 &&
                strcmp(g_lls_tables[j].destinationPort, service->slsDestinationUdpPort) == 0 &&
                g_lls_tables[j].type == TABLE_TYPE_HELD) {
                service_held = (HeldData*)g_lls_tables[j].parsed_data;
                break;
            }
        }
        
        const char* app_type = determine_app_type(service_held);
        fprintf(f, "<strong>App:</strong> %s</div>\n", app_type);
        
        fprintf(f, "</div></div>\n"); // Close summary section
        
        //fprintf(f, "<div class='service-container'>\n");

        // Print SLT info for this service
        fprintf(f, "<details><summary>Service Details (from SLT)</summary>\n<div class='details-content'>\n");
        const char* category_desc = "Unknown";
        int category_num = atoi(service->serviceCategory);
        switch(category_num) {
            case 1: category_desc = "Linear A/V Service"; break;
            case 2: category_desc = "Linear Audio Only Service"; break;
            case 3: category_desc = "App-Based Service"; break;
            case 4: category_desc = "ESG Service"; break;
            case 5: category_desc = "EAS Service"; break;
            case 6: category_desc = "DRM Data Service"; break;
        }
        const char* protocol_str = strcmp(service->slsProtocol, "1") == 0 ? "ROUTE" : (strcmp(service->slsProtocol, "2") == 0 ? "MMT" : service->slsProtocol);
        fprintf(f, "<ul>\n");
        fprintf(f, "<li><strong>Global Service ID:</strong> %s</li>\n", service->globalServiceID);
        fprintf(f, "<li><strong>Category:</strong> %s (%s)</li>\n", service->serviceCategory, category_desc);
        fprintf(f, "<li><strong>SLS Destination:</strong> %s:%s</li>\n", service->slsDestinationIpAddress, service->slsDestinationUdpPort);
        fprintf(f, "<li><strong>SLS Source:</strong> %s</li>\n", service->slsSourceIpAddress);
        fprintf(f, "<li><strong>SLS Protocol Version:</strong> %s.%s (%s)</li>\n", service->slsMajorProtocolVersion, service->slsMinorProtocolVersion, protocol_str);
        if (service->protected) fprintf(f, "<li><strong>Protected:</strong> Yes</li>\n");
        if (service->broadbandAccessRequired) fprintf(f, "<li><strong>Broadband Required:</strong> Yes</li>\n");
        if (service->hidden) fprintf(f, "<li><strong>Hidden:</strong> Yes</li>\n");
        if (service->hideInGuide) fprintf(f, "<li><strong>Hide in Guide:</strong> Yes</li>\n");
        fprintf(f, "</ul>\n");
        fprintf(f, "</div></details>\n");

        // Print associated tables for this service (MPD, HELD, ESG)
        int found_items_for_service = 0;
        int fdt_count = 0;
        int mpd_count = 0;
        int stsid_count = 0;
        int usd_route_count = 0;
        int usd_mmt_count = 0;
        int service_signaling_count = 0;
        int mp_table_xml_count = 0;
        int held_count = 0;
        int esg_count = 0;
        int dwd_count = 0;
        
        // Pre-count S-TSID entries for collapsible wrapper
        int total_stsid_count = 0;
        for (int precount_j = 0; precount_j < g_lls_table_count; precount_j++) {
            if (g_lls_tables[precount_j].type != TABLE_TYPE_STSID) continue;
            if (strcmp(g_lls_tables[precount_j].destinationIp, service->slsDestinationIpAddress) != 0) continue;
            if (strcmp(g_lls_tables[precount_j].destinationPort, service->slsDestinationUdpPort) != 0) continue;
            total_stsid_count++;
        }
        int stsid_wrapper_opened = 0;
        
        DBG_PRINTF("DEBUG: Checking for ESG fragments for service %s at %s:%s\n", 
            service->serviceId, service->slsDestinationIpAddress, service->slsDestinationUdpPort);
        for (int debug_j = 0; debug_j < g_lls_table_count; debug_j++) {
            if (g_lls_tables[debug_j].type == TABLE_TYPE_ESG_FRAGMENT) {
                DBG_PRINTF("  Found ESG fragment at table index %d: destIp='%s' destPort='%s'\n",
                    debug_j, g_lls_tables[debug_j].destinationIp, g_lls_tables[debug_j].destinationPort);
            }
        }

        // Define the desired display order
        TableType display_order[] = {
            TABLE_TYPE_USER_SERVICE_DESCRIPTION,     // 3. USD ROUTE
            TABLE_TYPE_USBD,                          // 3. USBD
            TABLE_TYPE_USD,                           // 4. USD 
            TABLE_TYPE_STSID,                 // 2. S-TSID (stream descriptions)
            TABLE_TYPE_MP_TABLE_XML,                  // 6. MMT MP Table XML
            TABLE_TYPE_MP_TABLE_BINARY,               // 7. MMT MP Table Binary
            TABLE_TYPE_SERVICE_SIGNALING,             // 5. Service Signaling
            TABLE_TYPE_MPD,                    // 1. MPD (most important for media info)
            TABLE_TYPE_HELD,                          // 8. HELD
            TABLE_TYPE_ESG_FRAGMENT,                  // 9. ESG
            TABLE_TYPE_DWD,                            // 10. DWD
            TABLE_TYPE_EFDT
        };
        int num_types = sizeof(display_order) / sizeof(display_order[0]);

        // Process tables in the specified order
        for (int order_idx = 0; order_idx < num_types; order_idx++) {
            TableType current_type = display_order[order_idx];
            
            // Find all tables of this type for this service
            for (int j = 0; j < g_lls_table_count; j++) {
                if (g_lls_tables[j].type != current_type) continue;
                if (strcmp(g_lls_tables[j].destinationIp, service->slsDestinationIpAddress) != 0) continue;
                if (strcmp(g_lls_tables[j].destinationPort, service->slsDestinationUdpPort) != 0) continue;

                found_items_for_service = 1;

                switch (current_type) {
                    case TABLE_TYPE_FDT: {
                        fdt_count++;
                        FDTInstanceData* fdt_data = (FDTInstanceData*)g_lls_tables[j].parsed_data;
                        fprintf(f, "<details><summary>File Description Table (FDT) Instance %d (Expires: %s)</summary>\n", fdt_count, fdt_data->expires);
                        fprintf(f, "<div class='details-content'><table>\n<thead><tr><th>Content Location</th><th>TOI</th><th>Content Length</th><th>Content Type</th></tr></thead>\n<tbody>\n");
                        FDTFileInfo* file = fdt_data->head;
                        while(file) {
                             fprintf(f, "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>\n", file->contentLocation, file->toi, file->contentLength, file->contentType);
                            file = file->next;
                        }
                        fprintf(f, "</tbody></table><h4>Raw XML</h4><pre>");
                        fprintf_escaped_xml(f, g_lls_tables[j].content_id);
                        fprintf(f, "</pre></div></details>\n");
                        break;
                    }
                    case TABLE_TYPE_MPD: {
                        mpd_count++;
                        MpdData* mpd_data = (MpdData*)g_lls_tables[j].parsed_data;
                        fprintf(f, "<details><summary>Media Presentation Description (MPD) Instance %d (Published: %s)</summary>\n", mpd_count, mpd_data->publishTime);
                        fprintf(f, "<div class='details-content'><div class='mpd-summary'>");
                        fprintf(f, "<strong>Type:</strong> %s<br>\n", mpd_data->type);
                        fprintf(f, "<strong>Min Buffer Time:</strong> %s<br>\n", mpd_data->minBufferTime);
                        fprintf(f, "<strong>Profiles:</strong> %s\n</div>\n", mpd_data->profiles);
                        
                        MpdAdaptationSet* as = mpd_data->head_as;
                        while(as) {
                            fprintf(f, "<h4>Adaptation Set (Content: %s, Mime: %s", as->contentType, as->mimeType);
                            if(strlen(as->lang) > 0) fprintf(f, ", Lang: %s", as->lang);
                            if(strlen(as->par) > 0) fprintf(f, ", PAR: %s", as->par);
                            fprintf(f, ")</h4>\n");
                            
                            // Debug: Let's also check AdaptationSet level attributes
                            /*fprintf(f, "<div style='background-color: #f0f0f0; padding: 5px; margin: 5px 0; font-size: 12px;'>");
                            fprintf(f, "<strong>Debug - AdaptationSet attributes:</strong> ");
                            fprintf(f, "contentType='%s' mimeType='%s' lang='%s' par='%s'", 
                                as->contentType, as->mimeType, as->lang, as->par);
                            fprintf(f, "</div>");*/
                            
                            MpdRepresentation* rep = as->head_rep;
                            while(rep) {
                                fprintf(f, "<h5>Representation ID: %s</h5><ul>\n", rep->id);
                                
                                // Debug: Show all parsed attributes
                                /*fprintf(f, "<li><strong>Debug - All parsed attributes:</strong><br>\n");
                                fprintf(f, "id='%s' codecs='%s' bandwidth='%s'<br>\n", rep->id, rep->codecs, rep->bandwidth);
                                fprintf(f, "width='%s' height='%s' frameRate='%s'<br>\n", rep->width, rep->height, rep->frameRate);
                                fprintf(f, "audioSamplingRate='%s' audioChannelCount='%s'<br>\n", rep->audioSamplingRate, rep->audioChannelCount);
                                fprintf(f, "sar='%s' scanType='%s' displayAspectRatio='%s'</li>\n", rep->sar, rep->scanType, rep->displayAspectRatio);*/
                                
                                fprintf(f, "<li><strong>Bandwidth:</strong> %s", rep->bandwidth);
                                if(strlen(rep->bandwidth) > 0) {
                                    int bw = atoi(rep->bandwidth);
                                    if(bw > 1000000) {
                                        fprintf(f, " (%.1f Mbps)", bw / 1000000.0);
                                    } else if(bw > 1000) {
                                        fprintf(f, " (%.0f kbps)", bw / 1000.0);
                                    }
                                }
                                fprintf(f, "</li>\n");
                                
                                fprintf(f, "<li><strong>Codecs:</strong> %s</li>\n", rep->codecs);
                                
                                if(strlen(rep->width) > 0 && strlen(rep->height) > 0) {
                                    fprintf(f, "<li><strong>Resolution:</strong> %sx%s", rep->width, rep->height);
                                    if(strlen(rep->displayAspectRatio) > 0) {
                                        fprintf(f, " (%s)", rep->displayAspectRatio);
                                    }
                                    fprintf(f, "</li>\n");
                                }
                                
                                if(strlen(rep->frameRate) > 0) {
                                    fprintf(f, "<li><strong>Frame Rate:</strong> %s", rep->frameRate);
                                    // Parse fractional frame rates like "60000/1001"
                                    if(strchr(rep->frameRate, '/')) {
                                        char* slash = strchr(rep->frameRate, '/');
                                        int numerator = atoi(rep->frameRate);
                                        int denominator = atoi(slash + 1);
                                        if(denominator > 0) {
                                            double fps = (double)numerator / denominator;
                                            fprintf(f, " (%.2f fps)", fps);
                                        }
                                    }
                                    fprintf(f, "</li>\n");
                                }
                                
                                if(strlen(rep->scanType) > 0) fprintf(f, "<li><strong>Scan Type:</strong> %s</li>\n", rep->scanType);
                                if(strlen(rep->sar) > 0) fprintf(f, "<li><strong>Sample Aspect Ratio:</strong> %s</li>\n", rep->sar);
                                if(strlen(rep->audioSamplingRate) > 0) fprintf(f, "<li><strong>Audio Sample Rate:</strong> %s Hz</li>\n", rep->audioSamplingRate);
                                if(strlen(rep->audioChannelCount) > 0) fprintf(f, "<li><strong>Audio Channels:</strong> %s</li>\n", rep->audioChannelCount);
                                
                                fprintf(f, "<li><strong>Segment Template:</strong>");
                                if(rep->segmentTemplate.timeline) {
                                    fprintf(f, "<ul class='segment-list'><li><strong>Timescale:</strong> %s</li>\n", rep->segmentTemplate.timescale);
                                    SegmentTimelineS* s = rep->segmentTemplate.timeline;
                                    while(s) {
                                        fprintf(f, "<li><strong>S: t=</strong>%s, <strong>d=</strong>%s, <strong>r=</strong>%s</li>", s->t, s->d, strlen(s->r) > 0 ? s->r : "0");
                                        s = s->next;
                                    }
                                    fprintf(f, "</ul>");

                                } else {
                                    fprintf(f, "<ul class='segment-list'>\n");
                                    fprintf(f, "<li><strong>Initialization:</strong> %s</li>\n", rep->segmentTemplate.initialization);
                                    fprintf(f, "<li><strong>Media URL:</strong> %s</li>\n", rep->segmentTemplate.media);
                                    fprintf(f, "<li><strong>Timescale:</strong> %s, <strong>Duration:</strong> %s, <strong>Start:</strong> %s</li>\n", rep->segmentTemplate.timescale, rep->segmentTemplate.duration, rep->segmentTemplate.startNumber);
                                    fprintf(f, "</ul>");
                                }
                                if (rep->drmInfo) {
                                    fprintf(f, "<li><strong>DRM Protection:</strong><ul style='margin: 5px 0; padding-left: 20px;'>");
                                    DrmInfo* drm = rep->drmInfo;
                                    while (drm) {
                                        fprintf(f, "<li><strong>System:</strong> %s", drm->systemName);
                                        if (strlen(drm->contentId) > 0) {
                                            fprintf(f, " | <strong>Content ID:</strong> %s", drm->contentId);
                                        }
                                        if (strlen(drm->licenseUrl) > 0) {
                                            fprintf(f, "<br><strong>License URL:</strong> <a href='%s' target='_blank'>%s</a>", drm->licenseUrl, drm->licenseUrl);
                                        }
                                        if (strlen(drm->groupLicenseUrl) > 0) {
                                            fprintf(f, "<br><strong>Group License:</strong> %s", drm->groupLicenseUrl);
                                        }
                                        fprintf(f, "</li>");
                                        drm = drm->next;
                                    }
                                    fprintf(f, "</ul></li>");
                                } fprintf(f, "</li></ul>\n");

                                rep = rep->next;
                            }
                            as = as->next;
                        }
                        fprintf(f, "<h4>Raw XML</h4><pre>");
                        fprintf_escaped_xml(f, g_lls_tables[j].content_id);
                        fprintf(f, "</pre></div></details>\n");
                        break;
                    }
                    case TABLE_TYPE_HELD: {
                        held_count++;
                        HeldData* held_data = (HeldData*)g_lls_tables[j].parsed_data;
                        fprintf(f, "<details><summary>HTML Entry-point Description (HELD) Instance %d</summary>\n", held_count);
                        fprintf(f, "<div class='details-content'><ul>\n");
                        if(strlen(held_data->bbandEntryPageUrl) > 0) fprintf(f, "<li><strong>Broadband Entry Page:</strong> <a href='%s' target='_blank'>%s</a></li>\n", held_data->bbandEntryPageUrl, held_data->bbandEntryPageUrl);
                        if(strlen(held_data->clearBbandEntryPageUrl) > 0) fprintf(f, "<li><strong>Clear Broadband Entry Page:</strong> <a href='%s' target='_blank'>%s</a></li>\n", held_data->clearBbandEntryPageUrl, held_data->clearBbandEntryPageUrl);
                        if(strlen(held_data->coupledServices) > 0) fprintf(f, "<li><strong>Coupled Services:</strong> %s</li>\n", held_data->coupledServices);
                        fprintf(f, "</ul><h4>Raw XML</h4><pre>");
                        fprintf_escaped_xml(f, g_lls_tables[j].content_id);
                        fprintf(f, "</pre></div></details>\n");
                        break;
                    }
                    case TABLE_TYPE_ESG_FRAGMENT: {
                        // Only process ESG fragments once per service (on first encounter)
                        if (esg_count > 0) {
                            continue;
                        }
                        
                        // Create LLS table reference array for ESG display function
                        EsgLlsTableRef* esg_refs = malloc(sizeof(EsgLlsTableRef) * g_lls_table_count);
                        if (!esg_refs) {
                            break;
                        }
                        
                        for (int ref_idx = 0; ref_idx < g_lls_table_count; ref_idx++) {
                            esg_refs[ref_idx].type = g_lls_tables[ref_idx].type;
                            esg_refs[ref_idx].parsed_data = g_lls_tables[ref_idx].parsed_data;
                            esg_refs[ref_idx].content_id = g_lls_tables[ref_idx].content_id;
                            strncpy(esg_refs[ref_idx].destinationIp, g_lls_tables[ref_idx].destinationIp, 
                                    sizeof(esg_refs[ref_idx].destinationIp)-1);
                            esg_refs[ref_idx].destinationIp[sizeof(esg_refs[ref_idx].destinationIp)-1] = '\0';
                            strncpy(esg_refs[ref_idx].destinationPort, g_lls_tables[ref_idx].destinationPort,
                                    sizeof(esg_refs[ref_idx].destinationPort)-1);
                            esg_refs[ref_idx].destinationPort[sizeof(esg_refs[ref_idx].destinationPort)-1] = '\0';
                        }
                        
                        // Call the ESG display function from esg.c
                        EsgDisplayResult esg_result = render_esg_to_html(
                            f,
                            service->slsDestinationIpAddress,
                            service->slsDestinationUdpPort,
                            esg_refs,
                            g_lls_table_count,
                            fprintf_escaped_xml  // Pass your existing XML escaping function
                        );
                        
                        free(esg_refs);
                        
                        if (esg_result.success) {
                            esg_count = 1;
                            found_items_for_service = 1;
                        }
                        
                        break;
                    }
                    case TABLE_TYPE_USER_SERVICE_DESCRIPTION: {
                        usd_route_count++;
                        UserServiceDescriptionData* usd_data = (UserServiceDescriptionData*)g_lls_tables[j].parsed_data;
                        fprintf(f, "<details><summary>User Service Description (ROUTE) Instance %d</summary>\n", usd_route_count);
                        fprintf(f, "<div class='details-content'><table>\n<thead><tr><th>Content Type</th><th>Version</th><th>User Agent</th><th>Filter Codes</th></tr></thead>\n<tbody>\n");
                        UsdEntry* entry = usd_data->head;
                        while(entry) {
                             fprintf(f, "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>\n", entry->contentType, entry->version, entry->userAgent, entry->filterCodes);
                            entry = entry->next;
                        }
                        fprintf(f, "</tbody></table><h4>Raw XML</h4><pre>");
                        fprintf_escaped_xml(f, g_lls_tables[j].content_id);
                        fprintf(f, "</pre></div></details>\n");
                        break;
                    }
                    case TABLE_TYPE_USBD: {
                        usd_mmt_count++;
                        UsdbData* usbd_data = (UsdbData*)g_lls_tables[j].parsed_data;
                        fprintf(f, "<details><summary>User Service Bundle Description (USBD) Instance %d</summary>\n", usd_mmt_count);
                        fprintf(f, "<div class='details-content'><table>\n<thead><tr><th>ID</th><th>Content Type</th><th>Version</th></tr></thead>\n<tbody>\n");
                        UsdEntryMmt* entry = usbd_data->head;
                        while(entry) {
                             fprintf(f, "<tr><td>%s</td><td>%s</td><td>%s</td></tr>\n", entry->id, entry->contentType, entry->version);
                            entry = entry->next;
                        }
                        fprintf(f, "</tbody></table><h4>Raw XML</h4><pre>");
                        fprintf_escaped_xml(f, g_lls_tables[j].content_id);
                        fprintf(f, "</pre></div></details>\n");
                        break;
                    }
                    case TABLE_TYPE_USD: {
                        UsdData* usd_data = (UsdData*)g_lls_tables[j].parsed_data;
                        fprintf(f, "<details><summary>User Service Description (USD) - %s</summary>\n", usd_data->serviceName);
                        fprintf(f, "<div class='details-content'>\n");
                        fprintf(f, "<table><tr><th>Field</th><th>Value</th></tr>");
                        fprintf(f, "<tr><td><strong>Service ID</strong></td><td>%s</td></tr>", usd_data->serviceId);
                        if(strlen(usd_data->mmtPackageId) > 0)
                            fprintf(f, "<tr><td><strong>MMT Package ID</strong></td><td>%s</td></tr>", usd_data->mmtPackageId);
                        fprintf(f, "</table>");
                        
                        if(usd_data->components) {
                            fprintf(f, "<h4>Components:</h4><table><tr><th>Component ID</th><th>Type</th><th>Role</th><th>Description</th></tr>");
                            UsdComponent* comp = usd_data->components;
                            while(comp) {
                                fprintf(f, "<tr><td>%s</td><td>%d</td><td>%d</td><td>%s</td></tr>", 
                                    comp->componentId, comp->componentType, comp->componentRole, comp->description);
                                comp = comp->next;
                            }
                            fprintf(f, "</table>");
                        }
                        
                        fprintf(f, "<h4>Raw XML</h4><pre>");
                        fprintf_escaped_xml(f, g_lls_tables[j].content_id);
                        fprintf(f, "</pre></div></details>\n");
                        break;
                    }
                    case TABLE_TYPE_DWD: {
                        dwd_count++;
                        fprintf(f, "<details><summary>Dynamic Window Description (DWD) Instance %d</summary>\n", dwd_count);
                        fprintf(f, "<div class='details-content'><h4>Raw XML</h4><pre>");
                        fprintf_escaped_xml(f, g_lls_tables[j].content_id);
                        fprintf(f, "</pre></div></details>\n");
                        break;
                    }
                    case TABLE_TYPE_EFDT: {
                        fdt_count++;
                        FDTInstanceData* fdt_data = (FDTInstanceData*)g_lls_tables[j].parsed_data;
                        fprintf(f, "<details><summary>Extended File Description Table (EFDT) Instance %d (Expires: %s)</summary>\n", fdt_count, fdt_data->expires);
                        fprintf(f, "<div class='details-content'><table>\n<thead><tr><th>Content Location</th><th>TOI</th><th>Content Length</th><th>Content Type</th></tr></thead>\n<tbody>\n");
                        FDTFileInfo* file = fdt_data->head;
                        while(file) {
                            fprintf(f, "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>\n", file->contentLocation, file->toi, file->contentLength, file->contentType);
                            file = file->next;
                        }
                        fprintf(f, "</tbody></table><h4>Raw XML</h4><pre>");
                        fprintf_escaped_xml(f, g_lls_tables[j].content_id);
                        fprintf(f, "</pre></div></details>\n");
                        break;
                    }
                    case TABLE_TYPE_SERVICE_SIGNALING: {
                        service_signaling_count++;
                        ServiceSignalingData* meta_data = (ServiceSignalingData*)g_lls_tables[j].parsed_data;
                        fprintf(f, "<details><summary>Service Signaling (Metadata Envelope) %d</summary>\n", service_signaling_count);
                        fprintf(f, "<div class='details-content'><table>\n<thead><tr><th>Content Type</th><th>Version</th></tr></thead>\n<tbody>\n");
                        ServiceSignalingFragment* frag = meta_data->head;
                        while(frag) {
                             fprintf(f, "<tr><td>%s</td><td>%s</td></tr>\n", frag->contentType, frag->version);
                            frag = frag->next;
                        }
                        fprintf(f, "</tbody></table><h4>Raw XML</h4><pre>");
                        fprintf_escaped_xml(f, g_lls_tables[j].content_id);
                        fprintf(f, "</pre></div></details>\n");
                        
                        // For MMT streams, display descriptor details after first service signaling instance
                        if (strcmp(service->slsProtocol, "2") == 0 && service_signaling_count == 1) {
                            generate_mmt_descriptor_details(f, service, 1);
                        }
                        
                        break;
                    }
                    case TABLE_TYPE_STSID: {
                        stsid_count++;
                        
                        // Open collapsible wrapper for many S-TSID entries (>10)
                        if (total_stsid_count > 10 && stsid_count == 1 && !stsid_wrapper_opened) {
                            fprintf(f, "<details><summary>S-TSID Entries (%d total - click to expand)</summary>\n", total_stsid_count);
                            fprintf(f, "<div class='details-content stsid-wrapper'>\n");
                            stsid_wrapper_opened = 1;
                        }
                        
                        StsidData* stsid_data = (StsidData*)g_lls_tables[j].parsed_data;
                        
                        // Check if this S-TSID has streaming content (audio/video/captions)
                        // vs true file delivery content (not init/media segments)
                        int has_streaming_content = 0;
                        int has_file_delivery = 0;
                        StsidLogicalStream* check_ls = stsid_data->head_ls;
                        while (check_ls) {
                            if (check_ls->contentType[0] != '\0') {
                                has_streaming_content = 1;
                            }
                            // Check for true file delivery (not streaming init/media segments)
                            // Init segments (.m4i, _init.) and media segments (.m4s) are part of streaming
                            if (check_ls->head_file) {
                                StsidFileEntry* f_check = check_ls->head_file;
                                while (f_check) {
                                    // Skip if it looks like a streaming segment
                                    int is_streaming_segment = 
                                        (strstr(f_check->content_location, ".m4i") != NULL) ||
                                        (strstr(f_check->content_location, ".m4s") != NULL) ||
                                        (strstr(f_check->content_location, "_init.") != NULL) ||
                                        (strstr(f_check->content_location, "init.mp4") != NULL);
                                    
                                    if (!is_streaming_segment && f_check->content_location[0]) {
                                        has_file_delivery = 1;
                                        break;
                                    }
                                    f_check = f_check->next;
                                }
                            }
                            if (has_file_delivery) break;
                            check_ls = check_ls->next;
                        }
                        
                        // Print header with file icon if file delivery present
                        fprintf(f, "<details><summary>S-TSID (Stream Description) Instance %d", stsid_count);
                        if (has_file_delivery) {
                            fprintf(f, " 📁");
                        }
                        fprintf(f, "</summary>\n");
                        
                        // Only show ROUTE Session line if we have at least an IP
                        if (stsid_data->dIpAddr[0]) {
                            fprintf(f, "<div class='details-content'><h4>ROUTE Session: %s", stsid_data->dIpAddr);
                            if (stsid_data->dPort[0]) {
                                fprintf(f, ":%s", stsid_data->dPort);
                            }
                            fprintf(f, "</h4>\n");
                        } else {
                            fprintf(f, "<div class='details-content'>\n");
                        }
                        
                        StsidLogicalStream* ls = stsid_data->head_ls;
                        // For streaming content, show the traditional table format
                        if (has_streaming_content) {
                            fprintf(f, "<table>\n<thead><tr><th>TSI</th><th>Representation ID</th><th>Content Type</th><th>Content Ratings</th></tr></thead>\n<tbody>\n");
                            ls = stsid_data->head_ls;
                            while(ls) {
                                // Only show streams with MediaInfo (streaming content)
                                if (ls->contentType[0] != '\0' || ls->repId[0] != '\0') {
                                    fprintf(f, "<tr><td>%s</td><td>%s</td><td>%s</td><td>", 
                                            ls->tsi, 
                                            ls->repId[0] ? ls->repId : "N/A", 
                                            ls->contentType[0] ? ls->contentType : "N/A");
                                    ContentRatingInfo* rating = ls->head_rating;
                                    if (!rating) {
                                        fprintf(f, "N/A");
                                    } else {
                                        while(rating) {
                                            fprintf_escaped_xml(f, rating->value);
                                            if (rating->next) fprintf(f, "<br>");
                                            rating = rating->next;
                                        }
                                    }
                                    fprintf(f, "</td></tr>\n");
                                }
                                ls = ls->next;
                            }
                            fprintf(f, "</tbody></table>\n");
                        }
                        
                        // For true file delivery content, show file manifests
                        if (has_file_delivery) {
                            ls = stsid_data->head_ls;
                            while(ls) {
                                if (ls->head_file) {
                                    // Count non-streaming files
                                    int real_file_count = 0;
                                    uint64_t total_size = 0;
                                    StsidFileEntry* f_count = ls->head_file;
                                    while (f_count) {
                                        int is_streaming_segment = 
                                            (strstr(f_count->content_location, ".m4i") != NULL) ||
                                            (strstr(f_count->content_location, ".m4s") != NULL) ||
                                            (strstr(f_count->content_location, "_init.") != NULL) ||
                                            (strstr(f_count->content_location, "init.mp4") != NULL);
                                        if (!is_streaming_segment && f_count->content_location[0]) {
                                            real_file_count++;
                                            total_size += f_count->content_length;
                                        }
                                        f_count = f_count->next;
                                    }
                                    
                                    if (real_file_count > 0) {
                                        fprintf(f, "<h5>📁 File Delivery (TSI: %s) - %d file%s</h5>\n", 
                                                ls->tsi, real_file_count, real_file_count == 1 ? "" : "s");
                                        fprintf(f, "<table>\n<thead><tr><th>TOI</th><th>Filename</th><th>Size</th><th>Type</th></tr></thead>\n<tbody>\n");
                                        StsidFileEntry* file = ls->head_file;
                                        while (file) {
                                            // Skip streaming segments
                                            int is_streaming_segment = 
                                                (strstr(file->content_location, ".m4i") != NULL) ||
                                                (strstr(file->content_location, ".m4s") != NULL) ||
                                                (strstr(file->content_location, "_init.") != NULL) ||
                                                (strstr(file->content_location, "init.mp4") != NULL);
                                            
                                            if (!is_streaming_segment && file->content_location[0]) {
                                                // Format size nicely
                                                char size_str[32];
                                                if (file->content_length >= 1073741824) {
                                                    snprintf(size_str, sizeof(size_str), "%.2f GB", file->content_length / 1073741824.0);
                                                } else if (file->content_length >= 1048576) {
                                                    snprintf(size_str, sizeof(size_str), "%.2f MB", file->content_length / 1048576.0);
                                                } else if (file->content_length >= 1024) {
                                                    snprintf(size_str, sizeof(size_str), "%.2f KB", file->content_length / 1024.0);
                                                } else if (file->content_length > 0) {
                                                    snprintf(size_str, sizeof(size_str), "%lu B", (unsigned long)file->content_length);
                                                } else {
                                                    snprintf(size_str, sizeof(size_str), "N/A");
                                                }
                                                
                                                fprintf(f, "<tr><td>%u</td><td>", file->toi);
                                                fprintf_escaped_xml(f, file->content_location);
                                                fprintf(f, "</td><td>%s</td><td>%s</td></tr>\n", 
                                                        size_str, 
                                                        file->content_type[0] ? file->content_type : "N/A");
                                            }
                                            file = file->next;
                                        }
                                        fprintf(f, "</tbody></table>\n");
                                        
                                        // Show total size if we have any
                                        if (total_size > 0) {
                                            char total_str[32];
                                            if (total_size >= 1073741824) {
                                                snprintf(total_str, sizeof(total_str), "%.2f GB", total_size / 1073741824.0);
                                            } else if (total_size >= 1048576) {
                                                snprintf(total_str, sizeof(total_str), "%.2f MB", total_size / 1048576.0);
                                            } else {
                                                snprintf(total_str, sizeof(total_str), "%.2f KB", total_size / 1024.0);
                                            }
                                            fprintf(f, "<p><em>Total: %s</em></p>\n", total_str);
                                        }
                                    }
                                }
                                ls = ls->next;
                            }
                        }
                        
                        fprintf(f, "<details><summary>Raw XML</summary><pre>");
                        fprintf_escaped_xml(f, g_lls_tables[j].content_id);
                        fprintf(f, "</pre></details></div></details>\n");
                        break;
                    }
                    case TABLE_TYPE_MP_TABLE_XML: {
                        mp_table_xml_count++;
                        MpTableData* mpt_data = (MpTableData*)g_lls_tables[j].parsed_data;
                        fprintf(f, "<details><summary>MMT Signaling (MP Table - XML) Instance %d</summary>\n", mp_table_xml_count);
                        fprintf(f, "<div class='details-content'><h4>MMT Package ID: %s</h4><table>\n<thead><tr><th>Asset ID</th><th>Asset Type</th><th>Packet ID</th></tr></thead>\n<tbody>\n", mpt_data->mptPackageId);
                        MptAsset* asset = mpt_data->head_asset;
                        while(asset) {
                            fprintf(f, "<tr><td>%s</td><td>%s</td><td>%s</td></tr>\n", asset->assetId, asset->assetType, asset->packetId);
                            asset = asset->next;
                        }
                        fprintf(f, "</tbody></table><h4>Raw XML</h4><pre>");
                        fprintf_escaped_xml(f, g_lls_tables[j].content_id);
                        fprintf(f, "</pre></div></details>\n");
                        break;
                    }
                    
                    case TABLE_TYPE_MP_TABLE_BINARY: {
                        found_items_for_service = 1;
                        BinaryMptData* binary_mpt = (BinaryMptData*)g_lls_tables[j].parsed_data;
                        fprintf(f, "<details><summary>MMT Signaling (MP Table - Binary)</summary>\n");
                        fprintf(f, "<div class='details-content'><h4>Binary MMT Package Table</h4><table>\n<thead><tr><th>Asset ID</th><th>Asset Type</th><th>Codec</th><th>Packet ID</th></tr></thead>\n<tbody>\n");
                        BinaryMptAsset* asset = binary_mpt->head_asset;
                        while(asset) {
                            fprintf(f, "<tr><td>%s</td><td>%s</td><td>%s</td><td>%u</td></tr>\n", 
                                   asset->assetId, asset->assetType, asset->codec, asset->packetId);
                            asset = asset->next;
                        }
                        fprintf(f, "</tbody></table></div></details>\n");
                        break;
                    }
                    
                    default: break;
                }
            }
            
            // Close the S-TSID wrapper if we just finished processing S-TSID entries
            if (current_type == TABLE_TYPE_STSID && stsid_wrapper_opened) {
                fprintf(f, "</div></details>\n");
                stsid_wrapper_opened = 0;  // Reset so we don't close again
            }
        }
        
        // Look for associated Broadspan (DDA-AS) data from UDSTs
        int udst_instance_count = 0;
        for (int k = 0; k < g_lls_table_count; k++) {
            if (g_lls_tables[k].type == TABLE_TYPE_UDST) {
                UdstData* udst_data = (UdstData*)g_lls_tables[k].parsed_data;
                BroadSpanServiceInfo* bss_info = udst_data->head_service;
                while (bss_info) {
                    RsrvInfo* rsrv = bss_info->head_rsrv;
                    if (rsrv && strcmp(rsrv->srvid, service->serviceId) == 0) {
                        udst_linked_flags[k] = 1; // Mark this UDST as linked
                        found_items_for_service = 1;
                        udst_instance_count++;
                        fprintf(f, "<details><summary>Data Distribution &amp; Ancillary Services (UDST) Instance %d</summary>", udst_instance_count);
                        fprintf(f, "<div class='details-content'>\n");
                        fprintf(f, "<h3>BroadSpan Service: %s</h3>\n", bss_info->name);
                        fprintf(f, "<ul>\n");
                        fprintf(f, "<li><strong>Reservation Name:</strong> %s</li>\n", rsrv->name);
                        fprintf(f, "<li><strong>Service ID in UDST:</strong> %s</li>\n", rsrv->srvid);
                        fprintf(f, "<li><strong>Destination:</strong> %s:%s</li>\n", rsrv->destIP, rsrv->destPort);
                        fprintf(f, "<li><strong>Order ID:</strong> %s</li>\n", rsrv->orderId);
                        fprintf(f, "</ul>\n");
                        fprintf(f, "<h4>Raw XML</h4><pre>");
                        fprintf_escaped_xml(f, g_lls_tables[k].content_id);
                        fprintf(f, "</pre></div></details>\n");
                    }
                    bss_info = bss_info->next;
                }
            }
        }

        // Check for eGPS data associated with this service
        EgpsData* egps = find_egps_data(service->slsDestinationIpAddress, service->slsDestinationUdpPort);
        if (egps && render_egps_html(f, egps)) {
            found_items_for_service = 1;
        }

        // Check for MMT Stream Parameters (VSPD, ASPD, CAD descriptors)
        // This is similar to how we display MPD for ROUTE services
        
        ServiceDescriptors* descriptors = get_service_descriptors();
        int count = get_service_descriptor_count();
        
        ServiceDescriptors* svc_descriptors = NULL;
        for (int desc_idx = 0; desc_idx < count; desc_idx++) {
            if (strcmp(descriptors[desc_idx].destinationIp, service->slsDestinationIpAddress) == 0 &&
                    strcmp(descriptors[desc_idx].destinationPort, service->slsDestinationUdpPort) == 0) {
                svc_descriptors = &descriptors[desc_idx];
                break;
            }
        }
        
        if (svc_descriptors && (svc_descriptors->vspd || svc_descriptors->aspd || svc_descriptors->cad)) {
            found_items_for_service = 1;
            // Use the detailed descriptor function that includes helpful descriptions
            generate_mmt_descriptor_details(f, service, 1);
        }

        if (!found_items_for_service) {
            fprintf(f, "<p class='not-found'>No associated ROUTE/DASH or MMT signaling tables found for this service.</p>\n");
        }

        fprintf(f, "</div>\n");
    }

    // --- Global LLS Tables Section ---
    int header_printed = 0; // Flag to ensure the header is printed only once.

    // A single loop to find and print tables.
    for (int i = 0; i < g_lls_table_count; i++) {
        // This is the outer condition, same as before.
        if (g_lls_tables[i].destinationIp[0] == '\0' && 
            g_lls_tables[i].type != TABLE_TYPE_SLT && 
            g_lls_tables[i].type != TABLE_TYPE_CDT) {
            
            // This variable determines if we will actually print for the current table.
            int should_print_this_table = 0; 
            
            // Check the specific conditions from your switch statement.
            switch(g_lls_tables[i].type) {
                case TABLE_TYPE_UCT:
                    // UCT tables are always printed if they match the outer condition.
                    should_print_this_table = 1;
                    break;
                case TABLE_TYPE_UDST:
                    // UDST tables are only printed if they are not linked.
                    if (udst_linked_flags[i] == 0) {
                        should_print_this_table = 1;
                    }
                    break;
                case TABLE_TYPE_SYSTEM_TIME:
                    should_print_this_table = 1;
                    break;
                case TABLE_TYPE_RRT:
                    should_print_this_table = 1;
                    break;
                case TABLE_TYPE_SIGNATURE:
                    should_print_this_table = 1;
                    break;
                case TABLE_TYPE_UDS:
                    should_print_this_table = 1;
                    break;
                case TABLE_TYPE_AEAT:
                    should_print_this_table = 1;
                    break;
                case TABLE_TYPE_UNHANDLED:
                    should_print_this_table = 1;
                    break;
                default:
                    break;
            }

            // If this is the first table we're going to print, print the header first.
            if (should_print_this_table && !header_printed) {
                fprintf(f, "<h2>Other Global LLS Tables</h2>\n");
                header_printed = 1; // Set the flag so we don't print the header again.
            }

            // Now, if we should print, execute the original printing logic.
            if (should_print_this_table) {
                switch(g_lls_tables[i].type) {
                    case TABLE_TYPE_UCT: {
                        UctData* uct_data = (UctData*)g_lls_tables[i].parsed_data;
                        fprintf(f, "<details><summary>📦 User Content Table (UCT / NDP)</summary><div class='details-content'>\n");
                        NdPackage* package = uct_data->head_package;
                        while(package) {
                            fprintf(f, "<h3>Package: %s (IP: %s:%s)</h3>\n", package->name, package->dstIP, package->dstPort);
                            fprintf(f, "<table>\n<thead><tr><th>Element Name</th><th>TSI</th></tr></thead>\n<tbody>\n");
                            NdElement* element = package->head_element;
                            while (element) { fprintf(f, "<tr><td>%s</td><td>%s</td></tr>\n", element->name, element->tsi); element = element->next; }
                            fprintf(f, "</tbody></table>\n");
                            package = package->next;
                        }
                        fprintf(f, "<details><summary>Raw XML</summary><pre>");
                        fprintf_escaped_xml(f, g_lls_tables[i].content_id);
                        fprintf(f, "</pre></div></details>\n");
                        break;
                    }
                    case TABLE_TYPE_UDST: {
                        // This check is technically redundant now, but it's safe to keep.
                        if (udst_linked_flags[i] == 0) { 
                            UdstData* udst_data = (UdstData*)g_lls_tables[i].parsed_data;
                            fprintf(f, "<details><summary>📡 Unlinked User Defined Service Table (UDST)</summary><div class='details-content'>\n");
                            
                            // Display UDS entries (uses shared UdsData structure)
                            UdsData* uds = udst_data->head_uds;
                            while (uds) {
                                fprintf(f, "<div style='border:1px solid #ddd;margin:10px 0;padding:10px;border-radius:5px;'>\n");
                                fprintf(f, "<h4 style='margin-top:0;'>📡 %s</h4>\n", 
                                        uds->name[0] ? uds->name : "User Defined Stream");
                                fprintf(f, "<table>\n<tbody>\n");
                                if (uds->contextId[0]) {
                                    fprintf(f, "<tr><td><strong>Context ID</strong></td><td>%s</td></tr>\n", uds->contextId);
                                }
                                if (uds->destIP[0]) {
                                    fprintf(f, "<tr><td><strong>Destination</strong></td><td>%s:%s</td></tr>\n", 
                                            uds->destIP, uds->destPort);
                                }
                                if (uds->maxBitrate[0]) {
                                    long bitrate = atol(uds->maxBitrate);
                                    if (bitrate >= 1000000) {
                                        fprintf(f, "<tr><td><strong>Max Bitrate</strong></td><td>%.1f Mbps</td></tr>\n", bitrate / 1000000.0);
                                    } else if (bitrate >= 1000) {
                                        fprintf(f, "<tr><td><strong>Max Bitrate</strong></td><td>%.1f Kbps</td></tr>\n", bitrate / 1000.0);
                                    } else {
                                        fprintf(f, "<tr><td><strong>Max Bitrate</strong></td><td>%s bps</td></tr>\n", uds->maxBitrate);
                                    }
                                }
                                fprintf(f, "</tbody></table>\n");
                                
                                // Show sample payload if collected
                                if (uds->sample_collected && uds->sample_payload_len > 0) {
                                    fprintf(f, "<p><strong>Sample Payload:</strong> ");
                                    // Quick format detection
                                    int is_mpeg_ts = (uds->sample_payload_len >= 1 && uds->sample_payload[0] == 0x47);
                                    if (is_mpeg_ts) {
                                        uint16_t pid = ((uds->sample_payload[1] & 0x1F) << 8) | uds->sample_payload[2];
                                        fprintf(f, "MPEG-TS (PID 0x%04X)", pid);
                                    } else {
                                        fprintf(f, "Binary");
                                    }
                                    fprintf(f, "<br><code style='font-size:10px;'>");
                                    int hex_len = uds->sample_payload_len > 32 ? 32 : uds->sample_payload_len;
                                    for (int j = 0; j < hex_len; j++) {
                                        fprintf(f, "%02X ", uds->sample_payload[j]);
                                    }
                                    if (uds->sample_payload_len > 32) fprintf(f, "...");
                                    fprintf(f, "</code></p>\n");
                                } else {
                                    fprintf(f, "<p><em>No sample payload captured (stream may not be active)</em></p>\n");
                                }
                                
                                fprintf(f, "</div>\n");
                                uds = uds->next;
                            }
                            
                            // Display BroadSpan services (complex format)
                            BroadSpanServiceInfo* bss_info = udst_data->head_service;
                            while(bss_info) {
                                RsrvInfo* rsrv = bss_info->head_rsrv;
                                fprintf(f, "<h3>BroadSpan Service: %s</h3>\n", bss_info->name);
                                if (rsrv) {
                                    fprintf(f, "<ul>\n");
                                    if (rsrv->is_session) {
                                        // Session-based entry
                                        if (rsrv->sessionId[0]) {
                                            fprintf(f, "<li><strong>Session ID:</strong> %s</li>\n", rsrv->sessionId);
                                        }
                                    } else {
                                        // Reservation-based entry
                                        if (rsrv->name[0]) {
                                            fprintf(f, "<li><strong>Reservation Name:</strong> %s</li>\n", rsrv->name);
                                        }
                                        if (rsrv->srvid[0]) {
                                            fprintf(f, "<li><strong>Service ID:</strong> %s</li>\n", rsrv->srvid);
                                        }
                                    }
                                    if (rsrv->destIP[0]) {
                                        fprintf(f, "<li><strong>Destination:</strong> %s:%s</li>\n", rsrv->destIP, rsrv->destPort);
                                    }
                                    if (rsrv->orderId[0]) {
                                        fprintf(f, "<li><strong>Order ID:</strong> %s</li>\n", rsrv->orderId);
                                    }
                                    if (rsrv->fileName[0]) {
                                        fprintf(f, "<li><strong>File Name:</strong> %s</li>\n", rsrv->fileName);
                                    }
                                    if (rsrv->endsAt[0]) {
                                        fprintf(f, "<li><strong>Ends At:</strong> %s</li>\n", rsrv->endsAt);
                                    }
                                    fprintf(f, "</ul>\n");
                                }
                                bss_info = bss_info->next;
                            }
                            fprintf(f, "<details><summary>Raw XML</summary><pre>");
                            fprintf_escaped_xml(f, g_lls_tables[i].content_id);
                            fprintf(f, "</pre></div></details>\n");
                        }
                        break;
                    }
                    case TABLE_TYPE_SYSTEM_TIME: {
                        int found_system_time = 0;
                        for (int i = 0; i < g_lls_table_count; i++) {
                            if (g_lls_tables[i].type == TABLE_TYPE_SYSTEM_TIME) {
                                found_system_time = 1;
                                SystemTimeData* time_data = (SystemTimeData*)g_lls_tables[i].parsed_data;
                                fprintf(f, "<details><summary>🕐 System Time Details");
                                if (g_lls_tables[i].is_in_smt) {
                                    fprintf(f, " <span class='smt-badge' title='This table was delivered in a Signed Multi-Table (SMT)'>🔒 Signed</span>");
                                }
                                fprintf(f, " - Actual Timestamp in L1Detail</summary><div class='details-content'>\n");
                                fprintf(f, "<table>\n<thead><tr><th>Attribute</th><th>Value</th></tr></thead>\n<tbody>\n");
                                if (time_data->currentUtcOffset[0] != '\0') { fprintf(f, "<tr><td>currentUtcOffset</td><td>%s</td></tr>\n", time_data->currentUtcOffset); }
                                if (time_data->ptpPrepend[0] != '\0') { fprintf(f, "<tr><td>ptpPrepend</td><td>%s</td></tr>\n", time_data->ptpPrepend); }
                                if (time_data->leap59[0] != '\0') { fprintf(f, "<tr><td>leap59</td><td>%s</td></tr>\n", time_data->leap59); }
                                if (time_data->leap61[0] != '\0') { fprintf(f, "<tr><td>leap61</td><td>%s</td></tr>\n", time_data->leap61); }
                                if (time_data->utcLocalOffset[0] != '\0') { fprintf(f, "<tr><td>utcLocalOffset</td><td>%s</td></tr>\n", time_data->utcLocalOffset); }
                                if (time_data->dsStatus[0] != '\0') { fprintf(f, "<tr><td>dsStatus</td><td>%s</td></tr>\n", time_data->dsStatus); }
                                if (time_data->dsDayOfMonth[0] != '\0') { fprintf(f, "<tr><td>dsDayOfMonth</td><td>%s</td></tr>\n", time_data->dsDayOfMonth); }
                                if (time_data->dsHour[0] != '\0') { fprintf(f, "<tr><td>dsHour</td><td>%s</td></tr>\n", time_data->dsHour); }
                                fprintf(f, "</tbody></table>\n");
                                fprintf(f, "<details><summary>Raw XML</summary><pre>");
                                fprintf_escaped_xml(f, g_lls_tables[i].content_id);
                                fprintf(f, "</pre></details></div></details>\n");
                                break; // Only show first System Time
                            }
                        }
                        if (!found_system_time) {
                            fprintf(f, "<details><summary>System Time Details - Not Found</summary>\n");
                            fprintf(f, "<div class='details-content'><p class='not-found'>No System Time tables found in this capture.</p></div></details>\n");
                        }
                        break;
                    }
                    case TABLE_TYPE_RRT: {
                        RrtData* rrt = (RrtData*)g_lls_tables[i].parsed_data;
                        if (rrt) {
                            fprintf(f, "<details><summary>🔞 Rating Region Table (RRT)");
                            if (g_lls_tables[i].is_in_smt) {
                                fprintf(f, " <span class='smt-badge' title='This table was delivered in a Signed Multi-Table (SMT)'>🔒 Signed</span>");
                            }
                            fprintf(f, "</summary>\n");
                            fprintf(f, "<div class='details-content'>\n");
                            
                            if (rrt->num_regions == 0) {
                                fprintf(f, "<p class='not-found'>No rating regions found in RRT.</p>\n");
                            } else {
                                RrtRegion* region = rrt->regions;
                                while (region) {
                                    // Get region name - use ID-based lookup if name not provided
                                    const char* region_display_name = region->region_name;
                                    char region_name_buf[64];
                                    if (region_display_name[0] == '\0') {
                                        switch (region->region_id) {
                                            case 1: region_display_name = "United States"; break;
                                            case 2: region_display_name = "Canada"; break;
                                            default:
                                                snprintf(region_name_buf, sizeof(region_name_buf), "Region %d", region->region_id);
                                                region_display_name = region_name_buf;
                                        }
                                    }
                                    
                                    fprintf(f, "<h4>📺 %s (Region ID: %d)</h4>\n", region_display_name, region->region_id);
                                    
                                    if (region->num_dimensions == 0) {
                                        fprintf(f, "<p>No rating dimensions defined.</p>\n");
                                    } else {
                                        RrtDimension* dim = region->dimensions;
                                        while (dim) {
                                            fprintf(f, "<div style='margin: 10px 0; padding: 10px; background: #f8f9fa; border-radius: 5px;'>\n");
                                            fprintf(f, "<strong>%s</strong>", dim->dimension_name);
                                            if (dim->graduated_scale) {
                                                fprintf(f, " <em>(graduated scale)</em>");
                                            }
                                            fprintf(f, "<br>\n");
                                            
                                            if (dim->num_values > 0) {
                                                fprintf(f, "<span style='color: #666;'>Values: </span>");
                                                RrtRatingValue* val = dim->values;
                                                int first = 1;
                                                while (val) {
                                                    if (!first) fprintf(f, ", ");
                                                    first = 0;
                                                    
                                                    if (val->abbrev_name[0] != '\0') {
                                                        fprintf(f, "<strong>%s</strong>", val->abbrev_name);
                                                        if (val->full_name[0] != '\0' && strcmp(val->abbrev_name, val->full_name) != 0) {
                                                            fprintf(f, " (%s)", val->full_name);
                                                        }
                                                    } else if (val->full_name[0] != '\0') {
                                                        fprintf(f, "%s", val->full_name);
                                                    }
                                                    val = val->next;
                                                }
                                                fprintf(f, "\n");
                                            }
                                            fprintf(f, "</div>\n");
                                            dim = dim->next;
                                        }
                                    }
                                    region = region->next;
                                }
                            }
                            
                            fprintf(f, "<details><summary>Raw XML</summary><pre>");
                            fprintf_escaped_xml(f, g_lls_tables[i].content_id);
                            fprintf(f, "</pre></details>\n");
                            fprintf(f, "</div></details>\n");
                        }
                        break;
                    }
                    case TABLE_TYPE_SIGNATURE: {
                        SignatureData* sig = (SignatureData*)g_lls_tables[i].parsed_data;
                        if (sig) {
                            fprintf(f, "<details><summary>🔐 SMT Signature Block</summary>\n");
                            fprintf(f, "<div class='details-content signature-info'>\n");
                            fprintf(f, "<table>\n<thead><tr><th>Attribute</th><th>Value</th></tr></thead>\n<tbody>\n");
                            fprintf(f, "<tr><td>Signature Length</td><td>%d bytes</td></tr>\n", sig->signature_len);
                            fprintf(f, "<tr><td>Algorithm</td><td>%s</td></tr>\n", sig->algorithm_name);
                            fprintf(f, "<tr><td>Tables Covered</td><td>%d</td></tr>\n", sig->tables_covered);
                            fprintf(f, "<tr><td>Valid CMS Structure</td><td>%s</td></tr>\n", sig->is_cms_valid ? "Yes" : "Unknown");
                            fprintf(f, "</tbody></table>\n");
                            fprintf(f, "<details><summary>Raw XML</summary><pre>");
                            fprintf_escaped_xml(f, g_lls_tables[i].content_id);
                            fprintf(f, "</pre></details>\n");
                            fprintf(f, "</div></details>\n");
                        }
                        break;
                    }
                    case TABLE_TYPE_UDS: {
                        UdsData* uds = (UdsData*)g_lls_tables[i].parsed_data;
                        if (uds) {
                            fprintf(f, "<details><summary>📡 User Defined Stream (UDS)");
                            if (uds->name[0]) {
                                fprintf(f, ": %s", uds->name);
                            }
                            fprintf(f, "</summary>\n");
                            fprintf(f, "<div class='details-content'>\n");
                            fprintf(f, "<table>\n<thead><tr><th>Attribute</th><th>Value</th></tr></thead>\n<tbody>\n");
                            if (uds->contextId[0]) {
                                fprintf(f, "<tr><td>Context ID</td><td>%s</td></tr>\n", uds->contextId);
                            }
                            if (uds->destIP[0]) {
                                fprintf(f, "<tr><td>Destination</td><td>%s:%s</td></tr>\n", uds->destIP, uds->destPort);
                            }
                            if (uds->maxBitrate[0]) {
                                // Format bitrate nicely
                                long bitrate = atol(uds->maxBitrate);
                                if (bitrate >= 1000000) {
                                    fprintf(f, "<tr><td>Max Bitrate</td><td>%.1f Mbps</td></tr>\n", bitrate / 1000000.0);
                                } else if (bitrate >= 1000) {
                                    fprintf(f, "<tr><td>Max Bitrate</td><td>%.1f Kbps</td></tr>\n", bitrate / 1000.0);
                                } else {
                                    fprintf(f, "<tr><td>Max Bitrate</td><td>%s bps</td></tr>\n", uds->maxBitrate);
                                }
                            }
                            fprintf(f, "</tbody></table>\n");
                            
                            // Show sample payload if collected with analysis
                            if (uds->sample_collected && uds->sample_payload_len > 0) {
                                fprintf(f, "<h4>Sample Payload Analysis</h4>\n");
                                fprintf(f, "<p style='font-family:monospace;font-size:11px;'>");
                                
                                // Try to identify payload type
                                int is_gzip = (uds->sample_payload_len >= 2 && 
                                              uds->sample_payload[0] == 0x1f && uds->sample_payload[1] == 0x8b);
                                int is_xml = (uds->sample_payload_len >= 5 && 
                                             memcmp(uds->sample_payload, "<?xml", 5) == 0);
                                int is_mpeg_ts = (uds->sample_payload_len >= 1 && uds->sample_payload[0] == 0x47);
                                
                                if (is_gzip) {
                                    fprintf(f, "<strong>GZIP compressed data</strong><br>");
                                    int decomp_size = 0;
                                    int consumed = 0;
                                    char* decomp = decompress_gzip(uds->sample_payload, uds->sample_payload_len, &decomp_size, &consumed);
                                    if (decomp && decomp_size > 0) {
                                        if (decomp_size >= 5 && memcmp(decomp, "<?xml", 5) == 0) {
                                            fprintf(f, "Contains XML data<br>");
                                        }
                                        int preview_len = decomp_size > 80 ? 80 : decomp_size;
                                        fprintf(f, "Decompressed: <code>");
                                        for (int j = 0; j < preview_len; j++) {
                                            char c = decomp[j];
                                            if (c == '<') fprintf(f, "&lt;");
                                            else if (c == '>') fprintf(f, "&gt;");
                                            else if (c == '&') fprintf(f, "&amp;");
                                            else if (c >= 0x20 || c == '\n') fputc(c, f);
                                            else fprintf(f, ".");
                                        }
                                        if (decomp_size > 80) fprintf(f, "...");
                                        fprintf(f, "</code>");
                                        free(decomp);
                                    }
                                } else if (is_xml) {
                                    fprintf(f, "<strong>XML data</strong><br><code>");
                                    int preview_len = uds->sample_payload_len > 100 ? 100 : uds->sample_payload_len;
                                    for (int j = 0; j < preview_len; j++) {
                                        char c = uds->sample_payload[j];
                                        if (c == '<') fprintf(f, "&lt;");
                                        else if (c == '>') fprintf(f, "&gt;");
                                        else if (c == '&') fprintf(f, "&amp;");
                                        else if (c >= 0x20 || c == '\n') fputc(c, f);
                                    }
                                    if (uds->sample_payload_len > 100) fprintf(f, "...");
                                    fprintf(f, "</code>");
                                } else if (is_mpeg_ts) {
                                    uint16_t pid = ((uds->sample_payload[1] & 0x1F) << 8) | uds->sample_payload[2];
                                    fprintf(f, "<strong>MPEG-TS</strong> (PID 0x%04X", pid);
                                    if (pid == 0x1FFF) fprintf(f, " - Null/Stuffing");
                                    fprintf(f, ")<br>");
                                    fprintf(f, "Hex: ");
                                    int hex_len = uds->sample_payload_len > 32 ? 32 : uds->sample_payload_len;
                                    for (int j = 0; j < hex_len; j++) {
                                        fprintf(f, "%02X ", uds->sample_payload[j]);
                                    }
                                    if (uds->sample_payload_len > 32) fprintf(f, "...");
                                } else {
                                    // Check for RTP
                                    if (uds->sample_payload_len >= 12) {
                                        uint8_t rtp_version = (uds->sample_payload[0] >> 6) & 0x03;
                                        uint8_t rtp_pt = uds->sample_payload[1] & 0x7F;
                                        if (rtp_version == 2) {
                                            fprintf(f, "<em>Possible RTP:</em> Payload Type=%d", rtp_pt);
                                            if (rtp_pt == 33) fprintf(f, " (MP2T/MPEG-TS)");
                                            fprintf(f, "<br>");
                                        }
                                    }
                                    fprintf(f, "Hex: ");
                                    int hex_len = uds->sample_payload_len > 48 ? 48 : uds->sample_payload_len;
                                    for (int j = 0; j < hex_len; j++) {
                                        fprintf(f, "%02X ", uds->sample_payload[j]);
                                    }
                                    if (uds->sample_payload_len > 48) fprintf(f, "...");
                                }
                                fprintf(f, "</p>\n");
                            } else {
                                fprintf(f, "<p><em>No sample payload captured (stream may not be active)</em></p>\n");
                            }
                            
                            // Raw XML
                            fprintf(f, "<details><summary>Raw XML</summary><pre>");
                            fprintf_escaped_xml(f, g_lls_tables[i].content_id);
                            fprintf(f, "</pre></details>\n");
                            
                            fprintf(f, "</div></details>\n");
                        }
                        break;
                    }
                    case TABLE_TYPE_AEAT: {
                        AeatData* aeat = (AeatData*)g_lls_tables[i].parsed_data;
                        if (aeat) {
                            fprintf(f, "<details><summary>🚨 Advanced Emergency Alert Table (AEAT) - %d alert%s</summary>\n", 
                                    aeat->aea_count, aeat->aea_count != 1 ? "s" : "");
                            fprintf(f, "<div class='details-content'>\n");
                            
                            AeaEntry* aea = aeat->head_aea;
                            int alert_num = 0;
                            while (aea) {
                                alert_num++;
                                // Color code by priority
                                const char* priority_color = "#666";
                                const char* priority_bg = "#f8f9fa";
                                if (aea->priority[0]) {
                                    int p = atoi(aea->priority);
                                    if (p == 1) { priority_color = "#fff"; priority_bg = "#dc3545"; }  // Red - Extreme
                                    else if (p == 2) { priority_color = "#000"; priority_bg = "#fd7e14"; }  // Orange - Severe
                                    else if (p == 3) { priority_color = "#000"; priority_bg = "#ffc107"; }  // Yellow - Moderate
                                    else if (p == 4) { priority_color = "#000"; priority_bg = "#17a2b8"; }  // Blue - Minor
                                }
                                
                                fprintf(f, "<div style='border:1px solid #ddd;margin:10px 0;padding:10px;border-radius:5px;'>\n");
                                fprintf(f, "<h4 style='margin-top:0;background:%s;color:%s;padding:8px;border-radius:3px;'>", 
                                        priority_bg, priority_color);
                                if (aea->eventDesc[0]) {
                                    fprintf(f, "%s", aea->eventDesc);
                                } else {
                                    fprintf(f, "Alert #%d", alert_num);
                                }
                                if (aea->eventCode[0]) {
                                    fprintf(f, " <span style='font-weight:normal;'>(%s)</span>", aea->eventCode);
                                }
                                fprintf(f, "</h4>\n");
                                
                                fprintf(f, "<table>\n<tbody>\n");
                                if (aea->issuer[0]) {
                                    fprintf(f, "<tr><td><strong>Issuer</strong></td><td>%s</td></tr>\n", aea->issuer);
                                }
                                if (aea->category[0]) {
                                    fprintf(f, "<tr><td><strong>Category</strong></td><td>%s</td></tr>\n", aea->category);
                                }
                                if (aea->audience[0]) {
                                    fprintf(f, "<tr><td><strong>Audience</strong></td><td>%s</td></tr>\n", aea->audience);
                                }
                                if (aea->priority[0]) {
                                    const char* priority_desc = "";
                                    int p = atoi(aea->priority);
                                    if (p == 1) priority_desc = " (Extreme)";
                                    else if (p == 2) priority_desc = " (Severe)";
                                    else if (p == 3) priority_desc = " (Moderate)";
                                    else if (p == 4) priority_desc = " (Minor)";
                                    else if (p == 5) priority_desc = " (Unknown)";
                                    fprintf(f, "<tr><td><strong>Priority</strong></td><td>%s%s</td></tr>\n", aea->priority, priority_desc);
                                }
                                if (aea->wakeup[0]) {
                                    fprintf(f, "<tr><td><strong>Wakeup</strong></td><td>%s%s</td></tr>\n", 
                                            aea->wakeup, 
                                            strcmp(aea->wakeup, "true") == 0 ? " ⏰ (device should wake)" : "");
                                }
                                if (aea->effective[0]) {
                                    fprintf(f, "<tr><td><strong>Effective</strong></td><td>%s</td></tr>\n", aea->effective);
                                }
                                if (aea->expires[0]) {
                                    fprintf(f, "<tr><td><strong>Expires</strong></td><td>%s</td></tr>\n", aea->expires);
                                }
                                if (aea->eventCode[0]) {
                                    fprintf(f, "<tr><td><strong>Event Code</strong></td><td>%s", aea->eventCode);
                                    if (aea->eventCodeType[0]) {
                                        fprintf(f, " (%s)", aea->eventCodeType);
                                    }
                                    fprintf(f, "</td></tr>\n");
                                }
                                if (aea->location[0]) {
                                    fprintf(f, "<tr><td><strong>Location</strong></td><td>%s", aea->location);
                                    if (aea->locationType[0]) {
                                        fprintf(f, " (%s)", aea->locationType);
                                    }
                                    fprintf(f, "</td></tr>\n");
                                }
                                fprintf(f, "</tbody></table>\n");
                                
                                // Alert text
                                if (aea->aeaText[0]) {
                                    fprintf(f, "<div style='background:#f8f9fa;padding:10px;margin:10px 0;border-left:4px solid %s;'>", priority_bg);
                                    fprintf(f, "<strong>Alert Message:</strong><br>%s</div>\n", aea->aeaText);
                                }
                                
                                // Media attachments
                                if (aea->head_media) {
                                    fprintf(f, "<h5>Media Attachments</h5>\n");
                                    fprintf(f, "<table>\n<thead><tr><th>Type</th><th>Description</th><th>File</th><th>Size</th></tr></thead>\n<tbody>\n");
                                    AeatMedia* media = aea->head_media;
                                    while (media) {
                                        fprintf(f, "<tr><td>%s</td><td>%s</td><td><code>%s</code></td><td>", 
                                                media->contentType[0] ? media->contentType : "—",
                                                media->mediaDesc[0] ? media->mediaDesc : "—",
                                                media->url[0] ? media->url : "—");
                                        if (media->contentLength[0]) {
                                            long len = atol(media->contentLength);
                                            if (len >= 1048576) {
                                                fprintf(f, "%.1f MB", len / 1048576.0);
                                            } else if (len >= 1024) {
                                                fprintf(f, "%.1f KB", len / 1024.0);
                                            } else {
                                                fprintf(f, "%s bytes", media->contentLength);
                                            }
                                        } else {
                                            fprintf(f, "—");
                                        }
                                        fprintf(f, "</td></tr>\n");
                                        media = media->next;
                                    }
                                    fprintf(f, "</tbody></table>\n");
                                }
                                
                                // Technical details (collapsed)
                                fprintf(f, "<details><summary>Technical Details</summary>\n");
                                fprintf(f, "<table>\n<tbody>\n");
                                if (aea->aeaId[0]) {
                                    fprintf(f, "<tr><td>AEA ID</td><td><code>%s</code></td></tr>\n", aea->aeaId);
                                }
                                if (aea->aeaType[0]) {
                                    fprintf(f, "<tr><td>Type</td><td>%s</td></tr>\n", aea->aeaType);
                                }
                                if (aea->audience[0]) {
                                    fprintf(f, "<tr><td>Audience</td><td>%s</td></tr>\n", aea->audience);
                                }
                                fprintf(f, "</tbody></table>\n</details>\n");
                                
                                fprintf(f, "</div>\n");
                                aea = aea->next;
                            }
                            
                            // Raw XML
                            fprintf(f, "<details><summary>Raw XML</summary><pre>");
                            fprintf_escaped_xml(f, g_lls_tables[i].content_id);
                            fprintf(f, "</pre></details>\n");
                            
                            fprintf(f, "</div></details>\n");
                        }
                        break;
                    }
                    case TABLE_TYPE_UNHANDLED: {
                        UnhandledTableData* unhandled = (UnhandledTableData*)g_lls_tables[i].parsed_data;
                        if (unhandled) {
                            fprintf(f, "<details><summary>❓ Unhandled Table: &lt;%s&gt;", unhandled->root_element);
                            if (g_lls_tables[i].is_in_smt) {
                                fprintf(f, " <span class='smt-badge' title='This table was delivered in a Signed Multi-Table (SMT)'>🔒 Signed</span>");
                            }
                            fprintf(f, "</summary>\n");
                            fprintf(f, "<div class='details-content'>\n");
                            fprintf(f, "<p style='color: #856404; background: #fff3cd; padding: 10px; border-radius: 5px;'>"
                                       "This table type is recognized but not fully parsed by RENDER.</p>\n");
                            fprintf(f, "<table>\n<thead><tr><th>Attribute</th><th>Value</th></tr></thead>\n<tbody>\n");
                            fprintf(f, "<tr><td>Root Element</td><td><code>&lt;%s&gt;</code></td></tr>\n", unhandled->root_element);
                            if (unhandled->namespace_uri[0] != '\0') {
                                fprintf(f, "<tr><td>Namespace</td><td><code>%s</code></td></tr>\n", unhandled->namespace_uri);
                            }
                            fprintf(f, "</tbody></table>\n");
                            fprintf(f, "<details><summary>Raw XML</summary><pre>");
                            fprintf_escaped_xml(f, g_lls_tables[i].content_id);
                            fprintf(f, "</pre></details>\n");
                            fprintf(f, "</div></details>\n");
                        }
                        break;
                    }
                    default: break;
                }
            }
        }
        
    }
    
    // --- Unknown Services Section ---
    // Check if there are any unknown services first (excluding junk and BPS)
    int has_unknown_services = 0;
    for (int i = 0; i < g_data_usage_count; i++) {
        if (is_junk_entry(&g_data_usage[i])) continue;
        const char* svc_name = get_service_name_for_destination(g_data_usage[i].destinationIp, g_data_usage[i].destinationPort);
        if (!svc_name && !g_data_usage[i].is_lls && !g_data_usage[i].is_signaling && 
            strcmp(g_data_usage[i].stream_type, "Stuffing") != 0 &&
            strcmp(g_data_usage[i].stream_type, "BPS Packet(s)") != 0) {
            has_unknown_services = 1;
            break;
        }
    }
    if (has_unknown_services) {
        fprintf(f, "<h2>Unknown Services</h2>\n");
        fprintf(f, "<p>The following streams were detected but could not be associated with any service in the SLT or LLS.</p>\n");
        generate_unknown_service_analysis(f);
    }
    
    // --- Input Info Section ---
    fprintf(f, "<h2>Input Info</h2>\n");
    fprintf(f, "<table>\n<thead><tr><th>Attribute</th><th>Value</th></tr></thead>\n<tbody>\n");
    
    // Input type
    fprintf(f, "<tr><td><strong>Input Type</strong></td><td>%s</td></tr>\n", get_input_type_string(g_original_input_type));
    
    // File name
    fprintf(f, "<tr><td><strong>File Name</strong></td><td>%s</td></tr>\n", g_input_filename);
    
    // Total packets processed
    fprintf(f, "<tr><td><strong>Total Packets Processed</strong></td><td>%d</td></tr>\n", g_packet_count);
    
    // Capture start and duration, from the capture file's packet timestamps.
    // STLTP: the span of the STLTP stream's outer packets. PCAP / ALP-PCAP: first to last packet.
    {
        int have_span = 0;
        double start_s = 0.0, duration_seconds = 0.0;
        if (g_timing_estimated) {
            duration_seconds = g_user_duration_s;      // start time unknown: start_s stays 0
            have_span = 1;
        } else if (g_original_input_type == INPUT_TYPE_DEBUG) {
            fprintf(f, "<tr><td><strong>Capture Duration</strong></td><td>Unknown</td></tr>\n");
        } else
#ifdef STLTP_HAS_ROBUST_READER
        if (g_original_input_type == INPUT_TYPE_STLTP) {
            if (g_stltp_stats && g_stltp_stats->capture_timing_valid) {
                start_s = g_stltp_stats->capture_start_us / 1e6;
                duration_seconds = (g_stltp_stats->capture_end_us - g_stltp_stats->capture_start_us) / 1e6;
                have_span = 1;
            } else {
                fprintf(f, "<tr><td><strong>Capture Duration</strong></td><td>Unknown</td></tr>\n");
            }
        } else
#endif
        if ((g_input_type == INPUT_TYPE_PCAP || g_input_type == INPUT_TYPE_ALP_PCAP) &&
            g_pcap_timing_valid && g_packet_count > 1) {
            start_s = g_first_packet_time.tv_sec + g_first_packet_time.tv_usec / 1e6;
            duration_seconds = (double)(g_last_packet_time.tv_sec - g_first_packet_time.tv_sec) +
                               (double)(g_last_packet_time.tv_usec - g_first_packet_time.tv_usec) / 1000000.0;
            have_span = 1;
        }

        if (have_span) {
            char start_str[64] = "";
            time_t start_t = (time_t)start_s;
            struct tm *start_tm = localtime(&start_t);
            if (start_tm && start_t > 0) {
                strftime(start_str, sizeof(start_str), "%Y-%m-%d %H:%M:%S %Z", start_tm);
                fprintf(f, "<tr><td><strong>Capture Start</strong></td><td>%s</td></tr>\n", start_str);
            }
            const char* dur_note = g_timing_estimated ? " (given with -t)" : "";
            if (duration_seconds >= 3600.0) {
                int hours = (int)(duration_seconds / 3600);
                int minutes = (int)((duration_seconds - hours * 3600) / 60);
                double secs = duration_seconds - hours * 3600 - minutes * 60;
                fprintf(f, "<tr><td><strong>Capture Duration</strong></td><td>%d h %d min %.1f s%s</td></tr>\n",
                        hours, minutes, secs, dur_note);
            } else if (duration_seconds >= 60.0) {
                int minutes = (int)(duration_seconds / 60);
                double remaining_seconds = duration_seconds - (minutes * 60);
                fprintf(f, "<tr><td><strong>Capture Duration</strong></td><td>%d minutes, %.1f seconds%s</td></tr>\n",
                        minutes, remaining_seconds, dur_note);
            } else {
                fprintf(f, "<tr><td><strong>Capture Duration</strong></td><td>%.1f seconds%s</td></tr>\n",
                        duration_seconds, dur_note);
            }
        }
    }
    
    // File modification time
    struct stat file_stat;
    if (stat(g_input_filename, &file_stat) == 0) {
        char mod_time_str[64];
        struct tm *mod_tm = localtime(&file_stat.st_mtime);
        strftime(mod_time_str, sizeof(mod_time_str), "%Y-%m-%d %H:%M:%S %Z", mod_tm);
        fprintf(f, "<tr><td><strong>File Last Modified</strong></td><td>%s</td></tr>\n", mod_time_str);
    } else {
        fprintf(f, "<tr><td><strong>File Last Modified</strong></td><td>Unable to determine</td></tr>\n");
    }
    
    // Current time (when analysis was run)
    time_t current_time = time(NULL);
    char current_time_str[64];
    struct tm *current_tm = localtime(&current_time);
    strftime(current_time_str, sizeof(current_time_str), "%Y-%m-%d %H:%M:%S %Z", current_tm);
    fprintf(f, "<tr><td><strong>Analysis Run Time</strong></td><td>%s</td></tr>\n", current_time_str);
    
    fprintf(f, "</tbody></table>\n");
    
    // STLTP Processing Statistics (only shown when input was STLTP)
    if (g_stltp_stats && g_original_input_type == INPUT_TYPE_STLTP) {
        fprintf(f, "\n<details class=\"stltp-stats\">\n");
        fprintf(f, "<summary><strong>STLTP Processing Statistics</strong></summary>\n");
        fprintf(f, "<table>\n<thead><tr><th>Metric</th><th>Value</th></tr></thead>\n<tbody>\n");
        
        // Core processing metrics
        fprintf(f, "<tr><td>Outer RTP Packets</td><td>%u</td></tr>\n", g_stltp_stats->outer_packets);
        fprintf(f, "<tr><td>Baseband Packets (BBPs)</td><td>%u</td></tr>\n", g_stltp_stats->bbp_count);
        fprintf(f, "<tr><td>Preamble Packets</td><td>%u</td></tr>\n", g_stltp_stats->preamble_packet_count);
        fprintf(f, "<tr><td>T&amp;M Packets</td><td>%u</td></tr>\n", g_stltp_stats->timing_packet_count);
        
#ifdef STLTP_HAS_ROBUST_READER
        // Capture file and stream selection
        fprintf(f, "<tr><td colspan=\"2\" style=\"background-color:#f5f5f5;\"><strong>Capture</strong></td></tr>\n");
        fprintf(f, "<tr><td style=\"padding-left:20px;\">File Format</td><td>");
        fprintf_escaped_xml(f, g_stltp_stats->capture_format[0] ? g_stltp_stats->capture_format : "unknown");
        fprintf(f, "</td></tr>\n");
        fprintf(f, "<tr><td style=\"padding-left:20px;\">Link Type</td><td>%s (%u)</td></tr>\n",
                stltp_link_type_name(g_stltp_stats->link_type), g_stltp_stats->link_type);
        fprintf(f, "<tr><td style=\"padding-left:20px;\">STLTP Stream</td><td>");
        fprintf_escaped_xml(f, g_stltp_stats->stream_desc[0] ? g_stltp_stats->stream_desc : "none found");
        fprintf(f, "</td></tr>\n");
        if (g_stltp_stats->ignored_stream_packets > 0) {
            // Informational: other RTP traffic, a second feed, or tunnel packets before the first usable one
            fprintf(f, "<tr><td style=\"padding-left:20px;\">Other-Stream Packets Ignored</td><td>%u</td></tr>\n",
                    g_stltp_stats->ignored_stream_packets);
        }
#endif
        
        // ALP packet breakdown
        fprintf(f, "<tr><td colspan=\"2\" style=\"background-color:#f5f5f5;\"><strong>ALP Packets: %u total</strong></td></tr>\n", 
                g_stltp_stats->alp_packet_count);
        fprintf(f, "<tr><td style=\"padding-left:20px;\">Type 0 (IPv4)</td><td>%u</td></tr>\n", 
                g_stltp_stats->alp_type_counts[0]);
        if (g_stltp_stats->alp_type_counts[2] > 0) {
            fprintf(f, "<tr><td style=\"padding-left:20px;\">Type 2 (Compressed IPv4)</td><td>%u</td></tr>\n", 
                    g_stltp_stats->alp_type_counts[2]);
        }
        fprintf(f, "<tr><td style=\"padding-left:20px;\">Type 4 (Signaling)</td><td>%u</td></tr>\n", 
                g_stltp_stats->alp_type_counts[4]);
        if (g_stltp_stats->alp_type_counts[6] > 0) {
            fprintf(f, "<tr><td style=\"padding-left:20px;\">Type 6 (Extension)</td><td>%u</td></tr>\n", 
                    g_stltp_stats->alp_type_counts[6]);
        }
        if (g_stltp_stats->alp_type_counts[7] > 0) {
            fprintf(f, "<tr><td style=\"padding-left:20px;\">Type 7 (MPEG-TS)</td><td>%u</td></tr>\n", 
                    g_stltp_stats->alp_type_counts[7]);
        }
        
        // Spanning packet stats
        fprintf(f, "<tr><td colspan=\"2\" style=\"background-color:#f5f5f5;\"><strong>Spanning Packets</strong></td></tr>\n");
        fprintf(f, "<tr><td style=\"padding-left:20px;\">Started</td><td>%u</td></tr>\n", 
                g_stltp_stats->spanning_started);
        fprintf(f, "<tr><td style=\"padding-left:20px;\">Completed</td><td>%u</td></tr>\n", 
                g_stltp_stats->spanning_complete);
        if (g_stltp_stats->spanning_discarded > 0) {
            fprintf(f, "<tr><td style=\"padding-left:20px;color:#d9534f;\">Discarded</td><td style=\"color:#d9534f;\">%u</td></tr>\n", 
                    g_stltp_stats->spanning_discarded);
        }
        if (g_stltp_stats->orphan_continuations > 0) {
            fprintf(f, "<tr><td style=\"padding-left:20px;color:#f0ad4e;\">Orphan Continuations</td><td style=\"color:#f0ad4e;\">%u</td></tr>\n", 
                    g_stltp_stats->orphan_continuations);
        }
        
        // Error stats (only show if non-zero)
        int stltp_capture_issues = 0;
#ifdef STLTP_HAS_ROBUST_READER
        stltp_capture_issues = g_stltp_stats->outer_rtp_gaps > 0 || g_stltp_stats->tunnel_drops > 0 ||
                               g_stltp_stats->truncated_packets > 0 || g_stltp_stats->fragmented_packets > 0 ||
                               g_stltp_stats->capture_error || g_stltp_stats->stream_desc[0] == '\0';
#endif
        if (g_stltp_stats->rejected_packets > 0 || g_stltp_stats->sync_errors > 0 || 
            g_stltp_stats->inner_rtp_gaps > 0 || stltp_capture_issues) {
            fprintf(f, "<tr><td colspan=\"2\" style=\"background-color:#f5f5f5;\"><strong>Errors/Issues</strong></td></tr>\n");
#ifdef STLTP_HAS_ROBUST_READER
            // Capture-level problems first: they explain most of what follows
            if (g_stltp_stats->stream_desc[0] == '\0') {
                fprintf(f, "<tr><td style=\"padding-left:20px;color:#d9534f;\">No STLTP Stream Found</td><td style=\"color:#d9534f;\">check capture filter / STLTP_STREAM</td></tr>\n");
            }
            if (g_stltp_stats->capture_error) {
                fprintf(f, "<tr><td style=\"padding-left:20px;color:#d9534f;\">Capture File Corrupt</td><td style=\"color:#d9534f;\">reading stopped early</td></tr>\n");
            }
            if (g_stltp_stats->outer_rtp_gaps > 0) {
                // Loss before the depacketizer: network or capture dropped tunnel packets
                fprintf(f, "<tr><td style=\"padding-left:20px;color:#d9534f;\">Outer RTP Gaps (capture/network loss)</td><td style=\"color:#d9534f;\">%u (%u packets lost)</td></tr>\n",
                        g_stltp_stats->outer_rtp_gaps, g_stltp_stats->outer_rtp_gap_packets);
            }
            if (g_stltp_stats->tunnel_drops > 0) {
                fprintf(f, "<tr><td style=\"padding-left:20px;color:#f0ad4e;\">Inner Packets Dropped in Tunnel</td><td style=\"color:#f0ad4e;\">%u</td></tr>\n",
                        g_stltp_stats->tunnel_drops);
            }
            if (g_stltp_stats->truncated_packets > 0) {
                fprintf(f, "<tr><td style=\"padding-left:20px;color:#d9534f;\">Truncated Frames (snaplen too small)</td><td style=\"color:#d9534f;\">%u skipped</td></tr>\n",
                        g_stltp_stats->truncated_packets);
            }
            if (g_stltp_stats->fragmented_packets > 0) {
                fprintf(f, "<tr><td style=\"padding-left:20px;color:#f0ad4e;\">IP Fragments</td><td style=\"color:#f0ad4e;\">%u skipped</td></tr>\n",
                        g_stltp_stats->fragmented_packets);
            }
#endif
            if (g_stltp_stats->rejected_packets > 0) {
                fprintf(f, "<tr><td style=\"padding-left:20px;color:#d9534f;\">Rejected Packets</td><td style=\"color:#d9534f;\">%u</td></tr>\n", 
                        g_stltp_stats->rejected_packets);
            }
            if (g_stltp_stats->sync_errors > 0) {
                fprintf(f, "<tr><td style=\"padding-left:20px;color:#d9534f;\">Sync Errors</td><td style=\"color:#d9534f;\">%u</td></tr>\n", 
                        g_stltp_stats->sync_errors);
            }
            if (g_stltp_stats->inner_rtp_gaps > 0) {
                fprintf(f, "<tr><td style=\"padding-left:20px;color:#f0ad4e;\">Inner RTP Gaps</td><td style=\"color:#f0ad4e;\">%u (%u packets lost)</td></tr>\n", 
                        g_stltp_stats->inner_rtp_gaps, g_stltp_stats->inner_rtp_gap_packets);
                // Per-PLP breakdown
                for (int i = 0; i < g_stltp_stats->plp_gap_count; i++) {
                    fprintf(f, "<tr><td style=\"padding-left:40px;color:#888;\">PLP %d</td><td style=\"color:#888;\">%u gaps (%u lost)</td></tr>\n",
                            g_stltp_stats->plp_gaps[i].plp_id,
                            g_stltp_stats->plp_gaps[i].gaps,
                            g_stltp_stats->plp_gaps[i].packets_lost);
                }
            }
        }
        
        // Total bytes
        fprintf(f, "<tr><td><strong>Total ALP Bytes</strong></td><td>");
        if (g_stltp_stats->total_alp_bytes >= 1073741824) {
            fprintf(f, "%.2f GB", (double)g_stltp_stats->total_alp_bytes / 1073741824.0);
        } else if (g_stltp_stats->total_alp_bytes >= 1048576) {
            fprintf(f, "%.2f MB", (double)g_stltp_stats->total_alp_bytes / 1048576.0);
        } else if (g_stltp_stats->total_alp_bytes >= 1024) {
            fprintf(f, "%.2f KB", (double)g_stltp_stats->total_alp_bytes / 1024.0);
        } else {
            fprintf(f, "%zu bytes", g_stltp_stats->total_alp_bytes);
        }
        fprintf(f, "</td></tr>\n");
        
        fprintf(f, "</tbody></table>\n");
        fprintf(f, "</details>\n");
    }
    
    consolidate_data_usage_entries();
    generate_data_usage_chart(f);

    fprintf(f, "</div>\n</body>\n</html>\n");

    // After the loop, if the header was never printed, it means nothing was found.
    if (!header_printed) {
        //fprintf(f, "<p class='not-found'>No other global LLS tables found.</p>\n");
    }

    fclose(f);
}

/**
 * @brief Frees all globally allocated memory.
 */
void cleanup() {
    ServiceDescriptors* descriptors = get_service_descriptors();
    int descriptor_count = get_service_descriptor_count();

    // Per-window bitrate counts
    for (int i = 0; i < g_data_usage_count; i++) {
        free(g_data_usage[i].rate_bins);
        g_data_usage[i].rate_bins = NULL;
    }
    free(g_total_rate_bins);
    g_total_rate_bins = NULL;
    
    for (int i = 0; i < g_lls_table_count; i++) {
        free(g_lls_tables[i].content_id);
        free_parsed_data(&g_lls_tables[i]);
    }
    free_reassembly_buffers();
    free_bps_data(g_bps_data);
    g_bps_data = NULL;
    
    // Free ROUTE image storage
    for (int i = 0; i < g_route_image_count; i++) {
        free(g_route_images[i].data);
        g_route_images[i].data = NULL;
    }
    g_route_image_count = 0;
    
    // Free STLTP stats
    if (g_stltp_stats) {
        free(g_stltp_stats);
        g_stltp_stats = NULL;
    }
    
    // Free eGPS data
    free_all_egps_data();
    
    if (get_enhanced_l1_signaling_data()) {
        free_enhanced_l1_signaling_data(get_enhanced_l1_signaling_data());
        set_enhanced_l1_signaling_data(NULL);
    }
    
    // Free service descriptors
    for (int i = 0; i < descriptor_count; i++) {
        if (descriptors[i].vspd) {
            free(descriptors[i].vspd);
        }
        if (descriptors[i].aspd) {
            free(descriptors[i].aspd);
        }
        if (descriptors[i].cad) {
            CadEntry* current = descriptors[i].cad->head;
            while (current) {
                CadEntry* next = current->next;
                free(current);
                current = next;
            }
            free(descriptors[i].cad);
        }
    }
}

/**
 * @brief Frees any remaining fragment reassembly buffers.
 */
void free_reassembly_buffers() {
    ReassemblyBuffer* current = g_reassembly_head;
    while(current != NULL) {
        ReassemblyBuffer* next = current->next;
        free(current->buffer);
        free(current);
        current = next;
    }
    g_reassembly_head = NULL;
}



void free_usbd_data(UsdbData* data) {
    if (!data) return;
    UsdEntryMmt* current = data->head;
    while (current != NULL) {
        UsdEntryMmt* next = current->next;
        free(current);
        current = next;
    }
    free(data);
}

void free_usd_data(UsdData* data) {
    if (!data) return;
    
    // Free components
    UsdComponent* current_comp = data->components;
    while (current_comp != NULL) {
        UsdComponent* next_comp = current_comp->next;
        free(current_comp);
        current_comp = next_comp;
    }
    
    // Free assets (existing code)
    UsdAsset* current = data->assets;
    while (current != NULL) {
        UsdAsset* next = current->next;
        free(current);
        current = next;
    }
    free(data);
}

/**
 * @brief Frees memory associated with a parsed table struct.
 */
void free_parsed_data(LlsTable* table) {
    if (!table->parsed_data) return;

    switch (table->type) {
        case TABLE_TYPE_SLT:
            free_slt_data((SltData*)table->parsed_data);
            break;
        case TABLE_TYPE_UCT:
            free_uct_data((UctData*)table->parsed_data);
            break;
        case TABLE_TYPE_UDST:
            free_udst_data((UdstData*)table->parsed_data);
            break;
        case TABLE_TYPE_FDT:
            free_fdt_data((FDTInstanceData*)table->parsed_data);
            break;
        case TABLE_TYPE_EFDT:
            free_fdt_data((FDTInstanceData*)table->parsed_data);
            break;
        case TABLE_TYPE_MPD:
            free_mpd_data((MpdData*)table->parsed_data);
            break;
        case TABLE_TYPE_HELD:
            free_held_data((HeldData*)table->parsed_data);
            break;
        case TABLE_TYPE_ESG_FRAGMENT:
            free_esg_data((EsgFragmentData*)table->parsed_data);
            break;
        case TABLE_TYPE_SGDD: {
            SgddData* sgdd = (SgddData*)table->parsed_data;
            if (sgdd) {
                SgddEntry* entry = sgdd->entries;
                while (entry) {
                    SgddEntry* next_entry = entry->next;
                    SgddDeliveryUnit* unit = entry->deliveryUnits;
                    while (unit) {
                        SgddDeliveryUnit* next_unit = unit->next;
                        SgddFragment* frag = unit->fragments;
                        while (frag) {
                            SgddFragment* next_frag = frag->next;
                            free(frag);
                            frag = next_frag;
                        }
                        free(unit);
                        unit = next_unit;
                    }
                    free(entry);
                    entry = next_entry;
                }
                free(sgdd);
            }
            break;
        }
        case TABLE_TYPE_USER_SERVICE_DESCRIPTION:
            free_user_service_description_data((UserServiceDescriptionData*)table->parsed_data);
            break;
        case TABLE_TYPE_USBD:
            free_usbd_data((UsdbData*)table->parsed_data);
            break;
        case TABLE_TYPE_USD:
            free_usd_data((UsdData*)table->parsed_data);
            break;
        case TABLE_TYPE_SERVICE_SIGNALING:
            free_service_signaling_data((ServiceSignalingData*)table->parsed_data);
            break;
        case TABLE_TYPE_STSID:
            free_stsid_data((StsidData*)table->parsed_data);
            break;
        case TABLE_TYPE_MP_TABLE_XML:
            free_mp_table_data((MpTableData*)table->parsed_data);
            break;
        case TABLE_TYPE_MP_TABLE_BINARY: {
            BinaryMptData* binary_mpt = (BinaryMptData*)table->parsed_data;
            if (binary_mpt) {
                BinaryMptAsset* asset = binary_mpt->head_asset;
                while (asset) {
                    BinaryMptAsset* next = asset->next;
                    free(asset);
                    asset = next;
                }
                free(binary_mpt);
            }
            break;
        }
        case TABLE_TYPE_CDT: {
            CdtData* cdt_data = (CdtData*)table->parsed_data;
            if (cdt_data) {
                free_certificate_info(cdt_data->certificates);
                free(cdt_data);
            }
            break;
        }
        case TABLE_TYPE_SYSTEM_TIME:
        case TABLE_TYPE_SIGNATURE:
        case TABLE_TYPE_DWD: // Placeholder, just free the main struct
        case TABLE_TYPE_UNHANDLED: // Simple struct, just free it
        case TABLE_TYPE_UDS: // Simple struct with inline arrays
            free(table->parsed_data);
            break;
        case TABLE_TYPE_EGPS:
            free_egps_data((EgpsData*)table->parsed_data);
            break;
        case TABLE_TYPE_AEAT: {
            AeatData* aeat_data = (AeatData*)table->parsed_data;
            if (aeat_data) {
                AeaEntry* aea = aeat_data->head_aea;
                while (aea) {
                    AeaEntry* next_aea = aea->next;
                    AeatMedia* media = aea->head_media;
                    while (media) {
                        AeatMedia* next_media = media->next;
                        free(media);
                        media = next_media;
                    }
                    free(aea);
                    aea = next_aea;
                }
                free(aeat_data);
            }
            break;
        }
        case TABLE_TYPE_RRT: {
            RrtData* rrt_data = (RrtData*)table->parsed_data;
            if (rrt_data) {
                RrtRegion* region = rrt_data->regions;
                while (region) {
                    RrtRegion* next_region = region->next;
                    RrtDimension* dim = region->dimensions;
                    while (dim) {
                        RrtDimension* next_dim = dim->next;
                        RrtRatingValue* val = dim->values;
                        while (val) {
                            RrtRatingValue* next_val = val->next;
                            free(val);
                            val = next_val;
                        }
                        free(dim);
                        dim = next_dim;
                    }
                    free(region);
                    region = next_region;
                }
                free(rrt_data);
            }
            break;
        }
        case TABLE_TYPE_LMT: {
            LmtData* lmt_data = (LmtData*)table->parsed_data;
            if (lmt_data) {
                LmtService* current_service = lmt_data->services;
                while (current_service) {
                    LmtService* next_service = current_service->next;
                    
                    // Free multicast list for this service
                    LmtMulticast* current_multicast = current_service->multicasts;
                    while (current_multicast) {
                        LmtMulticast* next_multicast = current_multicast->next;
                        free(current_multicast);
                        current_multicast = next_multicast;
                    }
                    
                    free(current_service);
                    current_service = next_service;
                }
                free(lmt_data);
            }
            break;
        }
        default:
            free(table->parsed_data); // Default case
            break;
    }
    table->parsed_data = NULL;
}

/**
 * @brief Frees memory for an SltData struct and its linked list of services.
 */
void free_slt_data(SltData* data) {
    if (!data) return;
    ServiceInfo* current = data->head;
    while (current != NULL) {
        ServiceInfo* next = current->next;
        free(current);
        current = next;
    }
    free(data);
}

/**
 * @brief Frees memory for a FDTInstanceData struct and its file list.
 */
void free_fdt_data(FDTInstanceData* data) {
    if (!data) return;
    FDTFileInfo* current = data->head;
    while(current != NULL) {
        FDTFileInfo* next = current->next;
        free(current);
        current = next;
    }
    free(data);
}

/**
 * @brief Frees memory for a MpdData struct and its contents.
 */
void free_mpd_data(MpdData* data) {
    if (!data) return;
    MpdAdaptationSet* current_as = data->head_as;
    while (current_as != NULL) {
        // Since timelines can be shared across Representations, we must free it carefully.
        SegmentTimelineS* timeline_to_free = NULL;
        if (current_as->head_rep) {
            timeline_to_free = current_as->head_rep->segmentTemplate.timeline;
        }

        MpdRepresentation* current_rep = current_as->head_rep;
        while(current_rep != NULL) {
            MpdRepresentation* next_rep = current_rep->next;
            
            // Free DRM info
            DrmInfo* current_drm = current_rep->drmInfo;
            while (current_drm != NULL) {
                DrmInfo* next_drm = current_drm->next;
                DrmKeyId* current_key = current_drm->keyIds;
                while (current_key != NULL) {
                    DrmKeyId* next_key = current_key->next;
                    free(current_key);
                    current_key = next_key;
                }
                free(current_drm);
                current_drm = next_drm;
            }
            
            free(current_rep);
            current_rep = next_rep;
        }

        // Now, free the single, shared timeline for the whole Adaptation Set.
        SegmentTimelineS* current_s = timeline_to_free;
        while(current_s != NULL) {
            SegmentTimelineS* next_s = current_s->next;
            free(current_s);
            current_s = next_s;
        }
        
        MpdAdaptationSet* next_as = current_as->next;
        free(current_as);
        current_as = next_as;
    }
    free(data);
}

/**
 * @brief Frees memory for a HeldData struct.
 */
void free_held_data(HeldData* data) {
    if (!data) return;
    free(data);
}

/**
 * @brief Frees memory for a UserServiceDescriptionData struct.
 */
void free_user_service_description_data(UserServiceDescriptionData* data) {
    if (!data) return;
    UsdEntry* current = data->head;
    while (current != NULL) {
        UsdEntry* next = current->next;
        free(current);
        current = next;
    }
    free(data);
}

/**
 * @brief Frees memory for a ServiceSignalingData struct.
 */
void free_service_signaling_data(ServiceSignalingData* data) {
    if (!data) return;
    ServiceSignalingFragment* current = data->head;
    while (current != NULL) {
        ServiceSignalingFragment* next = current->next;
        free(current);
        current = next;
    }
    free(data);
}

/**
 * @brief Frees memory for an StsidData struct.
 */
void free_stsid_data(StsidData* data) {
    if (!data) return;
    StsidLogicalStream* current_ls = data->head_ls;
    while (current_ls != NULL) {
        ContentRatingInfo* current_rating = current_ls->head_rating;
        while (current_rating != NULL) {
            ContentRatingInfo* next_rating = current_rating->next;
            free(current_rating);
            current_rating = next_rating;
        }
        StsidFileEntry* current_file = current_ls->head_file;
        while (current_file != NULL) {
            StsidFileEntry* next_file = current_file->next;
            free(current_file);
            current_file = next_file;
        }
        StsidLogicalStream* next_ls = current_ls->next;
        free(current_ls);
        current_ls = next_ls;
    }
    free(data);
}

/**
 * @brief Frees memory for an MpTableData struct.
 */
void free_mp_table_data(MpTableData* data) {
    if (!data) return;
    MptAsset* current = data->head_asset;
    while (current != NULL) {
        MptAsset* next = current->next;
        free(current);
        current = next;
    }
    free(data);
}

/**
 * @brief Frees memory for a UctData struct and its contents.
 */
void free_uct_data(UctData* data) {
    if (!data) return;
    NdPackage* current_pkg = data->head_package;
    while (current_pkg != NULL) {
        NdElement* current_elem = current_pkg->head_element;
        while(current_elem != NULL) {
            NdElement* next_elem = current_elem->next;
            free(current_elem);
            current_elem = next_elem;
        }
        NdPackage* next_pkg = current_pkg->next;
        free(current_pkg);
        current_pkg = next_pkg;
    }
    free(data);
}

/**
 * @brief Frees memory for a UdstData struct and its contents.
 */
void free_udst_data(UdstData* data) {
    if (!data) return;
    
    // Free UDS entries
    UdsData* uds = data->head_uds;
    while (uds != NULL) {
        UdsData* next_uds = uds->next;
        free(uds);
        uds = next_uds;
    }
    
    // Free BroadSpan services
    BroadSpanServiceInfo* current_svc = data->head_service;
    while (current_svc != NULL) {
        if (current_svc->head_rsrv) {
            free(current_svc->head_rsrv);
        }
        BroadSpanServiceInfo* next_svc = current_svc->next;
        free(current_svc);
        current_svc = next_svc;
    }
    free(data);
}
