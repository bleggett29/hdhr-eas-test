/**
 * input.c - STLTP to ALP Depacketizer
 * 
 * Complete implementation based on libatsc3 architecture for processing
 * ATSC 3.0 STLTP (Studio-Transmitter Link Tunnel Protocol) PCAP files
 * and extracting ALP (ATSC Link-layer Protocol) packets.
 * 
 * Version: 2026-11-03-v15 (tunnel reassembly fix; pcap/pcapng reader with VLAN, Linux cooked,
 *          raw IP and IP options; truncation handling; outer stream lock)
 */

#include "input.h"
#include "debug_log.h"
#include "progress.h"
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <time.h>
#include <strings.h>
#include <stdint.h>
#include <stdbool.h>

// ============================================================================
// Constants
// ============================================================================

#define MAX_PLPS                    64
#define MAX_ALP_PACKET_SIZE         65535
#define CARRYOVER_MAX_SIZE          65536
#define REASSEMBLY_BUFFER_SIZE      (512 * 1024)

// ============================================================================
// Debug Control
// ============================================================================

static int g_verbose = 0;
static int g_diag = 0;
static FILE* g_diag_out = NULL;

#define DIAG(...) do { if (g_diag && g_diag_out) fprintf(g_diag_out, __VA_ARGS__); } while(0)
#define VERBOSE(...) do { if (g_verbose) printf(__VA_ARGS__); } while(0)

// ============================================================================
// Base64 encoding
// ============================================================================

static const char base64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

char* base64_encode(const uint8_t *data, size_t input_length, size_t *output_length) {
    *output_length = 4 * ((input_length + 2) / 3);
    char *encoded_data = malloc(*output_length + 1);
    if (!encoded_data) return NULL;
    
    size_t i, j;
    for (i = 0, j = 0; i < input_length;) {
        uint32_t octet_a = i < input_length ? data[i++] : 0;
        uint32_t octet_b = i < input_length ? data[i++] : 0;
        uint32_t octet_c = i < input_length ? data[i++] : 0;
        uint32_t triple = (octet_a << 16) + (octet_b << 8) + octet_c;
        
        encoded_data[j++] = base64_table[(triple >> 18) & 0x3F];
        encoded_data[j++] = base64_table[(triple >> 12) & 0x3F];
        encoded_data[j++] = base64_table[(triple >> 6) & 0x3F];
        encoded_data[j++] = base64_table[triple & 0x3F];
    }
    
    int mod = input_length % 3;
    if (mod == 1) {
        encoded_data[*output_length - 1] = '=';
        encoded_data[*output_length - 2] = '=';
    } else if (mod == 2) {
        encoded_data[*output_length - 1] = '=';
    }
    
    encoded_data[*output_length] = '\0';
    return encoded_data;
}

// ============================================================================
// ALP Header Parsing - Matches A/330 exactly
// ============================================================================

/**
 * Parse ALP packet header to determine total packet length.
 * 
 * Returns: total packet length (header + payload), or 0 on error
 * Sets *header_len to the header size
 * Sets *payload_len to the payload size
 * 
 * Per A/330:
 * - Type 0 (IPv4): [type(3)|PC(1)|HM(1)|len(11)]
 * - Type 4 (Signaling): Same structure as Type 0
 * - Type 2 (Compressed IP): [type(3)|PC(1)|context(4)|len(11)] 
 * - Type 6 (Extension): [type(3)|reserved(4)|HEF(1)][len(16)]
 * - Type 7 (MPEG-TS): [type(3)|PC(1)|HDME(1)|NUMTS(3)]
 */
static size_t alp_get_packet_length(const uint8_t* data, size_t available,
                                     size_t* header_len, size_t* payload_len) {
    if (available < 2) return 0;
    
    uint8_t byte0 = data[0];
    uint8_t byte1 = data[1];
    uint8_t packet_type = (byte0 >> 5) & 0x07;
    uint8_t pc = (byte0 >> 4) & 0x01;
    uint8_t bit3 = (byte0 >> 3) & 0x01;  // HM for type 0/4, HDME for type 7, etc
    
    size_t hlen = 0;
    size_t plen = 0;
    
    switch (packet_type) {
        case 0:  // IPv4
        case 4:  // Signaling (LLS)
        {
            // 11-bit length in bits[2:0] of byte0 and all of byte1
            uint16_t len11 = ((byte0 & 0x07) << 8) | byte1;
            plen = len11;
            
            if (pc == 0) {
                // Single packet mode
                if (bit3 == 0) {
                    // HM=0: No additional header, 11-bit length only
                    hlen = 2;
                } else {
                    // HM=1: Has single_packet_header (at least 1 byte)
                    // single_packet_header format:
                    //   bits 7-3: length_MSB (5 bits, extends to 16-bit length)
                    //   bit 2: reserved (should be 1)
                    //   bit 1: SIF (sub_stream_identification_flag)
                    //   bit 0: HEF (header_extension_flag)
                    if (available < 3) return 0;
                    hlen = 3;
                    
                    uint8_t sph = data[2];
                    uint8_t length_msb = (sph >> 3) & 0x1F;  // 5-bit extension
                    uint8_t sif = (sph >> 1) & 0x01;
                    uint8_t hef = sph & 0x01;
                    
                    // Combine for 16-bit length: length_MSB(5) | len11(11)
                    plen = ((uint32_t)length_msb << 11) | len11;
                    
                    if (sif) hlen++;  // SID byte
                    
                    if (hef && available >= hlen + 2) {
                        // Header extension: ext_type(1) + ext_len(1) + ext_bytes
                        uint8_t ext_len = data[hlen + 1];
                        hlen += 2 + ext_len;
                    }
                }
            } else {
                // PC=1: Segmentation or Concatenation
                if (available < 3) return 0;
                hlen = 3;
                
                uint8_t seg_concat = bit3;
                if (seg_concat == 0) {
                    // Segmentation header
                    uint8_t seg_hdr = data[2];
                    uint8_t sif = (seg_hdr >> 1) & 0x01;
                    uint8_t hef = seg_hdr & 0x01;
                    
                    if (sif) hlen++;
                    if (hef && available >= hlen + 2) {
                        uint8_t ext_len = data[hlen + 1];
                        hlen += 2 + ext_len;
                    }
                } else {
                    // Concatenation header (complex - just use base)
                    // [length_MSB(4)|count_minus_2(3)|SIF(1)]
                    if (available < 4) return 0;
                    uint8_t count_minus_2 = (data[2] >> 1) & 0x07;
                    uint8_t sif = data[2] & 0x01;
                    int count = count_minus_2 + 2;
                    
                    // Each component has 12-bit length
                    int extra_bits = count * 12;
                    int extra_bytes = (extra_bits + 7) / 8;
                    hlen = 3 + extra_bytes;
                    if (sif) hlen++;
                    
                    // Use the combined length field
                    uint8_t len_msb = (data[2] >> 4) & 0x0F;
                    plen = (len_msb << 11) | len11;
                }
            }
            
            // For signaling packets (type 4), the length field specifies the
            // payload length AFTER the 5-byte signaling info header.
            if (packet_type == 4) {
                // Sanity check: type 4 headers should not be huge
                // Max reasonable: 2 (base) + 1 (sph) + 1 (sid) + 2 + ~32 (ext) = ~40 bytes
                if (hlen > 40) {
                    // This is garbage - we're parsing at the wrong position
                    static int garbage_hlen_count = 0;
                    if (garbage_hlen_count < 20) {
                        garbage_hlen_count++;
                        DBG_PRINTF("\n");
                        DBG_PRINTF("╔══════════════════════════════════════════════════════════════╗\n");
                        DBG_PRINTF("║ GARBAGE TYPE 4 HEADER #%d                                     ║\n", garbage_hlen_count);
                        DBG_PRINTF("╠══════════════════════════════════════════════════════════════╣\n");
                        DBG_PRINTF("║ Calculated hlen=%zu (WAY too large, max ~40)\n", hlen);
                        DBG_PRINTF("║ PC=%d, HM/bit3=%d, calculated plen=%zu\n", pc, bit3, plen);
                        DBG_PRINTF("╟──────────────────────────────────────────────────────────────╢\n");
                        DBG_PRINTF("║ Raw bytes at this position:\n║ ");
                        for (size_t i = 0; i < 32 && i < available; i++) {
                            DBG_PRINTF("%02x ", data[i]);
                            if ((i+1) % 16 == 0 && i < 31) DBG_PRINTF("\n║ ");
                        }
                        DBG_PRINTF("\n");
                        DBG_PRINTF("╟──────────────────────────────────────────────────────────────╢\n");
                        DBG_PRINTF("║ ANALYSIS:\n");
                        DBG_PRINTF("║   Byte[0] = 0x%02x -> type=%d (looks like type 4)\n", 
                               data[0], packet_type);
                        DBG_PRINTF("║   Byte[2] = 0x%02x -> seg_hdr (SIF=%d, HEF=%d)\n", 
                               available >= 3 ? data[2] : 0,
                               available >= 3 ? (data[2] >> 1) & 0x01 : 0,
                               available >= 3 ? data[2] & 0x01 : 0);
                        if (available >= 4) {
                            DBG_PRINTF("║   Byte[3] = 0x%02x (ext_type would be %d)\n", 
                                   data[3], (data[3] >> 5) & 0x07);
                            DBG_PRINTF("║   Byte[4] = 0x%02x (used as ext_len = %d!)\n", 
                                   data[4], data[4]);
                        }
                        DBG_PRINTF("║\n");
                        DBG_PRINTF("║ This position is MISALIGNED - returning parse error\n");
                        DBG_PRINTF("╚══════════════════════════════════════════════════════════════╝\n\n");
                    }
                    return 0;  // Signal parse error - will trigger resync
                }
                
                // Add signaling info header (5 bytes) to ALP header
                if (pc == 0 && bit3 == 0) {
                    // Simple case: 2-byte ALP header + 5-byte signaling info
                    hlen = 2 + 5;
                } else {
                    // Extended case: preserve calculated ALP header, add signaling info
                    hlen += 5;
                }
            }
            break;
        }
        
        case 2:  // Compressed IP (ROHC)
        {
            // Similar to type 0 but with context_id in bit3
            uint16_t len11 = ((byte0 & 0x07) << 8) | byte1;
            hlen = 2;
            plen = len11;
            break;
        }
        
        case 6:  // Extension packet type
        {
            if (available < 3) return 0;
            // 16-bit length in bytes 1-2
            uint16_t len16 = (data[1] << 8) | data[2];
            uint8_t hef = byte0 & 0x01;
            hlen = 3;
            if (hef && available >= 5) {
                uint8_t ext_len = data[4];
                hlen += 2 + ext_len;
            }
            plen = len16;
            break;
        }
        
        case 7:  // MPEG-TS
        {
            if (pc == 1) {
                // Packetized TS
                uint16_t len11 = ((byte0 & 0x07) << 8) | byte1;
                hlen = 2;
                plen = len11;
            } else {
                // Direct TS packets
                uint8_t numts = (byte0 & 0x07) + 1;  // 1-8 packets
                hlen = bit3 ? 2 : 1;  // HDME determines header size
                plen = numts * 188;
            }
            break;
        }
        
        case 1:
        case 3:
        case 5:
            // Reserved types - likely sync error
            return 0;
    }
    
    if (header_len) *header_len = hlen;
    if (payload_len) *payload_len = plen;
    
    return hlen + plen;
}

// ============================================================================
// Per-PLP State for ALP reassembly
// ============================================================================

typedef struct {
    // Pending ALP packet (started in previous BBP, not yet complete)
    uint8_t* pending_data;
    size_t pending_size;       // Current accumulated size
    size_t pending_expected;   // Expected total size (0 if unknown)
    size_t pending_header_len; // Header length of pending packet
    
    // Short fragment at end of BBP (less than a complete ALP header)
    uint8_t* short_frag;
    size_t short_frag_size;
    
    // Debug tracking for spanning packets
    uint32_t pending_start_bbp;   // BBP number where this packet started
    uint32_t pending_cont_count;  // Number of continuation BBPs
    
    // Track contribution boundaries for corruption diagnosis
    size_t cont_boundaries[32];   // Byte offsets where each contribution ended
    uint32_t cont_bbps[32];       // BBP numbers for each contribution
    int cont_boundary_count;
} plp_alp_state_t;

/* True if `avail` bytes are the start of a valid ALP header that needs more
 * bytes before the packet length is known (header split across BBPs). */
static int alp_header_incomplete(const uint8_t *p, size_t avail) {
    uint8_t tmp[64] = {0};
    size_t hlen = 0, plen = 0;
    if (avail == 0) return 0;
    if (avail < 2) return 1;
    if (avail >= sizeof(tmp)) return 0;
    memcpy(tmp, p, avail);
    return alp_get_packet_length(tmp, sizeof(tmp), &hlen, &plen) > 0 && hlen > avail;
}

/* A pending packet whose header was split across BBPs: move bytes from the
 * next BBP into it until its length is known. Returns bytes consumed. */
static size_t alp_pending_complete_header(plp_alp_state_t *st, const uint8_t *data, size_t len) {
    size_t used = 0, hlen, plen;
    while (st->pending_expected == 0 && used < len && st->pending_size < 64) {
        st->pending_data[st->pending_size++] = data[used++];
        if (st->pending_size >= 2) {
            size_t total = alp_get_packet_length(st->pending_data, st->pending_size, &hlen, &plen);
            if (total > 0) {
                st->pending_expected = total;
                st->pending_header_len = hlen;
            }
        }
    }
    return used;
}

// Per-PLP BBP reassembly state (for multi-RTP-packet BBPs)
typedef struct {
    uint8_t* buf;
    size_t size;
    size_t expected;
    bool active;
    // Inner RTP sequence tracking per PLP
    uint16_t last_seq;
    int seq_valid;
    uint32_t seq_gaps;
    uint32_t seq_gap_packets;
    // Per-PLP BBP tracking for discontinuity detection
    uint32_t last_bbp_num;  // Last BBP number seen for this PLP
    int bbp_num_valid;       // Whether we've seen a BBP yet
} plp_bbp_state_t;

// ============================================================================
// Depacketizer Context
// ============================================================================

typedef struct {
    plp_alp_state_t plp[MAX_PLPS];
    
    // Per-PLP BBP reassembly (for multi-RTP-packet BBPs)
    plp_bbp_state_t bbp[MAX_PLPS];
    
    // Preamble reassembly
    uint8_t* preamble_buf;
    size_t preamble_size;
    bool preamble_active;
    
    // T&M reassembly  
    uint8_t* tm_buf;
    size_t tm_size;
    bool tm_active;
    
    // Output
    uint8_t* out_alp;
    size_t out_alp_size;
    size_t out_alp_capacity;
    uint32_t out_alp_count;
    
    // Per-type counters
    uint32_t alp_type_counts[8];
    
    // L1
    uint8_t l1_basic[32];
    size_t l1_basic_size;
    uint8_t* l1_detail;
    size_t l1_detail_size;
    size_t l1_detail_capacity;
    
    // Stats
    uint32_t outer_pkts;
    uint32_t bbp_count;
    uint32_t preamble_count;
    uint32_t tm_count;
    uint32_t sync_errors;
    uint32_t spanning_complete;
    uint32_t rejected_packets;
    
    // Additional spanning packet stats
    uint32_t spanning_started;
    uint32_t spanning_discarded;
    uint32_t orphan_continuations;
    
    // RTP sequence tracking for gap detection
    uint16_t last_outer_seq;
    int outer_seq_valid;
    uint32_t outer_seq_gaps;
    uint32_t outer_seq_gap_packets;  // Estimated number of lost packets
    uint32_t tunnel_drops;           // Inner IP packets dropped during tunnel reassembly

    // Capture reading / stream selection
    uint32_t truncated_pkts;         // Frames cut short by the capture snaplen
    uint32_t fragmented_pkts;        // IP fragments (not reassembled)
    uint32_t skipped_frames;         // Not IPv4/UDP, or not an STLTP outer RTP packet
    uint32_t ignored_stream_pkts;    // Outer RTP packets from other streams / before lock
    int capture_error;               // File ended in a corrupt record
    char stream_desc[64];            // "src -> dst:port" of the locked stream

    // Capture timing (locked stream only)
    uint64_t cur_ts_us;              // timestamp of the outer packet being processed
    uint64_t first_ts_us, last_ts_us;
    int ts_missing;                  // some locked packets had no timestamp
    stltp_alp_time_t* alp_times;     // capture time of each output ALP packet
    size_t alp_times_count, alp_times_cap;
    
    // Current packet output context (for debugging)
    struct {
        int plp;
        uint32_t bbp_num;
        uint32_t start_bbp;     // For spanning packets
        uint32_t cont_count;    // Number of continuation BBPs
        int is_spanning;        // 1 if from spanning reassembly
        const char* region;     // "post-ptr", "pre-ptr", "ptr=max"
    } pkt_source;
} depack_ctx_t;

// Debug trace environment variables
static uint32_t g_trace_dest_ip = 0;   // Set via TRACE_DEST_IP env var
static uint16_t g_trace_dest_port = 0; // Set via TRACE_DEST_PORT env var
static uint32_t g_trace_tsi = 0;       // Set via TRACE_TSI env var
static int g_trace_tsi_set = 0;        // Whether TSI filter is active

// Extract TSI from LCT header in UDP payload
// Returns TSI or 0 if not parseable
static uint32_t extract_tsi_from_lct(const uint8_t* udp_payload, size_t udp_len) {
    if (udp_len < 4) return 0;  // Need at least LCT base header
    
    // LCT header format (RFC 5651):
    // Byte 0: V(4) | C(2) | r(2)
    // Byte 1: S(1) | O(2) | H(1) | T(1) | R(1) | A(1) | B(1)
    // Byte 2: HDR_LEN (header length in 32-bit words)
    // Byte 3: CP (codepoint)
    // Then: CCI (length = 32*(C+1) bits = 4*(C+1) bytes)
    // Then: TSI (length = 32*S + 16*H bits)
    // Then: TOI (length = 32*O + 16*H bits)
    
    uint8_t version = (udp_payload[0] >> 4) & 0x0F;
    if (version != 1) return 0;  // LCT version should be 1
    
    uint8_t c_flag = (udp_payload[0] >> 2) & 0x03;  // CCI size indicator
    uint8_t s_flag = (udp_payload[1] >> 7) & 0x01;  // TSI present/size
    uint8_t h_flag = (udp_payload[1] >> 4) & 0x01;  // Half-word flag
    
    // CCI length in bytes: 4*(C+1)
    size_t cci_len = 4 * (c_flag + 1);
    
    // TSI starts after base header (4 bytes) + CCI
    size_t tsi_offset = 4 + cci_len;
    
    // TSI length: 32*S + 16*H bits = 4*S + 2*H bytes
    size_t tsi_len = 4 * s_flag + 2 * h_flag;
    
    if (tsi_len == 0) return 0;  // No TSI field present
    if (udp_len < tsi_offset + tsi_len) return 0;
    
    // Extract TSI based on length
    const uint8_t* tsi_ptr = udp_payload + tsi_offset;
    if (tsi_len == 2) {
        // 16-bit TSI (S=0, H=1)
        return (tsi_ptr[0] << 8) | tsi_ptr[1];
    } else if (tsi_len == 4) {
        // 32-bit TSI (S=1, H=0)
        return (tsi_ptr[0] << 24) | (tsi_ptr[1] << 16) | 
               (tsi_ptr[2] << 8) | tsi_ptr[3];
    } else if (tsi_len == 6) {
        // 48-bit TSI (S=1, H=1) - return lower 32 bits
        return (tsi_ptr[2] << 24) | (tsi_ptr[3] << 16) | 
               (tsi_ptr[4] << 8) | tsi_ptr[5];
    }
    
    return 0;
}

// BBP dump range for detailed debugging
static uint32_t g_dump_bbp_start = 0;
static uint32_t g_dump_bbp_end = 0;

static void init_trace_config(void) {
    static int initialized = 0;
    if (initialized) return;
    initialized = 1;
    
    const char* trace_ip = getenv("TRACE_DEST_IP");
    const char* trace_port = getenv("TRACE_DEST_PORT");
    const char* trace_tsi = getenv("TRACE_TSI");
    const char* dump_bbp_start = getenv("DUMP_BBP_START");
    const char* dump_bbp_end = getenv("DUMP_BBP_END");
    
    if (trace_ip) {
        // Parse dotted decimal IP
        unsigned int a, b, c, d;
        if (sscanf(trace_ip, "%u.%u.%u.%u", &a, &b, &c, &d) == 4) {
            g_trace_dest_ip = (a << 24) | (b << 16) | (c << 8) | d;
            DBG_PRINTF("TRACE: Will trace packets to IP %s\n", trace_ip);
        }
    }
    if (trace_port) {
        g_trace_dest_port = (uint16_t)atoi(trace_port);
        DBG_PRINTF("TRACE: Will trace packets to port %u\n", g_trace_dest_port);
    }
    if (trace_tsi) {
        g_trace_tsi = (uint32_t)strtoul(trace_tsi, NULL, 0);  // Supports hex with 0x prefix
        g_trace_tsi_set = 1;
        DBG_PRINTF("TRACE: Will trace packets with TSI %u (0x%x)\n", g_trace_tsi, g_trace_tsi);
    }
    
    if (dump_bbp_start && dump_bbp_end) {
        g_dump_bbp_start = (uint32_t)strtoul(dump_bbp_start, NULL, 0);
        g_dump_bbp_end = (uint32_t)strtoul(dump_bbp_end, NULL, 0);
        DBG_PRINTF("DUMP: Will dump raw BBP data for BBPs %u through %u\n", g_dump_bbp_start, g_dump_bbp_end);
    }
    
    // If any trace filter is set, also enable TSI dumping for first few packets
    if (g_trace_dest_ip != 0 || g_trace_dest_port != 0 || g_trace_tsi_set) {
        DBG_PRINTF("TRACE: Will dump TSIs from first 20 unique streams seen\n");
    }
}

// Track unique TSIs seen for debugging
static uint32_t g_seen_tsis[100];
static int g_seen_tsi_count = 0;
static uint32_t g_trace_checked = 0;
static uint32_t g_trace_matched = 0;

// Check if we should trace this packet
static int should_trace_packet(const uint8_t* ip_header, size_t ip_len) {
    if (g_trace_dest_ip == 0 && g_trace_dest_port == 0 && !g_trace_tsi_set) return 0;
    if (ip_len < 24) return 0;  // Need at least IP header + UDP ports
    
    g_trace_checked++;
    
    uint32_t dest_ip = (ip_header[16] << 24) | (ip_header[17] << 16) | 
                       (ip_header[18] << 8) | ip_header[19];
    
    uint8_t ihl = (ip_header[0] & 0x0F) * 4;
    if (ip_len < (size_t)(ihl + 4)) return 0;
    
    uint16_t dest_port = (ip_header[ihl + 2] << 8) | ip_header[ihl + 3];
    
    // Extract TSI for debugging/filtering
    size_t udp_payload_offset = ihl + 8;
    uint32_t tsi = 0;
    if (ip_len > udp_payload_offset) {
        const uint8_t* udp_payload = ip_header + udp_payload_offset;
        size_t udp_payload_len = ip_len - udp_payload_offset;
        tsi = extract_tsi_from_lct(udp_payload, udp_payload_len);
        
        // Track unique TSIs seen (for debugging)
        if (g_seen_tsi_count < 20) {
            int found = 0;
            for (int i = 0; i < g_seen_tsi_count; i++) {
                if (g_seen_tsis[i] == tsi) { found = 1; break; }
            }
            if (!found && g_seen_tsi_count < 100) {
                g_seen_tsis[g_seen_tsi_count++] = tsi;
                DBG_PRINTF("TRACE: Saw TSI %u (0x%x) -> %d.%d.%d.%d:%d\n",
                        tsi, tsi,
                        ip_header[16], ip_header[17], ip_header[18], ip_header[19], dest_port);
            }
        }
    }
    
    // Check IP filter
    if (g_trace_dest_ip != 0 && dest_ip != g_trace_dest_ip) return 0;
    
    // Check port filter
    if (g_trace_dest_port != 0 && dest_port != g_trace_dest_port) return 0;
    
    // Check TSI filter
    if (g_trace_tsi_set && tsi != g_trace_tsi) return 0;
    
    g_trace_matched++;
    return 1;
}

// Get TSI for display (helper for trace output)
static uint32_t get_packet_tsi(const uint8_t* ip_header, size_t ip_len) {
    uint8_t ihl = (ip_header[0] & 0x0F) * 4;
    size_t udp_payload_offset = ihl + 8;
    if (ip_len <= udp_payload_offset) return 0;
    
    return extract_tsi_from_lct(ip_header + udp_payload_offset, ip_len - udp_payload_offset);
}

static depack_ctx_t* depack_new(void) {
    depack_ctx_t* ctx = calloc(1, sizeof(depack_ctx_t));
    if (!ctx) return NULL;
    
    ctx->preamble_buf = malloc(64 * 1024);
    ctx->tm_buf = malloc(64 * 1024);
    
    ctx->out_alp_capacity = 16 * 1024 * 1024;
    ctx->out_alp = malloc(ctx->out_alp_capacity);
    
    ctx->l1_detail_capacity = 8192;
    ctx->l1_detail = malloc(ctx->l1_detail_capacity);
    
    for (int i = 0; i < MAX_PLPS; i++) {
        ctx->plp[i].pending_data = malloc(CARRYOVER_MAX_SIZE);
        ctx->plp[i].short_frag = malloc(256);
        ctx->bbp[i].buf = malloc(REASSEMBLY_BUFFER_SIZE);
    }
    
    return ctx;
}

static void depack_free(depack_ctx_t* ctx) {
    if (!ctx) return;
    
    free(ctx->preamble_buf);
    free(ctx->tm_buf);
    free(ctx->out_alp);
    free(ctx->alp_times);
    free(ctx->l1_detail);
    
    for (int i = 0; i < MAX_PLPS; i++) {
        free(ctx->plp[i].pending_data);
        free(ctx->plp[i].short_frag);
        free(ctx->bbp[i].buf);
    }
    
    free(ctx);
}

// ============================================================================
// Output an ALP packet (write to output buffer)
// ============================================================================

static void output_alp_packet(depack_ctx_t* ctx, const uint8_t* data, size_t len) {
    if (len < 2 || len > MAX_ALP_PACKET_SIZE) {
        static int bad_len_count = 0;
        if (bad_len_count < 10) {
            bad_len_count++;
            DBG_PRINTF("\n=== REJECT ALP BAD LENGTH #%d ===\n", bad_len_count);
            DBG_PRINTF("len=%zu, BBP #%u, region=%s\n", len,
                    ctx->pkt_source.bbp_num, ctx->pkt_source.region ? ctx->pkt_source.region : "?");
            if (len > 0) {
                DBG_PRINTF("First bytes: ");
                for (size_t i = 0; i < 16 && i < len; i++) {
                    DBG_PRINTF("%02x ", data[i]);
                }
                DBG_PRINTF("\n");
            }
            DBG_PRINTF("================================\n\n");
        }
        ctx->rejected_packets++;
        return;
    }
    
    // Verify this looks like a valid ALP packet
    uint8_t type = (data[0] >> 5) & 0x07;
    if (type == 1 || type == 3 || type == 5) {
        // Reserved types - don't output
        static int reserved_reject_count = 0;
        if (reserved_reject_count < 10) {
            reserved_reject_count++;
            DBG_PRINTF("\n=== REJECTED RESERVED TYPE #%d ===\n", reserved_reject_count);
            DBG_PRINTF("Type: %d, len: %zu, BBP #%u, region=%s\n", type, len,
                    ctx->pkt_source.bbp_num, ctx->pkt_source.region ? ctx->pkt_source.region : "?");
            if (ctx->pkt_source.is_spanning) {
                DBG_PRINTF("Spanning from BBP #%u (%u conts)\n",
                        ctx->pkt_source.start_bbp, ctx->pkt_source.cont_count);
            }
            DBG_PRINTF("First 32 bytes: ");
            for (size_t i = 0; i < 32 && i < len; i++) {
                DBG_PRINTF("%02x ", data[i]);
            }
            DBG_PRINTF("\n==================================\n\n");
        }
        ctx->rejected_packets++;
        return;
    }
    
    // === CORRUPTION DETECTOR ===
    // Look for packets containing gzipped data that has corruption patterns
    // Specifically: valid ASCII/XML followed by garbage bytes
    if (type == 0 && len > 50) {
        size_t hlen, plen;
        size_t total = alp_get_packet_length(data, len, &hlen, &plen);
        
        if (total > 0 && len >= hlen + 28) {  // Need IP + UDP headers
            const uint8_t* ip = data + hlen;
            uint8_t ip_ver = (ip[0] >> 4) & 0x0F;
            uint8_t ihl = (ip[0] & 0x0F) * 4;
            
            if (ip_ver == 4 && ihl >= 20 && len >= hlen + ihl + 8) {
                const uint8_t* udp_payload = ip + ihl + 8;
                size_t udp_payload_len = len - hlen - ihl - 8;
                
                // Scan for corruption pattern: valid text followed by high bytes
                // Look for "time" followed by garbage (your specific example)
                // Also look for any sudden transition from printable ASCII to garbage
                
                int corruption_found = 0;
                size_t corruption_offset = 0;
                const char* corruption_type = NULL;
                
                // Pattern 1: "time" followed by non-ASCII (your specific case)
                for (size_t i = 0; i + 10 < udp_payload_len; i++) {
                    if (udp_payload[i] == 't' && udp_payload[i+1] == 'i' &&
                        udp_payload[i+2] == 'm' && udp_payload[i+3] == 'e') {
                        // Check if followed by garbage
                        int garbage = 0;
                        for (size_t j = i + 4; j < i + 14 && j < udp_payload_len; j++) {
                            uint8_t c = udp_payload[j];
                            // Garbage = non-printable, non-whitespace, non-XML chars
                            if (c >= 0x80 || (c < 0x20 && c != 0x09 && c != 0x0A && c != 0x0D)) {
                                garbage++;
                            }
                        }
                        if (garbage >= 4) {
                            corruption_found = 1;
                            corruption_offset = i + 4;
                            corruption_type = "TIME_PATTERN";
                            break;
                        }
                    }
                }
                
                // Pattern 2: General - long run of printable ASCII then sudden garbage
                if (!corruption_found) {
                    int ascii_run = 0;
                    for (size_t i = 0; i < udp_payload_len; i++) {
                        uint8_t c = udp_payload[i];
                        int is_printable = (c >= 0x20 && c <= 0x7E) || 
                                           c == 0x09 || c == 0x0A || c == 0x0D;
                        
                        if (is_printable) {
                            ascii_run++;
                        } else if (ascii_run > 50) {
                            // Had a good run of ASCII, now hit non-printable
                            // Check if the next several bytes are garbage
                            int garbage = 0;
                            for (size_t j = i; j < i + 10 && j < udp_payload_len; j++) {
                                uint8_t gc = udp_payload[j];
                                if (gc >= 0x80 || (gc < 0x20 && gc != 0x09 && gc != 0x0A && gc != 0x0D)) {
                                    garbage++;
                                }
                            }
                            if (garbage >= 5) {
                                corruption_found = 1;
                                corruption_offset = i;
                                corruption_type = "ASCII_TO_GARBAGE";
                                break;
                            }
                            ascii_run = 0;
                        } else {
                            ascii_run = 0;
                        }
                    }
                }
                
                // Pattern 3: Gzip with suspicious trailer
                if (!corruption_found && udp_payload_len > 20 && 
                    udp_payload[0] == 0x1f && udp_payload[1] == 0x8b) {
                    // It's gzipped - check for corruption in the data
                    // Look for the pattern where deflate stream suddenly has garbage
                    // This is harder to detect, but we can look for unusual byte patterns
                    
                    // Check if the last part looks corrupted (all zeros or all 0xFF)
                    int suspicious_end = 1;
                    for (size_t i = udp_payload_len - 8; i < udp_payload_len; i++) {
                        if (udp_payload[i] != 0x00 && udp_payload[i] != 0xFF) {
                            suspicious_end = 0;
                            break;
                        }
                    }
                    if (suspicious_end) {
                        corruption_found = 1;
                        corruption_offset = udp_payload_len - 8;
                        corruption_type = "GZIP_BAD_TRAILER";
                    }
                }
                
                if (corruption_found) {
                    uint16_t dest_port = (ip[ihl + 2] << 8) | ip[ihl + 3];
                    uint16_t src_port = (ip[ihl + 0] << 8) | ip[ihl + 1];
                    
                    DBG_PRINTF("\n");
                    DBG_PRINTF("╔════════════════════════════════════════════════════════════════════════════════╗\n");
                    DBG_PRINTF("║ *** CORRUPTION DETECTED: %s at UDP offset %zu ***\n", corruption_type, corruption_offset);
                    DBG_PRINTF("╠════════════════════════════════════════════════════════════════════════════════╣\n");
                    DBG_PRINTF("║ PACKET INFO:\n");
                    DBG_PRINTF("║   ALP packet #%u, total length: %zu bytes\n", ctx->out_alp_count + 1, len);
                    DBG_PRINTF("║   ALP header: %zu bytes, payload: %zu bytes\n", hlen, plen);
                    DBG_PRINTF("║   Dest IP: %d.%d.%d.%d:%d\n", ip[16], ip[17], ip[18], ip[19], dest_port);
                    DBG_PRINTF("║   Src IP:  %d.%d.%d.%d:%d\n", ip[12], ip[13], ip[14], ip[15], src_port);
                    DBG_PRINTF("║   UDP payload length: %zu bytes\n", udp_payload_len);
                    DBG_PRINTF("╟────────────────────────────────────────────────────────────────────────────────╢\n");
                    DBG_PRINTF("║ BBP SOURCE INFO:\n");
                    DBG_PRINTF("║   Current BBP: #%u, PLP: %d\n", ctx->pkt_source.bbp_num, ctx->pkt_source.plp);
                    DBG_PRINTF("║   Region: %s\n", ctx->pkt_source.region ? ctx->pkt_source.region : "(none)");
                    if (ctx->pkt_source.is_spanning) {
                        DBG_PRINTF("║   *** SPANNING PACKET ***\n");
                        DBG_PRINTF("║   Started at BBP #%u\n", ctx->pkt_source.start_bbp);
                        DBG_PRINTF("║   Continuations: %u BBPs\n", ctx->pkt_source.cont_count);
                        
                        // Show contribution boundaries
                        int plp_idx = ctx->pkt_source.plp;
                        if (plp_idx >= 0 && plp_idx < MAX_PLPS) {
                            plp_alp_state_t* st = &ctx->plp[plp_idx];
                            if (st->cont_boundary_count > 0) {
                                DBG_PRINTF("║   CONTRIBUTION BOUNDARIES:\n");
                                for (int i = 0; i < st->cont_boundary_count && i < 32; i++) {
                                    size_t start = (i == 0) ? 0 : st->cont_boundaries[i-1];
                                    size_t end = st->cont_boundaries[i];
                                    DBG_PRINTF("║     BBP #%u: bytes %zu-%zu (%zu bytes)\n",
                                           st->cont_bbps[i], start, end-1, end - start);
                                }
                                
                                // Determine which contribution contains the corruption
                                // corruption_offset is in UDP payload; need to map to ALP packet offset
                                size_t alp_corruption_offset = hlen + ihl + 8 + corruption_offset;
                                DBG_PRINTF("║   Corruption at ALP offset %zu (UDP payload offset %zu)\n",
                                       alp_corruption_offset, corruption_offset);
                                for (int i = 0; i < st->cont_boundary_count && i < 32; i++) {
                                    size_t start = (i == 0) ? 0 : st->cont_boundaries[i-1];
                                    size_t end = st->cont_boundaries[i];
                                    if (alp_corruption_offset >= start && alp_corruption_offset < end) {
                                        DBG_PRINTF("║   >>> CORRUPTION IS IN CONTRIBUTION FROM BBP #%u <<<\n",
                                               st->cont_bbps[i]);
                                        break;
                                    }
                                }
                            }
                        }
                    } else {
                        DBG_PRINTF("║   Single-BBP packet (not spanning)\n");
                    }
                    DBG_PRINTF("╟────────────────────────────────────────────────────────────────────────────────╢\n");
                    DBG_PRINTF("║ CORRUPTION LOCATION (UDP payload offset %zu):\n", corruption_offset);
                    
                    // Show context before corruption (as ASCII)
                    size_t ctx_start = corruption_offset > 60 ? corruption_offset - 60 : 0;
                    DBG_PRINTF("║ ASCII before: \"");
                    for (size_t i = ctx_start; i < corruption_offset && i < udp_payload_len; i++) {
                        uint8_t c = udp_payload[i];
                        if (c >= 32 && c <= 126) DBG_PRINTF("%c", c);
                        else if (c == '\n' || c == '\r') DBG_PRINTF(" ");
                        else DBG_PRINTF(".");
                    }
                    DBG_PRINTF("\"\n");
                    
                    // Show the corruption point in hex
                    DBG_PRINTF("║ Hex at corruption: ");
                    for (size_t i = corruption_offset; i < corruption_offset + 32 && i < udp_payload_len; i++) {
                        DBG_PRINTF("%02x ", udp_payload[i]);
                    }
                    DBG_PRINTF("\n");
                    
                    // Show as ASCII too
                    DBG_PRINTF("║ ASCII at corruption: \"");
                    for (size_t i = corruption_offset; i < corruption_offset + 32 && i < udp_payload_len; i++) {
                        uint8_t c = udp_payload[i];
                        if (c >= 32 && c <= 126) DBG_PRINTF("%c", c);
                        else DBG_PRINTF(".");
                    }
                    DBG_PRINTF("\"\n");
                    
                    DBG_PRINTF("╟────────────────────────────────────────────────────────────────────────────────╢\n");
                    DBG_PRINTF("║ FULL ALP PACKET HEX DUMP:\n");
                    for (size_t i = 0; i < len; i++) {
                        if (i % 32 == 0) DBG_PRINTF("║ %04zx: ", i);
                        DBG_PRINTF("%02x ", data[i]);
                        if ((i + 1) % 32 == 0) DBG_PRINTF("\n");
                    }
                    if (len % 32 != 0) DBG_PRINTF("\n");
                    
                    DBG_PRINTF("╟────────────────────────────────────────────────────────────────────────────────╢\n");
                    DBG_PRINTF("║ UDP PAYLOAD ONLY (for analysis):\n");
                    for (size_t i = 0; i < udp_payload_len; i++) {
                        if (i % 32 == 0) DBG_PRINTF("║ %04zx: ", i);
                        DBG_PRINTF("%02x ", udp_payload[i]);
                        if ((i + 1) % 32 == 0) DBG_PRINTF("\n");
                    }
                    if (udp_payload_len % 32 != 0) DBG_PRINTF("\n");
                    
                    DBG_PRINTF("╚════════════════════════════════════════════════════════════════════════════════╝\n\n");
                    
                    // Also dump to a file for easier analysis
                    static int corruption_dump_count = 0;
                    if (corruption_dump_count < 10) {
                        corruption_dump_count++;
                        char filename[256];
                        snprintf(filename, sizeof(filename), "/tmp/corruption_%d_bbp%u.bin", 
                                 corruption_dump_count, ctx->pkt_source.bbp_num);
                        FILE* f = fopen(filename, "wb");
                        if (f) {
                            fwrite(data, 1, len, f);
                            fclose(f);
                            DBG_PRINTF(">>> Dumped to %s\n\n", filename);
                        }
                    }
                }
            }
        }
    }
    // === END CORRUPTION DETECTOR ===
    
    // For IPv4 packets (type 0), validate the IP header
    if (type == 0) {
        // Calculate header length to find IP payload
        size_t hlen, plen;
        size_t total = alp_get_packet_length(data, len, &hlen, &plen);
        
        if (total == 0) {
            static int len_reject_count = 0;
            if (len_reject_count < 10) {
                len_reject_count++;
                DBG_PRINTF("\n=== REJECTED TYPE 0 BAD LENGTH #%d ===\n", len_reject_count);
                DBG_PRINTF("total=%zu, len=%zu\n", total, len);
                DBG_PRINTF("First 16 bytes: ");
                for (size_t i = 0; i < 16 && i < len; i++) {
                    DBG_PRINTF("%02x ", data[i]);
                }
                DBG_PRINTF("\n======================================\n\n");
            }
            ctx->rejected_packets++;
            return;
        }
        
        // Check IP header
        if (hlen < len && len - hlen >= 20) {
            const uint8_t* ip = data + hlen;
            uint8_t version = (ip[0] >> 4) & 0x0F;
            uint8_t ihl = ip[0] & 0x0F;
            
            if (version != 4 || ihl < 5) {
                static int ip_reject_count = 0;
                if (ip_reject_count < 10) {
                    ip_reject_count++;
                    DBG_PRINTF("\n=== REJECTED TYPE 0 BAD IP #%d ===\n", ip_reject_count);
                    DBG_PRINTF("version=%d, ihl=%d\n", version, ihl);
                    DBG_PRINTF("ALP bytes: ");
                    for (size_t i = 0; i < hlen && i < 8; i++) {
                        DBG_PRINTF("%02x ", data[i]);
                    }
                    DBG_PRINTF("| IP bytes: ");
                    for (size_t i = 0; i < 16 && hlen + i < len; i++) {
                        DBG_PRINTF("%02x ", ip[i]);
                    }
                    DBG_PRINTF("\n==================================\n\n");
                }
                ctx->sync_errors++;
                ctx->rejected_packets++;
                return;
            }
            
            // Check destination IP is multicast (224.0.0.0 - 239.255.255.255)
            uint8_t dst_first_octet = ip[16];
            if (dst_first_octet < 224 || dst_first_octet > 239) {
                static int mcast_reject_count = 0;
                if (mcast_reject_count < 10) {
                    mcast_reject_count++;
                    DBG_PRINTF("\n=== REJECTED TYPE 0 NON-MULTICAST #%d ===\n", mcast_reject_count);
                    DBG_PRINTF("dst IP: %d.%d.%d.%d\n", ip[16], ip[17], ip[18], ip[19]);
                    DBG_PRINTF("ALP header: %02x %02x (type=%d, len=%zu)\n",
                            data[0], data[1], type, total);
                    DBG_PRINTF("IP header: ");
                    for (size_t i = 0; i < 20 && hlen + i < len; i++) {
                        DBG_PRINTF("%02x ", ip[i]);
                    }
                    DBG_PRINTF("\n=========================================\n\n");
                }
                ctx->sync_errors++;
                ctx->rejected_packets++;
                return;
            }
            
            // Validate IP total length makes sense
            uint16_t ip_total_len = (ip[2] << 8) | ip[3];
            if (ip_total_len < 20 || ip_total_len > plen) {
                static int iplen_reject_count = 0;
                if (iplen_reject_count < 10) {
                    iplen_reject_count++;
                    DBG_PRINTF("\n=== REJECTED TYPE 0 BAD IP LEN #%d ===\n", iplen_reject_count);
                    DBG_PRINTF("ip_total_len=%d, plen=%zu\n", ip_total_len, plen);
                    DBG_PRINTF("First 20 bytes: ");
                    for (size_t i = 0; i < 20 && i < len; i++) {
                        DBG_PRINTF("%02x ", data[i]);
                    }
                    DBG_PRINTF("\n=====================================\n\n");
                }
                ctx->sync_errors++;
                ctx->rejected_packets++;
                return;
            }
        }
    }
    
    // For signaling packets (type 4), do basic sanity check
    if (type == 4) {
        size_t hlen, plen;
        size_t total = alp_get_packet_length(data, len, &hlen, &plen);
        if (total == 0 || plen < 2) {
            VERBOSE("  REJECT ALP type 4: signaling packet too small (total=%zu plen=%zu)\n", total, plen);
            ctx->rejected_packets++;
            return;
        }
        VERBOSE("  ACCEPT ALP type 4 (signaling): len=%zu hlen=%zu plen=%zu\n", len, hlen, plen);
        
        // Dump short type 4 packets (len < 64) - these are suspicious
        static int type4_short_dumped = 0;
        if (len < 64 && type4_short_dumped < 10) {
            type4_short_dumped++;
            DBG_PRINTF("\n=== Short Type 4 Packet #%d ===\n", type4_short_dumped);
            DBG_PRINTF("Total length: %zu, header: %zu, payload: %zu\n", len, hlen, plen);
            DBG_PRINTF("All %zu bytes: ", len);
            for (size_t i = 0; i < len; i++) {
                DBG_PRINTF("%02x ", data[i]);
            }
            DBG_PRINTF("\n");
            DBG_PRINTF("================================\n\n");
        }
        
        // Dump first type 4 packet we see (for debugging LMT)
        static int type4_dumped = 0;
        if (!type4_dumped) {
            type4_dumped = 1;
            DBG_PRINTF("\n=== First Type 4 (Signaling) Packet Hex Dump ===\n");
            DBG_PRINTF("Total length: %zu, header: %zu, payload: %zu\n", len, hlen, plen);
            DBG_PRINTF("Bytes: ");
            for (size_t i = 0; i < len && i < 64; i++) {
                DBG_PRINTF("%02x ", data[i]);
                if ((i + 1) % 16 == 0) DBG_PRINTF("\n       ");
            }
            if (len > 64) DBG_PRINTF("... (%zu more bytes)", len - 64);
            DBG_PRINTF("\n");
            
            // Parse signaling header (after ALP header)
            if (len > hlen + 1) {
                uint8_t sig_type = data[hlen];
                uint8_t sig_info = (len > hlen + 1) ? data[hlen + 1] : 0;
                DBG_PRINTF("Signaling type byte: 0x%02x\n", sig_type);
                // For LLS, byte after header is table_id
                if ((sig_type & 0x01) == 0x01) {  // LLS indicator
                    uint8_t table_id = sig_info;
                    DBG_PRINTF("LLS table_id: %d (0x%02x)\n", table_id, table_id);
                    if (table_id == 254) DBG_PRINTF("*** This is LMT! ***\n");
                }
            }
            DBG_PRINTF("=================================================\n\n");
        }
    }
    
    // Track ROUTE packets that might contain S-TSID
    // S-TSID comes via ROUTE (type 0 IPv4) to specific multicast addresses
    // Set TRACE_STSID=239.255.7.1:8000 to filter to specific destination
    if (type == 0) {
        static uint32_t stsid_filter_ip = 0;
        static uint16_t stsid_filter_port = 0;
        static int stsid_filter_initialized = 0;
        
        if (!stsid_filter_initialized) {
            stsid_filter_initialized = 1;
            const char* trace_stsid = getenv("TRACE_STSID");
            if (trace_stsid) {
                unsigned int a, b, c, d, port;
                if (sscanf(trace_stsid, "%u.%u.%u.%u:%u", &a, &b, &c, &d, &port) == 5) {
                    stsid_filter_ip = (a << 24) | (b << 16) | (c << 8) | d;
                    stsid_filter_port = (uint16_t)port;
                    DBG_PRINTF("\n*** S-TSID TRACKING: Filtering to %s ***\n\n", trace_stsid);
                }
            }
        }
        
        // Skip if filter is set and this packet doesn't match
        if (stsid_filter_ip != 0) {
            size_t hlen_chk, plen_chk;
            alp_get_packet_length(data, len, &hlen_chk, &plen_chk);
            
            if (len > hlen_chk + 24) {
                const uint8_t* ip = data + hlen_chk;
                uint32_t dest_ip = (ip[16] << 24) | (ip[17] << 16) | (ip[18] << 8) | ip[19];
                uint8_t ihl = (ip[0] & 0x0F) * 4;
                uint16_t dest_port = (len > hlen_chk + ihl + 4) ? 
                                     (ip[ihl + 2] << 8) | ip[ihl + 3] : 0;
                
                if (dest_ip == stsid_filter_ip && dest_port == stsid_filter_port) {
                    // This packet matches our filter - dump it
                    static int filtered_stsid_count = 0;
                    filtered_stsid_count++;
                    
                    uint16_t ip_total_len = (ip[2] << 8) | ip[3];
                    uint16_t udp_len = (ip[ihl + 4] << 8) | ip[ihl + 5];
                    size_t udp_payload_len = len - hlen_chk - ihl - 8;
                    const uint8_t* udp_payload = ip + ihl + 8;
                    
                    DBG_PRINTF("\n╔══════════════════════════════════════════════════════════════╗\n");
                    DBG_PRINTF("║ TRACED PACKET #%d to %d.%d.%d.%d:%d                           \n", 
                           filtered_stsid_count, ip[16], ip[17], ip[18], ip[19], dest_port);
                    DBG_PRINTF("╠══════════════════════════════════════════════════════════════╣\n");
                    DBG_PRINTF("║ ALP total: %zu (hlen=%zu, plen=%zu)\n", len, hlen_chk, plen_chk);
                    DBG_PRINTF("║ IP total_length: %u, UDP length: %u\n", ip_total_len, udp_len);
                    DBG_PRINTF("║ UDP payload size: %zu\n", udp_payload_len);
                    DBG_PRINTF("╟──────────────────────────────────────────────────────────────╢\n");
                    DBG_PRINTF("║ Source: BBP #%u, PLP %d, region=%s\n",
                           ctx->pkt_source.bbp_num, ctx->pkt_source.plp,
                           ctx->pkt_source.region ? ctx->pkt_source.region : "?");
                    if (ctx->pkt_source.is_spanning) {
                        DBG_PRINTF("║ *** SPANNING: Started BBP #%u, %u continuations ***\n",
                               ctx->pkt_source.start_bbp, ctx->pkt_source.cont_count);
                    }
                    
                    // Length validation
                    if (ip_total_len != plen_chk) {
                        DBG_PRINTF("║ ⚠️  ALP/IP MISMATCH: IP=%u, ALP plen=%zu\n", ip_total_len, plen_chk);
                    }
                    if (udp_len != udp_payload_len + 8) {
                        DBG_PRINTF("║ ⚠️  UDP MISMATCH: hdr=%u, actual=%zu\n", udp_len, udp_payload_len + 8);
                    }
                    
                    DBG_PRINTF("╟──────────────────────────────────────────────────────────────╢\n");
                    DBG_PRINTF("║ Last 150 bytes as ASCII:\n║ ");
                    size_t start = (udp_payload_len > 150) ? udp_payload_len - 150 : 0;
                    for (size_t i = start; i < udp_payload_len; i++) {
                        uint8_t c = udp_payload[i];
                        if (c >= 32 && c <= 126) DBG_PRINTF("%c", c);
                        else if (c == '\n' || c == '\r') DBG_PRINTF(" ");
                        else DBG_PRINTF(".");
                    }
                    DBG_PRINTF("\n");
                    DBG_PRINTF("╚══════════════════════════════════════════════════════════════╝\n\n");
                }
            }
        }
    }
    
    // Debug: After outputting type 4, show what would come next in the buffer
    // (This helps debug why type 7 follows)
    static int post_type4_debug = 0;
    if (type == 4 && !post_type4_debug) {
        post_type4_debug = 1;
        // We can't easily see what's next from here, but we'll add debug in the parsing loop
    }
    
    // Trace matching type 0 packets
    if (type == 0) {
        size_t hlen, plen;
        alp_get_packet_length(data, len, &hlen, &plen);
        if (hlen < len && should_trace_packet(data + hlen, len - hlen)) {
            const uint8_t* ip = data + hlen;
            uint8_t ihl = (ip[0] & 0x0F) * 4;
            uint16_t dest_port = (len > hlen + ihl + 4) ? (ip[ihl + 2] << 8) | ip[ihl + 3] : 0;
            uint16_t ip_total_len = (ip[2] << 8) | ip[3];
            uint32_t tsi = get_packet_tsi(ip, len - hlen);
            
            DBG_PRINTF("\n=== TRACE: OUTPUT ALP PACKET ===\n");
            DBG_PRINTF("Dest: %d.%d.%d.%d:%d, TSI: %u (0x%x)\n", 
                    ip[16], ip[17], ip[18], ip[19], dest_port, tsi, tsi);
            DBG_PRINTF("ALP len=%zu (hlen=%zu, plen=%zu), IP total_len=%u\n", 
                    len, hlen, plen, ip_total_len);
            DBG_PRINTF("Source: PLP %d, BBP #%u", ctx->pkt_source.plp, ctx->pkt_source.bbp_num);
            if (ctx->pkt_source.is_spanning) {
                DBG_PRINTF(" (SPANNING from BBP #%u, %u continuations, region=%s)\n",
                        ctx->pkt_source.start_bbp, ctx->pkt_source.cont_count,
                        ctx->pkt_source.region ? ctx->pkt_source.region : "?");
            } else {
                DBG_PRINTF(" (single-BBP, region=%s)\n",
                        ctx->pkt_source.region ? ctx->pkt_source.region : "?");
            }
            
            // Show packet structure
            DBG_PRINTF("ALP header: ");
            for (size_t i = 0; i < hlen && i < 8; i++) DBG_PRINTF("%02x ", data[i]);
            DBG_PRINTF("\nIP header: ");
            for (size_t i = 0; i < 20 && hlen + i < len; i++) DBG_PRINTF("%02x ", ip[i]);
            DBG_PRINTF("\nUDP header+payload start: ");
            for (size_t i = ihl; i < ihl + 32 && hlen + i < len; i++) DBG_PRINTF("%02x ", ip[i]);
            DBG_PRINTF("\n");
            
            // Check for truncation
            if (ip_total_len != plen) {
                DBG_PRINTF("*** WARNING: IP total_len (%u) != ALP plen (%zu) ***\n", ip_total_len, plen);
            }
            if (len < hlen + ip_total_len) {
                DBG_PRINTF("*** WARNING: Packet truncated! Have %zu bytes, IP says %zu ***\n",
                        len, hlen + ip_total_len);
            }
            DBG_PRINTF("=================================\n\n");
        }
    }
    
    // Ensure capacity
    if (ctx->out_alp_size + len > ctx->out_alp_capacity) {
        size_t new_cap = ctx->out_alp_capacity * 2;
        uint8_t* new_buf = realloc(ctx->out_alp, new_cap);
        if (!new_buf) return;
        ctx->out_alp = new_buf;
        ctx->out_alp_capacity = new_cap;
    }
    
    // Debug: dump unexpected packet types that shouldn't be in this stream
    if (type == 2 || type == 6 || type == 7) {
        static int unexpected_type_count = 0;
        if (unexpected_type_count < 20) {
            unexpected_type_count++;
            DBG_PRINTF("\n=== UNEXPECTED ALP TYPE %d (#%d) ===\n", type, unexpected_type_count);
            DBG_PRINTF("BBP #%u, PLP %d, region=%s\n", 
                    ctx->pkt_source.bbp_num, ctx->pkt_source.plp,
                    ctx->pkt_source.region ? ctx->pkt_source.region : "?");
            if (ctx->pkt_source.is_spanning) {
                DBG_PRINTF("Spanning from BBP #%u (%u continuations)\n",
                        ctx->pkt_source.start_bbp, ctx->pkt_source.cont_count);
            }
            DBG_PRINTF("Packet len=%zu, first 32 bytes:\n", len);
            for (size_t i = 0; i < 32 && i < len; i++) {
                DBG_PRINTF("%02x ", data[i]);
            }
            DBG_PRINTF("\n");
            // Also show what the ALP header decodes to
            if (len >= 2) {
                uint8_t b0 = data[0], b1 = data[1];
                DBG_PRINTF("ALP decode: type=%d PC=%d HM/bit3=%d len_msb=%d len_lsb=%d\n",
                        (b0 >> 5) & 0x07, (b0 >> 4) & 0x01, (b0 >> 3) & 0x01,
                        b0 & 0x07, b1);
                DBG_PRINTF("11-bit length = %d\n", ((b0 & 0x07) << 8) | b1);
            }
            DBG_PRINTF("=====================================\n\n");
        }
        
        // Type 7 (MPEG-TS) validation: check for 0x47 sync bytes
        if (type == 7) {
            size_t hdr_size = ((data[0] >> 3) & 0x01) ? 2 : 1;  // HDME determines header size
            uint8_t pc = (data[0] >> 4) & 0x01;
            
            if (pc == 0) {
                // Direct TS mode - payload should be TS packets starting with 0x47
                if (len > hdr_size) {
                    uint8_t first_payload_byte = data[hdr_size];
                    if (first_payload_byte != 0x47) {
                        static int ts_reject_count = 0;
                        if (ts_reject_count < 10) {
                            ts_reject_count++;
                            DBG_PRINTF("\n*** REJECTING FAKE TYPE 7 #%d ***\n", ts_reject_count);
                            DBG_PRINTF("First payload byte is 0x%02x, not 0x47 (TS sync)\n", first_payload_byte);
                            DBG_PRINTF("This is likely misaligned parsing hitting random data\n");
                            DBG_PRINTF("*********************************\n\n");
                        }
                        ctx->rejected_packets++;
                        ctx->sync_errors++;
                        return;  // Don't output this garbage
                    }
                }
            } else {
                // Packetized TS mode - also should have 0x47 sync bytes
                // For PC=1, header is 2 bytes, then TS data
                if (len > 2 && data[2] != 0x47) {
                    static int ts_pc1_reject_count = 0;
                    if (ts_pc1_reject_count < 10) {
                        ts_pc1_reject_count++;
                        DBG_PRINTF("\n*** REJECTING FAKE TYPE 7 PC=1 #%d ***\n", ts_pc1_reject_count);
                        DBG_PRINTF("Byte at offset 2 is 0x%02x, not 0x47 (TS sync)\n", data[2]);
                        DBG_PRINTF("*********************************\n\n");
                    }
                    ctx->rejected_packets++;
                    ctx->sync_errors++;
                    return;
                }
            }
        }
    }
    
    // Capture time = arrival of the outer packet that completed this ALP packet
    if (ctx->alp_times_count == ctx->alp_times_cap) {
        size_t nc = ctx->alp_times_cap ? ctx->alp_times_cap * 2 : 65536;
        stltp_alp_time_t* nt = realloc(ctx->alp_times, nc * sizeof(*nt));
        if (nt) { ctx->alp_times = nt; ctx->alp_times_cap = nc; }
    }
    if (ctx->alp_times_count < ctx->alp_times_cap) {
        ctx->alp_times[ctx->alp_times_count].offset = ctx->out_alp_size;
        ctx->alp_times[ctx->alp_times_count].ts_us = ctx->cur_ts_us;
        ctx->alp_times_count++;
    }

    memcpy(ctx->out_alp + ctx->out_alp_size, data, len);
    ctx->out_alp_size += len;
    ctx->out_alp_count++;
    ctx->alp_type_counts[type]++;
    
    if (ctx->pkt_source.is_spanning) {
        VERBOSE("  OUTPUT ALP: BBP #%u type=%d len=%zu total=%u (spanning from #%u, %u conts)\n", 
                ctx->pkt_source.bbp_num, type, len, ctx->out_alp_count,
                ctx->pkt_source.start_bbp, ctx->pkt_source.cont_count);
    } else {
        VERBOSE("  OUTPUT ALP: BBP #%u type=%d len=%zu total=%u\n", 
                ctx->pkt_source.bbp_num, type, len, ctx->out_alp_count);
    }
}

// ============================================================================
// Process Baseband Packet - Extract ALP packets
// ============================================================================

/**
 * Process a complete Baseband Packet and extract ALP packets.
 * 
 * Per A/322 Section 5.2:
 * - BBP header contains pointer to first NEW ALP packet
 * - Bytes before pointer are continuation of previous ALP packet
 * - Pointer = max (127 or 8191) means no new ALP packet starts
 * 
 * BBP Header structure per A/322 Section 5.2.2:
 * Mode 0 (1 byte): [mode=0(1)][pointer(7)]
 * Mode 1 (2+ bytes): [mode=1(1)][pointer_lsb(7)] [pointer_msb(6)][OFI(2)]
 *   OFI=00: No extension
 *   OFI=01: Short ext [ext_type(3)][ext_len(5)] + ext_len bytes
 *   OFI=10: Long ext [ext_type(3)][ext_len_lsb(5)][ext_len_msb(8)] + ext_len bytes
 *   OFI=11: Mixed ext [num_ext(3)][ext_len_lsb(5)][ext_len_msb(8)] + ext_len bytes
 */
static void process_bbp(depack_ctx_t* ctx, int plp, const uint8_t* data, size_t len) {
    if (len < 1 || plp < 0 || plp >= MAX_PLPS) return;
    
    // Note: an earlier version rejected any BBP whose first byte was 0x45 as a
    // probable tunnel misparse. 0x45 is a valid base field (mode 0, pointer 69),
    // so that check silently dropped good BBPs. Removed in v15.

    ctx->bbp_count++;
    plp_alp_state_t* st = &ctx->plp[plp];
    
    // Detailed BBP dump for debugging
    int do_dump = (g_dump_bbp_start > 0 && g_dump_bbp_end > 0 &&
                   ctx->bbp_count >= g_dump_bbp_start && ctx->bbp_count <= g_dump_bbp_end);
    
    if (do_dump) {
        DBG_PRINTF("\n");
        DBG_PRINTF("================================================================================\n");
        DBG_PRINTF("BBP #%u RAW DUMP (PLP %d, len=%zu)\n", ctx->bbp_count, plp, len);
        DBG_PRINTF("================================================================================\n");
        
        // State before processing
        DBG_PRINTF("PENDING STATE BEFORE:\n");
        DBG_PRINTF("  pending_size=%zu, pending_expected=%zu\n", st->pending_size, st->pending_expected);
        if (st->pending_size > 0 && st->pending_expected > 0) {
            DBG_PRINTF("  need %zu more bytes to complete\n", st->pending_expected - st->pending_size);
            DBG_PRINTF("  started at BBP #%u\n", st->pending_start_bbp);
            
            // Show what type of ALP packet is pending
            if (st->pending_size >= 2) {
                uint8_t pkt_type = (st->pending_data[0] >> 5) & 0x07;
                DBG_PRINTF("  pending ALP type=%d\n", pkt_type);
                
                // If type 0 (IP), show more info
                if (pkt_type == 0 && st->pending_size >= st->pending_header_len + 20) {
                    const uint8_t* ip = st->pending_data + st->pending_header_len;
                    uint8_t ihl = (ip[0] & 0x0F) * 4;
                    if (st->pending_size >= st->pending_header_len + ihl + 4) {
                        uint16_t dst_port = (ip[ihl + 2] << 8) | ip[ihl + 3];
                        DBG_PRINTF("  pending IP dest: %d.%d.%d.%d:%d\n", 
                               ip[16], ip[17], ip[18], ip[19], dst_port);
                    }
                }
                
                // Show last 64 bytes of pending data as ASCII
                DBG_PRINTF("  pending data last 64 ASCII: \"");
                size_t start = st->pending_size > 64 ? st->pending_size - 64 : 0;
                for (size_t i = start; i < st->pending_size; i++) {
                    uint8_t c = st->pending_data[i];
                    DBG_PRINTF("%c", (c >= 32 && c <= 126) ? c : '.');
                }
                DBG_PRINTF("\"\n");
            }
        }
        DBG_PRINTF("\n");
        
        // Raw header bytes (first 16)
        DBG_PRINTF("RAW HEADER (first 16 bytes):\n  ");
        for (size_t i = 0; i < 16 && i < len; i++) {
            DBG_PRINTF("%02x ", data[i]);
        }
        DBG_PRINTF("\n\n");
        
        // Full raw dump - complete
        DBG_PRINTF("RAW DATA (%zu bytes):\n", len);
        for (size_t i = 0; i < len; i++) {
            if (i % 32 == 0) DBG_PRINTF("  %04zx: ", i);
            DBG_PRINTF("%02x ", data[i]);
            if ((i + 1) % 32 == 0) DBG_PRINTF("\n");
        }
        if (len % 32 != 0) DBG_PRINTF("\n");
        DBG_PRINTF("\n");
    }
    
    const uint8_t* p = data;
    size_t remaining = len;
    
    // Track extension info for debugging discards
    uint8_t bbp_ext_type = 0;
    uint16_t bbp_ext_len = 0;
    const uint8_t* bbp_ext_data = NULL;
    
    // Parse base field byte 0
    uint8_t b0 = *p++;
    remaining--;
    
    uint8_t mode = (b0 >> 7) & 0x01;
    uint16_t pointer = b0 & 0x7F;
    uint16_t max_ptr;
    
    if (mode == 0) {
        // Mode 0: 7-bit pointer, 1 byte header total
        max_ptr = 0x7F;
    } else {
        // Mode 1: 13-bit pointer, at least 2 bytes header
        if (remaining < 1) return;
        uint8_t b1 = *p++;
        remaining--;
        
        pointer |= ((b1 >> 2) & 0x3F) << 7;
        max_ptr = 0x1FFF;  // 8191
        
        uint8_t ofi = b1 & 0x03;
        
        // Handle optional extension field
        if (ofi != 0x00) {
            if (remaining < 1) return;
            uint8_t ext_byte0 = *p++;
            remaining--;
            
            uint8_t ext_type = (ext_byte0 >> 5) & 0x07;
            uint16_t ext_len = ext_byte0 & 0x1F;
            
            if (ofi == 0x02 || ofi == 0x03) {
                // Long or Mixed extension mode - 13-bit ext_len
                if (remaining < 1) return;
                uint8_t ext_byte1 = *p++;
                remaining--;
                ext_len |= (ext_byte1 << 5);
            }
            
            // Save extension info for discard debugging
            bbp_ext_type = ext_type;
            bbp_ext_len = ext_len;
            bbp_ext_data = p;  // Points to extension content
            
            // Sanity check: extension length should not be larger than remaining payload
            // If it is, the header is likely corrupt - skip extensions
            if (ext_len > remaining) {
                VERBOSE("  BBP: ext_len %u > remaining %zu, ignoring extension (likely corrupt)\n", 
                        ext_len, remaining);
                // Don't skip - treat remaining as payload
            } else if (ext_len > 0) {
                // Debug: verify padding extension content
                static int ext_debug_count = 0;
                if (ext_type == 7 && ext_len > 100 && ext_debug_count < 3) {
                    ext_debug_count++;
                    DBG_PRINTF("\n=== BBP Extension Debug #%d ===\n", ext_debug_count);
                    DBG_PRINTF("ext_type=%d (padding), ext_len=%u\n", ext_type, ext_len);
                    
                    // Count how many 0x00 bytes vs non-zero
                    size_t zero_count = 0;
                    size_t nonzero_count = 0;
                    for (size_t i = 0; i < ext_len && i < remaining; i++) {
                        if (p[i] == 0x00) zero_count++;
                        else nonzero_count++;
                    }
                    DBG_PRINTF("Content: %zu zeros, %zu non-zeros\n", zero_count, nonzero_count);
                    
                    // Show first 32 bytes
                    DBG_PRINTF("First 32 bytes: ");
                    for (size_t i = 0; i < 32 && i < ext_len && i < remaining; i++) {
                        DBG_PRINTF("%02x ", p[i]);
                    }
                    DBG_PRINTF("\n");
                    
                    // Show last 32 bytes
                    if (ext_len > 64) {
                        DBG_PRINTF("Last 32 bytes:  ");
                        size_t start = (ext_len < remaining ? ext_len : remaining) - 32;
                        for (size_t i = 0; i < 32; i++) {
                            DBG_PRINTF("%02x ", p[start + i]);
                        }
                        DBG_PRINTF("\n");
                    }
                    DBG_PRINTF("================================\n\n");
                }
                
                // Skip extension bytes
                // ext_type=7 means padding
                p += ext_len;
                remaining -= ext_len;
            }
            
            (void)ext_type;  // We just skip extension data for now
        }
    }
    
    // p now points to payload, remaining is payload length
    const uint8_t* payload = p;
    size_t payload_len = remaining;
    
    // Debug: show BBP header bytes for cases with warnings
    size_t hdr_len = p - data;
    
    // Detailed dump: show our interpretation
    if (do_dump) {
        DBG_PRINTF("HEADER INTERPRETATION:\n");
        DBG_PRINTF("  mode=%d, pointer=%u (0x%x), max_ptr=%u\n", mode, pointer, pointer, max_ptr);
        DBG_PRINTF("  header_len=%zu, payload_len=%zu\n", hdr_len, payload_len);
        if (bbp_ext_len > 0) {
            DBG_PRINTF("  extension: type=%d, len=%u\n", bbp_ext_type, bbp_ext_len);
        }
        DBG_PRINTF("\n");
        
        DBG_PRINTF("PAYLOAD REGIONS:\n");
        if (pointer == max_ptr) {
            DBG_PRINTF("  pointer=max: entire payload (%zu bytes) is continuation\n", payload_len);
        } else {
            DBG_PRINTF("  pre-pointer region: bytes 0-%u (%u bytes)\n", pointer > 0 ? pointer-1 : 0, pointer);
            DBG_PRINTF("  post-pointer region: bytes %u-%zu (%zu bytes)\n", pointer, payload_len-1, payload_len - pointer);
        }
        DBG_PRINTF("\n");
        
        // Show pre-pointer region content
        if (pointer > 0 && pointer != max_ptr) {
            DBG_PRINTF("PRE-POINTER REGION (%u bytes):\n", pointer);
            for (size_t i = 0; i < pointer && i < payload_len; i++) {
                if (i % 32 == 0) DBG_PRINTF("  %04zx: ", i);
                DBG_PRINTF("%02x ", payload[i]);
                if ((i + 1) % 32 == 0) DBG_PRINTF("\n");
            }
            if (pointer % 32 != 0) DBG_PRINTF("\n");
            DBG_PRINTF("\n");
        }
        
        // Show post-pointer region content
        if (pointer < payload_len) {
            size_t post_len = payload_len - pointer;
            DBG_PRINTF("POST-POINTER REGION (%zu bytes):\n", post_len);
            for (size_t i = 0; i < post_len; i++) {
                if (i % 32 == 0) DBG_PRINTF("  %04zx: ", pointer + i);
                DBG_PRINTF("%02x ", payload[pointer + i]);
                if ((i + 1) % 32 == 0) DBG_PRINTF("\n");
            }
            if (post_len % 32 != 0) DBG_PRINTF("\n");
            DBG_PRINTF("\n");
        }
        
        DBG_PRINTF("--------------------------------------------------------------------------------\n");
    }
    
    if (g_verbose) {
        DBG_PRINTF("BBP #%u PLP%d: len=%zu mode=%d ptr=%u payload=%zu pending=%zu (hdr=%zu bytes: ",
                ctx->bbp_count, plp, len, mode, pointer, payload_len, st->pending_size, hdr_len);
        for (size_t i = 0; i < hdr_len && i < 8; i++) {
            DBG_PRINTF("%02x ", data[i]);
        }
        DBG_PRINTF(")\n");
    } else {
        VERBOSE("BBP #%u PLP%d: len=%zu mode=%d ptr=%u payload=%zu pending=%zu\n",
                ctx->bbp_count, plp, len, mode, pointer, payload_len, st->pending_size);
    }
    
    // Case 1: Pointer = max -> entire payload is continuation
    if (pointer == max_ptr) {
        // Update BBP tracking for this PLP
        plp_bbp_state_t* bbp_st = &ctx->bbp[plp];
        bbp_st->last_bbp_num = ctx->bbp_count;
        bbp_st->bbp_num_valid = 1;
        
        // Header split across BBPs: finish it so the packet length is known
        if (st->pending_size > 0 && st->pending_expected == 0) {
            size_t used = alp_pending_complete_header(st, payload, payload_len);
            payload += used;
            payload_len -= used;
        }
        
        if (st->pending_size > 0 && st->pending_expected > 0) {
            size_t need = st->pending_expected - st->pending_size;
            size_t copy = (payload_len < need) ? payload_len : need;
            memcpy(st->pending_data + st->pending_size, payload, copy);
            st->pending_size += copy;
            st->pending_cont_count++;
            
            // Track contribution boundary
            if (st->cont_boundary_count < 32) {
                st->cont_boundaries[st->cont_boundary_count] = st->pending_size;
                st->cont_bbps[st->cont_boundary_count] = ctx->bbp_count;
                st->cont_boundary_count++;
            }
            
            if (st->pending_size >= st->pending_expected) {
                // Debug: check if this is an LLS packet completing
                uint8_t pkt_type = (st->pending_data[0] >> 5) & 0x07;
                if (pkt_type == 0 && st->pending_expected > 22) {
                    size_t hlen_chk, plen_chk;
                    alp_get_packet_length(st->pending_data, st->pending_expected, &hlen_chk, &plen_chk);
                    if (hlen_chk + 19 < st->pending_expected) {
                        const uint8_t* ip = st->pending_data + hlen_chk;
                        if (ip[16] == 224 && ip[17] == 0 && ip[18] == 23 && ip[19] == 60) {
                            DBG_PRINTF("\n=== LLS SPANNING PACKET COMPLETE (ptr=max) ===\n");
                            DBG_PRINTF("Started BBP #%u, completed BBP #%u (%u continuations)\n",
                                    st->pending_start_bbp, ctx->bbp_count, st->pending_cont_count);
                            DBG_PRINTF("Total size: %zu bytes\n", st->pending_expected);
                            uint16_t ip_len = (ip[2] << 8) | ip[3];
                            DBG_PRINTF("IP total_length field: %u\n", ip_len);
                            DBG_PRINTF("Last 32 bytes: ");
                            size_t start = st->pending_expected > 32 ? st->pending_expected - 32 : 0;
                            for (size_t i = start; i < st->pending_expected; i++) {
                                DBG_PRINTF("%02x ", st->pending_data[i]);
                            }
                            DBG_PRINTF("\n");
                            // For ptr=max, remaining bytes after completing pending (if any)
                            size_t leftover = payload_len - copy;
                            if (leftover > 0) {
                                DBG_PRINTF("Leftover %zu bytes after pending: ", leftover);
                                const uint8_t* left = payload + copy;
                                for (size_t i = 0; i < 32 && i < leftover; i++) {
                                    DBG_PRINTF("%02x ", left[i]);
                                }
                                DBG_PRINTF("\n");
                            } else {
                                DBG_PRINTF("(ptr=max: no post-ptr in this BBP, next pkt in future BBP)\n");
                            }
                            DBG_PRINTF("==============================================\n\n");
                        }
                    }
                }
                
                // Set packet source for tracing
                ctx->pkt_source.plp = plp;
                ctx->pkt_source.bbp_num = ctx->bbp_count;
                ctx->pkt_source.start_bbp = st->pending_start_bbp;
                ctx->pkt_source.cont_count = st->pending_cont_count;
                ctx->pkt_source.is_spanning = 1;
                ctx->pkt_source.region = "ptr=max";
                
                output_alp_packet(ctx, st->pending_data, st->pending_expected);
                ctx->spanning_complete++;
                st->pending_size = 0;
                st->pending_expected = 0;
            }
        } else if (payload_len > 0) {
            // No pending packet but we have continuation data - orphan
            ctx->orphan_continuations++;
            VERBOSE("  BBP #%u Orphan continuation (ptr=max): %zu bytes\n", ctx->bbp_count, payload_len);
        }
        return;
    }
    
    // Validate pointer
    if (pointer > payload_len) {
        VERBOSE("  ERROR: pointer %u > payload_len %zu, resetting state\n", pointer, payload_len);
        ctx->sync_errors++;
        st->pending_size = 0;
        st->pending_expected = 0;
        st->short_frag_size = 0;
        return;
    }
    
    // === Process Pre-Pointer Region (continuation bytes) ===
    if (pointer > 0) {
        const uint8_t* pre_ptr = payload;
        size_t pre_len = pointer;
        
        // NOTE: short_frag is NOT prepended here.
        // short_frag contains leftover bytes from the PREVIOUS BBP's post-pointer
        // parsing (i.e., the START of a new ALP packet header). It has nothing to
        // do with continuation data. The short_frag will be discarded in the
        // post-pointer section since we're starting fresh with new packets there.
        //
        // The pre-pointer region contains CONTINUATION bytes for a spanning ALP
        // packet - prepending short_frag here would corrupt that packet!
        
        // CRITICAL: Validate that this pre-pointer data belongs to the pending packet
        // by checking for discontinuity in BBP sequence for this PLP
        plp_bbp_state_t* bbp_st = &ctx->bbp[plp];
        if (st->pending_size > 0 && st->pending_expected > 0 && bbp_st->bbp_num_valid) {
            // Check if there's a gap in BBPs for this PLP
            uint32_t expected_bbp = bbp_st->last_bbp_num + 1;
            // Allow some gap for interleaved PLPs - but if gap is too large, it's suspicious
            // Typically PLPs alternate, so gap of 2-4 is normal. Gap > 10 suggests packet loss.
            uint32_t bbp_gap = ctx->bbp_count - expected_bbp;
            
            // Also check if the pending packet's start BBP matches our tracking
            // If the pending packet started many BBPs ago but our last_bbp was different,
            // there may have been a discontinuity
            if (bbp_gap > 10 && st->pending_start_bbp != bbp_st->last_bbp_num) {
                static int discontinuity_warnings = 0;
                if (discontinuity_warnings < 20) {
                    discontinuity_warnings++;
                    DBG_PRINTF("\n=== BBP DISCONTINUITY DETECTED (PLP %d) #%d ===\n", plp, discontinuity_warnings);
                    DBG_PRINTF("Last BBP for PLP: #%u, Current BBP: #%u (gap=%u)\n",
                           bbp_st->last_bbp_num, ctx->bbp_count, bbp_gap);
                    DBG_PRINTF("Pending packet started at BBP #%u\n", st->pending_start_bbp);
                    DBG_PRINTF("Pre-pointer region first 32 bytes: ");
                    for (size_t i = 0; i < 32 && i < pre_len; i++) {
                        DBG_PRINTF("%02x ", pre_ptr[i]);
                    }
                    DBG_PRINTF("\nPending data last 32 bytes: ");
                    size_t start = st->pending_size > 32 ? st->pending_size - 32 : 0;
                    for (size_t i = start; i < st->pending_size; i++) {
                        DBG_PRINTF("%02x ", st->pending_data[i]);
                    }
                    DBG_PRINTF("\n");
                    
                    // Check for obvious mismatch: if pending data is text/XML and pre-ptr is binary
                    int pending_is_text = 0;
                    int preptr_is_text = 0;
                    
                    // Sample last 64 bytes of pending for printable chars
                    size_t sample_start = st->pending_size > 64 ? st->pending_size - 64 : 0;
                    int printable = 0;
                    for (size_t i = sample_start; i < st->pending_size; i++) {
                        uint8_t c = st->pending_data[i];
                        if ((c >= 0x20 && c <= 0x7e) || c == '\n' || c == '\r' || c == '\t') printable++;
                    }
                    if (printable > (int)(st->pending_size - sample_start) * 70 / 100) pending_is_text = 1;
                    
                    // Sample first 64 bytes of pre-ptr
                    printable = 0;
                    size_t sample_len = pre_len > 64 ? 64 : pre_len;
                    for (size_t i = 0; i < sample_len; i++) {
                        uint8_t c = pre_ptr[i];
                        if ((c >= 0x20 && c <= 0x7e) || c == '\n' || c == '\r' || c == '\t') printable++;
                    }
                    if (printable > (int)sample_len * 70 / 100) preptr_is_text = 1;
                    
                    DBG_PRINTF("Content analysis: pending=%s, pre-ptr=%s\n",
                           pending_is_text ? "TEXT" : "BINARY",
                           preptr_is_text ? "TEXT" : "BINARY");
                    
                    if (pending_is_text && !preptr_is_text) {
                        DBG_PRINTF(">>> MISMATCH: Text packet getting binary continuation - DISCARDING <<<\n");
                        DBG_PRINTF("===================================================\n\n");
                        
                        // Discard the pending packet and pre-pointer data
                        st->pending_size = 0;
                        st->pending_expected = 0;
                        st->cont_boundary_count = 0;
                        ctx->sync_errors++;
                        
                        // Update BBP tracking
                        bbp_st->last_bbp_num = ctx->bbp_count;
                        
                        // Skip to post-pointer processing
                        goto process_post_pointer;
                    }
                    DBG_PRINTF("===================================================\n\n");
                }
            }
        }
        // Update BBP tracking for this PLP
        bbp_st->last_bbp_num = ctx->bbp_count;
        bbp_st->bbp_num_valid = 1;
        
        const uint8_t* region = pre_ptr;
        size_t region_len = pre_len;
        
        // Header split across BBPs: finish it so the packet length is known
        if (st->pending_size > 0 && st->pending_expected == 0) {
            size_t used = alp_pending_complete_header(st, region, region_len);
            region += used;
            region_len -= used;
        }
        
        if (st->pending_size > 0 && st->pending_expected > 0) {
            // We have a pending packet - append continuation bytes
            size_t need = st->pending_expected - st->pending_size;
            size_t copy = (region_len < need) ? region_len : need;
            
            VERBOSE("  BBP #%u Pre-pointer: %zu bytes, pending needs %zu more, copying %zu\n", 
                    ctx->bbp_count, region_len, need, copy);
            
            memcpy(st->pending_data + st->pending_size, region, copy);
            st->pending_size += copy;
            st->pending_cont_count++;
            
            // Track contribution boundary
            if (st->cont_boundary_count < 32) {
                st->cont_boundaries[st->cont_boundary_count] = st->pending_size;
                st->cont_bbps[st->cont_boundary_count] = ctx->bbp_count;
                st->cont_boundary_count++;
            }
            
            if (st->pending_size >= st->pending_expected) {
                // Debug: check if this is an LLS packet completing
                uint8_t pkt_type = (st->pending_data[0] >> 5) & 0x07;
                if (pkt_type == 0 && st->pending_expected > 22) {
                    size_t hlen_chk, plen_chk;
                    alp_get_packet_length(st->pending_data, st->pending_expected, &hlen_chk, &plen_chk);
                    if (hlen_chk + 19 < st->pending_expected) {
                        const uint8_t* ip = st->pending_data + hlen_chk;
                        if (ip[16] == 224 && ip[17] == 0 && ip[18] == 23 && ip[19] == 60) {
                            DBG_PRINTF("\n=== LLS SPANNING PACKET COMPLETE (pre-ptr) ===\n");
                            DBG_PRINTF("Started BBP #%u, completed BBP #%u (%u continuations)\n",
                                    st->pending_start_bbp, ctx->bbp_count, st->pending_cont_count);
                            DBG_PRINTF("Total size: %zu bytes\n", st->pending_expected);
                            uint16_t ip_len = (ip[2] << 8) | ip[3];
                            DBG_PRINTF("IP total_length field: %u\n", ip_len);
                            DBG_PRINTF("Last 32 bytes: ");
                            size_t start = st->pending_expected > 32 ? st->pending_expected - 32 : 0;
                            for (size_t i = start; i < st->pending_expected; i++) {
                                DBG_PRINTF("%02x ", st->pending_data[i]);
                            }
                            DBG_PRINTF("\n");
                            // Show next 32 bytes (start of post-pointer region)
                            const uint8_t* post_ptr = payload + pointer;
                            size_t post_len = payload_len - pointer;
                            DBG_PRINTF("Next 32 bytes (post-ptr): ");
                            for (size_t i = 0; i < 32 && i < post_len; i++) {
                                DBG_PRINTF("%02x ", post_ptr[i]);
                            }
                            if (post_len > 0) {
                                uint8_t next_type = (post_ptr[0] >> 5) & 0x07;
                                DBG_PRINTF("\n  -> Next byte 0x%02x = type %d", post_ptr[0], next_type);
                            }
                            DBG_PRINTF("\n==============================================\n\n");
                        }
                    }
                }
                
                // Packet complete!
                ctx->pkt_source.plp = plp;
                ctx->pkt_source.bbp_num = ctx->bbp_count;
                ctx->pkt_source.start_bbp = st->pending_start_bbp;
                ctx->pkt_source.cont_count = st->pending_cont_count;
                ctx->pkt_source.is_spanning = 1;
                ctx->pkt_source.region = "pre-ptr";
                
                output_alp_packet(ctx, st->pending_data, st->pending_expected);
                ctx->spanning_complete++;
                st->pending_size = 0;
                st->pending_expected = 0;
            }
            
            // Any remaining bytes in pre_ptr region after completing pending?
            // Per A/322, these are PADDING between end of continuation and the pointer.
            // Do NOT try to parse them as ALP packets.
            if (copy < region_len) {
                size_t padding_bytes = region_len - copy;
                VERBOSE("  BBP #%u Pre-ptr padding: %zu bytes (skipping)\n",
                        ctx->bbp_count, padding_bytes);
            }
        } else if (st->pending_size > 0) {
            // We have pending data but don't know expected length
            // Append and try to parse header
            size_t space = CARRYOVER_MAX_SIZE - st->pending_size;
            size_t copy = (region_len < space) ? region_len : space;
            memcpy(st->pending_data + st->pending_size, region, copy);
            st->pending_size += copy;
            
            // Try to determine length
            if (st->pending_size >= 2) {
                size_t hlen, plen;
                size_t total = alp_get_packet_length(st->pending_data, st->pending_size, &hlen, &plen);
                if (total > 0) {
                    st->pending_expected = total;
                    st->pending_header_len = hlen;
                    
                    if (st->pending_size >= total) {
                        ctx->pkt_source.plp = plp;
                        ctx->pkt_source.bbp_num = ctx->bbp_count;
                        ctx->pkt_source.start_bbp = st->pending_start_bbp;
                        ctx->pkt_source.cont_count = st->pending_cont_count;
                        ctx->pkt_source.is_spanning = 1;
                        ctx->pkt_source.region = "pre-ptr-deferred";
                        
                        output_alp_packet(ctx, st->pending_data, total);
                        ctx->spanning_complete++;
                        st->pending_size = 0;
                        st->pending_expected = 0;
                    }
                }
            }
        } else {
            // No pending packet - these are orphan continuation bytes
            // This happens at start of stream or after discontinuity
            VERBOSE("  BBP #%u Orphan continuation: %zu bytes (discarding)\n", ctx->bbp_count, region_len);
        }
        
        // Note: No memory to free - region points directly to payload
    }
    
process_post_pointer:
    // === Process Post-Pointer Region (new ALP packets) ===
    {
    const uint8_t* post_ptr = payload + pointer;
    size_t post_len = payload_len - pointer;
    
    VERBOSE("  BBP #%u Post-pointer: %zu bytes at offset %u\n", ctx->bbp_count, post_len, pointer);
    
    // Debug: show first bytes of post-pointer after completing a spanning packet
    static int post_span_debug = 0;
    if (st->pending_size == 0 && st->pending_expected == 0 && post_span_debug < 5) {
        // We just completed a spanning packet (or had none)
        // Show what's at the start of post-pointer
        if (post_len > 0) {
            post_span_debug++;
            DBG_PRINTF("  [DEBUG] Post-pointer first 20 bytes: ");
            for (size_t i = 0; i < 20 && i < post_len; i++) {
                DBG_PRINTF("%02x ", post_ptr[i]);
            }
            DBG_PRINTF("\n");
        }
    }
    
    // Prepend any short fragment from previous BBP
    uint8_t* work = NULL;
    size_t work_len = 0;
    
    if (st->short_frag_size > 0) {
        // We have leftover bytes from the previous BBP.
        // When pointer == 0, this BBP starts with a NEW ALP packet,
        // so the short_frag bytes are orphaned (can't be completed).
        // When pointer > 0, the pre-pointer region is continuation data,
        // but that's for a spanning packet (in pending_data), not short_frag.
        // In either case, short_frag bytes should be DISCARDED.
        static int short_frag_discard_count = 0;
        if (short_frag_discard_count < 5) {
            short_frag_discard_count++;
            DBG_PRINTF("  [INFO] Discarding %zu short_frag byte(s) from previous BBP: ",
                   st->short_frag_size);
            for (size_t i = 0; i < st->short_frag_size; i++) {
                DBG_PRINTF("%02x ", st->short_frag[i]);
            }
            DBG_PRINTF("(BBP #%u, pointer=%u)\n", ctx->bbp_count, pointer);
        }
        st->short_frag_size = 0;
    }
    
    work = (uint8_t*)post_ptr;
    work_len = post_len;
    
    // Clear any existing pending (new ALP packets start here)
    // If pending wasn't completed by pre-pointer region, it's a discontinuity
    if (st->pending_size > 0) {
        ctx->spanning_discarded++;
        
        // Check if this was an LLS packet being discarded
        uint8_t pkt_type = (st->pending_data[0] >> 5) & 0x07;
        bool is_lls = false;
        bool should_trace = false;
        
        if (pkt_type == 0 && st->pending_size > 22 && st->pending_header_len > 0) {
            const uint8_t* ip = st->pending_data + st->pending_header_len;
            if (st->pending_header_len + 19 < st->pending_size) {
                if (ip[16] == 224 && ip[17] == 0 && ip[18] == 23 && ip[19] == 60) {
                    is_lls = true;
                }
                should_trace = should_trace_packet(ip, st->pending_size - st->pending_header_len);
            }
        }
        
        if (is_lls) {
            DBG_PRINTF("\n=== WARNING: DISCARDING INCOMPLETE LLS PACKET ===\n");
            DBG_PRINTF("Started BBP #%u, discarding at BBP #%u\n", 
                    st->pending_start_bbp, ctx->bbp_count);
            DBG_PRINTF("Had %zu of %zu expected bytes (%zu missing)\n",
                    st->pending_size, st->pending_expected, 
                    st->pending_expected - st->pending_size);
            DBG_PRINTF("First 32 bytes: ");
            for (size_t i = 0; i < 32 && i < st->pending_size; i++) {
                DBG_PRINTF("%02x ", st->pending_data[i]);
            }
            DBG_PRINTF("\n=================================================\n\n");
        } else if (should_trace) {
            const uint8_t* ip = st->pending_data + st->pending_header_len;
            uint8_t ihl = (ip[0] & 0x0F) * 4;
            uint16_t dest_port = (st->pending_size > st->pending_header_len + ihl + 4) ?
                                 (ip[ihl + 2] << 8) | ip[ihl + 3] : 0;
            uint32_t tsi = get_packet_tsi(ip, st->pending_size - st->pending_header_len);
            DBG_PRINTF("\n=== TRACE: DISCARDING INCOMPLETE PACKET ===\n");
            DBG_PRINTF("Dest: %d.%d.%d.%d:%d, TSI: %u (0x%x)\n", 
                    ip[16], ip[17], ip[18], ip[19], dest_port, tsi, tsi);
            DBG_PRINTF("Started BBP #%u, discarding at BBP #%u (PLP %d)\n", 
                    st->pending_start_bbp, ctx->bbp_count, plp);
            DBG_PRINTF("Had %zu of %zu expected bytes (%zu missing, %.1f%% complete)\n",
                    st->pending_size, st->pending_expected, 
                    st->pending_expected - st->pending_size,
                    100.0 * st->pending_size / st->pending_expected);
            DBG_PRINTF("First 48 bytes: ");
            for (size_t i = 0; i < 48 && i < st->pending_size; i++) {
                DBG_PRINTF("%02x ", st->pending_data[i]);
            }
            DBG_PRINTF("\n============================================\n\n");
        } else {
            // Log first 20 discards regardless of type for debugging
            static int general_discard_count = 0;
            if (general_discard_count < 20) {
                general_discard_count++;
                DBG_PRINTF("\n=== DISCARD #%d ===\n", general_discard_count);
                DBG_PRINTF("Started BBP #%u, discarding at BBP #%u (PLP %d)\n", 
                        st->pending_start_bbp, ctx->bbp_count, plp);
                DBG_PRINTF("Had %zu of %zu expected bytes (%zu missing)\n",
                        st->pending_size, st->pending_expected, 
                        st->pending_expected - st->pending_size);
                DBG_PRINTF("ALP type=%d\n", pkt_type);
                
                // Show first 48 bytes
                DBG_PRINTF("First 48 bytes:\n  ");
                for (size_t i = 0; i < 48 && i < st->pending_size; i++) {
                    DBG_PRINTF("%02x ", st->pending_data[i]);
                    if ((i + 1) % 16 == 0) DBG_PRINTF("\n  ");
                }
                DBG_PRINTF("\n");
                
                // Show last 48 bytes (where the discontinuity happens)
                if (st->pending_size > 48) {
                    size_t start = st->pending_size - 48;
                    DBG_PRINTF("Last 48 bytes (offset %zu):\n  ", start);
                    for (size_t i = 0; i < 48; i++) {
                        DBG_PRINTF("%02x ", st->pending_data[start + i]);
                        if ((i + 1) % 16 == 0) DBG_PRINTF("\n  ");
                    }
                    DBG_PRINTF("\n");
                }
                
                // Show what was in current BBP's pre-pointer region
                DBG_PRINTF("Current BBP pre-ptr region (%u bytes, ptr=%u):\n  ", pointer, pointer);
                const uint8_t* pre_ptr_data = payload;
                for (size_t i = 0; i < (size_t)pointer && i < 64; i++) {
                    DBG_PRINTF("%02x ", pre_ptr_data[i]);
                    if ((i + 1) % 16 == 0) DBG_PRINTF("\n  ");
                }
                if (pointer > 64) DBG_PRINTF("... (truncated)");
                DBG_PRINTF("\n");
                
                // Show start of post-pointer region for context
                DBG_PRINTF("Post-ptr start (first 32 bytes):\n  ");
                const uint8_t* post_ptr_data = payload + pointer;
                size_t post_len = payload_len - pointer;
                for (size_t i = 0; i < 32 && i < post_len; i++) {
                    DBG_PRINTF("%02x ", post_ptr_data[i]);
                }
                DBG_PRINTF("\n");
                
                // Show BBP extension info
                if (bbp_ext_len > 0) {
                    DBG_PRINTF("BBP Extension: type=%d len=%u\n", bbp_ext_type, bbp_ext_len);
                    
                    // Check if extension contains non-zero data that might be the missing bytes
                    size_t missing = st->pending_expected - st->pending_size;
                    if (bbp_ext_data && bbp_ext_len >= missing) {
                        // Check last 'missing' bytes of extension for non-zero data
                        size_t check_start = bbp_ext_len - missing;
                        size_t nonzero = 0;
                        for (size_t i = check_start; i < bbp_ext_len; i++) {
                            if (bbp_ext_data[i] != 0x00) nonzero++;
                        }
                        DBG_PRINTF("Extension last %zu bytes (where missing data might be): %zu non-zeros\n", 
                                missing, nonzero);
                        if (nonzero > 0) {
                            DBG_PRINTF("  Last %zu bytes of extension:\n  ", missing < 64 ? missing : (size_t)64);
                            size_t show_start = bbp_ext_len > 64 ? bbp_ext_len - 64 : 0;
                            for (size_t i = show_start; i < bbp_ext_len && i - show_start < 64; i++) {
                                DBG_PRINTF("%02x ", bbp_ext_data[i]);
                                if ((i - show_start + 1) % 16 == 0) DBG_PRINTF("\n  ");
                            }
                            DBG_PRINTF("\n");
                        }
                    }
                }
                DBG_PRINTF("==================\n\n");
            }
            VERBOSE("  BBP #%u Discarding incomplete pending packet (%zu bytes)\n", ctx->bbp_count, st->pending_size);
        }
        st->pending_size = 0;
        st->pending_expected = 0;
    }
    
    // Parse ALP packets from post-pointer region
    size_t pos = 0;
    
    // Track last successfully parsed packet for debugging misalignments
    static size_t last_good_pos = 0;
    static size_t last_good_len = 0;
    static uint8_t last_good_type = 0;
    static uint32_t last_good_bbp = 0;
    
    // Debug: track first packet position in this BBP
    int first_packet_in_bbp = 1;
    
    // Debug: Check if first byte of post-pointer looks suspicious
    // A valid ALP packet should start with type 0 (0x00-0x1F) or type 4 (0x80-0x9F)
    // But type 4 with length 0 (0x80 0x00) is suspicious
    if (work_len > 2 && work[0] == 0x80 && work[1] == 0x00) {
        static int suspicious_start_count = 0;
        if (suspicious_start_count < 10) {
            suspicious_start_count++;
            DBG_PRINTF("\n╔══════════════════════════════════════════════════════════════╗\n");
            DBG_PRINTF("║ SUSPICIOUS BBP START #%d (BBP #%u, PLP %d)                    ║\n",
                   suspicious_start_count, ctx->bbp_count, plp);
            DBG_PRINTF("╠══════════════════════════════════════════════════════════════╣\n");
            DBG_PRINTF("║ Post-ptr starts with 0x80 0x00 (type 4, len=0) - very unusual!\n");
            DBG_PRINTF("║ This might be an extraneous byte causing misalignment.\n");
            DBG_PRINTF("╟──────────────────────────────────────────────────────────────╢\n");
            DBG_PRINTF("║ BBP info: len=%zu, mode=%d, pointer=%u\n", len, mode, pointer);
            DBG_PRINTF("║ BBP header was %zu bytes\n", hdr_len);
            DBG_PRINTF("║ Raw BBP header bytes: ");
            for (size_t i = 0; i < hdr_len && i < 16; i++) {
                DBG_PRINTF("%02x ", data[i]);
            }
            DBG_PRINTF("\n");
            DBG_PRINTF("╟──────────────────────────────────────────────────────────────╢\n");
            DBG_PRINTF("║ First 64 bytes of payload (post-ptr):\n║ ");
            for (size_t i = 0; i < 64 && i < work_len; i++) {
                DBG_PRINTF("%02x ", work[i]);
                if ((i+1) % 16 == 0 && i < 63) DBG_PRINTF("\n║ ");
            }
            DBG_PRINTF("\n");
            DBG_PRINTF("╟──────────────────────────────────────────────────────────────╢\n");
            DBG_PRINTF("║ If byte[1:2] is '00 64' and byte[3:4] is '45 00', then:\n");
            DBG_PRINTF("║   -> There's an extra 0x80 byte at the start!\n");
            DBG_PRINTF("║   -> Real packet: type 0, len=100, starts at offset 1\n");
            if (work_len > 4 && work[1] == 0x00 && work[3] == 0x45 && work[4] == 0x00) {
                DBG_PRINTF("║ *** CONFIRMED: Extra byte at start! ***\n");
                DBG_PRINTF("║ Bytes 1-4: %02x %02x %02x %02x (ALP hdr + IP start)\n",
                       work[1], work[2], work[3], work[4]);
                uint16_t alp_len = ((work[1] & 0x07) << 8) | work[2];
                DBG_PRINTF("║ ALP length field at offset 1: %u\n", alp_len);
            }
            DBG_PRINTF("╚══════════════════════════════════════════════════════════════╝\n\n");
        }
    }
    
    while (pos < work_len) {
        // Skip stuffing bytes
        while (pos < work_len && work[pos] == 0xFF) pos++;
        if (pos >= work_len) break;
        
        // Debug: dump raw bytes when we first see a type 4 packet
        uint8_t peek_type = (work[pos] >> 5) & 0x07;
        static int raw_type4_dump = 0;
        if (peek_type == 4 && !raw_type4_dump) {
            raw_type4_dump = 1;
            DBG_PRINTF("\n=== Raw bytes at type 4 packet start in BBP ===\n");
            DBG_PRINTF("Position in work buffer: %zu, work_len: %zu\n", pos, work_len);
            DBG_PRINTF("Raw 80 bytes starting at type 4: ");
            for (size_t i = 0; i < 80 && pos + i < work_len; i++) {
                DBG_PRINTF("%02x ", work[pos + i]);
                if ((i + 1) % 16 == 0) DBG_PRINTF("\n                                   ");
            }
            DBG_PRINTF("\n");
            DBG_PRINTF("==============================================\n\n");
        }
        
        // Debug: For type 0 packets going to LLS multicast, dump extra context
        // to diagnose length mismatches
        if (peek_type == 0 && work_len - pos >= 24) {
            // Peek at what would be the IP dest address
            // First need to figure out ALP header length
            uint8_t b0 = work[pos];
            uint8_t pc = (b0 >> 4) & 0x01;
            uint8_t hm = (b0 >> 3) & 0x01;
            size_t peek_hlen = 2;
            if (pc == 0 && hm == 1) peek_hlen = 3;
            
            if (pos + peek_hlen + 19 < work_len) {
                const uint8_t* peek_ip = work + pos + peek_hlen;
                // Check for LLS multicast 224.0.23.60
                if (peek_ip[16] == 224 && peek_ip[17] == 0 && peek_ip[18] == 23 && peek_ip[19] == 60) {
                    // This is an LLS packet - dump extensive context
                    static int lls_context_dump = 0;
                    if (lls_context_dump < 5) {
                        lls_context_dump++;
                        uint16_t alp_len = ((b0 & 0x07) << 8) | work[pos + 1];
                        uint16_t ip_len = (peek_ip[2] << 8) | peek_ip[3];
                        
                        DBG_PRINTF("\n=== LLS PACKET CONTEXT DUMP #%d (BBP #%u) ===\n", 
                                lls_context_dump, ctx->bbp_count);
                        DBG_PRINTF("Position in work buffer: %zu (work_len=%zu)\n", pos, work_len);
                        DBG_PRINTF("ALP byte0=0x%02x: type=%d PC=%d HM=%d len_msb=%d\n",
                                b0, peek_type, pc, hm, b0 & 0x07);
                        DBG_PRINTF("ALP byte1=0x%02x: len_lsb=%d\n", work[pos+1], work[pos+1]);
                        DBG_PRINTF("ALP 11-bit length field: %u (payload bytes)\n", alp_len);
                        DBG_PRINTF("ALP header size: %zu, total ALP packet: %zu\n", peek_hlen, peek_hlen + alp_len);
                        DBG_PRINTF("IP total_length field: %u\n", ip_len);
                        if (alp_len != ip_len) {
                            DBG_PRINTF("*** LENGTH MISMATCH: ALP says %u, IP says %u ***\n", alp_len, ip_len);
                        }
                        DBG_PRINTF("\n20 bytes BEFORE this position: ");
                        for (size_t i = (pos >= 20 ? pos - 20 : 0); i < pos; i++) {
                            DBG_PRINTF("%02x ", work[i]);
                        }
                        DBG_PRINTF("\n60 bytes STARTING at this position: ");
                        for (size_t i = 0; i < 60 && pos + i < work_len; i++) {
                            DBG_PRINTF("%02x ", work[pos + i]);
                        }
                        DBG_PRINTF("\n==============================================\n\n");
                    }
                }
            }
        }
        
        size_t remaining = work_len - pos;
        if (alp_header_incomplete(work + pos, remaining)) {
            // ALP header split across BBPs. Per A/322 the next BBP's pointer marks
            // the first packet that STARTS there, so the rest of this packet is in
            // the next BBP's pre-pointer region. Carry it as a pending packet whose
            // length becomes known once the header is complete.
            // (Earlier versions saved this as short_frag and then discarded it.)
            memcpy(st->pending_data, work + pos, remaining);
            st->pending_size = remaining;
            st->pending_expected = 0;
            st->pending_header_len = 0;
            st->pending_start_bbp = ctx->bbp_count;
            st->pending_cont_count = 0;
            st->cont_boundary_count = 1;
            st->cont_boundaries[0] = remaining;
            st->cont_bbps[0] = ctx->bbp_count;
            ctx->spanning_started++;
            break;
        }
        
        size_t hlen, plen;
        size_t total = alp_get_packet_length(work + pos, remaining, &hlen, &plen);
        uint8_t pkt_type = (work[pos] >> 5) & 0x07;
        
        if (total == 0) {
            // Parse error - skip one byte and try to resync
            static int sync_error_count = 0;
            
            if (sync_error_count < 20) {
                sync_error_count++;
                DBG_PRINTF("\n╔══════════════════════════════════════════════════════════════╗\n");
                DBG_PRINTF("║ SYNC ERROR #%d (BBP #%u, PLP %d)                               \n", 
                       sync_error_count, ctx->bbp_count, plp);
                DBG_PRINTF("╠══════════════════════════════════════════════════════════════╣\n");
                DBG_PRINTF("║ Position: %zu / %zu in work buffer\n", pos, work_len);
                DBG_PRINTF("║ Byte at pos: 0x%02x (would be type %d)\n", 
                       work[pos], (work[pos] >> 5) & 0x07);
                DBG_PRINTF("╟──────────────────────────────────────────────────────────────╢\n");
                DBG_PRINTF("║ 32 bytes at error position:\n║ ");
                for (size_t i = 0; i < 32 && pos + i < work_len; i++) {
                    DBG_PRINTF("%02x ", work[pos + i]);
                    if ((i+1) % 16 == 0 && i < 31) DBG_PRINTF("\n║ ");
                }
                DBG_PRINTF("\n");
                DBG_PRINTF("╟──────────────────────────────────────────────────────────────╢\n");
                DBG_PRINTF("║ 32 bytes BEFORE error (context):\n║ ");
                size_t ctx_start = (pos >= 32) ? pos - 32 : 0;
                for (size_t i = ctx_start; i < pos; i++) {
                    DBG_PRINTF("%02x ", work[i]);
                    if ((i - ctx_start + 1) % 16 == 0) DBG_PRINTF("\n║ ");
                }
                DBG_PRINTF("\n");
                
                // Look for valid ALP headers nearby
                DBG_PRINTF("╟──────────────────────────────────────────────────────────────╢\n");
                DBG_PRINTF("║ Scanning for valid ALP starts (type 0 or 4) nearby:\n");
                for (size_t scan = pos; scan < work_len - 2 && scan < pos + 64; scan++) {
                    uint8_t b = work[scan];
                    uint8_t t = (b >> 5) & 0x07;
                    if (t == 0 || t == 4) {
                        // Check if next byte looks reasonable (not 0xFF, not 0x00)
                        uint8_t b1 = work[scan + 1];
                        if (b1 != 0xFF && b1 != 0x00) {
                            DBG_PRINTF("║   Offset +%zu: 0x%02x (type %d)\n", scan - pos, b, t);
                        }
                    }
                }
                DBG_PRINTF("╚══════════════════════════════════════════════════════════════╝\n\n");
            }
            ctx->sync_errors++;
            pos++;
            continue;
        }
        
        if (total > remaining) {
            // Packet extends beyond BBP - save as pending
            // But sanity check - ALP packets shouldn't be huge
            if (total > 65535) {
                VERBOSE("  REJECT: Unreasonable spanning size %zu (type=%d), skipping\n", total, pkt_type);
                ctx->sync_errors++;
                pos++;  // Skip one byte and try to resync
                continue;
            }
            memcpy(st->pending_data, work + pos, remaining);
            st->pending_size = remaining;
            st->pending_expected = total;
            st->pending_header_len = hlen;
            st->pending_start_bbp = ctx->bbp_count;
            st->pending_cont_count = 0;
            
            // Initialize contribution tracking
            st->cont_boundary_count = 1;
            st->cont_boundaries[0] = remaining;  // First contribution ends here
            st->cont_bbps[0] = ctx->bbp_count;
            
            ctx->spanning_started++;
            
            // Trace matching packets
            if (pkt_type == 0 && remaining > hlen + 24) {
                const uint8_t* ip_start = work + pos + hlen;
                if (should_trace_packet(ip_start, remaining - hlen)) {
                    uint8_t ihl = (ip_start[0] & 0x0F) * 4;
                    uint16_t dest_port = (ip_start[ihl + 2] << 8) | ip_start[ihl + 3];
                    uint32_t tsi = get_packet_tsi(ip_start, remaining - hlen);
                    DBG_PRINTF("\n=== TRACE: SPANNING START (BBP #%u, PLP %d) ===\n", ctx->bbp_count, plp);
                    DBG_PRINTF("Dest: %d.%d.%d.%d:%d, TSI: %u (0x%x)\n", 
                            ip_start[16], ip_start[17], ip_start[18], ip_start[19], dest_port, tsi, tsi);
                    DBG_PRINTF("Expected total: %zu, have: %zu, need: %zu more\n", 
                            total, remaining, total - remaining);
                    DBG_PRINTF("ALP type=%d, hlen=%zu, plen=%zu\n", pkt_type, hlen, plen);
                    DBG_PRINTF("First 48 bytes: ");
                    for (size_t i = 0; i < 48 && pos + i < work_len; i++) {
                        DBG_PRINTF("%02x ", work[pos + i]);
                    }
                    DBG_PRINTF("\n================================================\n\n");
                }
            }
            
            // Debug: dump info for LLS-bound packets (type 0 going to 224.0.23.60)
            if (pkt_type == 0 && remaining >= 22) {
                // Check if dest IP is 224.0.23.60 (LLS multicast)
                const uint8_t* ip_start = work + pos + hlen;
                if (remaining > hlen + 19) {
                    uint8_t dst_ip[4] = {ip_start[16], ip_start[17], ip_start[18], ip_start[19]};
                    if (dst_ip[0] == 224 && dst_ip[1] == 0 && dst_ip[2] == 23 && dst_ip[3] == 60) {
                        DBG_PRINTF("\n=== LLS SPANNING PACKET START (BBP #%u) ===\n", ctx->bbp_count);
                        DBG_PRINTF("Expected total: %zu, have: %zu, need: %zu more\n", 
                                total, remaining, total - remaining);
                        DBG_PRINTF("ALP header (%zu bytes): ", hlen);
                        for (size_t i = 0; i < hlen && pos + i < work_len; i++) {
                            DBG_PRINTF("%02x ", work[pos + i]);
                        }
                        DBG_PRINTF("\nFirst 32 bytes of IP: ");
                        for (size_t i = 0; i < 32 && pos + hlen + i < work_len; i++) {
                            DBG_PRINTF("%02x ", work[pos + hlen + i]);
                        }
                        DBG_PRINTF("\n================================================\n\n");
                    }
                }
            }
            
            VERBOSE("  BBP #%u: Spanning packet: have %zu, need %zu (type=%d first_bytes=%02x %02x %02x %02x)\n", 
                    ctx->bbp_count, remaining, total, pkt_type,
                    work[pos], pos+1 < work_len ? work[pos+1] : 0,
                    pos+2 < work_len ? work[pos+2] : 0, pos+3 < work_len ? work[pos+3] : 0);
            break;
        }
        
        // Complete packet - output it
        // But first, validate that it's actually a real ALP packet
        // (not misaligned data that happens to look like a valid header)
        
        // Type 7 (MPEG-TS) sanity check: must have 0x47 sync bytes
        if (pkt_type == 7) {
            size_t ts_hdr_size = ((work[pos] >> 3) & 0x01) ? 2 : 1;  // HDME
            uint8_t ts_pc = (work[pos] >> 4) & 0x01;
            
            size_t ts_data_offset = ts_pc ? 2 : ts_hdr_size;
            if (pos + ts_data_offset < work_len) {
                uint8_t first_ts_byte = work[pos + ts_data_offset];
                if (first_ts_byte != 0x47) {
                    // This is NOT a real MPEG-TS packet - it's misaligned data
                    static int fake_ts_count = 0;
                    if (fake_ts_count < 10) {
                        fake_ts_count++;
                        DBG_PRINTF("\n╔══════════════════════════════════════════════════════════════╗\n");
                        DBG_PRINTF("║ FAKE TYPE 7 DETECTED #%d (BBP #%u, PLP %d)                    ║\n", 
                               fake_ts_count, ctx->bbp_count, plp);
                        DBG_PRINTF("╠══════════════════════════════════════════════════════════════╣\n");
                        DBG_PRINTF("║ Position in work buffer: %zu / %zu\n", pos, work_len);
                        DBG_PRINTF("║ BBP pointer was: %u (post-ptr starts at byte %u)\n", pointer, pointer);
                        DBG_PRINTF("║ First packet in this BBP's post-ptr region: %s\n", 
                               first_packet_in_bbp ? "YES" : "no");
                        DBG_PRINTF("╟──────────────────────────────────────────────────────────────╢\n");
                        DBG_PRINTF("║ Byte 0x%02x at offset %zu is not 0x47 (TS sync)\n", 
                               first_ts_byte, ts_data_offset);
                        DBG_PRINTF("║ This 0x%02x byte was misinterpreted as ALP type 7\n", work[pos]);
                        DBG_PRINTF("║ Would have skipped %zu bytes - RECOVERING instead\n", total);
                        DBG_PRINTF("╟──────────────────────────────────────────────────────────────╢\n");
                        DBG_PRINTF("║ PREVIOUS PACKET (from last good parse):\n");
                        DBG_PRINTF("║   BBP #%u, pos=%zu, len=%zu, type=%d\n",
                               last_good_bbp, last_good_pos, last_good_len, last_good_type);
                        if (last_good_bbp == ctx->bbp_count) {
                            DBG_PRINTF("║   (same BBP) Expected next: pos %zu, actual: %zu\n",
                                   last_good_pos + last_good_len, pos);
                            if (pos != last_good_pos + last_good_len) {
                                DBG_PRINTF("║   *** POSITION MISMATCH! ***\n");
                            }
                        } else {
                            DBG_PRINTF("║   (different BBP - last good was in earlier BBP)\n");
                        }
                        DBG_PRINTF("╟──────────────────────────────────────────────────────────────╢\n");
                        if (last_good_bbp == ctx->bbp_count && last_good_pos < work_len) {
                            DBG_PRINTF("║ Last good packet bytes (first 48):\n║ ");
                            for (size_t i = 0; i < 48 && last_good_pos + i < work_len; i++) {
                                DBG_PRINTF("%02x ", work[last_good_pos + i]);
                                if ((i+1) % 16 == 0 && i < 47) DBG_PRINTF("\n║ ");
                            }
                            DBG_PRINTF("\n");
                        }
                        DBG_PRINTF("╟──────────────────────────────────────────────────────────────╢\n");
                        DBG_PRINTF("║ 48 bytes BEFORE current position:\n║ ");
                        size_t ctx_start = (pos >= 48) ? pos - 48 : 0;
                        for (size_t i = ctx_start; i < pos; i++) {
                            DBG_PRINTF("%02x ", work[i]);
                            if ((i - ctx_start + 1) % 16 == 0) DBG_PRINTF("\n║ ");
                        }
                        DBG_PRINTF("\n");
                        DBG_PRINTF("╟──────────────────────────────────────────────────────────────╢\n");
                        DBG_PRINTF("║ 48 bytes at current (bad) position:\n║ ");
                        for (size_t i = 0; i < 48 && pos + i < work_len; i++) {
                            DBG_PRINTF("%02x ", work[pos + i]);
                            if ((i+1) % 16 == 0 && i < 47) DBG_PRINTF("\n║ ");
                        }
                        DBG_PRINTF("\n");
                        DBG_PRINTF("╚══════════════════════════════════════════════════════════════╝\n\n");
                    }
                    ctx->sync_errors++;
                    pos++;  // Skip one byte and resync
                    continue;
                }
            }
        }
        
        // Type 6 (Extension) sanity check: these are rare, and if the stream
        // doesn't normally have them, a sudden type 6 is likely misaligned parsing
        if (pkt_type == 6) {
            // Type 6 has 16-bit length field - could be huge if misaligned
            // For now, just warn and let it through, but track it
            static int type6_count = 0;
            if (type6_count < 5) {
                type6_count++;
                DBG_PRINTF("\n=== TYPE 6 (EXTENSION) PACKET #%d ===\n", type6_count);
                DBG_PRINTF("BBP #%u, len=%zu - verify this is expected\n", ctx->bbp_count, total);
                DBG_PRINTF("First 16 bytes: ");
                for (size_t i = 0; i < 16 && pos + i < work_len; i++) {
                    DBG_PRINTF("%02x ", work[pos + i]);
                }
                DBG_PRINTF("\n=====================================\n\n");
            }
        }
        
        ctx->pkt_source.plp = plp;
        ctx->pkt_source.bbp_num = ctx->bbp_count;
        ctx->pkt_source.start_bbp = ctx->bbp_count;  // Same as current
        ctx->pkt_source.cont_count = 0;
        ctx->pkt_source.is_spanning = 0;
        ctx->pkt_source.region = "post-ptr";
        
        output_alp_packet(ctx, work + pos, total);
        
        // Debug: if we just output a type 4, show what comes next
        uint8_t just_output_type = (work[pos] >> 5) & 0x07;
        static int showed_post_type4 = 0;
        if (just_output_type == 4 && !showed_post_type4) {
            showed_post_type4 = 1;
            size_t next_pos = pos + total;
            DBG_PRINTF("\n=== Bytes following type 4 packet in BBP ===\n");
            DBG_PRINTF("Type 4 ended at pos=%zu (len=%zu), work_len=%zu\n", pos, total, work_len);
            DBG_PRINTF("Next 32 bytes at pos %zu: ", next_pos);
            for (size_t i = 0; i < 32 && next_pos + i < work_len; i++) {
                DBG_PRINTF("%02x ", work[next_pos + i]);
            }
            DBG_PRINTF("\n");
            if (next_pos < work_len) {
                uint8_t next_byte = work[next_pos];
                uint8_t next_type = (next_byte >> 5) & 0x07;
                DBG_PRINTF("Next byte 0x%02x would be type %d\n", next_byte, next_type);
            }
            DBG_PRINTF("=============================================\n\n");
        }
        
        // Update last good packet tracking
        last_good_pos = pos;
        last_good_len = total;
        last_good_type = just_output_type;
        last_good_bbp = ctx->bbp_count;
        first_packet_in_bbp = 0;
        
        pos += total;
    }
    }  // End of post-pointer block
}

// ============================================================================
// Process Preamble (L1 Signaling)
// ============================================================================

static void process_preamble(depack_ctx_t* ctx, const uint8_t* data, size_t len) {
    if (len < 2) return;
    
    uint16_t preamble_len = (data[0] << 8) | data[1];
    if (preamble_len > len - 2) return;
    
    ctx->preamble_count++;
    
    // Extract L1-Basic (first 25 bytes after length field)
    if (preamble_len >= STLTP_L1_BASIC_SIZE && ctx->l1_basic_size == 0) {
        memcpy(ctx->l1_basic, data + 2, STLTP_L1_BASIC_SIZE);
        ctx->l1_basic_size = STLTP_L1_BASIC_SIZE;
        
        // Rest is L1-Detail
        size_t detail_len = preamble_len - STLTP_L1_BASIC_SIZE;
        if (detail_len > 0 && detail_len <= ctx->l1_detail_capacity) {
            memcpy(ctx->l1_detail, data + 2 + STLTP_L1_BASIC_SIZE, detail_len);
            ctx->l1_detail_size = detail_len;
        }
        
        DIAG("[L1] Preamble: Basic=%zu Detail=%zu\n", ctx->l1_basic_size, ctx->l1_detail_size);
    }
}

// ============================================================================
// RTP Parsing
// ============================================================================

static int parse_outer_rtp(const uint8_t* data, size_t len,
                           int* marker, uint16_t* pkt_offset,
                           uint16_t* seq_num,
                           const uint8_t** payload, size_t* payload_len) {
    if (len < 12) return -1;
    
    uint8_t ver = (data[0] >> 6) & 0x03;
    uint8_t pad = (data[0] >> 5) & 0x01;
    uint8_t ext = (data[0] >> 4) & 0x01;
    uint8_t cc = data[0] & 0x0F;
    uint8_t m = (data[1] >> 7) & 0x01;
    uint8_t pt = data[1] & 0x7F;
    
    if (ver != 2 || pt != STLTP_OUTER_PT || cc != 0) return -1;
    
    *marker = m;
    *seq_num = (data[2] << 8) | data[3];
    *pkt_offset = (data[10] << 8) | data[11];
    
    size_t hlen = 12;
    if (ext && len >= hlen + 4) {
        uint16_t ext_len = (data[hlen + 2] << 8) | data[hlen + 3];
        hlen += 4 + ext_len * 4;
    }
    
    if (hlen >= len) return -1;
    
    *payload_len = len - hlen;
    if (pad && *payload_len > 0) {
        uint8_t pad_len = data[len - 1];
        if (pad_len <= *payload_len) *payload_len -= pad_len;
    }
    
    *payload = data + hlen;
    return 0;
}

static int parse_inner_rtp(const uint8_t* data, size_t len,
                           uint8_t* pt, int* marker, uint32_t* ssrc,
                           uint16_t* seq_num,
                           const uint8_t** payload, size_t* payload_len) {
    if (len < 12) return -1;
    
    uint8_t ver = (data[0] >> 6) & 0x03;
    uint8_t pad = (data[0] >> 5) & 0x01;
    uint8_t ext = (data[0] >> 4) & 0x01;
    uint8_t cc = data[0] & 0x0F;
    
    if (ver != 2) return -1;
    
    *marker = (data[1] >> 7) & 0x01;
    *pt = data[1] & 0x7F;
    *seq_num = (data[2] << 8) | data[3];
    *ssrc = (data[8] << 24) | (data[9] << 16) | (data[10] << 8) | data[11];
    
    size_t hlen = 12 + cc * 4;
    if (ext && len >= hlen + 4) {
        uint16_t ext_len = (data[hlen + 2] << 8) | data[hlen + 3];
        hlen += 4 + ext_len * 4;
    }
    
    if (hlen >= len) return -1;
    
    *payload_len = len - hlen;
    if (pad && *payload_len > 0) {
        uint8_t pad_len = data[len - 1];
        if (pad_len <= *payload_len) *payload_len -= pad_len;
    }
    
    *payload = data + hlen;
    return 0;
}

// ============================================================================
// Route Inner Packet
// ============================================================================

static void route_inner(depack_ctx_t* ctx, uint16_t port, uint8_t pt,
                        int marker, uint32_t ssrc, uint16_t seq_num,
                        const uint8_t* data, size_t len) {
    // BBP (ports 30000-30063)
    if (port >= STLTP_PORT_BBP_BASE && port <= STLTP_PORT_BBP_MAX) {
        int plp = port - STLTP_PORT_BBP_BASE;
        if (plp < 0 || plp >= MAX_PLPS) return;
        
        plp_bbp_state_t* bbp = &ctx->bbp[plp];
        plp_alp_state_t* alp_st = &ctx->plp[plp];
        
        // Check for inner RTP sequence gaps
        if (bbp->seq_valid) {
            uint16_t expected_seq = bbp->last_seq + 1;
            if (seq_num != expected_seq) {
                uint16_t gap = (seq_num > expected_seq) ? 
                               (seq_num - expected_seq) : 
                               (65536 - expected_seq + seq_num);
                bbp->seq_gaps++;
                bbp->seq_gap_packets += gap;
                
                // Log first few gaps per PLP
                static int inner_gap_log_count[MAX_PLPS] = {0};
                if (inner_gap_log_count[plp] < 10) {
                    inner_gap_log_count[plp]++;
                    DBG_PRINTF("\n=== INNER RTP SEQ GAP (PLP %d) #%d (around BBP #%u) ===\n", 
                           plp, inner_gap_log_count[plp], ctx->bbp_count);
                    DBG_PRINTF("Expected seq %u, got %u (%u packets lost)\n", expected_seq, seq_num, gap);
                    DBG_PRINTF("BBP active=%d, size=%zu, expected=%zu\n", 
                           bbp->active, bbp->size, bbp->expected);
                    DBG_PRINTF("SSRC (BBP len)=%u, marker=%d\n", ssrc, marker);
                    if (alp_st->pending_size > 0) {
                        DBG_PRINTF("*** ALP pending: %zu of %zu bytes (started BBP #%u) - WILL BE DISCARDED ***\n",
                               alp_st->pending_size, alp_st->pending_expected, alp_st->pending_start_bbp);
                    }
                    DBG_PRINTF("======================================\n\n");
                }
                
                // CRITICAL: Any inner RTP sequence gap means we lost BBP data.
                // Even if the gap is at a BBP boundary (marker=1), we don't know
                // if the lost packets contained the END of an ALP spanning packet.
                // We MUST reset all reassembly state to prevent corruption.
                
                // Reset BBP state
                if (bbp->active) {
                    bbp->active = false;
                    bbp->size = 0;
                    bbp->expected = 0;
                }
                
                // Reset ALP reassembly state - any pending packet is now invalid
                // because we lost unknown BBP data that may have contained its continuation
                if (alp_st->pending_size > 0) {
                    ctx->spanning_discarded++;
                }
                alp_st->pending_size = 0;
                alp_st->pending_expected = 0;
                alp_st->short_frag_size = 0;
                alp_st->cont_boundary_count = 0;
            }
        }
        bbp->last_seq = seq_num;
        bbp->seq_valid = 1;
        
        if (marker) {
            // Marker bit set = start of new BBP
            
            // Check if we have an incomplete previous BBP
            if (bbp->active && bbp->expected > 0 && bbp->size < bbp->expected) {
                // Previous BBP was incomplete - this is a discontinuity
                static int incomplete_bbp_count = 0;
                if (incomplete_bbp_count < 10) {
                    incomplete_bbp_count++;
                    DBG_PRINTF("\n=== INCOMPLETE BBP DISCARDED (PLP %d) #%d ===\n", plp, incomplete_bbp_count);
                    DBG_PRINTF("Had %zu of %zu expected bytes (%zu missing)\n",
                           bbp->size, bbp->expected, bbp->expected - bbp->size);
                    if (alp_st->pending_size > 0) {
                        DBG_PRINTF("Discarding pending ALP packet (%zu of %zu bytes)\n",
                               alp_st->pending_size, alp_st->pending_expected);
                    }
                    DBG_PRINTF("=============================================\n\n");
                }
                
                // Reset ALP reassembly state - any pending packet is now invalid
                alp_st->pending_size = 0;
                alp_st->pending_expected = 0;
                alp_st->short_frag_size = 0;
                alp_st->cont_boundary_count = 0;
                ctx->spanning_discarded++;
            }
            // Flush any complete previous BBP
            else if (bbp->active && bbp->size >= bbp->expected && bbp->expected > 0) {
                process_bbp(ctx, plp, bbp->buf, bbp->expected);
            }
            
            bbp->expected = ssrc;  // SSRC = BBP length for baseband
            bbp->size = 0;
            bbp->active = true;
        }
        
        if (bbp->active) {
            size_t space = REASSEMBLY_BUFFER_SIZE - bbp->size;
            size_t copy = (len < space) ? len : space;
            memcpy(bbp->buf + bbp->size, data, copy);
            bbp->size += copy;
            
            if (bbp->expected > 0 && bbp->size >= bbp->expected) {
                process_bbp(ctx, plp, bbp->buf, bbp->expected);
                bbp->active = false;
            }
        }
    }
    // Preamble (port 30064)
    else if (port == STLTP_PORT_PREAMBLE && pt == STLTP_PT_PREAMBLE) {
        if (marker) {
            ctx->preamble_size = 0;
            ctx->preamble_active = true;
        }
        
        if (ctx->preamble_active) {
            size_t space = 64 * 1024 - ctx->preamble_size;
            size_t copy = (len < space) ? len : space;
            memcpy(ctx->preamble_buf + ctx->preamble_size, data, copy);
            ctx->preamble_size += copy;
            
            if (ctx->preamble_size >= 2) {
                uint16_t expected = (ctx->preamble_buf[0] << 8) | ctx->preamble_buf[1];
                if (ctx->preamble_size >= (size_t)(expected + 2)) {
                    process_preamble(ctx, ctx->preamble_buf, ctx->preamble_size);
                    ctx->preamble_active = false;
                }
            }
        }
    }
    // T&M (port 30065)
    else if (port == STLTP_PORT_TM && pt == STLTP_PT_TM) {
        if (marker) {
            ctx->tm_size = 0;
            ctx->tm_active = true;
        }
        
        if (ctx->tm_active) {
            size_t space = 64 * 1024 - ctx->tm_size;
            size_t copy = (len < space) ? len : space;
            memcpy(ctx->tm_buf + ctx->tm_size, data, copy);
            ctx->tm_size += copy;
            
            if (ctx->tm_size >= 2) {
                uint16_t expected = (ctx->tm_buf[0] << 8) | ctx->tm_buf[1];
                if (ctx->tm_size >= expected) {
                    ctx->tm_count++;
                    ctx->tm_active = false;
                }
            }
        }
    }
}

// ============================================================================
// Process Tunnel Payload
// ============================================================================

/* Route one complete inner IPv4/UDP/RTP packet to its STLTP stream. */
static void route_inner_ip(depack_ctx_t* ctx, const uint8_t* p, size_t ip_len) {
    if (ip_len < 28 || (p[0] >> 4) != 4 || p[9] != 17) return;
    uint8_t ihl = (p[0] & 0x0F) * 4;
    if (ihl < 20 || ihl + 8 > ip_len) return;

    uint16_t dst_port = (p[ihl + 2] << 8) | p[ihl + 3];
    uint8_t inner_pt;
    int inner_m;
    uint32_t inner_ssrc;
    uint16_t inner_seq;
    const uint8_t* inner_payload;
    size_t inner_payload_len;

    if (parse_inner_rtp(p + ihl + 8, ip_len - ihl - 8, &inner_pt, &inner_m,
                        &inner_ssrc, &inner_seq, &inner_payload, &inner_payload_len) == 0) {
        route_inner(ctx, dst_port, inner_pt, inner_m, inner_ssrc, inner_seq,
                    inner_payload, inner_payload_len);
    }
}

/*
 * Finish the inner packet held in cont_buf, if it is complete.
 * Returns 1 if a packet was routed, 0 if more bytes are needed,
 * -1 if the buffered bytes can't be a valid packet (discarded).
 */
static int flush_continuation(depack_ctx_t* ctx, uint8_t* cont_buf, size_t* cont_size) {
    if (*cont_size < 4) return 0;
    if ((cont_buf[0] >> 4) != 4) { *cont_size = 0; return -1; }
    uint16_t ip_len = (cont_buf[2] << 8) | cont_buf[3];
    if (ip_len < 20) { *cont_size = 0; return -1; }
    if (*cont_size < ip_len) return 0;
    if (*cont_size > ip_len) {
        // More bytes than the packet needs: framing is off somewhere upstream
        *cont_size = 0;
        return -1;
    }
    route_inner_ip(ctx, cont_buf, ip_len);
    *cont_size = 0;
    return 1;
}

static void process_tunnel(depack_ctx_t* ctx, int outer_marker, uint16_t pkt_offset,
                           const uint8_t* payload, size_t payload_len,
                           uint8_t* cont_buf, size_t* cont_size) {
    // M=0: entire payload continues the inner packet already in progress
    if (!outer_marker) {
        if (*cont_size == 0) return;          // nothing in progress (e.g. after an outer gap)
        if (*cont_size + payload_len > 64 * 1024) {
            *cont_size = 0;
            ctx->tunnel_drops++;
            return;
        }
        memcpy(cont_buf + *cont_size, payload, payload_len);
        *cont_size += payload_len;
        // An inner packet can end exactly at the end of this payload; finish it now
        // so it doesn't wait for (and get mixed up with) the next outer packet.
        if (flush_continuation(ctx, cont_buf, cont_size) < 0) ctx->tunnel_drops++;
        return;
    }

    if (pkt_offset > payload_len) {           // malformed packet_offset
        if (*cont_size > 0) ctx->tunnel_drops++;
        *cont_size = 0;
        return;
    }

    // M=1: bytes before pkt_offset (possibly none) finish the packet in progress.
    // pkt_offset == 0 is valid: the previous inner packet ended exactly at the end
    // of the previous outer payload.
    if (*cont_size > 0) {
        if (*cont_size + pkt_offset <= 64 * 1024) {
            memcpy(cont_buf + *cont_size, payload, pkt_offset);
            *cont_size += pkt_offset;
            if (flush_continuation(ctx, cont_buf, cont_size) <= 0) ctx->tunnel_drops++;
        } else {
            ctx->tunnel_drops++;
        }
        *cont_size = 0;
    }

    // Packets starting at pkt_offset
    const uint8_t* p = payload + pkt_offset;
    size_t rem = payload_len - pkt_offset;

    while (rem > 0) {
        if (rem < 4) {
            // Not even the IP length field yet; carry over
            memcpy(cont_buf, p, rem);
            *cont_size = rem;
            break;
        }
        if ((p[0] >> 4) != 4) break;          // not IPv4: stop parsing this payload
        uint16_t ip_len = (p[2] << 8) | p[3];
        if (ip_len < 20) break;

        if (ip_len > rem) {
            // Spans into the next outer packet
            memcpy(cont_buf, p, rem);
            *cont_size = rem;
            break;
        }

        route_inner_ip(ctx, p, ip_len);
        p += ip_len;
        rem -= ip_len;
    }
}

// ============================================================================
// Capture file reader: classic pcap (us/ns, either byte order) and pcapng
// ============================================================================

#define CAP_MAX_PACKET  (1024 * 1024)
#define CAP_MAX_BLOCK   (16 * 1024 * 1024)
#define CAP_MAX_IFACES  64

typedef struct {
    FILE *f;
    int is_pcapng;
    int swapped;                          // file byte order differs from host
    uint32_t linktype;                    // classic pcap: one link type for the file
    uint32_t if_linktype[CAP_MAX_IFACES]; // pcapng: per interface
    uint32_t if_snaplen[CAP_MAX_IFACES];
    uint8_t if_tsresol[CAP_MAX_IFACES];   // pcapng if_tsresol (default 6 = microseconds)
    int64_t if_tsoffset[CAP_MAX_IFACES];  // pcapng if_tsoffset, seconds
    uint32_t if_count;
    int ns;                               // classic pcap with nanosecond timestamps
    uint8_t *buf;
    size_t buf_cap;
    char format[32];
    uint64_t file_size;                   // for progress display
} cap_reader_t;

static uint32_t cap_u32(const cap_reader_t *r, const uint8_t *p) {
    uint32_t v; memcpy(&v, p, 4);
    return r->swapped ? __builtin_bswap32(v) : v;
}

static uint16_t cap_u16(const cap_reader_t *r, const uint8_t *p) {
    uint16_t v; memcpy(&v, p, 2);
    return r->swapped ? __builtin_bswap16(v) : v;
}

/* pcapng timestamp in if_tsresol units -> microseconds */
static uint64_t cap_ts_to_us(uint64_t t, uint8_t resol) {
    if (resol & 0x80) {                           // 2^-n seconds
        unsigned n = resol & 0x7F;
        if (n > 63) return 0;
        return (uint64_t)(((unsigned __int128)t * 1000000u) >> n);
    }
    if (resol == 6) return t;
    uint64_t f = 1;
    if (resol > 6) {
        for (unsigned k = 6; k < resol && k < 25; k++) f *= 10;
        return t / f;
    }
    for (unsigned k = resol; k < 6; k++) f *= 10;
    return t * f;
}

static int cap_ensure(cap_reader_t *r, size_t n) {
    if (n <= r->buf_cap) return 0;
    uint8_t *nb = realloc(r->buf, n);
    if (!nb) return -1;
    r->buf = nb;
    r->buf_cap = n;
    return 0;
}

static void cap_close(cap_reader_t *r) {
    if (r->f) fclose(r->f);
    free(r->buf);
    memset(r, 0, sizeof(*r));
}

static int cap_open(cap_reader_t *r, const char *filename) {
    uint8_t hdr[24];
    uint32_t magic;
    int ns = 0;

    memset(r, 0, sizeof(*r));
    r->f = fopen(filename, "rb");
    if (!r->f) return -1;
    {
        struct stat st;
        if (fstat(fileno(r->f), &st) == 0 && st.st_size > 0) r->file_size = (uint64_t)st.st_size;
    }
    if (fread(hdr, 1, 4, r->f) != 4) goto fail;
    memcpy(&magic, hdr, 4);

    if (magic == 0x0A0D0D0A) {            // pcapng Section Header Block
        r->is_pcapng = 1;
        snprintf(r->format, sizeof(r->format), "pcapng");
        if (fseek(r->f, 0, SEEK_SET) != 0) goto fail;
        return 0;                         // SHB is parsed by cap_next()
    }

    switch (magic) {
        case 0xa1b2c3d4: break;
        case 0xd4c3b2a1: r->swapped = 1; break;
        case 0xa1b23c4d: ns = 1; break;
        case 0x4d3cb2a1: ns = 1; r->swapped = 1; break;
        default: goto fail;
    }
    r->ns = ns;
    if (fread(hdr + 4, 1, 20, r->f) != 20) goto fail;
    r->linktype = cap_u32(r, hdr + 20) & 0xFFFF;   // upper bits carry FCS info
    snprintf(r->format, sizeof(r->format), "pcap%s%s", ns ? "-ns" : "", r->swapped ? "-swapped" : "");
    return 0;

fail:
    cap_close(r);
    return -1;
}

/*
 * Next packet. Returns 1 with *data valid until the next call, 0 at end of
 * file (including a cut-off last record), -1 if the file is corrupt.
 * *ts_us is the capture timestamp in microseconds since the epoch, or 0 if
 * the record has none (pcapng Simple Packet Block).
 */
static int cap_next(cap_reader_t *r, const uint8_t **data, uint32_t *caplen,
                    uint32_t *origlen, uint32_t *linktype, uint64_t *ts_us) {
    if (!r->is_pcapng) {
        uint8_t rec[16];
        if (fread(rec, 1, 16, r->f) != 16) return 0;
        uint32_t sec = cap_u32(r, rec);
        uint32_t frac = cap_u32(r, rec + 4);
        uint32_t incl = cap_u32(r, rec + 8);
        uint32_t orig = cap_u32(r, rec + 12);
        if (incl > CAP_MAX_PACKET) return -1;      // classic pcap can't resync
        if (cap_ensure(r, incl ? incl : 1)) return -1;
        if (fread(r->buf, 1, incl, r->f) != incl) return 0;
        *data = r->buf; *caplen = incl; *origlen = orig; *linktype = r->linktype;
        *ts_us = (uint64_t)sec * 1000000u + (r->ns ? frac / 1000u : frac);
        return 1;
    }

    for (;;) {
        uint8_t bh[8];
        uint32_t raw_type;
        if (fread(bh, 1, 8, r->f) != 8) return 0;
        memcpy(&raw_type, bh, 4);

        if (raw_type == 0x0A0D0D0A) {              // new section: byte order from BOM
            uint8_t bom[4];
            uint32_t b;
            if (fread(bom, 1, 4, r->f) != 4) return 0;
            memcpy(&b, bom, 4);
            if (b == 0x1A2B3C4D) r->swapped = 0;
            else if (b == 0x4D3C2B1A) r->swapped = 1;
            else return -1;
            uint32_t blen = cap_u32(r, bh + 4);
            if (blen < 28 || blen > CAP_MAX_BLOCK || (blen & 3)) return -1;
            r->if_count = 0;                       // interface IDs are per section
            snprintf(r->format, sizeof(r->format), "pcapng%s", r->swapped ? "-swapped" : "");
            if (fseek(r->f, (long)blen - 12, SEEK_CUR) != 0) return 0;
            continue;
        }

        uint32_t btype = cap_u32(r, bh);
        uint32_t blen = cap_u32(r, bh + 4);
        if (blen < 12 || blen > CAP_MAX_BLOCK || (blen & 3)) return -1;
        size_t body = blen - 12;
        if (cap_ensure(r, body + 4)) return -1;
        if (fread(r->buf, 1, body + 4, r->f) != body + 4) return 0;  // body + trailing length
        const uint8_t *b = r->buf;

        if (btype == 1) {                          // Interface Description Block
            if (body < 8) return -1;
            if (r->if_count < CAP_MAX_IFACES) {
                uint32_t i = r->if_count;
                r->if_linktype[i] = cap_u16(r, b);
                r->if_snaplen[i] = cap_u32(r, b + 4);
                r->if_tsresol[i] = 6;
                r->if_tsoffset[i] = 0;
                // Options: if_tsresol (9) and if_tsoffset (14) affect timestamps
                size_t o = 8;
                while (o + 4 <= body) {
                    uint16_t code = cap_u16(r, b + o), olen = cap_u16(r, b + o + 2);
                    if (code == 0 || o + 4 + olen > body) break;
                    if (code == 9 && olen >= 1) r->if_tsresol[i] = b[o + 4];
                    if (code == 14 && olen == 8) {
                        uint64_t v = ((uint64_t)cap_u32(r, b + o + 4) << 32) | cap_u32(r, b + o + 8);
                        if (r->swapped == 0) {   // little-endian section: low word first
                            v = ((uint64_t)cap_u32(r, b + o + 8) << 32) | cap_u32(r, b + o + 4);
                        }
                        r->if_tsoffset[i] = (int64_t)v;
                    }
                    o += 4 + ((olen + 3u) & ~3u);
                }
            }
            r->if_count++;
        } else if (btype == 6 || btype == 2) {     // Enhanced / obsolete Packet Block
            if (body < 20) return -1;
            uint32_t ifid = (btype == 6) ? cap_u32(r, b) : cap_u16(r, b);
            uint32_t cl = cap_u32(r, b + 12);
            uint32_t ol = cap_u32(r, b + 16);
            if (cl > body - 20) return -1;
            if (ifid >= r->if_count || ifid >= CAP_MAX_IFACES) continue;
            uint64_t t = ((uint64_t)cap_u32(r, b + 4) << 32) | cap_u32(r, b + 8);
            *ts_us = cap_ts_to_us(t, r->if_tsresol[ifid]) + (uint64_t)(r->if_tsoffset[ifid] * 1000000);
            *data = b + 20; *caplen = cl; *origlen = ol; *linktype = r->if_linktype[ifid];
            return 1;
        } else if (btype == 3) {                   // Simple Packet Block (interface 0)
            if (body < 4 || r->if_count == 0) continue;
            uint32_t ol = cap_u32(r, b);
            uint32_t cl = ol;
            if (r->if_snaplen[0] && cl > r->if_snaplen[0]) cl = r->if_snaplen[0];
            if (cl > body - 4) cl = (uint32_t)(body - 4);
            *data = b + 4; *caplen = cl; *origlen = ol; *linktype = r->if_linktype[0];
            *ts_us = 0;                             // Simple Packet Blocks carry no timestamp
            return 1;
        }
        // any other block type: skip
    }
}

/* Offset of the IPv4 header inside a captured frame, or -1. */
static int link_ipv4_offset(uint32_t linktype, const uint8_t *p, uint32_t len) {
    uint32_t off;
    uint16_t et;

    switch (linktype) {
        case 1:                                    // Ethernet
            if (len < 14) return -1;
            off = 12;
            break;
        case 113:                                  // Linux cooked v1 (tcpdump -i any)
            if (len < 16) return -1;
            off = 14;
            break;
        case 276:                                  // Linux cooked v2
            if (len < 20) return -1;
            et = (p[0] << 8) | p[1];
            return (et == 0x0800) ? 20 : -1;
        case 101:                                  // raw IP
        case 228:                                  // raw IPv4
            return (len >= 1 && (p[0] >> 4) == 4) ? 0 : -1;
        case 0:                                    // BSD loopback, host byte order
        case 108: {                                // OpenBSD loopback, network order
            if (len < 4) return -1;
            uint32_t be = ((uint32_t)p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3];
            uint32_t le = ((uint32_t)p[3] << 24) | (p[2] << 16) | (p[1] << 8) | p[0];
            return (be == 2 || le == 2) ? 4 : -1;  // AF_INET
        }
        default:
            return -1;
    }

    // Ethernet / cooked v1: skip VLAN tags (802.1Q, 802.1ad, legacy QinQ)
    for (int tags = 0; ; tags++) {
        if (off + 2 > len) return -1;
        et = (p[off] << 8) | p[off + 1];
        if ((et == 0x8100 || et == 0x88A8 || et == 0x9100) && tags < 4) {
            off += 4;
            continue;
        }
        break;
    }
    return (et == 0x0800) ? (int)(off + 2) : -1;
}

typedef struct {
    uint32_t src, dst;
    uint16_t sport, dport;
    const uint8_t *payload;
    size_t len;
} udp_view_t;

#define FRAME_OK          1
#define FRAME_SKIP        0    // not IPv4/UDP
#define FRAME_TRUNCATED  -1    // capture cut the packet short
#define FRAME_FRAGMENT   -2    // IP fragment

/* Locate the UDP payload using the IP and UDP length fields, so Ethernet
 * padding and FCS bytes are never treated as payload. */
static int frame_to_udp(uint32_t linktype, const uint8_t *p, uint32_t caplen, udp_view_t *u) {
    int off = link_ipv4_offset(linktype, p, caplen);
    if (off < 0) return FRAME_SKIP;

    const uint8_t *ip = p + off;
    size_t avail = caplen - off;
    if (avail < 20) return FRAME_TRUNCATED;
    if ((ip[0] >> 4) != 4) return FRAME_SKIP;
    size_t ihl = (ip[0] & 0x0F) * 4;
    size_t tot = (ip[2] << 8) | ip[3];
    if (ihl < 20 || tot < ihl) return FRAME_SKIP;
    if (tot > avail) return FRAME_TRUNCATED;
    if (ip[9] != 17) return FRAME_SKIP;
    if (((ip[6] << 8) | ip[7]) & 0x3FFF) return FRAME_FRAGMENT;   // MF set or offset != 0
    if (tot < ihl + 8) return FRAME_SKIP;

    const uint8_t *udp = ip + ihl;
    size_t ulen = (udp[4] << 8) | udp[5];
    if (ulen < 8 || ulen > tot - ihl) return FRAME_SKIP;

    u->src = ((uint32_t)ip[12] << 24) | (ip[13] << 16) | (ip[14] << 8) | ip[15];
    u->dst = ((uint32_t)ip[16] << 24) | (ip[17] << 16) | (ip[18] << 8) | ip[19];
    u->sport = (udp[0] << 8) | udp[1];
    u->dport = (udp[2] << 8) | udp[3];
    u->payload = udp + 8;
    u->len = ulen - 8;
    return FRAME_OK;
}

/* Outer RTP packet whose first inner packet is IPv4/UDP to an STLTP inner port.
 * Used to pick the STLTP stream out of a capture that may contain others. */
static int looks_like_stltp_start(int marker, uint16_t pkt_offset,
                                  const uint8_t *payload, size_t len) {
    if (!marker || (size_t)pkt_offset + 28 > len) return 0;
    const uint8_t *p = payload + pkt_offset;
    if ((p[0] >> 4) != 4 || p[9] != 17) return 0;
    size_t ihl = (p[0] & 0x0F) * 4;
    if (ihl < 20 || (size_t)pkt_offset + ihl + 8 > len) return 0;
    uint16_t dport = (p[ihl + 2] << 8) | p[ihl + 3];
    return dport >= STLTP_PORT_BBP_BASE && dport <= STLTP_PORT_SECURITY;
}

static void ipv4_to_str(uint32_t a, char *out, size_t n) {
    snprintf(out, n, "%u.%u.%u.%u", a >> 24, (a >> 16) & 0xFF, (a >> 8) & 0xFF, a & 0xFF);
}

// ============================================================================
// Public API
// ============================================================================

const char* get_input_type_string(int input_type) {
    switch(input_type) {
        case INPUT_TYPE_PCAP: return "PCAP File";
        case INPUT_TYPE_DEBUG: return "Debug File";
        case INPUT_TYPE_ALP_PCAP: return "ALP-PCAP File";
        case INPUT_TYPE_STLTP: return "STLTP File";
        default: return "Unknown";
    }
}

int detect_stltp_file(const char *filename) {
    cap_reader_t rd;
    const uint8_t *frame;
    uint32_t caplen, origlen, lt, n = 0;
    uint64_t ts_us;
    int hits = 0;

    if (cap_open(&rd, filename) != 0) return 0;
    while (n < 5000 && hits < 3 && cap_next(&rd, &frame, &caplen, &origlen, &lt, &ts_us) > 0) {
        udp_view_t u;
        int m;
        uint16_t pkt_offset, seq;
        const uint8_t *pl;
        size_t pl_len;
        n++;
        if (frame_to_udp(lt, frame, caplen, &u) != FRAME_OK) continue;
        if (parse_outer_rtp(u.payload, u.len, &m, &pkt_offset, &seq, &pl, &pl_len) != 0) continue;
        if (looks_like_stltp_start(m, pkt_offset, pl, pl_len)) hits++;
    }
    cap_close(&rd);
    return hits >= 3;
}

int detect_file_type(const char* filename) {
    const char* ext = strrchr(filename, '.');
    if (ext) {
        if (strcasecmp(ext, ".dbg") == 0) return INPUT_TYPE_DEBUG;
        if (strcasecmp(ext, ".pcap") == 0 || strcasecmp(ext, ".pcapng") == 0) {
            if (detect_stltp_file(filename)) return INPUT_TYPE_STLTP;
            
            FILE* f = fopen(filename, "rb");
            if (f) {
                fseek(f, 20, SEEK_SET);
                uint32_t link_type;
                if (fread(&link_type, 4, 1, f) == 1) {
                    if (link_type == DLT_ATSC_ALP || link_type == 289) {
                        fclose(f);
                        return INPUT_TYPE_ALP_PCAP;
                    }
                }
                fclose(f);
            }
            return INPUT_TYPE_PCAP;
        }
    }
    return INPUT_TYPE_PCAP;
}

stltp_extract_t* stltp_extract_create(void) {
    return calloc(1, sizeof(stltp_extract_t));
}

void stltp_extract_free(stltp_extract_t *extract) {
    if (!extract) return;
    free(extract->alp_data);
    free(extract->l1_basic);
    free(extract->l1_detail);
    free(extract->l1_basic_b64);
    free(extract->l1_detail_b64);
    free(extract->timing_mgmt);
    free(extract->alp_times);
    free(extract);
}

int process_stltp_file(const char *filename, stltp_extract_t *extract) {
    DBG_PRINTF("STLTP input.c version: 2026-11-03-v15 (tunnel reassembly fix, pcap/pcapng reader, stream lock)\n");
    fflush(stdout);
    
    const char* verbose_env = getenv("STLTP_VERBOSE");
    g_verbose = (verbose_env && verbose_env[0] == '1');
    
    const char* diag_env = getenv("STLTP_DIAG");
    if (diag_env && diag_env[0]) {
        g_diag = 1;
        g_diag_out = (diag_env[0] != '1' || diag_env[1]) ? fopen(diag_env, "w") : stderr;
        if (!g_diag_out) g_diag_out = stderr;
    }
    
    init_trace_config();
    
    cap_reader_t rd;
    if (cap_open(&rd, filename) != 0) {
        printf("Cannot open %s as pcap or pcapng\n", filename);
        return 1;
    }

    depack_ctx_t* ctx = depack_new();
    if (!ctx) { cap_close(&rd); return 1; }

    uint8_t* cont_buf = malloc(64 * 1024);
    size_t cont_size = 0;

    // Optional: STLTP_STREAM=a.b.c.d:port selects the outer stream by destination
    uint32_t want_dst = 0;
    uint16_t want_port = 0;
    const char* stream_env = getenv("STLTP_STREAM");
    if (stream_env && stream_env[0]) {
        unsigned a, b, c, d, port;
        if (sscanf(stream_env, "%u.%u.%u.%u:%u", &a, &b, &c, &d, &port) == 5 &&
            a < 256 && b < 256 && c < 256 && d < 256 && port < 65536) {
            want_dst = (a << 24) | (b << 16) | (c << 8) | d;
            want_port = (uint16_t)port;
        } else {
            DBG_PRINTF("Ignoring malformed STLTP_STREAM=%s (expected a.b.c.d:port)\n", stream_env);
        }
    }

    int locked = 0;
    uint32_t lock_src = 0, lock_dst = 0;
    uint16_t lock_port = 0;
    uint32_t first_linktype = 0xFFFFFFFF;
    int rc;
    const uint8_t* frame;
    uint32_t caplen, origlen, linktype;
    uint64_t ts_us;

    printf("Processing: %s (%s)\n", filename, rd.format);

    progress_t prog;
    uint32_t frames_read = 0;
    progress_begin(&prog, "Reading STLTP capture", rd.file_size);

    while ((rc = cap_next(&rd, &frame, &caplen, &origlen, &linktype, &ts_us)) > 0) {
        if ((++frames_read & 255) == 0) {
            progress_update(&prog, (uint64_t)ftello(rd.f));
        }
        if (first_linktype == 0xFFFFFFFF) first_linktype = linktype;

        udp_view_t u;
        int fr = frame_to_udp(linktype, frame, caplen, &u);
        if (fr == FRAME_TRUNCATED) { ctx->truncated_pkts++; continue; }
        if (fr == FRAME_FRAGMENT)  { ctx->fragmented_pkts++; continue; }
        if (fr != FRAME_OK)        { ctx->skipped_frames++; continue; }

        int outer_m;
        uint16_t pkt_offset;
        uint16_t seq_num;
        const uint8_t* outer_payload;
        size_t outer_payload_len;

        if (parse_outer_rtp(u.payload, u.len, &outer_m, &pkt_offset,
                            &seq_num, &outer_payload, &outer_payload_len) != 0) {
            ctx->skipped_frames++;
            continue;
        }

        // Stream lock: follow exactly one outer STLTP stream
        if (!locked) {
            if (want_port && (u.dst != want_dst || u.dport != want_port)) {
                ctx->ignored_stream_pkts++;
                continue;
            }
            if (!looks_like_stltp_start(outer_m, pkt_offset, outer_payload, outer_payload_len)) {
                ctx->ignored_stream_pkts++;
                continue;
            }
            locked = 1;
            lock_src = u.src; lock_dst = u.dst; lock_port = u.dport;
            char s_src[16], s_dst[16];
            ipv4_to_str(lock_src, s_src, sizeof(s_src));
            ipv4_to_str(lock_dst, s_dst, sizeof(s_dst));
            snprintf(ctx->stream_desc, sizeof(ctx->stream_desc), "%s -> %s:%u", s_src, s_dst, lock_port);
            progress_clear(&prog);
            printf("Locked onto STLTP stream %s\n", ctx->stream_desc);
        } else if (u.src != lock_src || u.dst != lock_dst || u.dport != lock_port) {
            ctx->ignored_stream_pkts++;
            continue;
        }

        if (ctx->outer_seq_valid) {
            uint16_t expected = ctx->last_outer_seq + 1;
            if (seq_num != expected) {
                uint16_t gap = (seq_num > expected) ? (seq_num - expected) : (65536 - expected + seq_num);
                ctx->outer_seq_gaps++;
                ctx->outer_seq_gap_packets += gap;

                static int gap_log_count = 0;
                if (gap_log_count < 10) {
                    gap_log_count++;
                    DBG_PRINTF("\n=== OUTER RTP SEQUENCE GAP #%d (BBP #%u) ===\n", gap_log_count, ctx->bbp_count);
                    DBG_PRINTF("Expected seq %u, got %u (%u packets lost)\n", expected, seq_num, gap);
                    DBG_PRINTF("File position: packet #%u\n", ctx->outer_pkts + 1);
                    DBG_PRINTF("Outer RTP: marker=%d, pkt_offset=%u, payload_len=%zu\n",
                           outer_m, pkt_offset, outer_payload_len);
                    if (cont_size > 0) {
                        DBG_PRINTF("*** Discarding %zu bytes of incomplete inner IP data ***\n", cont_size);
                    }
                    DBG_PRINTF("=============================================\n\n");
                }
                // The partial inner packet being assembled lost its middle
                if (cont_size > 0) ctx->tunnel_drops++;
                cont_size = 0;
            }
        }
        ctx->last_outer_seq = seq_num;
        ctx->outer_seq_valid = 1;

        // Capture time of the locked stream: span for duration, and per-ALP stamps
        ctx->cur_ts_us = ts_us;
        if (ts_us == 0) {
            ctx->ts_missing = 1;
        } else {
            if (ctx->first_ts_us == 0 || ts_us < ctx->first_ts_us) ctx->first_ts_us = ts_us;
            if (ts_us > ctx->last_ts_us) ctx->last_ts_us = ts_us;
        }

        ctx->outer_pkts++;
        process_tunnel(ctx, outer_m, pkt_offset, outer_payload, outer_payload_len,
                       cont_buf, &cont_size);
    }

    progress_end(&prog);

    if (rc < 0) {
        ctx->capture_error = 1;
        printf("WARNING: capture file is corrupt; stopped reading early\n");
    }
    if (!locked) {
        printf("WARNING: no STLTP stream found in %s\n", filename);
    }
    snprintf(extract->capture_format, sizeof(extract->capture_format), "%s", rd.format);
    extract->capture_start_us = ctx->first_ts_us;
    extract->capture_end_us = ctx->last_ts_us;
    extract->capture_timing_valid = !ctx->ts_missing && ctx->first_ts_us > 0 &&
                                    ctx->last_ts_us > ctx->first_ts_us;
    if (extract->capture_timing_valid && ctx->alp_times_count > 0) {
        extract->alp_times = ctx->alp_times;          // hand over ownership
        extract->alp_times_count = ctx->alp_times_count;
        ctx->alp_times = NULL;
        ctx->alp_times_count = 0;
    }
    extract->link_type = (first_linktype == 0xFFFFFFFF) ? 0 : first_linktype;

    cap_close(&rd);
    free(cont_buf);
    
    // Copy results
    if (ctx->out_alp_size > 0) {
        extract->alp_data = malloc(ctx->out_alp_size);
        if (extract->alp_data) {
            memcpy(extract->alp_data, ctx->out_alp, ctx->out_alp_size);
            extract->alp_size = ctx->out_alp_size;
        }
    }
    
    if (ctx->l1_basic_size > 0) {
        extract->l1_basic = malloc(ctx->l1_basic_size);
        if (extract->l1_basic) {
            memcpy(extract->l1_basic, ctx->l1_basic, ctx->l1_basic_size);
            extract->l1_basic_size = ctx->l1_basic_size;
        }
        
        size_t b64_len;
        extract->l1_basic_b64 = base64_encode(ctx->l1_basic, ctx->l1_basic_size, &b64_len);
        
        if (ctx->l1_detail_size > 0) {
            extract->l1_detail = malloc(ctx->l1_detail_size);
            if (extract->l1_detail) {
                memcpy(extract->l1_detail, ctx->l1_detail, ctx->l1_detail_size);
                extract->l1_detail_size = ctx->l1_detail_size;
            }
            
            size_t combined_size = ctx->l1_basic_size + ctx->l1_detail_size;
            uint8_t* combined = malloc(combined_size);
            if (combined) {
                memcpy(combined, ctx->l1_basic, ctx->l1_basic_size);
                memcpy(combined + ctx->l1_basic_size, ctx->l1_detail, ctx->l1_detail_size);
                extract->l1_detail_b64 = base64_encode(combined, combined_size, &b64_len);
                free(combined);
            }
        }
    }
    
    extract->rtp_packet_count = ctx->outer_pkts;
    extract->alp_packet_count = ctx->out_alp_count;
    extract->preamble_packet_count = ctx->preamble_count;
    extract->timing_packet_count = ctx->tm_count;
    
    // Copy extended statistics to extract struct for HTML reporting
    extract->outer_packets = ctx->outer_pkts;
    extract->bbp_count = ctx->bbp_count;
    
    // Copy ALP type counts
    for (int i = 0; i < 8; i++) {
        extract->alp_type_counts[i] = ctx->alp_type_counts[i];
    }
    
    // Copy spanning packet stats
    extract->spanning_started = ctx->spanning_started;
    extract->spanning_complete = ctx->spanning_complete;
    extract->spanning_discarded = ctx->spanning_discarded;
    extract->orphan_continuations = ctx->orphan_continuations;
    
    // Copy error stats
    extract->rejected_packets = ctx->rejected_packets;
    extract->outer_rtp_gaps = ctx->outer_seq_gaps;
    extract->outer_rtp_gap_packets = ctx->outer_seq_gap_packets;
    extract->tunnel_drops = ctx->tunnel_drops;
    extract->truncated_packets = ctx->truncated_pkts;
    extract->fragmented_packets = ctx->fragmented_pkts;
    extract->skipped_frames = ctx->skipped_frames;
    extract->ignored_stream_packets = ctx->ignored_stream_pkts;
    extract->capture_error = ctx->capture_error;
    snprintf(extract->stream_desc, sizeof(extract->stream_desc), "%s", ctx->stream_desc);
    extract->sync_errors = ctx->sync_errors;
    
    // Calculate and copy inner RTP gap stats
    uint32_t total_inner_gaps = 0;
    uint32_t total_inner_gap_packets = 0;
    int plp_gap_idx = 0;
    for (int i = 0; i < MAX_PLPS && plp_gap_idx < STLTP_MAX_PLPS; i++) {
        if (ctx->bbp[i].seq_gaps > 0) {
            total_inner_gaps += ctx->bbp[i].seq_gaps;
            total_inner_gap_packets += ctx->bbp[i].seq_gap_packets;
            // Store per-PLP breakdown
            extract->plp_gaps[plp_gap_idx].plp_id = i;
            extract->plp_gaps[plp_gap_idx].gaps = ctx->bbp[i].seq_gaps;
            extract->plp_gaps[plp_gap_idx].packets_lost = ctx->bbp[i].seq_gap_packets;
            plp_gap_idx++;
        }
    }
    extract->plp_gap_count = plp_gap_idx;
    extract->inner_rtp_gaps = total_inner_gaps;
    extract->inner_rtp_gap_packets = total_inner_gap_packets;
    
    // Copy total bytes
    extract->total_alp_bytes = ctx->out_alp_size;
    
    DBG_PRINTF("\nSTLTP Processing Complete:\n");
    DBG_PRINTF("  Outer packets:    %u\n", ctx->outer_pkts);
    DBG_PRINTF("  Outer RTP gaps:   %u (%u packets lost)\n", ctx->outer_seq_gaps, ctx->outer_seq_gap_packets);
    DBG_PRINTF("  Tunnel drops:     %u\n", ctx->tunnel_drops);
    DBG_PRINTF("  Stream:           %s\n", ctx->stream_desc[0] ? ctx->stream_desc : "(none)");
    DBG_PRINTF("  Other streams:    %u packets ignored\n", ctx->ignored_stream_pkts);
    DBG_PRINTF("  Truncated frames: %u\n", ctx->truncated_pkts);
    DBG_PRINTF("  IP fragments:     %u\n", ctx->fragmented_pkts);
    DBG_PRINTF("  BBPs processed:   %u\n", ctx->bbp_count);
    DBG_PRINTF("  Preambles:        %u\n", ctx->preamble_count);
    DBG_PRINTF("  T&M packets:      %u\n", ctx->tm_count);
    DBG_PRINTF("  ALP packets:      %u\n", ctx->out_alp_count);
    DBG_PRINTF("    Type 0 (IPv4):      %u\n", ctx->alp_type_counts[0]);
    DBG_PRINTF("    Type 2 (Compressed):%u\n", ctx->alp_type_counts[2]);
    DBG_PRINTF("    Type 4 (Signaling): %u\n", ctx->alp_type_counts[4]);
    DBG_PRINTF("    Type 6 (Extension): %u\n", ctx->alp_type_counts[6]);
    DBG_PRINTF("    Type 7 (MPEG-TS):   %u\n", ctx->alp_type_counts[7]);
    DBG_PRINTF("  Spanning packets:\n");
    DBG_PRINTF("    Started:        %u\n", ctx->spanning_started);
    DBG_PRINTF("    Completed:      %u\n", ctx->spanning_complete);
    DBG_PRINTF("    Discarded:      %u\n", ctx->spanning_discarded);
    DBG_PRINTF("    Orphan conts:   %u\n", ctx->orphan_continuations);
    DBG_PRINTF("  Rejected packets: %u\n", ctx->rejected_packets);
    DBG_PRINTF("  Sync errors:      %u\n", ctx->sync_errors);
    if (ctx->outer_seq_gaps > 0) {
        DBG_PRINTF("  RTP seq gaps:     %u (est. %u packets lost)\n", 
               ctx->outer_seq_gaps, ctx->outer_seq_gap_packets);
    }
    
    // Report inner RTP sequence gaps per PLP
    if (total_inner_gaps > 0) {
        DBG_PRINTF("  Inner RTP gaps:   %u (est. %u packets lost)\n", 
               total_inner_gaps, total_inner_gap_packets);
        DBG_PRINTF("    Per-PLP breakdown:\n");
        for (int i = 0; i < MAX_PLPS; i++) {
            if (ctx->bbp[i].seq_gaps > 0) {
                DBG_PRINTF("      PLP %d: %u gaps (%u packets lost)\n", 
                       i, ctx->bbp[i].seq_gaps, ctx->bbp[i].seq_gap_packets);
            }
        }
    }
    
    DBG_PRINTF("  Total ALP bytes:  %zu\n", ctx->out_alp_size);
    
    // Print trace stats if tracing was enabled
    if (g_trace_dest_ip != 0 || g_trace_dest_port != 0 || g_trace_tsi_set) {
        DBG_PRINTF("\nTrace Statistics:\n");
        DBG_PRINTF("  Packets checked:  %u\n", g_trace_checked);
        DBG_PRINTF("  Packets matched:  %u\n", g_trace_matched);
        DBG_PRINTF("  Unique TSIs seen: %d\n", g_seen_tsi_count);
    }
    
    depack_free(ctx);
    return 0;
}

int create_virtual_alp_pcap_from_stltp(const char *stltp_filename,
                                        uint8_t **pcap_data, size_t *pcap_size,
                                        char **l1_basic_b64, char **l1_detail_b64,
                                        stltp_extract_t **stats_out) {
    *pcap_data = NULL;
    *pcap_size = 0;
    if (l1_basic_b64) *l1_basic_b64 = NULL;
    if (l1_detail_b64) *l1_detail_b64 = NULL;
    if (stats_out) *stats_out = NULL;
    
    stltp_extract_t* extract = stltp_extract_create();
    if (!extract) return 1;
    
    if (process_stltp_file(stltp_filename, extract) != 0) {
        stltp_extract_free(extract);
        return 1;
    }
    
    if (extract->alp_size == 0) {
        printf("Warning: No ALP data extracted\n");
        stltp_extract_free(extract);
        return 1;
    }
    
    // Create PCAP from extracted ALP packets
    // Each ALP packet in extract->alp_data is properly delimited
    size_t est_size = 24 + extract->alp_packet_count * (16 + 2000);
    *pcap_data = malloc(est_size);
    if (!*pcap_data) { stltp_extract_free(extract); return 1; }
    
    size_t pos = 0;
    
    // PCAP header
    struct {
        uint32_t magic, v_major_minor;
        int32_t thiszone;
        uint32_t sigfigs, snaplen, network;
    } pcap_hdr = {0xa1b2c3d4, 0x00040002, 0, 0, 65535, DLT_ATSC_ALP};
    memcpy(*pcap_data, &pcap_hdr, 24);
    pos = 24;
    
    // Record timestamps: the real capture time of each ALP packet when the
    // capture had timestamps; otherwise synthetic (now + 1 ms per packet),
    // which is NOT real time - a3render.c shows bitrates as N/A in that case.
    uint32_t ts = (uint32_t)time(NULL);
    int real_ts = extract->capture_timing_valid && extract->alp_times_count > 0;
    size_t ts_idx = 0;
    size_t alp_pos = 0;
    uint32_t pkt_num = 0;
    
    while (alp_pos < extract->alp_size) {
        const uint8_t* pkt = extract->alp_data + alp_pos;
        size_t rem = extract->alp_size - alp_pos;
        
        if (rem < 2) break;
        
        size_t hlen, plen;
        size_t pkt_len = alp_get_packet_length(pkt, rem, &hlen, &plen);
        
        if (pkt_len == 0 || pkt_len > rem) {
            alp_pos++;
            continue;
        }
        
        // Debug: track packet types being written
        uint8_t pkt_type = (pkt[0] >> 5) & 0x07;
        static int type4_context_dumped = 0;
        if (pkt_type == 4 && !type4_context_dumped) {
            type4_context_dumped = 1;
            DBG_PRINTF("\n=== Context around first type 4 packet ===\n");
            DBG_PRINTF("Position in ALP buffer: %zu\n", alp_pos);
            DBG_PRINTF("PCAP position: %zu (packet #%u)\n", pos, pkt_num);
            
            // Show previous packet info
            if (pkt_num > 0) {
                // Look back in PCAP buffer to find previous packet
                size_t prev_pos = 24;  // Start after PCAP header
                size_t last_pkt_start = 24;
                uint32_t last_pkt_len = 0;
                
                while (prev_pos < pos) {
                    uint32_t incl_len;
                    memcpy(&incl_len, *pcap_data + prev_pos + 8, 4);
                    last_pkt_start = prev_pos + 16;  // Data starts after record header
                    last_pkt_len = incl_len;
                    prev_pos += 16 + incl_len;
                }
                
                if (last_pkt_len > 0) {
                    const uint8_t* prev_pkt = *pcap_data + last_pkt_start;
                    uint8_t prev_type = (prev_pkt[0] >> 5) & 0x07;
                    DBG_PRINTF("Previous packet: type=%d, len=%u\n", prev_type, last_pkt_len);
                    DBG_PRINTF("  Last 32 bytes: ");
                    size_t start = (last_pkt_len > 32) ? last_pkt_len - 32 : 0;
                    for (size_t i = start; i < last_pkt_len; i++) {
                        DBG_PRINTF("%02x ", prev_pkt[i]);
                    }
                    DBG_PRINTF("\n");
                }
            }
            
            DBG_PRINTF("Type 4 packet: len=%zu\n", pkt_len);
            DBG_PRINTF("  First 64 bytes: ");
            for (size_t i = 0; i < pkt_len && i < 64; i++) {
                DBG_PRINTF("%02x ", pkt[i]);
                if ((i + 1) % 16 == 0) DBG_PRINTF("\n                  ");
            }
            DBG_PRINTF("\n");
            
            // Also show what comes after
            if (alp_pos + pkt_len < extract->alp_size) {
                const uint8_t* next_pkt = extract->alp_data + alp_pos + pkt_len;
                size_t next_rem = extract->alp_size - alp_pos - pkt_len;
                if (next_rem >= 2) {
                    size_t next_hlen, next_plen;
                    size_t next_len = alp_get_packet_length(next_pkt, next_rem, &next_hlen, &next_plen);
                    uint8_t next_type = (next_pkt[0] >> 5) & 0x07;
                    DBG_PRINTF("Next packet: type=%d, len=%zu\n", next_type, next_len);
                    DBG_PRINTF("  First 20 bytes: ");
                    for (size_t i = 0; i < 20 && i < next_rem; i++) {
                        DBG_PRINTF("%02x ", next_pkt[i]);
                    }
                    DBG_PRINTF("\n");
                }
            }
            DBG_PRINTF("===========================================\n\n");
        }
        
        // Grow buffer if needed
        if (pos + 16 + pkt_len > est_size) {
            est_size *= 2;
            uint8_t* new_buf = realloc(*pcap_data, est_size);
            if (!new_buf) break;
            *pcap_data = new_buf;
        }
        
        // Write record
        struct { uint32_t ts_sec, ts_usec, incl_len, orig_len; } rec = {
            ts + pkt_num / 1000, (pkt_num % 1000) * 1000, (uint32_t)pkt_len, (uint32_t)pkt_len
        };
        if (real_ts) {
            while (ts_idx + 1 < extract->alp_times_count &&
                   extract->alp_times[ts_idx + 1].offset <= alp_pos) {
                ts_idx++;
            }
            uint64_t t = extract->alp_times[ts_idx].ts_us;
            rec.ts_sec = (uint32_t)(t / 1000000u);
            rec.ts_usec = (uint32_t)(t % 1000000u);
        }
        memcpy(*pcap_data + pos, &rec, 16);
        pos += 16;
        memcpy(*pcap_data + pos, pkt, pkt_len);
        pos += pkt_len;
        
        alp_pos += pkt_len;
        pkt_num++;
    }
    
    // Debug: Write first 5000 packets to a debug PCAP file
    {
        FILE* dbg = fopen("/tmp/stltp_debug.pcap", "wb");
        if (dbg) {
            // Write up to first 5000 packets or entire file, whichever is smaller
            size_t dbg_pos = 24;  // Start after PCAP header
            uint32_t dbg_count = 0;
            
            fwrite(*pcap_data, 1, 24, dbg);  // PCAP header
            
            while (dbg_pos < pos && dbg_count < 5000) {
                // Read record header
                uint32_t incl_len;
                memcpy(&incl_len, *pcap_data + dbg_pos + 8, 4);
                
                size_t rec_size = 16 + incl_len;
                if (dbg_pos + rec_size > pos) break;
                
                fwrite(*pcap_data + dbg_pos, 1, rec_size, dbg);
                dbg_pos += rec_size;
                dbg_count++;
            }
            
            fclose(dbg);
            DBG_PRINTF("DEBUG: Wrote %u packets to /tmp/stltp_debug.pcap\n", dbg_count);
        }
    }
    
    *pcap_size = pos;
    
    if (l1_basic_b64 && extract->l1_basic_b64) {
        *l1_basic_b64 = extract->l1_basic_b64;
        extract->l1_basic_b64 = NULL;
    }
    if (l1_detail_b64 && extract->l1_detail_b64) {
        *l1_detail_b64 = extract->l1_detail_b64;
        extract->l1_detail_b64 = NULL;
    }
    
    DBG_PRINTF("Created ALP-PCAP: %zu bytes, %u packets\n", *pcap_size, pkt_num);
    
    // Copy stats to output if requested
    if (stats_out) {
        *stats_out = calloc(1, sizeof(stltp_extract_t));
        if (*stats_out) {
            // Copy every statistics field at once, then drop the data pointers
            // (they stay owned by `extract` and are freed below). Copying the
            // whole struct means fields added to stltp_extract_t later can't be
            // silently left out, as happened with the v15 capture fields.
            **stats_out = *extract;
            (*stats_out)->alp_data = NULL;
            (*stats_out)->alp_size = 0;
            (*stats_out)->l1_basic = NULL;
            (*stats_out)->l1_basic_size = 0;
            (*stats_out)->l1_detail = NULL;
            (*stats_out)->l1_detail_size = 0;
            (*stats_out)->l1_basic_b64 = NULL;
            (*stats_out)->l1_detail_b64 = NULL;
            (*stats_out)->timing_mgmt = NULL;
            (*stats_out)->timing_mgmt_size = 0;
            (*stats_out)->alp_times = NULL;
            (*stats_out)->alp_times_count = 0;
        }
    }
    
    stltp_extract_free(extract);
    return 0;
}

// ============================================================================
// parse_alp_packet - Used by downstream processing
// ============================================================================

int parse_alp_packet(const u_char* alp_data, int alp_len,
                     const u_char** ip_payload, int* ip_len,
                     const u_char** signaling_payload, int* signaling_len) {
    *ip_payload = NULL;
    *ip_len = 0;
    *signaling_payload = NULL;
    *signaling_len = 0;
    
    if (alp_len < 2) return ALP_PARSE_ERROR;
    
    uint8_t b0 = alp_data[0];
    uint8_t type = (b0 >> 5) & 0x07;
    // PC / HM bits are interpreted by alp_get_packet_length()
    
    // Get header and payload lengths
    size_t hlen, plen;
    size_t total = alp_get_packet_length(alp_data, alp_len, &hlen, &plen);
    
    if (total == 0 || total > (size_t)alp_len) {
        return ALP_PARSE_ERROR;
    }
    
    if (type == 0) {
        // IPv4 packet
        const uint8_t* ip = alp_data + hlen;
        size_t ip_avail = alp_len - hlen;
        
        if (ip_avail < 20) return ALP_PARSE_ERROR;
        if ((ip[0] >> 4) != 4) return ALP_PARSE_ERROR;  // Not IPv4
        
        uint16_t ip_total = (ip[2] << 8) | ip[3];
        if (ip_total > ip_avail) return ALP_PARSE_ERROR;
        
        *ip_payload = ip;
        *ip_len = ip_total;
        return ALP_PARSE_IPV4;
    }
    else if (type == 4) {
        // Signaling packet (LLS)
        // Per A/330 Section 5.2.1, signaling packets have a 5-byte info header:
        //   signaling_type (1 byte)
        //   signaling_type_extension (2 bytes)
        //   signaling_version (1 byte)
        //   signaling_format/encoding/reserved (1 byte)
        // After this header comes the actual LLS table data
        // Note: We return the full payload INCLUDING the 5-byte header
        // because the downstream LMT parser expects to skip it itself
        // 
        // hlen is 7 (2 ALP + 5 signaling info), but we want to return
        // data starting at the signaling info header (offset 2)
        
        *signaling_payload = alp_data + 2;  // Skip only ALP header, keep signaling info
        *signaling_len = plen + 5;          // Include signaling info header in length
        return ALP_PARSE_SIGNALING;
    }
    else if (type == 6) {
        // Extension packet
        *signaling_payload = alp_data + hlen;
        *signaling_len = plen;
        return ALP_PARSE_EXTENSION_ONLY;
    }
    
    return ALP_PARSE_ERROR;
}

// ============================================================================
// Utility functions
// ============================================================================

void multicast_ip_to_mac(uint32_t ip, uint8_t *mac) {
    mac[0] = 0x01; mac[1] = 0x00; mac[2] = 0x5e;
    mac[3] = (ip >> 16) & 0x7f;
    mac[4] = (ip >> 8) & 0xff;
    mac[5] = ip & 0xff;
}

uint8_t* remove_variable_artifacts(const uint8_t *data, size_t data_len, size_t *cleaned_len) {
    uint8_t *cleaned_data = malloc(data_len);
    if (!cleaned_data) {
        DBG_PRINTF("Memory allocation failed\n");
        return NULL;
    }
    
    size_t pos = 0;
    size_t cleaned_pos = 0;
    int removed_count = 0;
    int three_byte_count = 0;
    int four_byte_count = 0;
    
    DBG_PRINTF("Removing variable-length artifacts (3 or 4 bytes based on second byte flag)...\n");
    
    while (pos < data_len) {
        if (pos + 188 <= data_len) {
            // Check if this starts with e7 (artifact marker)
            if (data[pos] == 0xe7 && pos + 1 < data_len) {
                // Check the second byte's high nibble to determine artifact length
                uint8_t second_byte = data[pos + 1];
                uint8_t flag_nibble = second_byte >> 4;
                
                int artifact_len;
                if (flag_nibble == 0x0) {
                    artifact_len = 3;
                    three_byte_count++;
                } else if (flag_nibble == 0x4) {
                    artifact_len = 4;
                    four_byte_count++;
                } else {
                    artifact_len = 3;
                    three_byte_count++;
                }
                
                pos += artifact_len;
                removed_count++;
                
                int remaining_in_chunk = 188 - artifact_len;
                if (pos + remaining_in_chunk <= data_len) {
                    memcpy(cleaned_data + cleaned_pos, data + pos, remaining_in_chunk);
                    cleaned_pos += remaining_in_chunk;
                    pos += remaining_in_chunk;
                } else {
                    size_t remaining = data_len - pos;
                    memcpy(cleaned_data + cleaned_pos, data + pos, remaining);
                    cleaned_pos += remaining;
                    break;
                }
            } else {
                memcpy(cleaned_data + cleaned_pos, data + pos, 188);
                cleaned_pos += 188;
                pos += 188;
            }
        } else {
            size_t remaining = data_len - pos;
            if (remaining >= 2 && data[pos] == 0xe7) {
                uint8_t second_byte = data[pos + 1];
                uint8_t flag_nibble = second_byte >> 4;
                int artifact_len = (flag_nibble == 0x4) ? 4 : 3;
                
                if (remaining >= (size_t)artifact_len) {
                    pos += artifact_len;
                    removed_count++;
                    
                    if (pos < data_len) {
                        size_t final_remaining = data_len - pos;
                        memcpy(cleaned_data + cleaned_pos, data + pos, final_remaining);
                        cleaned_pos += final_remaining;
                    }
                } else {
                    memcpy(cleaned_data + cleaned_pos, data + pos, remaining);
                    cleaned_pos += remaining;
                }
            } else {
                memcpy(cleaned_data + cleaned_pos, data + pos, remaining);
                cleaned_pos += remaining;
            }
            break;
        }
    }
    
    DBG_PRINTF("Removed %d variable-length artifacts\n", removed_count);
    DBG_PRINTF("  3-byte artifacts (0X): %d\n", three_byte_count);
    DBG_PRINTF("  4-byte artifacts (4X): %d\n", four_byte_count);
    DBG_PRINTF("Total bytes removed: %zu (%.2f%%)\n", 
           data_len - cleaned_pos, (double)(data_len - cleaned_pos) / data_len * 100.0);
    
    *cleaned_len = cleaned_pos;
    return cleaned_data;
}

int create_virtual_pcap_from_debug(const char *debug_filename, uint8_t **pcap_data, size_t *pcap_size) {
    FILE *input_file = fopen(debug_filename, "rb");
    if (!input_file) {
        printf("Error: Cannot open debug file %s\n", debug_filename);
        return 1;
    }
    
    fseek(input_file, 0, SEEK_END);
    size_t file_size = ftell(input_file);
    fseek(input_file, 0, SEEK_SET);
    
    DBG_PRINTF("Debug file size: %zu bytes\n", file_size);
    
    uint8_t *raw_data = malloc(file_size);
    if (!raw_data) {
        DBG_PRINTF("Memory allocation failed\n");
        fclose(input_file);
        return 1;
    }
    
    size_t bytes_read = fread(raw_data, 1, file_size, input_file);
    fclose(input_file);
    
    if (bytes_read != file_size) {
        printf("Error reading debug file\n");
        free(raw_data);
        return 1;
    }
    
    size_t cleaned_len;
    uint8_t *cleaned_data = remove_variable_artifacts(raw_data, file_size, &cleaned_len);
    free(raw_data);
    
    if (!cleaned_data) {
        return 1;
    }
    
    DBG_PRINTF("Cleaned data size: %zu bytes\n", cleaned_len);
    DBG_PRINTF("Scanning for IPv4 multicast UDP packets...\n");
    
    // Allocate array for packet offsets - use a reasonable upper bound
    size_t max_packets = cleaned_len / 20;
    if (max_packets == 0) max_packets = 1;
    size_t *packet_offsets = malloc(max_packets * sizeof(size_t));
    if (!packet_offsets) {
        DBG_PRINTF("Memory allocation failed for packet_offsets\n");
        free(cleaned_data);
        return 1;
    }
    size_t packet_count = 0;
    
    for (size_t pos = 0; pos + 20 <= cleaned_len; pos++) {
        if (cleaned_data[pos] == 0x45 &&
            cleaned_data[pos + 9] == 17 &&
            cleaned_data[pos + 16] >= 224 &&
            cleaned_data[pos + 16] <= 239) {
            
            uint8_t version = cleaned_data[pos] >> 4;
            uint8_t ihl = cleaned_data[pos] & 0xF;
            
            if (version == 4 && ihl >= 5) {
                if (packet_count < max_packets) {
                    packet_offsets[packet_count++] = pos;
                }
            }
        }
    }
    
    DBG_PRINTF("Found %zu potential packets in debug file\n", packet_count);
    
    // Calculate estimated size more carefully
    size_t estimated_size = 24;  // PCAP header
    for (size_t i = 0; i < packet_count; i++) {
        size_t current_start = packet_offsets[i];
        if (current_start + 4 <= cleaned_len) {
            uint16_t total_len = (cleaned_data[current_start + 2] << 8) | cleaned_data[current_start + 3];
            if (total_len >= 20) {
                estimated_size += 16 + 14 + total_len;  // record header + eth header + IP packet
            }
        }
    }
    
    *pcap_data = malloc(estimated_size);
    if (!*pcap_data) {
        DBG_PRINTF("Memory allocation failed for pcap_data\n");
        free(cleaned_data);
        free(packet_offsets);
        return 1;
    }
    
    size_t pcap_pos = 0;
    
    // PCAP global header
    struct {
        uint32_t magic_number;
        uint16_t version_major;
        uint16_t version_minor;
        int32_t  thiszone;
        uint32_t sigfigs;
        uint32_t snaplen;
        uint32_t network;
    } pcap_hdr = {
        .magic_number = 0xa1b2c3d4,
        .version_major = 2,
        .version_minor = 4,
        .thiszone = 0,
        .sigfigs = 0,
        .snaplen = 65535,
        .network = 1  // Ethernet
    };
    
    memcpy(*pcap_data + pcap_pos, &pcap_hdr, 24);
    pcap_pos += 24;
    
    uint32_t timestamp = (uint32_t)time(NULL);
    size_t packets_written = 0;
    
    for (size_t i = 0; i < packet_count; i++) {
        size_t current_start = packet_offsets[i];
        size_t next_start = (i + 1 < packet_count) ? packet_offsets[i + 1] : cleaned_len;
        size_t packet_chunk_len = next_start - current_start;
        
        if (packet_chunk_len < 20) continue;
        if (current_start + 4 > cleaned_len) continue;
        
        uint16_t total_len = (cleaned_data[current_start + 2] << 8) | cleaned_data[current_start + 3];
        
        // Validate the packet
        if (total_len >= 20 && total_len <= packet_chunk_len && 
            current_start + total_len <= cleaned_len) {
            
            uint32_t dest_ip = (cleaned_data[current_start + 16] << 24) |
                              (cleaned_data[current_start + 17] << 16) |
                              (cleaned_data[current_start + 18] << 8) |
                              cleaned_data[current_start + 19];
            
            uint8_t eth_header[14];
            multicast_ip_to_mac(dest_ip, eth_header);
            
            eth_header[6] = 0x00;
            eth_header[7] = 0x11;
            eth_header[8] = 0x22;
            eth_header[9] = 0x33;
            eth_header[10] = 0x44;
            eth_header[11] = 0x55;
            eth_header[12] = 0x08;
            eth_header[13] = 0x00;
            
            uint32_t full_packet_len = 14 + total_len;
            
            // Make sure we don't overflow
            if (pcap_pos + 16 + full_packet_len > estimated_size) {
                printf("Warning: PCAP buffer overflow prevented, stopping\n");
                break;
            }
            
            struct {
                uint32_t ts_sec;
                uint32_t ts_usec;
                uint32_t incl_len;
                uint32_t orig_len;
            } rec_hdr = {
                .ts_sec = timestamp + (uint32_t)i,
                .ts_usec = 0,
                .incl_len = full_packet_len,
                .orig_len = full_packet_len
            };
            
            memcpy(*pcap_data + pcap_pos, &rec_hdr, 16);
            pcap_pos += 16;
            
            memcpy(*pcap_data + pcap_pos, eth_header, 14);
            pcap_pos += 14;
            memcpy(*pcap_data + pcap_pos, cleaned_data + current_start, total_len);
            pcap_pos += total_len;
            packets_written++;
        }
    }
    
    *pcap_size = pcap_pos;
    
    free(cleaned_data);
    free(packet_offsets);
    
    DBG_PRINTF("Created virtual PCAP with %zu packets (%zu bytes)\n", packets_written, *pcap_size);
    return 0;
}
