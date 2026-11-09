#ifndef INPUT_H
#define INPUT_H

#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>

// Fallback definition if u_char is still not defined
#ifndef u_char
typedef unsigned char u_char;
#endif

// Input type constants
#define INPUT_TYPE_PCAP 0
#define INPUT_TYPE_DEBUG 1
#define INPUT_TYPE_ALP_PCAP 2
#define INPUT_TYPE_STLTP 3

// ALP parsing return codes
#define ALP_PARSE_ERROR -1
#define ALP_PARSE_IPV4 0
#define ALP_PARSE_SIGNALING 1
#define ALP_PARSE_EXTENSION_ONLY 2

// ALP packet types
#define ALP_PACKET_TYPE_IPV4 0x00
#define ALP_PACKET_TYPE_COMPRESSED_IPV4 0x01
#define ALP_PACKET_TYPE_LINK_LAYER_SIGNALING 0x04
#define ALP_PACKET_TYPE_PACKET_TYPE_EXTENSION 0x07

#ifndef DLT_ATSC_ALP
#define DLT_ATSC_ALP 289
#endif

// ============================================================================
// STLTP Constants per A/324
// ============================================================================

// Outer tunnel RTP payload type (Table 6.2)
#define STLTP_OUTER_PT 97   // 0x61 - STL Transport Protocol

// Inner stream RTP payload types (Section 9)
#define STLTP_PT_TM       76   // 0x4C - Timing & Management
#define STLTP_PT_PREAMBLE 77   // 0x4D - Preamble (L1-Basic + L1-Detail)
#define STLTP_PT_BBP      78   // 0x4E - Baseband Packets

// Inner stream destination ports (Section 9)
#define STLTP_PORT_BBP_BASE  30000  // Baseband Packets start (PLP 0)
#define STLTP_PORT_BBP_MAX   30063  // Baseband Packets end (PLP 63)
#define STLTP_PORT_PREAMBLE  30064  // Preamble stream
#define STLTP_PORT_TM        30065  // Timing & Management
#define STLTP_PORT_SECURITY  30066  // Security Data Stream

// Inner stream multicast address
#define STLTP_INNER_MCAST_ADDR 0xEF003330  // 239.0.51.48

// L1 signaling sizes (A/322)
#define STLTP_L1_BASIC_SIZE 25  // 200 bits = 25 bytes

// ALP header structure
typedef struct {
    uint8_t packet_type;
    uint8_t payload_configuration;
    uint16_t length;
    uint8_t* payload;
} alp_packet_t;

// Per-PLP RTP gap statistics (for HTML display)
#define STLTP_MAX_PLPS 64
typedef struct {
    int plp_id;
    uint32_t gaps;
    uint32_t packets_lost;
} stltp_plp_gap_t;

// Capture time of one extracted ALP packet
typedef struct {
    size_t offset;                    // byte offset of the packet in alp_data
    uint64_t ts_us;                   // capture time, microseconds since the epoch
} stltp_alp_time_t;

// STLTP extraction results
#define STLTP_HAS_ROBUST_READER 1   // capture reader v15 fields below are present
typedef struct {
    uint8_t *alp_data;           // Extracted ALP packets (descrambled)
    size_t alp_size;
    uint8_t *l1_basic;           // L1-Basic data (raw bytes, 25 bytes)
    size_t l1_basic_size;
    uint8_t *l1_detail;          // L1-Detail data (raw bytes, variable)
    size_t l1_detail_size;
    char *l1_basic_b64;          // L1-Basic as base64 string
    char *l1_detail_b64;         // L1-Detail as base64 string
    uint8_t *timing_mgmt;        // Timing & Management data
    size_t timing_mgmt_size;
    
    // Basic stats (existing)
    uint32_t alp_packet_count;
    uint32_t preamble_packet_count;
    uint32_t timing_packet_count;
    uint32_t rtp_packet_count;
    
    // Extended STLTP processing statistics
    uint32_t outer_packets;           // Total outer RTP packets processed
    uint32_t bbp_count;               // Baseband packets processed
    
    // ALP type breakdown
    uint32_t alp_type_counts[8];      // Per-type ALP packet counts
    
    // Spanning packet statistics
    uint32_t spanning_started;        // Spanning packets started
    uint32_t spanning_complete;       // Spanning packets completed successfully
    uint32_t spanning_discarded;      // Spanning packets discarded (incomplete)
    uint32_t orphan_continuations;    // Continuation packets without a start
    
    // Error statistics
    uint32_t rejected_packets;        // Packets rejected due to validation failures
    uint32_t sync_errors;             // Synchronization errors detected
    
    // Outer (tunnel) RTP sequence gap statistics - real loss in the capture/network
    uint32_t outer_rtp_gaps;          // Outer RTP sequence gaps
    uint32_t outer_rtp_gap_packets;   // Estimated outer packets lost
    uint32_t tunnel_drops;            // Inner packets dropped while reassembling the tunnel

    // Capture reading / stream selection
    uint32_t truncated_packets;       // Frames cut short by the capture snaplen (skipped)
    uint32_t fragmented_packets;      // IP fragments (skipped, not reassembled)
    uint32_t skipped_frames;          // Not IPv4/UDP or not STLTP outer RTP
    uint32_t ignored_stream_packets;  // Outer RTP from other streams, or before the lock
    int capture_error;                // 1 if the file ended in a corrupt record
    char capture_format[32];          // "pcap", "pcap-ns", "pcapng", ...
    uint32_t link_type;               // Link type of the first packet (1=Ethernet, 113/276=Linux cooked, ...)
    char stream_desc[64];             // Locked outer stream, "src -> dst:port"

    // Capture timing (from the capture file's packet timestamps)
    int capture_timing_valid;         // 1 if every locked packet had a timestamp and time advanced
    uint64_t capture_start_us;        // first / last outer packet of the locked stream,
    uint64_t capture_end_us;          //   microseconds since the epoch
    stltp_alp_time_t *alp_times;      // per-ALP capture times (NULL if timing invalid)
    size_t alp_times_count;

    // Inner RTP sequence gap statistics
    uint32_t inner_rtp_gaps;          // Total inner RTP sequence gaps
    uint32_t inner_rtp_gap_packets;   // Estimated packets lost to inner gaps
    
    // Per-PLP gap breakdown
    int plp_gap_count;                // Number of PLPs with gaps
    stltp_plp_gap_t plp_gaps[STLTP_MAX_PLPS];  // Per-PLP gap info
    
    // Total bytes
    size_t total_alp_bytes;           // Total ALP data extracted
} stltp_extract_t;

// Function prototypes - existing
int detect_file_type(const char* filename);
const char* get_input_type_string(int input_type);
uint8_t* remove_variable_artifacts(const uint8_t *data, size_t data_len, size_t *cleaned_len);
void multicast_ip_to_mac(uint32_t ip, uint8_t *mac);
int create_virtual_pcap_from_debug(const char *debug_filename, uint8_t **pcap_data, size_t *pcap_size);
int parse_alp_packet(const u_char* alp_data, int alp_len, const u_char** ip_payload, int* ip_len, 
                     const u_char** signaling_payload, int* signaling_len);

// Function prototypes - STLTP support
int detect_stltp_file(const char *filename);
stltp_extract_t* stltp_extract_create(void);
void stltp_extract_free(stltp_extract_t *extract);
int process_stltp_file(const char *filename, stltp_extract_t *extract);
int create_virtual_alp_pcap_from_stltp(const char *stltp_filename, uint8_t **pcap_data, size_t *pcap_size,
                                       char **l1_basic_b64, char **l1_detail_b64,
                                       stltp_extract_t **stats_out);

// Base64 encoding helper
char* base64_encode(const uint8_t *data, size_t input_length, size_t *output_length);

#endif // INPUT_H
