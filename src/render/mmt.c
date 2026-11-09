// ============================================================================
// DIRECT_PARSING Compile-Time Configuration
// ============================================================================
// 
// This flag controls how media parameters are extracted from MMT streams:
//
// DIRECT_PARSING = 1 (Default):
//   - Uses libavcodec for direct HEVC video parameter parsing
//   - Uses direct_parsers library for direct AC-4 audio parameter parsing
//   - Falls back to signaling descriptors (VSPD/ASPD) when direct parsing fails
//   - Provides the most complete information but requires external libraries
//   - Dependencies: libavcodec (FFmpeg), direct_parsers library
//
// DIRECT_PARSING = 0:
//   - Uses ONLY signaling data from descriptors (VSPD/ASPD/CAD)
//   - No direct parsing of video/audio streams
//   - Reduced dependencies (no libavcodec or direct_parsers needed)
//   - May have less complete information if descriptors are missing
//   - Recommended when: 
//     * Signaling data is reliable and complete
//     * Want to minimize external dependencies
//     * Avoiding potential segmentation faults from direct parsing
//
// To change the mode, simply modify the #define below before compiling.
// ============================================================================

#define DIRECT_PARSING 1

#include "mmt.h"
#include "debug_log.h"

#if DIRECT_PARSING
#include "direct_parsers.h"
#endif // DIRECT_PARSING

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <zlib.h>
#include <time.h>
#include <libxml/parser.h>
#include <libxml/tree.h>


// Module-level state
static ServiceDescriptors g_service_descriptors[MAX_SERVICE_DESCRIPTORS];
static int g_service_descriptor_count = 0;

static MptTable g_mpt_tables[MAX_MPT_TABLES];
static int g_mpt_table_count = 0;

static PacketIdLog g_packet_id_log[MAX_UNIQUE_PIDS];
static int g_packet_id_log_count = 0;
static bool packet_id_seen[65536] = {false};

static MmtMediaParamsCache g_mmt_params_cache[100];
static int g_mmt_params_cache_count = 0;

static MmtMessageStats g_mmt_message_stats[MAX_MESSAGE_TYPES];
static int g_mmt_message_stats_count = 0;

static int parse_mpt_descriptor_header(const uint8_t** data_ptr, size_t* remaining_ptr,
                                        uint16_t* tag_out, uint16_t* length_out);
void parse_vspd_descriptor(const uint8_t* data, uint16_t length,
                           const char* destIp, const char* destPort);
void parse_aspd_descriptor(const uint8_t* data, uint16_t length,
                           const char* destIp, const char* destPort);
void parse_cad_descriptor(const uint8_t* data, uint16_t length,
                          const char* destIp, const char* destPort);
void parse_spd_descriptor(const uint8_t* data, uint16_t length,
                          const char* destIp, const char* destPort);



/**
 * @brief Enhanced MMT packet header parser based on libatsc3 logic
 */
int parse_mmt_packet_header(const uint8_t* buffer, size_t length, mmt_packet_header_t* header) {
    if (!buffer || !header || length < 4) {
        return -1;
    }
    
    memset(header, 0, sizeof(mmt_packet_header_t));
    
    const uint8_t* pos = buffer;
    size_t remaining = length;
    
    // Parse fixed header (4 bytes minimum)
    if (remaining < 4) return -1;
    
    // Byte 0: version (2), packet_counter_flag (1), fec_type (2), extension_flag (1), rap_flag (1), r (1)
    header->version = (pos[0] >> 6) & 0x3;                  // bits 7-6 (2 bits)
    header->packet_counter_flag = (pos[0] >> 5) & 0x1;      // bit 5 (1 bit)
    header->fec_type = (pos[0] >> 3) & 0x3;                 // bits 4-3 (2 bits)
    header->extension_flag = (pos[0] >> 2) & 0x1;           // bit 2 (1 bit)
    header->rap_flag = (pos[0] >> 1) & 0x1;                 // bit 1 (1 bit)
    // bit 0 is reserved
    
    // Byte 1: upper 4 bits reserved/flags, lower 4 bits is payload type
    header->payload_type = pos[1] & 0x0F;  // Lower 4 bits
    
    // Bytes 2-3: packet_id
    header->packet_id = ntohs(*(uint16_t*)(pos + 2));
    
    pos += 4;
    remaining -= 4;
    
    // Parse timestamp (4 bytes) - ALWAYS present
    if (remaining < 4) return -1;
    header->timestamp = ntohl(*(uint32_t*)pos);
    pos += 4;
    remaining -= 4;
    
    // Parse packet sequence number (4 bytes) - ALWAYS present
    if (remaining < 4) return -1;
    header->packet_sequence_number = ntohl(*(uint32_t*)pos);
    pos += 4;
    remaining -= 4;
    
    // Parse r/TB/DS/TP + flow_label (2 bytes) - ALWAYS present for signaling packets
    // Byte 0: r(1) TB(1) DS(2) TP(4 upper bits)
    // Byte 1: TP(1 lower bit) flow_label(7)
    if (header->payload_type == 2) {  // Signaling packets have these fields
        if (remaining < 2) return -1;
        // We can skip these for now, just advance position
        pos += 2;
        remaining -= 2;
    }
    
    // Parse packet counter if present (4 bytes) - ONLY if packet_counter_flag is set
    if (header->packet_counter_flag) {
        if (remaining < 4) return -1;
        header->packet_counter = ntohl(*(uint32_t*)pos);
        pos += 4;
        remaining -= 4;
    }
    
    // Parse QoS classifier if present (1 byte)
    if (header->qos_flag) {
        if (remaining < 1) return -1;
        header->qos_classifier = pos[0];
        pos += 1;
        remaining -= 1;
    }
    
    // Parse header extension if present
    if (header->extension_flag) {
        if (remaining < 4) return -1;
        header->extension_type = ntohs(*(uint16_t*)pos);
        header->extension_length = ntohs(*(uint16_t*)(pos + 2));
        pos += 4;
        remaining -= 4;
        
        if (remaining < header->extension_length) return -1;
        if (header->extension_length > 0) {
            header->extension_data = malloc(header->extension_length);
            if (header->extension_data) {
                memcpy(header->extension_data, pos, header->extension_length);
            }
        }
        pos += header->extension_length;
        remaining -= header->extension_length;
    }
    
    // Calculate payload offset and length
    header->payload_length = remaining;
    
    #if DEBUG_MMT
    DBG_PRINTF("MMT Header: Version=%d, PacketID=%u, Timestamp=%u, SeqNum=%u, PayloadLen=%u\n",
           header->version, header->packet_id, header->timestamp, 
           header->packet_sequence_number, header->payload_length);
    #endif
    
    return pos - buffer; // Return header length
}

// Parse MPU header
int parse_mpu_header(const uint8_t* buffer, size_t length, MpuHeader* header) {
    if (!buffer || !header || length < 8) return -1;
    
    const uint8_t* pos = buffer;
    
    header->mpu_sequence_number = ntohl(*(uint32_t*)pos);
    pos += 4;
    
    header->fragmentation_indicator = (pos[0] >> 6) & 0x3;
    header->fragment_type = pos[0] & 0x7;
    pos += 4;
    
    header->mfu_data = pos;
    header->mfu_data_length = length - (pos - buffer);
    
    return pos - buffer;
}

/**
 * @brief Cleanup functions
 */
void free_mmt_packet_header(mmt_packet_header_t* header) {
    if (header && header->extension_data) {
        free(header->extension_data);
        header->extension_data = NULL;
    }
}

#if !DIRECT_PARSING   // only called when direct parsing is disabled
/**
 * @brief Simple AC-4 DSI parser - gets codec string only
 * Does NOT set channel info - that comes from ASPD
 */
static int parse_ac4_dsi_simple(const uint8_t* dsi_data, size_t dsi_len, MmtMediaParams* params) {
    if (!dsi_data || !params || dsi_len < 3) {
        return -1;
    }
    
    DBG_PRINTF("DEBUG AC-4: Simple DSI parsing (len=%zu)\n", dsi_len);
    
    // Byte 0: bits 7-5 = ac4_dsi_version (3 bits), bits 4-0 = bitstream_version upper 5 bits
    uint8_t byte0 = dsi_data[0];
    uint8_t ac4_dsi_version = (byte0 >> 5) & 0x07;
    
    // Byte 1: bit 7-6 = bitstream_version lower 2 bits
    uint8_t byte1 = dsi_data[1];
    uint8_t bitstream_version = ((byte0 & 0x1F) << 2) | ((byte1 >> 6) & 0x03);
    
    DBG_PRINTF("DEBUG AC-4: DSI version=%u, bitstream_version=%u\n", 
           ac4_dsi_version, bitstream_version);
    
    // Try to find presentation_version (usually around byte 7-10)
    uint8_t presentation_version = 1;  // Default
    if (dsi_len > 10) {
        for (size_t i = 6; i < 12 && i < dsi_len; i++) {
            if (dsi_data[i] <= 5) {
                presentation_version = dsi_data[i];
                break;
            }
        }
    }
    
    // Build codec string
    snprintf(params->audio_codec, sizeof(params->audio_codec),
             "ac-4.%02u.%02u.%02u", bitstream_version, ac4_dsi_version, presentation_version);
    
    DBG_PRINTF("DEBUG AC-4: Codec string: %s\n", params->audio_codec);
    DBG_PRINTF("DEBUG AC-4: Channel info will come from ASPD descriptor\n");
    
    return 0;
}
#endif // !DIRECT_PARSING

void extract_ac4_params(const uint8_t* data, size_t len, MmtMediaParams* params) {
    DBG_PRINTF("DEBUG AC-4: extract_ac4_params called with len=%zu\n", len);

    if (len < 8) {
        DBG_PRINTF("DEBUG AC-4: Data too short for 'dac4' search\n");
        return;
    }

    const uint8_t* dsi_data = NULL;
    size_t dsi_len = 0;

    // Find 'dac4' box
    for (size_t i = 4; i <= len - 4; i++) {
        if (data[i] == 'd' && data[i+1] == 'a' && data[i+2] == 'c' && data[i+3] == '4') {
            const uint8_t* box_start = &data[i - 4];
            uint32_t box_size_be = 0;
            memcpy(&box_size_be, box_start, 4);
            uint32_t box_size = ntohl(box_size_be);

            DBG_PRINTF("DEBUG AC-4: Found 'dac4' at offset %zu, box_size = %u\n", i, box_size);

            if (box_size < 8 || box_size > (len - (i - 4))) {
                DBG_PRINTF("DEBUG AC-4: Invalid box size. Skipping.\n");
                continue;
            }

            dsi_data = &data[i + 4];
            dsi_len = box_size - 8;

            if (dsi_len == 0 || dsi_len > (len - (i + 4))) {
                continue;
            }
            
            DBG_PRINTF("DEBUG AC-4: DSI data starts at offset %zu, dsi_len = %zu\n", 
                   (size_t)(dsi_data - data), dsi_len);
            
            // After you find dac4_data and dac4_size, add:
            DBG_PRINTF("DSI HEX (first 50 bytes):\n");
            for (int i = 0; i < (dsi_len < 50 ? dsi_len : 50); i++) {
                DBG_PRINTF("%02x ", dsi_data[i]);
                if ((i+1) % 16 == 0) DBG_PRINTF("\n");
            }
            DBG_PRINTF("\n");
            
#if DIRECT_PARSING
            // Parse using AC-4 parser library - use ac4_parse_dac4 for DSI data from dac4 atom
            AC4AudioParams ac4_params;
            int ret = ac4_parse_dac4(dsi_data, dsi_len, &ac4_params);
            
            if (ret == 0 && ac4_params.error == 0) {
                DBG_PRINTF("DEBUG AC-4: Successfully parsed with ac4_parser library\n");
                DBG_PRINTF("DEBUG AC-4:   Version: %d\n", ac4_params.version);
                DBG_PRINTF("DEBUG AC-4:   Sample rate: %d Hz\n", ac4_params.sample_rate);
                DBG_PRINTF("DEBUG AC-4:   Channels: %d\n", ac4_params.channels);
                DBG_PRINTF("DEBUG AC-4:   Channel layout: %s\n", ac4_params.channel_layout);
                DBG_PRINTF("DEBUG AC-4:   Bitrate: %d kbps\n", ac4_params.bitrate);
                DBG_PRINTF("DEBUG AC-4:   Codec string: %s\n", ac4_params.codec_string);
                
                // Map AC-4 parser results to MmtMediaParams
                
                // Channel count and layout
                if (ac4_params.channels > 0) {
                    // Map to standard surround format strings
                    if (ac4_params.channels == 1) {
                        strcpy(params->audio_channels, "1.0");
                    } else if (ac4_params.channels == 2) {
                        strcpy(params->audio_channels, "2.0");
                    } else if (ac4_params.channels == 6) {
                        strcpy(params->audio_channels, "5.1");
                    } else if (ac4_params.channels == 8) {
                        strcpy(params->audio_channels, "7.1");
                    } else if (ac4_params.channels == 12) {
                        strcpy(params->audio_channels, "7.1.4");
                    } else {
                        snprintf(params->audio_channels, sizeof(params->audio_channels), 
                                "%d.0", ac4_params.channels);
                    }
                    DBG_PRINTF("DEBUG AC-4: Mapped to channel format: %s\n", params->audio_channels);
                }
                
                // Bitrate
                if (ac4_params.bitrate > 0) {
                    params->audio_bitrate_kbps = ac4_params.bitrate;
                    DBG_PRINTF("DEBUG AC-4: Bitrate: %d kbps\n", params->audio_bitrate_kbps);
                }
                
                // Build codec string in ATSC format: ac-4.XX.YY.ZZ
                // The AC-4 parser gives us version, we need to construct the rest
                // Format: ac-4.<bitstream_version>.01.<presentation_version>
                snprintf(params->audio_codec, sizeof(params->audio_codec),
                         "ac-4.%02d.01.%02d", 
                         ac4_params.version, 
                         0);  // presentation version not directly available
                
                DBG_PRINTF("DEBUG AC-4: Generated codec string: %s\n", params->audio_codec);
                DBG_PRINTF("DEBUG AC-4: Successfully extracted AC-4 params\n");
                return;
            } else {
                DBG_PRINTF("DEBUG AC-4: ac4_parse_dac4 failed: %s\n", 
                       ac4_params.error_msg[0] ? ac4_params.error_msg : "unknown error");
            }
#else
            // When DIRECT_PARSING is disabled, we rely on ASPD descriptor
            DBG_PRINTF("DEBUG AC-4: DIRECT_PARSING disabled - relying on ASPD descriptor for audio parameters\n");
            // Still set a basic codec string if we can
            parse_ac4_dsi_simple(dsi_data, dsi_len, params);
            return;
#endif // DIRECT_PARSING
        }
    }

    DBG_PRINTF("DEBUG AC-4: 'dac4' box not found or parsing failed\n");
}

/**
 * @brief Helper function to extract video params from VSPD descriptor
 * @return true if VSPD data was found and has complete video information, false otherwise
 */
static bool try_extract_video_params_from_vspd(const char* dest_ip, const char* dest_port, 
                                                MmtMediaParams* params) {
    // Look for VSPD descriptor for this service
    ServiceDescriptors* svc_desc = NULL;
    for (int i = 0; i < get_service_descriptor_count(); i++) {
        ServiceDescriptors* d = &get_service_descriptors()[i];
        if (strcmp(d->destinationIp, dest_ip) == 0 &&
            strcmp(d->destinationPort, dest_port) == 0) {
            svc_desc = d;
            break;
        }
    }
    
    if (!svc_desc || !svc_desc->vspd) {
        DBG_PRINTF("DEBUG VSPD: No VSPD descriptor found for %s:%s\n", dest_ip, dest_port);
        return false;
    }
    
    VspdData* vspd = svc_desc->vspd;
    
    // Check if VSPD has the essential video parameters
    bool has_resolution = (vspd->horizontal_size > 0 && vspd->vertical_size > 0);
    bool has_frame_rate = (strlen(vspd->frame_rate) > 0 || vspd->frame_rate_code > 0);
    bool has_scan_info = (vspd->progressive_flag || vspd->interlaced_flag);
    
    if (!has_resolution) {
        DBG_PRINTF("DEBUG VSPD: Found VSPD but missing resolution\n");
        return false;
    }
    
    if (!has_frame_rate) {
        DBG_PRINTF("DEBUG VSPD: Found VSPD but missing frame rate\n");
        return false;
    }
    
    if (!has_scan_info) {
        DBG_PRINTF("DEBUG VSPD: Found VSPD but missing progressive/interlaced info\n");
        return false;
    }
    
    // VSPD has complete information - use it!
    DBG_PRINTF("DEBUG VSPD: Using VSPD data for %s:%s\n", dest_ip, dest_port);
    
    // Fill in resolution
    snprintf(params->resolution, sizeof(params->resolution), "%ux%u", 
             vspd->horizontal_size, vspd->vertical_size);
    
    // Fill in frame rate
    if (strlen(vspd->frame_rate) > 0) {
        strncpy(params->frame_rate, vspd->frame_rate, sizeof(params->frame_rate) - 1);
        params->frame_rate[sizeof(params->frame_rate) - 1] = '\0';
    } else {
        // Map frame rate code to string if only code is available
        switch (vspd->frame_rate_code) {
            case 0x1: strcpy(params->frame_rate, "23.976 fps"); break;
            case 0x2: strcpy(params->frame_rate, "24 fps"); break;
            case 0x3: strcpy(params->frame_rate, "25 fps"); break;
            case 0x4: strcpy(params->frame_rate, "29.97 fps"); break;
            case 0x5: strcpy(params->frame_rate, "30 fps"); break;
            case 0x6: strcpy(params->frame_rate, "50 fps"); break;
            case 0x7: strcpy(params->frame_rate, "59.94 fps"); break;
            case 0x8: strcpy(params->frame_rate, "60 fps"); break;
            case 0x9: strcpy(params->frame_rate, "120 fps"); break;
            default: strcpy(params->frame_rate, "Unknown"); break;
        }
    }
    
    // Fill in scan type (progressive/interlaced)
    if (vspd->progressive_flag) {
        strcpy(params->scan_type, "progressive");
    } else if (vspd->interlaced_flag) {
        strcpy(params->scan_type, "interlaced");
    } else {
        strcpy(params->scan_type, "unknown");
    }
    
    // Build simplified codec string from VSPD data (with X for unknown fields)
    // Full format: codec.profile.compatibility.tier+level.constraints
    // VSPD format: codec.profile.X.tier+level.X
    if (strlen(vspd->codec_name) > 0 && vspd->profile_idc > 0 && vspd->level_idc > 0) {
        // Codec name should be a short FourCC (4 chars), but limit to 8 chars to be safe
        char safe_codec[9];
        strncpy(safe_codec, vspd->codec_name, 8);
        safe_codec[8] = '\0';
        
        char tier_char = vspd->tier_flag ? 'H' : 'L';
        
        // Build codec string with safe bounds
        // Max length: 8 (codec) + 1 (.) + 3 (profile) + 4 (.X.) + 1 (tier) + 3 (level) + 3 (.X) + 1 (null) = 24 bytes
        snprintf(params->video_codec, sizeof(params->video_codec),
                 "%.8s.%u.X.%c%u.X",
                 safe_codec,            // e.g., "hev1" (limited to 8 chars)
                 vspd->profile_idc,     // e.g., 2 for Main 10
                 tier_char,             // 'L' for Main, 'H' for High
                 vspd->level_idc);      // e.g., 123 for level 4.1
        
        DBG_PRINTF("DEBUG VSPD: Built simplified codec string: %s (X = unavailable from VSPD)\n", 
               params->video_codec);
    } else if (strlen(vspd->codec_name) > 0) {
        // Fallback: just use codec name if profile/level not available
        strncpy(params->video_codec, vspd->codec_name, sizeof(params->video_codec) - 1);
        params->video_codec[sizeof(params->video_codec) - 1] = '\0';
        DBG_PRINTF("DEBUG VSPD: Using basic codec name: %s (profile/level unavailable)\n", 
               params->video_codec);
    }
    
    DBG_PRINTF("DEBUG VSPD: Extracted from VSPD - Resolution: %s, Frame Rate: %s, Scan: %s, Codec: %s\n",
           params->resolution, params->frame_rate, params->scan_type, params->video_codec);
    
    return true;
}

/**
 * @brief Format video resolution with scan type suffix (e.g., "1920x1080p", "1920x1080i")
 * @param resolution String like "1920x1080"
 * @param scan_type String like "progressive", "interlaced", or "unknown"
 * @param output Buffer to write formatted string
 * @param output_size Size of output buffer
 */
static void format_video_resolution(const char* resolution, const char* scan_type, 
                                     char* output, size_t output_size) {
    DBG_PRINTF("DEBUG format_video_resolution: resolution='%s', scan_type='%s'\n", 
           resolution ? resolution : "NULL", scan_type ? scan_type : "NULL");
    
    if (!resolution || strlen(resolution) == 0) {
        snprintf(output, output_size, "Unknown");
        return;
    }
    
    // Determine scan suffix
    char scan_suffix = '\0';
    if (scan_type && strlen(scan_type) > 0) {
        if (strcmp(scan_type, "progressive") == 0) {
            scan_suffix = 'p';
            DBG_PRINTF("DEBUG format_video_resolution: Setting suffix to 'p'\n");
        } else if (strcmp(scan_type, "interlaced") == 0) {
            scan_suffix = 'i';
            DBG_PRINTF("DEBUG format_video_resolution: Setting suffix to 'i'\n");
        } else {
            DBG_PRINTF("DEBUG format_video_resolution: scan_type '%s' didn't match progressive or interlaced\n", scan_type);
        }
    } else {
        DBG_PRINTF("DEBUG format_video_resolution: scan_type is NULL or empty\n");
    }
    
    // Keep full resolution and add suffix
    if (scan_suffix) {
        snprintf(output, output_size, "%s%c", resolution, scan_suffix);
        DBG_PRINTF("DEBUG format_video_resolution: Output with suffix: '%s'\n", output);
    } else {
        snprintf(output, output_size, "%s", resolution);
        DBG_PRINTF("DEBUG format_video_resolution: Output without suffix: '%s'\n", output);
    }
}


void extract_mmt_media_params_from_mpu(const uint8_t* payload, size_t length, 
                                        const char* asset_type, MmtMediaParams* params,
                                        const char* dest_ip, const char* dest_port) {
    DBG_PRINTF("DEBUG MPU: Attempting to parse MPU for %s asset, length=%zu\n", asset_type, length);
    
    // Initialization fragments are typically much larger (100s to 1000s of bytes)
    if (length < 100) {
        DBG_PRINTF("DEBUG MPU: Payload too small (%zu bytes) - probably not initialization\n", length);
        return;
    }
    
    MpuHeader mpu;
    if (parse_mpu_header(payload, length, &mpu) < 0) {
        DBG_PRINTF("DEBUG MPU: Failed to parse MPU header\n");
        return;
    }
    
    DBG_PRINTF("DEBUG MPU: fragment_type=%d (0=init), mfu_data_length=%zu\n", 
           mpu.fragment_type, mpu.mfu_data_length);
    
    if (mpu.fragment_type != 0) {
        DBG_PRINTF("DEBUG MPU: Skipping non-initialization fragment\n");
        return;
    }
    
    // Also check MFU data size
    if (mpu.mfu_data_length < 50) {
        DBG_PRINTF("DEBUG MPU: MFU data too small (%zu bytes)\n", mpu.mfu_data_length);
        return;
    }
    
    DBG_PRINTF("DEBUG MPU: Processing initialization fragment for %s\n", asset_type);
    
    // Determine if this is video or audio based on asset_type
    // asset_type might be "video"/"audio" or a codec FourCC like "hev1", "hvc1", "avc1", "ac-4", "mp4a"
    bool is_video = false;
    bool is_audio = false;
    
    if (strcmp(asset_type, "video") == 0 || strcmp(asset_type, "Video") == 0 ||
        strcmp(asset_type, "hev1") == 0 || strcmp(asset_type, "hvc1") == 0 ||
        strcmp(asset_type, "avc1") == 0 || strcmp(asset_type, "avc3") == 0) {
        is_video = true;
    } else if (strcmp(asset_type, "audio") == 0 || strcmp(asset_type, "Audio") == 0 ||
               strncmp(asset_type, "ac-4", 4) == 0 ||  // FIX #3: Matches "ac-4", "ac-4.02", etc.
               strcmp(asset_type, "AC-4") == 0 ||
               strcmp(asset_type, "mp4a") == 0 ||
               strcmp(asset_type, "ac-3") == 0 || 
               strcmp(asset_type, "ec-3") == 0) {
        is_audio = true;
    }
    
    if (is_video) {
        // NEW: First try to get video parameters from VSPD descriptor
        // This avoids potential segmentation faults from direct video parsing
        DBG_PRINTF("DEBUG MPU: Video asset detected - checking VSPD first\n");
        
        bool vspd_success = try_extract_video_params_from_vspd(dest_ip, dest_port, params);
        
        if (vspd_success) {
            DBG_PRINTF("DEBUG MPU: Successfully extracted video params from VSPD\n");
            DBG_PRINTF("DEBUG MPU:   Resolution: %s, Frame Rate: %s, Scan: %s\n", 
                   params->resolution, params->frame_rate, params->scan_type);
        } else {
#if DIRECT_PARSING
            // VSPD data not available or incomplete - fall back to direct video parsing
            DBG_PRINTF("DEBUG MPU: VSPD unavailable or incomplete, attempting direct video parsing\n");
            DBG_PRINTF("DEBUG MPU: WARNING - Direct video parsing may cause segmentation fault\n");
            
            extract_hevc_params(mpu.mfu_data, mpu.mfu_data_length, params);
            if (strlen(params->resolution) > 0) {
                DBG_PRINTF("DEBUG MPU: Extracted video params from HEVC: %s %s %.2f fps\n", 
                       params->resolution, params->scan_type, atof(params->frame_rate));
            } else {
                DBG_PRINTF("DEBUG MPU: Could not extract video params from HEVC data\n");
            }
#else
            // DIRECT_PARSING disabled - only use VSPD
            DBG_PRINTF("DEBUG MPU: DIRECT_PARSING disabled - only using VSPD for video parameters\n");
            DBG_PRINTF("DEBUG MPU: No video parameters available without VSPD\n");
#endif // DIRECT_PARSING
        }
    } else if (is_audio) {
#if DIRECT_PARSING
        extract_ac4_params(mpu.mfu_data, mpu.mfu_data_length, params);
        if (strlen(params->audio_codec) > 0) {
            DBG_PRINTF("DEBUG MPU: Extracted audio params: %s %s\n", 
                   params->audio_codec, params->audio_channels);
        } else {
            DBG_PRINTF("DEBUG MPU: Could not extract audio params from AC-4 data\n");
        }
#else
        // DIRECT_PARSING disabled - rely on ASPD descriptor
        DBG_PRINTF("DEBUG MPU: DIRECT_PARSING disabled - relying on ASPD descriptor for audio parameters\n");
        DBG_PRINTF("DEBUG MPU: No direct AC-4 parsing will be performed\n");
#endif // DIRECT_PARSING
    } else {
        DBG_PRINTF("DEBUG MPU: Unknown asset type '%s' - cannot extract params\n", asset_type);
    }
}

// Cache management
void cache_mmt_params(const char* dest_ip, const char* dest_port, 
                      uint16_t packet_id, MmtMediaParams* params) {
    for (int i = 0; i < g_mmt_params_cache_count; i++) {
        if (strcmp(g_mmt_params_cache[i].destIp, dest_ip) == 0 &&
            strcmp(g_mmt_params_cache[i].destPort, dest_port) == 0 &&
            g_mmt_params_cache[i].packet_id == packet_id) {
            g_mmt_params_cache[i].params = *params;
            return;
        }
    }
    
    if (g_mmt_params_cache_count < 100) {
        strcpy(g_mmt_params_cache[g_mmt_params_cache_count].destIp, dest_ip);
        strcpy(g_mmt_params_cache[g_mmt_params_cache_count].destPort, dest_port);
        g_mmt_params_cache[g_mmt_params_cache_count].packet_id = packet_id;
        g_mmt_params_cache[g_mmt_params_cache_count].params = *params;
        
        DBG_PRINTF("DEBUG CACHE: ADD [%d] ip='%s' port='%s' pid=%u\n", 
               g_mmt_params_cache_count, dest_ip, dest_port, packet_id);
        DBG_PRINTF("DEBUG CACHE:   resolution='%s', video_codec='%s'\n",
               params->resolution, params->video_codec);
        DBG_PRINTF("DEBUG CACHE:   audio_codec='%s', audio_channels='%s', bitrate=%d\n",
               params->audio_codec, params->audio_channels, params->audio_bitrate_kbps);
        
        g_mmt_params_cache_count++;
    }
}

MmtMediaParams* get_cached_mmt_params(const char* dest_ip, const char* dest_port, 
                                      uint16_t packet_id) {
    DBG_PRINTF("DEBUG CACHE: Looking for ip='%s', port='%s', packet_id=%u\n", 
           dest_ip, dest_port, packet_id);
    DBG_PRINTF("DEBUG CACHE: Total cached entries: %d\n", g_mmt_params_cache_count);
    
    for (int i = 0; i < g_mmt_params_cache_count; i++) {
        DBG_PRINTF("DEBUG CACHE:   [%d] ip='%s', port='%s', pid=%u, resolution='%s'\n",
               i, g_mmt_params_cache[i].destIp, g_mmt_params_cache[i].destPort,
               g_mmt_params_cache[i].packet_id, g_mmt_params_cache[i].params.resolution);
        
        if (strcmp(g_mmt_params_cache[i].destIp, dest_ip) == 0 &&
            strcmp(g_mmt_params_cache[i].destPort, dest_port) == 0 &&
            g_mmt_params_cache[i].packet_id == packet_id) {
            DBG_PRINTF("DEBUG CACHE: MATCH FOUND!\n");
            return &g_mmt_params_cache[i].params;
        }
    }
    DBG_PRINTF("DEBUG CACHE: No match found\n");
    return NULL;
}

void print_mmt_params_cache(void) {
    DBG_PRINTF("\n=== MMT PARAMS CACHE DUMP ===\n");
    DBG_PRINTF("Total entries: %d\n", g_mmt_params_cache_count);
    for (int i = 0; i < g_mmt_params_cache_count; i++) {
        DBG_PRINTF("[%d] %s:%s PID=%u\n", i, 
               g_mmt_params_cache[i].destIp,
               g_mmt_params_cache[i].destPort,
               g_mmt_params_cache[i].packet_id);
        DBG_PRINTF("    Resolution: %s\n", g_mmt_params_cache[i].params.resolution);
        DBG_PRINTF("    Video Codec: %s\n", g_mmt_params_cache[i].params.video_codec);
        DBG_PRINTF("    Frame Rate: %s\n", g_mmt_params_cache[i].params.frame_rate);
        DBG_PRINTF("    Scan Type: %s\n", g_mmt_params_cache[i].params.scan_type);
        DBG_PRINTF("    Audio Codec: %s\n", g_mmt_params_cache[i].params.audio_codec);
        DBG_PRINTF("    Audio Channels: %s\n", g_mmt_params_cache[i].params.audio_channels);
        DBG_PRINTF("    Audio Bitrate: %d kbps\n", g_mmt_params_cache[i].params.audio_bitrate_kbps);
    }
    DBG_PRINTF("=== END CACHE DUMP ===\n\n");
}

void process_enhanced_mmt_payload(const u_char* payload, int len, ServiceDestination* dest_info) {
    if (len < 32) return;
    
    mmt_packet_header_t header;
    int header_len = parse_mmt_packet_header(payload, len, &header);
    
    if (header_len < 0) {
        #if DEBUG_MMT
        DBG_PRINTF("Failed to parse MMT packet header\n");
        #endif
        return;
    }
    
    // Record data usage (use packet ID as TSI equivalent for MMT)
    const char* description = get_stream_description(dest_info->destinationIpStr, 
                                                   dest_info->destinationPortStr, 
                                                   header.packet_id);
    record_data_usage(dest_info->destinationIpStr, dest_info->destinationPortStr, 
                     header.packet_id, len, description, NULL, NULL, 0);
    
    log_mmt_packet_id(header.packet_id);
    
    #if DEBUG_MMT
    DBG_PRINTF("MMT Packet: ID=%u, PayloadLen=%u on %s:%s\n", 
           header.packet_id, header.payload_length,
           dest_info->destinationIpStr, dest_info->destinationPortStr);
    #endif
    
    const uint8_t* payload_start = payload + header_len;
    size_t payload_size = header.payload_length;
    
    // Payload type is already extracted from byte 1 of the packet header (bits 0-3)
    uint8_t payload_type = header.payload_type;
    
    // Track statistics
    static int payload_type_counts[16] = {0};  // 4 bits = 0-15
    if (payload_type < 16) {
        payload_type_counts[payload_type]++;
    }
    
    // Print summary every 1000 packets
    if (g_packet_count % 1000 == 0 && g_packet_count > 0) {
        DBG_PRINTF("\n=== MMT PAYLOAD TYPE SUMMARY (after %d packets) ===\n", g_packet_count);
        DBG_PRINTF("Type 0 (MPU/Media):     %d packets\n", payload_type_counts[0]);
        DBG_PRINTF("Type 1 (Generic Obj):   %d packets\n", payload_type_counts[1]);
        DBG_PRINTF("Type 2 (SIGNALING):     %d packets\n", payload_type_counts[2]);
        DBG_PRINTF("Type 3 (Repair):        %d packets\n", payload_type_counts[3]);
        if (payload_type_counts[4] > 0 || payload_type_counts[5] > 0) {
            DBG_PRINTF("Type 4-5: %d packets\n", payload_type_counts[4] + payload_type_counts[5]);
        }
        DBG_PRINTF("===============================================\n\n");
    }
    
    if (payload_type == 2) {
        DBG_PRINTF("DEBUG: FOUND SIGNALING! MMT Packet ID=%u, PayloadType=%u\n", 
               header.packet_id, payload_type);
    }
    
    // Process signaling packets
    bool is_signaling = (payload_type == MMT_PAYLOAD_TYPE_SIGNALING_MESSAGE);
    
    if (is_signaling) {
        DBG_PRINTF("DEBUG: Identified signaling packet - PacketID=%u, PayloadType=%u\n", 
               header.packet_id, payload_type);
        
        // Parse both package-level (packet_id == 0) and component-level (packet_id != 0) signaling
        process_enhanced_mmt_signaling_payload(payload_start, payload_size, 
                                             dest_info->destinationIpStr, dest_info->destinationPortStr);
    } else {
        // This is a media packet - extract parameters from initialization MPUs
        const char* asset_type = get_media_type_from_mpt(dest_info->destinationIpStr, 
                                                         dest_info->destinationPortStr, 
                                                         header.packet_id);
        
        if (asset_type && (strcmp(asset_type, "video") == 0 || strcmp(asset_type, "audio") == 0 || 
                          strcmp(asset_type, "Video") == 0 || strcmp(asset_type, "Audio") == 0 ||
                          strcmp(asset_type, "hev1") == 0 || strcmp(asset_type, "hvc1") == 0 ||
                          strcmp(asset_type, "avc1") == 0 || strcmp(asset_type, "avc3") == 0 ||
                          strcmp(asset_type, "ac-4") == 0 || strcmp(asset_type, "mp4a") == 0 ||
                          strcmp(asset_type, "ac-3") == 0 || strcmp(asset_type, "ec-3") == 0)) {
            #if DEBUG_MMT
            DBG_PRINTF("Found media packet ID=%u, asset_type=%s\n", header.packet_id, asset_type);
            #endif
            
            MmtMediaParams params = {0};
            extract_mmt_media_params_from_mpu(payload_start, payload_size, asset_type, &params,
                                             dest_info->destinationIpStr, dest_info->destinationPortStr);
            
            if (strlen(params.resolution) > 0 || strlen(params.video_codec) > 0 ||
                strlen(params.audio_codec) > 0 || strlen(params.audio_channels) > 0 || 
                params.audio_bitrate_kbps > 0) {
                DBG_PRINTF("DEBUG MPU: Caching params - resolution='%s', video_codec='%s', audio_codec='%s', audio_channels='%s'\n",
                       params.resolution, params.video_codec, params.audio_codec, params.audio_channels);
                cache_mmt_params(dest_info->destinationIpStr, dest_info->destinationPortStr, 
                               header.packet_id, &params);
            } else {
                DBG_PRINTF("DEBUG MPU: NOT caching - no useful params extracted\n");
            }
        }
    }
    
    free_mmt_packet_header(&header);
}

/**
 * @brief Simplified MMT signaling processor - handles GZIP-compressed and uncompressed XML
 */
void process_enhanced_mmt_signaling_payload(const uint8_t* buffer, size_t size, const char* destIp, const char* destPort) {
    if (size < 10) return;
    
    DBG_PRINTF("Processing MMT signaling: %zu bytes from %s:%s\n", size, destIp, destPort);
    
    if (size >= 2 && buffer[0] == 0x18 && buffer[1] == 0x00) {
        DBG_PRINTF("DEBUG: Skipping flow control bytes (18 00) at start of buffer\n");
        buffer += 2;
        size -= 2;
    }
    
    // Try GZIP decompression if it starts with magic bytes
    if (buffer[0] == 0x1F && buffer[1] == 0x8B) {
        DBG_PRINTF("Found GZIP-compressed signaling\n");
        
        int decompressed_size = 0;
        int consumed_size = 0;
        char* decompressed = decompress_gzip(buffer, size, &decompressed_size, &consumed_size);
        
        if (decompressed && decompressed_size > 0) {
            DBG_PRINTF("Decompressed %d bytes\n", decompressed_size);
            
            // Try to parse as XML
            TableType type = TABLE_TYPE_UNKNOWN;
            void* parsed_data = NULL;
            char source_id[256];
            snprintf(source_id, sizeof(source_id), "MMT Signaling %s:%s", destIp, destPort);
            
            if (parse_xml(decompressed, decompressed_size, &type, &parsed_data, source_id) == 0 && parsed_data) {
                DBG_PRINTF("Successfully parsed XML table of type %d\n", type);
                store_unique_table(decompressed, decompressed_size, type, parsed_data, destIp, destPort, 0, -1);
                
                // If this is a USBD, also extract and store USD tables with proper IP/port
                if (type == TABLE_TYPE_USBD) {
                    DBG_PRINTF("Found USBD, extracting nested USD tables\n");
                    
                    xmlDocPtr doc = xmlReadMemory(decompressed, decompressed_size, "usbd.xml", NULL, XML_PARSE_RECOVER);
                    if (doc) {
                        xmlNodePtr root = xmlDocGetRootElement(doc);
                        if (root) {
                            xmlNodePtr cur_node = root->children;
                        
                            while (cur_node != NULL) {
                            if (cur_node->type == XML_ELEMENT_NODE && 
                                xmlStrcmp(cur_node->name, (const xmlChar *)"UserServiceDescription") == 0) {
                                
                                char* usd_xml = extract_node_as_xml(cur_node);
                                if (usd_xml) {
                                    TableType usd_type = TABLE_TYPE_USD;
                                    void* usd_parsed_data = NULL;
                                    if (parse_xml(usd_xml, strlen(usd_xml), &usd_type, &usd_parsed_data, "Nested USD") == 0 && usd_parsed_data) {
                                        store_unique_table(usd_xml, strlen(usd_xml), TABLE_TYPE_USD, usd_parsed_data, destIp, destPort, 0, -1);
                                    }
                                    free(usd_xml);
                                }
                            }
                            cur_node = cur_node->next;
                        }
                        }  // End of if (root) check
                        xmlFreeDoc(doc);
                    }
                }
            } else {
                DBG_PRINTF("Failed to parse decompressed content as XML\n");
            }
            
            free(decompressed);
            return;
        } else {
            DBG_PRINTF("GZIP decompression failed\n");
        }
    }
    
    // If not GZIP, check if it's uncompressed XML
    if (size > 5 && memcmp(buffer, "<?xml", 5) == 0) {
        DBG_PRINTF("Found uncompressed XML signaling\n");
        
        TableType type = TABLE_TYPE_UNKNOWN;
        void* parsed_data = NULL;
        char source_id[256];
        snprintf(source_id, sizeof(source_id), "MMT Signaling %s:%s", destIp, destPort);
        
        if (parse_xml((const char*)buffer, size, &type, &parsed_data, source_id) == 0 && parsed_data) {
            DBG_PRINTF("Successfully parsed XML table of type %d\n", type);
            store_unique_table((const char*)buffer, size, type, parsed_data, destIp, destPort, 0, -1);
            
            // If this is a USBD, also extract and store USD tables with proper IP/port
            if (type == TABLE_TYPE_USBD) {
                DBG_PRINTF("Found USBD (uncompressed), extracting nested USD tables\n");
                
                xmlDocPtr doc = xmlReadMemory((const char*)buffer, size, "usbd.xml", NULL, XML_PARSE_RECOVER);
                if (doc) {
                    xmlNodePtr root = xmlDocGetRootElement(doc);
                    if (root) {
                        xmlNodePtr cur_node = root->children;
                    
                        while (cur_node != NULL) {
                            if (cur_node->type == XML_ELEMENT_NODE && 
                                xmlStrcmp(cur_node->name, (const xmlChar *)"UserServiceDescription") == 0) {
                                
                                char* usd_xml = extract_node_as_xml(cur_node);
                                if (usd_xml) {
                                    TableType usd_type = TABLE_TYPE_USD;
                                    void* usd_parsed_data = NULL;
                                    if (parse_xml(usd_xml, strlen(usd_xml), &usd_type, &usd_parsed_data, "Nested USD") == 0 && usd_parsed_data) {
                                        store_unique_table(usd_xml, strlen(usd_xml), TABLE_TYPE_USD, usd_parsed_data, destIp, destPort, 0, -1);
                                        DBG_PRINTF("  Extracted and stored nested USD\n");
                                    }
                                    free(usd_xml);
                                }
                            }
                            cur_node = cur_node->next;
                        }
                    }
                    xmlFreeDoc(doc);
                }
            }
        } else {
            DBG_PRINTF("Failed to parse content as XML\n");
        }
        return;
    }
    
    // Otherwise, it's likely binary signaling (MPT, PA, MPI, etc.)
    DBG_PRINTF("Found binary MMT signaling (%zu bytes) - parsing...\n", size);
    
    int parsed = parse_binary_mmt_messages(buffer, size, destIp, destPort);
    if (parsed > 0) {
        DBG_PRINTF("Successfully parsed %d binary MMT message(s)\n", parsed);
    } else {
        DBG_PRINTF("Failed to parse binary MMT messages\n");
    }
    
    #if DEBUG_MMT
    DBG_PRINTF("First 64 bytes:\n");
    for (size_t i = 0; i < 64 && i < size; i++) {
        if (i % 16 == 0) DBG_PRINTF("%04x: ", (unsigned int)i);
        DBG_PRINTF("%02x ", buffer[i]);
        if ((i + 1) % 16 == 0) DBG_PRINTF("\n");
    }
    if (size % 16 != 0) DBG_PRINTF("\n");
    #endif
}

/**
 * @brief Fixed MMT signaling processor with deduplication
 */
void process_mmt_signaling_payload(const uint8_t* buffer, size_t size, const char* destIp, const char* destPort) {
    #if DEBUG_MMT
    char filename[256];
    snprintf(filename, sizeof(filename), "mmt_signaling_object_%d.bin", g_dump_count++);
    FILE* f_dump = fopen(filename, "wb");
    if (f_dump) {
        fwrite(buffer, 1, size, f_dump);
        fclose(f_dump);
        DBG_PRINTF("--> DEBUG: Dumped %zu bytes for MMT signaling object to %s\n", size, filename);
    }
    #endif

    const uint8_t* payload_to_process = buffer;
    size_t size_to_process = size;
    char* decompressed_buffer = NULL;

    // Check for GZIP compression
    const uint8_t gzip_magic[] = {0x1f, 0x8b}; 
    if (size > 2 && memcmp(buffer, gzip_magic, 2) == 0) {
        DBG_PRINTF("--> Found GZIP stream in MMT signaling. Decompressing...\n");
        int decompressed_size = 0;
        int consumed_size = 0;
        decompressed_buffer = decompress_gzip(buffer, size, &decompressed_size, &consumed_size);
        if(decompressed_buffer) {
            payload_to_process = (uint8_t*)decompressed_buffer;
            size_to_process = decompressed_size;
            
            #if DEBUG_MMT
            fprintf(stderr, "Decompressed %d bytes (consumed %d)\n", decompressed_size, consumed_size);
            fprintf(stderr, "First 64 decompressed bytes: ");
            for (int i = 0; i < 64 && i < decompressed_size; i++) {
                fprintf(stderr, "%02x ", (uint8_t)decompressed_buffer[i]);
                if ((i + 1) % 16 == 0) fprintf(stderr, "\n                              ");
            }
            fprintf(stderr, "\n");
            // Also check as string
            fprintf(stderr, "As string: %.100s\n", decompressed_buffer);
            #endif
        } else {
            DBG_PRINTF("--> ERROR: GZIP decompression failed\n");
            return;
        }
    }

    // Check if the payload is XML
    const char* xml_marker = "<?xml";
    const uint8_t* xml_start = NULL;
    
    // Search for XML marker (might not be at the beginning)
    for (int offset = 0; offset < size_to_process && offset < 100; offset++) {
        if (size_to_process - offset > 5 && 
            memcmp(payload_to_process + offset, xml_marker, 5) == 0) {
            xml_start = payload_to_process + offset;
            break;
        }
    }

    if (xml_start) {
        size_t xml_len = size_to_process - (xml_start - payload_to_process);
        DBG_PRINTF("--> Found XML in MMT signaling payload\n");
        
        char source_id[512];
        snprintf(source_id, sizeof(source_id), "MMT Signaling (XML) on %s:%s", destIp, destPort);

        TableType type = TABLE_TYPE_UNKNOWN;
        void* parsed_data = NULL;
        if (parse_xml((const char*)xml_start, xml_len, &type, &parsed_data, source_id) == 0) {
            if (parsed_data) {
                store_unique_table((const char*)xml_start, xml_len, type, parsed_data, destIp, destPort, 0, -1);
            }
        }
    } else {
        DBG_PRINTF("--> No XML found. Attempting to parse MMT signaling payload as binary.\n");
        
        // Use the multiformat parser
        // TODO: Implement proper binary MP table parsing
        DBG_PRINTF("DEBUG: Found binary data in MMT signaling, %zu bytes (parsing not implemented yet)\n", size_to_process);
        /*if (parsed_data) {
            // Create a unique content ID to prevent duplicates
            char content_id_str[256];
            snprintf(content_id_str, sizeof(content_id_str), "Binary_MMT_%s:%s_size_%zu", 
                     destIp, destPort, size_to_process);
            
            // Check if we already have this exact binary MP table
            int already_stored = 0;
            for (int i = 0; i < g_lls_table_count; i++) {
                if (g_lls_tables[i].type == TABLE_TYPE_MP_TABLE_BINARY &&
                    strcmp(g_lls_tables[i].destinationIp, destIp) == 0 &&
                    strcmp(g_lls_tables[i].destinationPort, destPort) == 0) {
                    already_stored = 1;
                    break;
                }
            }
            
            if (!already_stored) {
                store_unique_table(content_id_str, strlen(content_id_str), 
                                 TABLE_TYPE_MP_TABLE_BINARY, parsed_data, destIp, destPort, 0, -1);
            } else {
                free_binary_mp_table_data(parsed_data);
            }
        }*/
    }

    if(decompressed_buffer) {
        free(decompressed_buffer);
    }
}

int parse_binary_mmt_messages(const uint8_t* buffer, size_t size, 
                               const char* destIp, const char* destPort) {
    
    if (size < 2) {
        DBG_PRINTF("WARN: Buffer too small for MMT signaling header\n");
        return -1;
    }
    
    DBG_PRINTF("Found binary MMT signaling (%zu bytes) - parsing...\n", size);
    
    const uint8_t* pos = buffer;
    size_t remaining = size;
    
    // Parse fragmentation header (2 bytes)
    uint8_t frag_header = pos[0];
    uint8_t frag_counter = pos[1];
    
    uint8_t frag_indicator = (frag_header >> 6) & 0x03;
    uint8_t h_flag = (frag_header >> 1) & 0x01;  // length extension
    uint8_t a_flag = frag_header & 0x01;          // aggregation
    
    DBG_PRINTF("DEBUG: Fragmentation: fi=%u, h=%u, a=%u, counter=%u\n",
           frag_indicator, h_flag, a_flag, frag_counter);
    
    pos += 2;
    remaining -= 2;
    
    // Handle aggregation
    if (a_flag) {
        if (remaining < 1) {
            DBG_PRINTF("WARN: No data for aggregation count\n");
            return -1;
        }
        uint8_t num_messages = pos[0];
        DBG_PRINTF("DEBUG: Aggregated: %u messages\n", num_messages);
        pos++;
        remaining--;
    }
    
    // Read message_id (2 bytes)
    if (remaining < 2) {
        DBG_PRINTF("WARN: Not enough data for message_id\n");
        return -1;
    }
    
    uint16_t message_id = (pos[0] << 8) | pos[1];
    pos += 2;
    remaining -= 2;
    
    DBG_PRINTF("DEBUG: Message ID: 0x%04x\n", message_id);
    
    // Read version (1 byte)
    if (remaining < 1) {
        DBG_PRINTF("WARN: Not enough data for version\n");
        return -1;
    }
    
    uint8_t version = pos[0];
    pos++;
    remaining--;
    
    // Read length - size depends on message_id range
    uint32_t msg_length = 0;
    
    if (message_id == 0x0000 || (message_id >= 0x0001 && message_id <= 0x0010)) {
        // PA (0x0000) and MPI (0x0001-0x0010) use 32-bit length
        if (remaining < 4) {
            DBG_PRINTF("WARN: Not enough data for 32-bit length\n");
            return -1;
        }
        msg_length = (pos[0] << 24) | (pos[1] << 16) | (pos[2] << 8) | pos[3];
        pos += 4;
        remaining -= 4;
        DBG_PRINTF("DEBUG: Using 32-bit length (PA/MPI): %u\n", msg_length);
        
    } else if (message_id == 0x8100 || message_id == 0x8101) {
        // ATSC3 messages (0x8100, 0x8101) use 32-bit length
        if (remaining < 4) {
            DBG_PRINTF("WARN: Not enough data for 32-bit length\n");
            return -1;
        }
        msg_length = (pos[0] << 24) | (pos[1] << 16) | (pos[2] << 8) | pos[3];
        pos += 4;
        remaining -= 4;
        DBG_PRINTF("DEBUG: Using 32-bit length (ATSC3): %u\n", msg_length);
        
    } else {
        // MPT (0x0011-0x0020) and others use 16-bit length
        if (remaining < 2) {
            DBG_PRINTF("WARN: Not enough data for 16-bit length\n");
            return -1;
        }
        msg_length = (pos[0] << 8) | pos[1];
        pos += 2;
        remaining -= 2;
        DBG_PRINTF("DEBUG: Using 16-bit length: %u\n", msg_length);
    }
    
    DBG_PRINTF("MMT Signaling: ID=0x%04x, version=%u, length=%u\n",
           message_id, version, msg_length);
    
    // Track this message (will update parse status later)
    bool was_parsed = false;
    
    if (msg_length > remaining) {
        DBG_PRINTF("ERROR: Message length %u exceeds remaining %zu bytes\n",
               msg_length, remaining);
        
        // Hex dump for debugging
        DBG_PRINTF("Hex dump of first %zu bytes of signaling data:\n", (size < 100 ? size : 100));
        for (size_t i = 0; i < size && i < 100; i++) {
            if (i % 16 == 0) DBG_PRINTF("  %04zx: ", i);
            DBG_PRINTF("%02x ", buffer[i]);
            if ((i + 1) % 16 == 0) DBG_PRINTF("\n");
        }
        if (size % 16 != 0) DBG_PRINTF("\n");
        
        return -1;
    }
    
    int messages_parsed = 0;
    
    // Dispatch based on message_id
    if (message_id >= 0x0001 && message_id <= 0x0010) {
        // MPI messages (Package Info)
        const char* subset_name = "Unknown";
        if (message_id == 0x0001) {
            subset_name = "Subset-First";
        } else if (message_id == 0x0010) {
            subset_name = "Complete";
        } else {
            DBG_PRINTF("Found MPI message: Subset-%u\n", message_id - 1);
        }
        if (message_id == 0x0001 || message_id == 0x0010) {
            DBG_PRINTF("Found MPI message: %s\n", subset_name);
        }
        
        // Parse MPI message - contains descriptors for VSPD, ASPD, CAD
        parse_mpi_message_improved(pos, msg_length, destIp, destPort);
        messages_parsed++;
        was_parsed = true;  // Fully parsed now        
    } else if (message_id >= 0x0011 && message_id <= 0x0020) {
        // MPT messages (Package Table) - Contains assets with descriptors!
        const char* subset_name = "Unknown";
        bool is_complete = (message_id == 0x0020);
        
        if (message_id == 0x0011) {
            subset_name = "Subset-First";
        } else if (message_id == 0x0020) {
            subset_name = "Complete";
        } else {
            DBG_PRINTF("Found MPT message: Subset-%u\n", message_id - 0x11);
        }
        if (message_id == 0x0011 || message_id == 0x0020) {
            DBG_PRINTF("Found MPT message: %s\n", subset_name);
        }
        
        // Parse MPT message
        DBG_PRINTF("Parsing MPT (MMT Package Table) message (%u bytes)...\n", msg_length);
        
        const uint8_t* mpt_data = pos;
        size_t mpt_remaining = msg_length;
        
        if (mpt_remaining < 5) {
            DBG_PRINTF("  MPT message too short\n");
        } else {
            uint8_t table_id = mpt_data[0];
            uint8_t mpt_version = mpt_data[1];
            uint16_t table_length = (mpt_data[2] << 8) | mpt_data[3];
            uint8_t mp_table_mode = (mpt_data[4] >> 6) & 0x03;
            
            DBG_PRINTF("  Table ID: 0x%02x, Version: %u, Length: %u, Mode: %u%s\n",
                   table_id, mpt_version, table_length, mp_table_mode,
                   is_complete ? "" : " (Subset)");
            
            mpt_data += 5;
            mpt_remaining -= 5;
            
            // Find or create MPT table entry
            MptTable* mpt_table = NULL;
            for (int idx = 0; idx < g_mpt_table_count; idx++) {
                if (g_mpt_tables[idx].table_id == table_id &&
                    strcmp(g_mpt_tables[idx].source_ip, destIp) == 0 &&
                    strcmp(g_mpt_tables[idx].source_port, destPort) == 0) {
                    mpt_table = &g_mpt_tables[idx];
                    break;
                }
            }
            
            if (!mpt_table && g_mpt_table_count < MAX_MPT_TABLES) {
                mpt_table = &g_mpt_tables[g_mpt_table_count++];
                strncpy(mpt_table->source_ip, destIp, sizeof(mpt_table->source_ip) - 1);
                strncpy(mpt_table->source_port, destPort, sizeof(mpt_table->source_port) - 1);
            }
            
            if (mpt_table) {
                mpt_table->table_id = table_id;
                mpt_table->version = mpt_version;
                mpt_table->is_complete = is_complete;
                mpt_table->last_updated = time(NULL);
            }
            
            // Only complete messages (0x0020) have package_id and MPT descriptors
            if (is_complete) {
                // Parse package_id
                if (mpt_remaining >= 1) {
                    uint8_t pkg_id_len = mpt_data[0];
                    mpt_data++;
                    mpt_remaining--;
                    
                    DBG_PRINTF("  Package ID length: %u\n", pkg_id_len);
                    
                    if (mpt_remaining >= pkg_id_len) {
                        DBG_PRINTF("  Package ID: %.*s\n", pkg_id_len, (char*)mpt_data);
            
                        // ADD THIS: Store package_id if we have an mpt_table
                        if (mpt_table && pkg_id_len > 0) {
                            size_t copy_len = pkg_id_len < sizeof(mpt_table->package_id) - 1 ? 
                                            pkg_id_len : sizeof(mpt_table->package_id) - 1;
                            memcpy(mpt_table->package_id, mpt_data, copy_len);
                            mpt_table->package_id[copy_len] = '\0';
                        }
                        
                        mpt_data += pkg_id_len;
                        mpt_remaining -= pkg_id_len;
                    }
                }
                
                // Parse MPT_descriptors_length
                if (mpt_remaining >= 2) {
                    uint16_t mpt_desc_len = (mpt_data[0] << 8) | mpt_data[1];
                    mpt_data += 2;
                    mpt_remaining -= 2;
                    
                    DBG_PRINTF("  MPT descriptors length: %u\n", mpt_desc_len);
                    
                    // Skip descriptors for now
                    if (mpt_desc_len > 0 && mpt_remaining >= mpt_desc_len) {
                        mpt_data += mpt_desc_len;
                        mpt_remaining -= mpt_desc_len;
                    }
                }
            } else {
                // Subset messages skip directly to number_of_assets
                DBG_PRINTF("  (Subset: skipping package_id and MPT descriptors)\n");
            }
            
            // Parse number_of_assets (same for both complete and subset)
            if (mpt_remaining >= 1) {
                uint8_t num_assets = mpt_data[0];
                mpt_data++;
                mpt_remaining--;
                
                DBG_PRINTF("  Number of assets: %u\n", num_assets);
                
                // Store num_assets in the table
                if (mpt_table) {
                    mpt_table->num_assets = num_assets;
                }

                // Parse each asset (MODIFIED to store data)
                for (int i = 0; i < num_assets && mpt_remaining >= 3; i++) {
                    DBG_PRINTF("  Asset %d:\n", i + 1);
                    
                    // Create a pointer to store this asset's data
                    MptAssetInfo* stored_asset = NULL;
                    if (mpt_table && i < 32) {
                        stored_asset = &mpt_table->assets[i];
                        memset(stored_asset, 0, sizeof(MptAssetInfo));
                    }
                    
                    // identifier_mapping (1 byte) - identifier_type
                    if (mpt_remaining < 1) break;
                    uint8_t identifier_type = mpt_data[0];
                    mpt_data++;
                    mpt_remaining--;
                    
                    DBG_PRINTF("    Identifier type: 0x%02x\n", identifier_type);
                    
                    if (identifier_type == 0x00) {
                        // asset_id format
                        // asset_id_scheme (4 bytes)
                        if (mpt_remaining < 4) break;
                        uint32_t asset_id_scheme = (mpt_data[0] << 24) | (mpt_data[1] << 16) | 
                                                (mpt_data[2] << 8) | mpt_data[3];
                        mpt_data += 4;
                        mpt_remaining -= 4;
                        
                        const char* scheme_name = "Unknown";
                        if (asset_id_scheme == 0x00) scheme_name = "UUID";
                        else if (asset_id_scheme == 0x01) scheme_name = "URI";
                        DBG_PRINTF("    Asset ID scheme: 0x%08x (%s)\n", asset_id_scheme, scheme_name);
                        
                        // Store scheme
                        if (stored_asset) {
                            stored_asset->asset_id_scheme = asset_id_scheme;
                        }
                        
                        // asset_id_length (4 bytes)
                        if (mpt_remaining < 4) break;
                        uint32_t asset_id_length = (mpt_data[0] << 24) | (mpt_data[1] << 16) | 
                                                (mpt_data[2] << 8) | mpt_data[3];
                        mpt_data += 4;
                        mpt_remaining -= 4;
                        
                        // asset_id (variable)
                        if (mpt_remaining < asset_id_length) break;
                        DBG_PRINTF("    Asset ID (%u bytes): %.*s\n", 
                            asset_id_length, (int)asset_id_length, (char*)mpt_data);
                        
                        // Store asset_id
                        if (stored_asset) {
                            size_t copy_len = asset_id_length < sizeof(stored_asset->asset_id) - 1 ? 
                                            asset_id_length : sizeof(stored_asset->asset_id) - 1;
                            memcpy(stored_asset->asset_id, mpt_data, copy_len);
                            stored_asset->asset_id[copy_len] = '\0';
                        }
                        
                        mpt_data += asset_id_length;
                        mpt_remaining -= asset_id_length;
                        
                    } else {
                        DBG_PRINTF("    Unsupported identifier_type: 0x%02x\n", identifier_type);
                        break;
                    }
                    
                    // asset_type (4 bytes - FourCC)
                    if (mpt_remaining < 4) break;
                    char asset_type[5] = {0};
                    memcpy(asset_type, mpt_data, 4);
                    DBG_PRINTF("    Asset type: %.4s\n", asset_type);
                    
                    // Store asset_type
                    if (stored_asset) {
                        memcpy(stored_asset->asset_type, asset_type, 4);
                        stored_asset->asset_type[4] = '\0';
                    }
                    
                    mpt_data += 4;
                    mpt_remaining -= 4;
                    
                    // flags byte: [reserved:6][default_asset_flag:1][asset_clock_relation_flag:1]
                    if (mpt_remaining < 1) break;
                    uint8_t flags = mpt_data[0];
                    uint8_t default_asset_flag = (flags >> 1) & 0x01;
                    uint8_t asset_clock_relation_flag = flags & 0x01;
                    mpt_data++;
                    mpt_remaining--;
                    
                    if (default_asset_flag) {
                        DBG_PRINTF("    Default asset: YES\n");
                    }
                    
                    // Store default flag
                    if (stored_asset) {
                        stored_asset->is_default = default_asset_flag;
                    }
                    
                    // Handle asset_clock_relation if present
                    if (asset_clock_relation_flag) {
                        if (mpt_remaining < 2) break;
                        uint8_t clock_relation_id = mpt_data[0];
                        uint8_t timescale_flag = mpt_data[1] & 0x01;
                        DBG_PRINTF("    Clock relation ID: %u, timescale_flag: %u\n", 
                            clock_relation_id, timescale_flag);
                        mpt_data += 2;
                        mpt_remaining -= 2;
                        
                        if (timescale_flag && mpt_remaining >= 4) {
                            uint32_t asset_timescale = (mpt_data[0] << 24) | (mpt_data[1] << 16) |
                                                    (mpt_data[2] << 8) | mpt_data[3];
                            DBG_PRINTF("    Asset timescale: %u\n", asset_timescale);
                            mpt_data += 4;
                            mpt_remaining -= 4;
                        }
                    }
                    
                    // asset_location_count (1 byte)
                    if (mpt_remaining < 1) break;
                    uint8_t location_count = mpt_data[0];
                    mpt_data++;
                    mpt_remaining--;
                    
                    DBG_PRINTF("    Asset location count: %u\n", location_count);
                    
                    // Parse each location (and store the packet_id)
                    uint16_t found_packet_id = 0;
                    bool found_packet = false;
                    
                    for (int loc = 0; loc < location_count && mpt_remaining >= 1; loc++) {
                        uint8_t location_type = mpt_data[0];
                        mpt_data++;
                        mpt_remaining--;
                        
                        DBG_PRINTF("      Location %d type: %u ", loc + 1, location_type);
                        
                        if (location_type == 0x00) {
                            // packet_id (same flow)
                            if (mpt_remaining < 2) break;
                            uint16_t packet_id = (mpt_data[0] << 8) | mpt_data[1];
                            DBG_PRINTF("(Packet ID: %u)\n", packet_id);
                            
                            if (!found_packet) {
                                found_packet_id = packet_id;
                                found_packet = true;
                            }
                            
                            mpt_data += 2;
                            mpt_remaining -= 2;
                            
                        } else if (location_type == 0x01) {
                            // IPv4 src + dst + port + packet_id
                            if (mpt_remaining < 12) break;
                            uint32_t dst_ip = (mpt_data[4] << 24) | (mpt_data[5] << 16) | 
                                            (mpt_data[6] << 8) | mpt_data[7];
                            uint16_t dst_port = (mpt_data[8] << 8) | mpt_data[9];
                            uint16_t packet_id = (mpt_data[10] << 8) | mpt_data[11];
                            
                            DBG_PRINTF("(IPv4: %u.%u.%u.%u:%u, Packet ID: %u)\n",
                                (dst_ip >> 24) & 0xFF, (dst_ip >> 16) & 0xFF,
                                (dst_ip >> 8) & 0xFF, dst_ip & 0xFF,
                                dst_port, packet_id);
                            
                            if (!found_packet) {
                                found_packet_id = packet_id;
                                found_packet = true;
                            }
                            
                            mpt_data += 12;
                            mpt_remaining -= 12;
                            
                        } else if (location_type == 0x02) {
                            // IPv6
                            if (mpt_remaining < 20) break;
                            DBG_PRINTF("(IPv6 address)\n");
                            mpt_data += 20;
                            mpt_remaining -= 20;
                            
                        } else if (location_type == 0x03) {
                            // URL
                            if (mpt_remaining < 1) break;
                            uint8_t url_length = mpt_data[0];
                            if (mpt_remaining < 1 + url_length) break;
                            DBG_PRINTF("(URL: %.*s)\n", url_length, mpt_data + 1);
                            mpt_data += 1 + url_length;
                            mpt_remaining -= 1 + url_length;
                            
                        } else {
                            DBG_PRINTF("(Unknown)\n");
                            break;
                        }
                    }
                    
                    // Store packet_id
                    if (stored_asset && found_packet) {
                        stored_asset->packet_id = found_packet_id;
                    }
                    
                    // asset_descriptors_length (2 bytes)
                    if (mpt_remaining < 2) break;
                    uint16_t asset_desc_length = (mpt_data[0] << 8) | mpt_data[1];
                    mpt_data += 2;
                    mpt_remaining -= 2;
                    
                    DBG_PRINTF("    Asset descriptors length: %u bytes\n", asset_desc_length);
                    
                    // Parse asset descriptors (VSPD, ASPD, CAD)
                    if (asset_desc_length > 0 && mpt_remaining >= asset_desc_length) {
                        size_t asset_desc_remaining = asset_desc_length;
                        const uint8_t* asset_desc_pos = mpt_data;
                        
                        while (asset_desc_remaining >= 4) {
                            uint16_t desc_tag = 0;
                            uint16_t desc_length = 0;
                            
                            if (parse_mpt_descriptor_header(&asset_desc_pos, &asset_desc_remaining,
                                                             &desc_tag, &desc_length) != 0) {
                                break;
                            }
                            
                            if (desc_length > asset_desc_remaining) break;
                            
                            // Parse descriptors
                            switch (desc_tag) {
                                case MMT_DESCRIPTOR_VSPD:
                                    DBG_PRINTF("      Found VSPD in MPT asset\n");
                                    parse_vspd_descriptor(asset_desc_pos, desc_length, destIp, destPort);
                                    break;
                                case MMT_DESCRIPTOR_ASPD:
                                    DBG_PRINTF("      Found ASPD in MPT asset\n");
                                    parse_aspd_descriptor(asset_desc_pos, desc_length, destIp, destPort);
                                    break;
                                case MMT_DESCRIPTOR_CAD:
                                    DBG_PRINTF("      Found CAD in MPT asset\n");
                                    parse_cad_descriptor(asset_desc_pos, desc_length, destIp, destPort);
                                    break;
                                default:
                                    DBG_PRINTF("      Descriptor: tag=0x%04X, len=%u\n", desc_tag, desc_length);
                                    break;
                            }
                            
                            asset_desc_pos += desc_length;
                            asset_desc_remaining -= desc_length;
                        }
                        
                        mpt_data += asset_desc_length;
                        mpt_remaining -= asset_desc_length;
                    }
                }
            }
            
            int total_audio_streams = 0;
            
            // Convert completed MPT to BinaryMptData and store it
            if (is_complete && mpt_table && mpt_table->num_assets > 0) {
                // Check if we already have a stored BinaryMptData for this destination
                int already_stored = 0;
                for (int check_idx = 0; check_idx < g_lls_table_count; check_idx++) {
                    if (g_lls_tables[check_idx].type == TABLE_TYPE_MP_TABLE_BINARY &&
                        strcmp(g_lls_tables[check_idx].destinationIp, destIp) == 0 &&
                        strcmp(g_lls_tables[check_idx].destinationPort, destPort) == 0) {
                        already_stored = 1;
                        break;
                    }
                }
                
                if (!already_stored) {
                    DBG_PRINTF("Converting MPT to BinaryMptData for storage and HTML display\n");
                    
                    // Allocate BinaryMptData structure
                    BinaryMptData* binary_mpt = (BinaryMptData*)calloc(1, sizeof(BinaryMptData));
                    if (binary_mpt) {
                        // Create linked list of assets
                        BinaryMptAsset* prev_asset = NULL;
                        
                        for (int asset_idx = 0; asset_idx < mpt_table->num_assets && asset_idx < 32; asset_idx++) {
                            MptAssetInfo* src_asset = &mpt_table->assets[asset_idx];
                            
                            // Skip empty assets
                            if (src_asset->packet_id == 0 && strlen(src_asset->asset_id) == 0) {
                                continue;
                            }
                            
                            BinaryMptAsset* new_asset = (BinaryMptAsset*)calloc(1, sizeof(BinaryMptAsset));
                            if (new_asset) {
                                // Copy asset data
                                strncpy(new_asset->assetId, src_asset->asset_id, sizeof(new_asset->assetId) - 1);
                                strncpy(new_asset->assetType, src_asset->asset_type, sizeof(new_asset->assetType) - 1);
                                
                                // Map asset_type codes to readable names for display
                                if (strcmp(src_asset->asset_type, "hvc1") == 0 || 
                                    strcmp(src_asset->asset_type, "hev1") == 0) {
                                    strcpy(new_asset->codec, "HEVC/H.265");
                                } else if (strcmp(src_asset->asset_type, "avc1") == 0 ||
                                          strcmp(src_asset->asset_type, "avc3") == 0) {
                                    strcpy(new_asset->codec, "AVC/H.264");
                                } else if (strcmp(src_asset->asset_type, "ac-4") == 0) {
                                    strcpy(new_asset->codec, "AC-4 Audio");
                                    total_audio_streams++;
                                } else if (strcmp(src_asset->asset_type, "mp4a") == 0) {
                                    strcpy(new_asset->codec, "AAC Audio");
                                    total_audio_streams++;
                                } else if (strcmp(src_asset->asset_type, "stpp") == 0) {
                                    strcpy(new_asset->codec, "TTML Subtitles");
                                } else if (strlen(src_asset->asset_type) > 0) {
                                    strncpy(new_asset->codec, src_asset->asset_type, sizeof(new_asset->codec) - 1);
                                } else {
                                    strcpy(new_asset->codec, "Unknown");
                                }
                                
                                new_asset->packetId = src_asset->packet_id;
                                new_asset->next = NULL;
                                
                                // Add to linked list
                                if (prev_asset == NULL) {
                                    binary_mpt->head_asset = new_asset;
                                } else {
                                    prev_asset->next = new_asset;
                                }
                                prev_asset = new_asset;
                            }
                        }
                        
                        // Store in g_lls_tables if we have at least one asset
                        if (binary_mpt->head_asset != NULL) {
                            char content_id[256];
                            snprintf(content_id, sizeof(content_id), "Binary_MPT_%s:%s_v%d", 
                                    destIp, destPort, mpt_table->version);
                            
                            store_unique_table(content_id, strlen(content_id), 
                                             TABLE_TYPE_MP_TABLE_BINARY, binary_mpt, destIp, destPort, 0, -1);
                            
                            DBG_PRINTF("Stored Binary MPT with %d asset(s) for display\n", mpt_table->num_assets);
                        } else {
                            // No assets were added, free the structure
                            free(binary_mpt);
                        }
                    }
                }
            }
        }
        
        messages_parsed++;
        was_parsed = true;  // MPT is parsed
        
    } else if (message_id == 0x8100) {
        // ATSC3 signaling message
        DBG_PRINTF("Found ATSC3 signaling message\n");
        
        // Parse ATSC3 message
        if (msg_length < 11) {
            DBG_PRINTF("  ATSC3 message too short for header (need 11, have %u)\n", msg_length);
            return messages_parsed;
        }
        
        uint16_t service_id = (pos[0] << 8) | pos[1];
        uint16_t content_type = (pos[2] << 8) | pos[3];
        uint8_t content_version = pos[4];
        uint8_t compression = pos[5];
        uint8_t uri_length = pos[6];
        
        pos += 7;
        
        // Map content_type to name
        const char* content_type_name = "Unknown";
        switch(content_type) {
            case 0x0001: content_type_name = "UserServiceDescription"; break;
            case 0x0002: content_type_name = "MPD"; break;
            case 0x0003: content_type_name = "HELD"; break;
            case 0x0005: content_type_name = "Video Stream Properties Descriptor"; break;
            case 0x0008: content_type_name = "Caption Asset Descriptor"; break;
            case 0x0009: content_type_name = "Audio Stream Properties Descriptor"; break;
            case 0x000C: content_type_name = "Security Properties Descriptor"; break;
            default: 
                if (content_type >= 0x000D) content_type_name = "Industry Reserved";
                break;
        }
        
        DBG_PRINTF("  Service ID: %u, Content Type: 0x%04X (%s)\n",
               service_id, content_type, content_type_name);
        DBG_PRINTF("  Version: %u, Compression: %u, URI length: %u\n",
               content_version, compression, uri_length);
        
        // Skip URI if present
        size_t bytes_consumed = 7;
        if (uri_length > 0) {
            if (bytes_consumed + uri_length + 4 > msg_length) {
                DBG_PRINTF("  Invalid URI length\n");
                return messages_parsed;
            }
            pos += uri_length;
            bytes_consumed += uri_length;
        }
        
        // Read content length
        if (bytes_consumed + 4 > msg_length) {
            DBG_PRINTF("  Message too short for content_length\n");
            return messages_parsed;
        }
        
        uint32_t content_length = (pos[0] << 24) | (pos[1] << 16) | (pos[2] << 8) | pos[3];
        pos += 4;
        bytes_consumed += 4;
        
        DBG_PRINTF("  Content length: %u bytes\n", content_length);
        
        if (bytes_consumed + content_length > msg_length) {
            DBG_PRINTF("  Content length exceeds message size\n");
            return messages_parsed;
        }
        
        // Check if binary descriptor
        int is_binary_descriptor = (content_type == 0x0005 ||  // VSPD
                                    content_type == 0x0008 ||  // CAD
                                    content_type == 0x0009);   // ASPD
        
        if (is_binary_descriptor && compression == 0) {
            // Uncompressed binary descriptor - parse directly
            DBG_PRINTF("  Found binary descriptor: %s (%u bytes)\n", 
                   content_type_name, content_length);
            
            // Parse the descriptor
            if (content_type == 0x0005) {
                parse_vspd_descriptor(pos, content_length, destIp, destPort);
            } else if (content_type == 0x0009) {
                parse_aspd_descriptor(pos, content_length, destIp, destPort);
            } else if (content_type == 0x0008) {
                parse_cad_descriptor(pos, content_length, destIp, destPort);
            }
            
            messages_parsed++;
            was_parsed = true;  // Binary descriptor parsed
        } else if (is_binary_descriptor && compression == 2) {
            // Compressed binary descriptor - decompress first, then parse
            DBG_PRINTF("  Found compressed binary descriptor: %s (%u bytes)\n", 
                   content_type_name, content_length);
            DBG_PRINTF("  Decompressing GZIP content...\n");
            
            int decompressed_size = 0;
            int consumed_size = 0;
            char* decompressed = decompress_gzip(pos, content_length, 
                                                 &decompressed_size, &consumed_size);
            
            if (decompressed && decompressed_size > 0) {
                DBG_PRINTF("  Decompressed to %d bytes\n", decompressed_size);
                
                // Debug: Hex dump of decompressed data
                DBG_PRINTF("  Decompressed data (first %d bytes): ", decompressed_size < 40 ? decompressed_size : 40);
                for (int i = 0; i < decompressed_size && i < 40; i++) {
                    DBG_PRINTF("%02x ", (uint8_t)decompressed[i]);
                }
                DBG_PRINTF("\n");
                
                // Check if it's actually XML (starts with '<' or '<?xml')
                if (decompressed_size > 5 && 
                    (decompressed[0] == '<' || memcmp(decompressed, "<?xml", 5) == 0)) {
                    DBG_PRINTF("  WARNING: Decompressed data appears to be XML, not binary!\n");
                    DBG_PRINTF("  First 60 chars: %.60s\n", decompressed);
                    
                    // Try to parse as XML instead
                    TableType type = TABLE_TYPE_UNKNOWN;
                    void* parsed_data = NULL;
                    char source_id[256];
                    snprintf(source_id, sizeof(source_id), "ATSC3_%04x_decompressed", content_type);
                    
                    if (parse_xml(decompressed, decompressed_size, &type, &parsed_data, source_id) == 0 && parsed_data) {
                        DBG_PRINTF("  Successfully parsed as XML type %d\n", type);
                        store_unique_table(decompressed, decompressed_size, type, parsed_data, destIp, destPort, 0, -1);
                    }
                } else {
                    // Parse as binary descriptor
                    if (content_type == 0x0005) {
                        parse_vspd_descriptor((uint8_t*)decompressed, decompressed_size, destIp, destPort);
                    } else if (content_type == 0x0009) {
                        parse_aspd_descriptor((uint8_t*)decompressed, decompressed_size, destIp, destPort);
                    } else if (content_type == 0x0008) {
                        parse_cad_descriptor((uint8_t*)decompressed, decompressed_size, destIp, destPort);
                    }
                }
                
                free(decompressed);
            } else {
                DBG_PRINTF("  GZIP decompression failed\n");
            }
            messages_parsed++;
        } else if (compression == 2) {
            // GZIP compressed XML content
            DBG_PRINTF("  Decompressing GZIP content (%u bytes)...\n", content_length);
            
            int decompressed_size = 0;
            int consumed_size = 0;
            char* decompressed = decompress_gzip(pos, content_length, 
                                                 &decompressed_size, &consumed_size);
            
            if (decompressed && decompressed_size > 0) {
                DBG_PRINTF("  Decompressed to %d bytes\n", decompressed_size);
                
                // Debug: Hex dump of decompressed data
                DBG_PRINTF("  Decompressed data (first %d bytes): ", decompressed_size < 40 ? decompressed_size : 40);
                for (int i = 0; i < decompressed_size && i < 40; i++) {
                    DBG_PRINTF("%02x ", (uint8_t)decompressed[i]);
                }
                DBG_PRINTF("\n");
                
                // Debug: Try to print as string if printable
                int printable_count = 0;
                for (int i = 0; i < decompressed_size && i < 40; i++) {
                    if (decompressed[i] >= 32 && decompressed[i] < 127) printable_count++;
                }
                if (printable_count > 20) {
                    DBG_PRINTF("  As string: %.60s\n", decompressed);
                }
                
                // Check if decompressed data is XML or binary
                bool is_xml = false;
                if (decompressed_size > 0 && 
                    (decompressed[0] == '<' || 
                     (decompressed_size >= 5 && memcmp(decompressed, "<?xml", 5) == 0))) {
                    is_xml = true;
                }
                
                if (is_xml) {
                    // Parse as XML
                    TableType type = TABLE_TYPE_UNKNOWN;
                    void* parsed_data = NULL;
                    char source_id[256];
                    snprintf(source_id, sizeof(source_id), "ATSC3_%04x", content_type);
                    
                    if (parse_xml(decompressed, decompressed_size, &type, 
                                 &parsed_data, source_id) == 0 && parsed_data) {
                        DBG_PRINTF("  Successfully parsed as type %d\n", type);
                        store_unique_table(decompressed, decompressed_size, type, 
                                         parsed_data, destIp, destPort, 0, -1);
                        was_parsed = true;  // Successfully parsed XML
                        
                        // If this is a USBD, also extract and store USD tables with proper IP/port
                        if (type == TABLE_TYPE_USBD) {
                        DBG_PRINTF("  Found USBD in ATSC3 message, extracting nested USD tables\n");
                        
                        xmlDocPtr doc = xmlReadMemory(decompressed, decompressed_size, "usbd.xml", NULL, XML_PARSE_RECOVER);
                        if (doc) {
                            xmlNodePtr root = xmlDocGetRootElement(doc);
                            if (root) {
                                xmlNodePtr cur_node = root->children;
                            
                                while (cur_node != NULL) {
                                    if (cur_node->type == XML_ELEMENT_NODE && 
                                        xmlStrcmp(cur_node->name, (const xmlChar *)"UserServiceDescription") == 0) {
                                        
                                        char* usd_xml = extract_node_as_xml(cur_node);
                                        if (usd_xml) {
                                            TableType usd_type = TABLE_TYPE_USD;
                                            void* usd_parsed_data = NULL;
                                            if (parse_xml(usd_xml, strlen(usd_xml), &usd_type, &usd_parsed_data, "Nested USD from ATSC3") == 0 && usd_parsed_data) {
                                                store_unique_table(usd_xml, strlen(usd_xml), TABLE_TYPE_USD, usd_parsed_data, destIp, destPort, 0, -1);
                                                DBG_PRINTF("    Extracted and stored nested USD\n");
                                            }
                                            free(usd_xml);
                                        }
                                    }
                                    cur_node = cur_node->next;
                                }
                            }
                            xmlFreeDoc(doc);
                        }
                    }
                }
                } else {
                    // Binary descriptor content
                    DBG_PRINTF("  Decompressed content is binary, not XML\n");
                    
                    // Handle specific binary descriptor types
                    if (content_type == 0x0005) {
                        // Video Stream Properties Descriptor
                        DBG_PRINTF("  Parsing Video Stream Properties Descriptor (binary format)\n");
                        parse_vspd_descriptor((const uint8_t*)decompressed, decompressed_size, destIp, destPort);
                        was_parsed = true;
                    } else if (content_type == 0x0008) {
                        // Caption Asset Descriptor
                        DBG_PRINTF("  Parsing Caption Asset Descriptor (binary format)\n");
                        parse_cad_descriptor((const uint8_t*)decompressed, decompressed_size, destIp, destPort);
                        was_parsed = true;
                    } else if (content_type == 0x0009) {
                        // Audio Stream Properties Descriptor  
                        DBG_PRINTF("  Parsing Audio Stream Properties Descriptor (binary format)\n");
                        parse_aspd_descriptor((const uint8_t*)decompressed, decompressed_size, destIp, destPort);
                        was_parsed = true;
                    } else if (content_type == 0x0006) {
                        // Unknown 0x0006 - acknowledged
                        DBG_PRINTF("  Content type 0x0006 (binary format)\n");
                        was_parsed = true;
                    } else if (content_type == 0x0011) {
                        // Unknown 0x0011 - acknowledged
                        DBG_PRINTF("  Content type 0x0011 (binary format)\n");
                        was_parsed = true;
                    } else if (content_type == 0x000c) {
                        // Security Properties Descriptor
                        DBG_PRINTF("  Parsing Security Properties Descriptor (binary format)\n");
                        parse_spd_descriptor((const uint8_t*)decompressed, decompressed_size, destIp, destPort);
                        was_parsed = true;
                    } else {
                        DBG_PRINTF("  Unknown binary descriptor type 0x%04x\n", content_type);
                    }
                }
                free(decompressed);
            }
            messages_parsed++;
        } else {
            DBG_PRINTF("  Uncompressed XML/text content - parsing not shown here\n");
            messages_parsed++;
            was_parsed = true;  // Assume parsed (basic handling)
        }
        
    } else if (message_id == 0x0000) {
        DBG_PRINTF("Found PA (Package Access) message\n");
        messages_parsed++;
        was_parsed = true;
        
    } else if (message_id == 0x0204) {
        DBG_PRINTF("Found HRBM message\n");
        messages_parsed++;
        was_parsed = true;
        
    } else {
        DBG_PRINTF("Found unknown message type: 0x%04x\n", message_id);
        messages_parsed++;
        was_parsed = false;
    }
    
    // Track this message
    track_mmt_message(message_id, destIp, destPort, was_parsed);
    
    return messages_parsed;
}

void parse_mpi_message_improved(const uint8_t* pos, size_t msg_length, 
                                const char* destIp, const char* destPort) {
    DBG_PRINTF("Parsing MPI (MMT Package Information) message (%zu bytes payload)...\n", msg_length);
    
    const uint8_t* mpi_pos = pos;
    size_t mpi_remaining = msg_length;
    
    // Show first bytes for debugging
    DBG_PRINTF("  First 16 bytes of MPI payload: ");
    for (size_t i = 0; i < (msg_length < 16 ? msg_length : 16); i++) {
        DBG_PRINTF("%02x ", mpi_pos[i]);
    }
    DBG_PRINTF("\n");
    
    // For MPI messages (0x1800), the structure is:
    // - MMT_package_id (2 bytes) - NOT length-prefixed!
    // - MPI_descriptors_length (2 bytes)
    // - MPI_descriptors (variable)
    // - number_of_assets (1 byte)
    // - assets (variable)
    
    if (mpi_remaining < 2) {
        DBG_PRINTF("ERROR: MPI message too short for package_id\n");
        return;
    }
    
    // Read 2-byte package ID directly (no length prefix)
    uint16_t package_id = (mpi_pos[0] << 8) | mpi_pos[1];
    mpi_pos += 2;
    mpi_remaining -= 2;
    
    DBG_PRINTF("  MMT Package ID: 0x%04x (%u)\n", package_id, package_id);
    
    // Parse descriptors_length (2 bytes)
    if (mpi_remaining < 2) {
        DBG_PRINTF("ERROR: Not enough data for descriptors_length\n");
        return;
    }
    
    uint16_t descriptors_length = (mpi_pos[0] << 8) | mpi_pos[1];
    mpi_pos += 2;
    mpi_remaining -= 2;
    
    DBG_PRINTF("  Descriptors length: %u bytes\n", descriptors_length);
    
    if (descriptors_length > mpi_remaining) {
        DBG_PRINTF("ERROR: Descriptors length %u exceeds remaining %zu\n", 
               descriptors_length, mpi_remaining);
        return;
    }
    
    // Parse descriptors
    size_t desc_remaining = descriptors_length;
    const uint8_t* desc_pos = mpi_pos;
    
    while (desc_remaining >= 4) {
        uint16_t desc_tag = 0;
        uint16_t desc_length = 0;
        
        if (parse_mpt_descriptor_header(&desc_pos, &desc_remaining, 
                                         &desc_tag, &desc_length) != 0) {
            DBG_PRINTF("ERROR: Failed to parse descriptor header\n");
            break;
        }
        
        if (desc_length > desc_remaining) {
            DBG_PRINTF("ERROR: Descriptor length %u exceeds remaining %zu\n", 
                   desc_length, desc_remaining);
            break;
        }
        
        // Identify and parse the descriptor
        const char* desc_name = "Unknown";
        switch (desc_tag) {
            case MMT_DESCRIPTOR_USD:
                desc_name = "USD (User Service Description)";
                DBG_PRINTF("  Found %s descriptor, %u bytes\n", desc_name, desc_length);
                DBG_PRINTF("    (XML content - parsing not yet implemented)\n");
                break;
                
            case MMT_DESCRIPTOR_MPD:
                desc_name = "MPD (Media Presentation Description)";
                DBG_PRINTF("  Found %s descriptor, %u bytes\n", desc_name, desc_length);
                DBG_PRINTF("    (XML content - parsing not yet implemented)\n");
                break;
                
            case MMT_DESCRIPTOR_HELD:
                desc_name = "HELD";
                DBG_PRINTF("  Found %s descriptor, %u bytes\n", desc_name, desc_length);
                break;
                
            case MMT_DESCRIPTOR_VSPD:
                desc_name = "VSPD (Video Stream Properties)";
                DBG_PRINTF("  Found %s descriptor, %u bytes\n", desc_name, desc_length);
                parse_vspd_descriptor(desc_pos, desc_length, destIp, destPort);
                break;
                
            case MMT_DESCRIPTOR_ASPD:
                desc_name = "ASPD (Audio Stream Properties)";
                DBG_PRINTF("  Found %s descriptor, %u bytes\n", desc_name, desc_length);
                parse_aspd_descriptor(desc_pos, desc_length, destIp, destPort);
                break;
                
            case MMT_DESCRIPTOR_CAD:
                desc_name = "CAD (Caption Asset)";
                DBG_PRINTF("  Found %s descriptor, %u bytes\n", desc_name, desc_length);
                parse_cad_descriptor(desc_pos, desc_length, destIp, destPort);
                break;
                
            case MMT_DESCRIPTOR_AEI:
                desc_name = "Application Event Info";
                DBG_PRINTF("  Found %s descriptor, %u bytes\n", desc_name, desc_length);
                break;
                
            case MMT_DESCRIPTOR_INED:
                desc_name = "Inband Event Descriptor";
                DBG_PRINTF("  Found %s descriptor, %u bytes\n", desc_name, desc_length);
                break;
                
            default:
                DBG_PRINTF("  Found descriptor 0x%04X, %u bytes (not yet implemented)\n", 
                       desc_tag, desc_length);
                break;
        }
        
        // Skip this descriptor's data
        desc_pos += desc_length;
        desc_remaining -= desc_length;
    }
    
    // Move past the descriptors in the main pointer
    mpi_pos += descriptors_length;
    mpi_remaining -= descriptors_length;
    
    // Parse number of assets
    if (mpi_remaining < 1) {
        DBG_PRINTF("  No assets in MPI\n");
        return;
    }
    
    uint8_t num_assets = mpi_pos[0];
    mpi_pos++;
    mpi_remaining--;
    
    DBG_PRINTF("  Number of assets: %u\n", num_assets);
    
    // Parse each asset
    for (int i = 0; i < num_assets && mpi_remaining >= 3; i++) {
        DBG_PRINTF("  Asset %d:\n", i + 1);
        
        // identifier_mapping (1 byte): identifier_type(4) + asset_id_scheme(4)
        uint8_t id_info = mpi_pos[0];
        uint8_t identifier_type = (id_info >> 4) & 0x0F;
        uint8_t asset_id_scheme = id_info & 0x0F;
        mpi_pos++;
        mpi_remaining--;
        
        DBG_PRINTF("    Identifier type: %u, Asset ID scheme: %u\n", 
               identifier_type, asset_id_scheme);
        
        // asset_id_length (1 byte)
        if (mpi_remaining < 1) break;
        uint8_t asset_id_length = mpi_pos[0];
        mpi_pos++;
        mpi_remaining--;
        
        // asset_id_byte (variable)
        if (mpi_remaining < asset_id_length) break;
        
        DBG_PRINTF("    Asset ID (%u bytes): ", asset_id_length);
        for (int j = 0; j < asset_id_length && j < 16; j++) {
            DBG_PRINTF("%02x ", mpi_pos[j]);
        }
        DBG_PRINTF("\n");
        
        mpi_pos += asset_id_length;
        mpi_remaining -= asset_id_length;
        
        // asset_type (4 bytes - if asset_id_scheme == 0)
        if (asset_id_scheme == 0 && mpi_remaining >= 4) {
            char asset_type[5] = {0};
            memcpy(asset_type, mpi_pos, 4);
            DBG_PRINTF("    Asset type: %.4s\n", asset_type);
            
            mpi_pos += 4;
            mpi_remaining -= 4;
        }
        
        // asset_descriptors_length (2 bytes)
        if (mpi_remaining < 2) break;
        uint16_t asset_desc_length = (mpi_pos[0] << 8) | mpi_pos[1];
        mpi_pos += 2;
        mpi_remaining -= 2;
        
        DBG_PRINTF("    Asset descriptors length: %u\n", asset_desc_length);
        
        // Parse asset descriptors
        if (asset_desc_length > 0 && mpi_remaining >= asset_desc_length) {
            size_t asset_desc_remaining = asset_desc_length;
            const uint8_t* asset_desc_pos = mpi_pos;
            
            while (asset_desc_remaining >= 4) {
                uint16_t asset_desc_tag = 0;
                uint16_t asset_desc_len = 0;
                
                if (parse_mpt_descriptor_header(&asset_desc_pos, &asset_desc_remaining,
                                                 &asset_desc_tag, &asset_desc_len) != 0) {
                    break;
                }
                
                if (asset_desc_len > asset_desc_remaining) break;
                
                // Parse asset-level descriptors
                switch (asset_desc_tag) {
                    case MMT_DESCRIPTOR_VSPD:
                        DBG_PRINTF("      Found VSPD for this asset:\n");
                        parse_vspd_descriptor(asset_desc_pos, asset_desc_len, destIp, destPort);
                        break;
                    case MMT_DESCRIPTOR_ASPD:
                        DBG_PRINTF("      Found ASPD for this asset:\n");
                        parse_aspd_descriptor(asset_desc_pos, asset_desc_len, destIp, destPort);
                        break;
                    case MMT_DESCRIPTOR_CAD:
                        DBG_PRINTF("      Found CAD for this asset:\n");
                        parse_cad_descriptor(asset_desc_pos, asset_desc_len, destIp, destPort);
                        break;
                    default:
                        DBG_PRINTF("      Asset descriptor: tag=0x%04X, len=%u\n",
                               asset_desc_tag, asset_desc_len);
                        break;
                }
                
                asset_desc_pos += asset_desc_len;
                asset_desc_remaining -= asset_desc_len;
            }
            
            mpi_pos += asset_desc_length;
            mpi_remaining -= asset_desc_length;
        }
        
        // MMT_general_location_info (variable length)
        if (mpi_remaining < 1) break;
        uint8_t location_type = mpi_pos[0];
        mpi_pos++;
        mpi_remaining--;
        
        DBG_PRINTF("    Location: ");
        
        if (location_type == 0x00) {  // packet_id
            if (mpi_remaining < 2) break;
            uint16_t packet_id = (mpi_pos[0] << 8) | mpi_pos[1];
            DBG_PRINTF("Packet ID %u (0x%04X)\n", packet_id, packet_id);
            mpi_pos += 2;
            mpi_remaining -= 2;
        } else if (location_type == 0x01) {  // IPv4
            if (mpi_remaining < 6) break;
            DBG_PRINTF("IPv4 %u.%u.%u.%u:%u\n", 
                   mpi_pos[0], mpi_pos[1], mpi_pos[2], mpi_pos[3],
                   (mpi_pos[4] << 8) | mpi_pos[5]);
            mpi_pos += 6;
            mpi_remaining -= 6;
        } else if (location_type == 0x02) {  // IPv6
            if (mpi_remaining < 18) break;
            DBG_PRINTF("IPv6 address + port\n");
            mpi_pos += 18;
            mpi_remaining -= 18;
        } else if (location_type == 0x03) {  // URL
            if (mpi_remaining < 1) break;
            uint8_t url_length = mpi_pos[0];
            if (mpi_remaining < 1 + url_length) break;
            DBG_PRINTF("URL: %.*s\n", url_length, mpi_pos + 1);
            mpi_pos += 1 + url_length;
            mpi_remaining -= 1 + url_length;
        } else {
            DBG_PRINTF("Unknown type %u\n", location_type);
            break;  // Don't know how to skip this
        }
    }
}

const char* get_media_type_from_mpt(const char* dest_ip, const char* dest_port, uint32_t packet_id) {
    int found_mpt_for_dest = 0;
    
    // Search through MP Table data (both XML and binary)
    for (int i = 0; i < g_lls_table_count; i++) {
        if ((g_lls_tables[i].type == TABLE_TYPE_MP_TABLE_XML ||
             g_lls_tables[i].type == TABLE_TYPE_MP_TABLE_BINARY) &&
            strcmp(g_lls_tables[i].destinationIp, dest_ip) == 0 &&
            strcmp(g_lls_tables[i].destinationPort, dest_port) == 0) {
            
            found_mpt_for_dest = 1;  // We found an MP Table for this service
            
            if (g_lls_tables[i].type == TABLE_TYPE_MP_TABLE_XML) {
                MpTableData* mpt_data = (MpTableData*)g_lls_tables[i].parsed_data;
                MptAsset* asset = mpt_data->head_asset;
                
                while (asset) {
                    if (atoi(asset->packetId) == packet_id) {
                        // Check asset type and ID for clues
                        // First check assetType field
                        if (strstr(asset->assetType, "video") || strstr(asset->assetType, "Video") ||
                            strcmp(asset->assetType, "hev1") == 0 || strcmp(asset->assetType, "hvc1") == 0 ||
                            strcmp(asset->assetType, "avc1") == 0 || strcmp(asset->assetType, "avc3") == 0) {
                            return "Video";
                        } else if (strstr(asset->assetType, "audio") || strstr(asset->assetType, "Audio") ||
                                   strcmp(asset->assetType, "ac-4") == 0 || strcmp(asset->assetType, "mp4a") == 0 ||
                                   strcmp(asset->assetType, "ec-3") == 0 || strcmp(asset->assetType, "ac-3") == 0) {
                            return "Audio";
                        } else if (strstr(asset->assetType, "data") || strstr(asset->assetType, "stpp") ||
                                   strstr(asset->assetType, "Data") || strcmp(asset->assetType, "wvtt") == 0) {
                            return "Data/Captions";
                        }
                        // Now check assetId field as fallback
                        if (strstr(asset->assetId, "video") || strstr(asset->assetId, "Video") ||
                            strstr(asset->assetId, "hev") || strstr(asset->assetId, "hvc") ||
                            strstr(asset->assetId, "avc")) {
                            return "Video";
                        } else if (strstr(asset->assetId, "audio") || strstr(asset->assetId, "Audio") ||
                                   strstr(asset->assetId, "ac-4") || strstr(asset->assetId, "mp4a")) {
                            return "Audio";
                        } else if (strstr(asset->assetId, "Data") || strstr(asset->assetId, "cc")) {
                            return "Data/Captions";
                        }
                        // If assetType is a known codec, classify it
                        if (strlen(asset->assetType) > 0) {
                            return asset->assetType;
                        }
                    }
                    asset = asset->next;
                }
            } else if (g_lls_tables[i].type == TABLE_TYPE_MP_TABLE_BINARY) {
                BinaryMptData* binary_mpt = (BinaryMptData*)g_lls_tables[i].parsed_data;
                BinaryMptAsset* asset = binary_mpt->head_asset;
                
                while (asset) {
                    if (asset->packetId == packet_id) {
                        // Check for video codecs in assetType
                        if (strstr(asset->assetType, "Video") || strstr(asset->assetType, "video") ||
                            strcmp(asset->assetType, "hev1") == 0 || strcmp(asset->assetType, "hvc1") == 0 ||
                            strcmp(asset->assetType, "avc1") == 0 || strcmp(asset->assetType, "avc3") == 0) {
                            return "Video";
                        // Check for audio codecs in assetType
                        } else if (strstr(asset->assetType, "Audio") || strstr(asset->assetType, "audio") ||
                                   strcmp(asset->assetType, "ac-4") == 0 || strcmp(asset->assetType, "mp4a") == 0 ||
                                   strcmp(asset->assetType, "ec-3") == 0 || strcmp(asset->assetType, "ac-3") == 0) {
                            return "Audio";
                        } else if (strlen(asset->assetType) > 0) {
                            return asset->assetType;
                        }
                        return "Media";
                    }
                    asset = asset->next;
                }
            } 
        }
    }
    
    // Fallback - guess based on packet ID patterns (common convention)
    if (found_mpt_for_dest) {
        if (packet_id == 0) return "Signaling";
        if (packet_id >= 256 && packet_id <= 511) return "Video";
        if (packet_id >= 512 && packet_id <= 767) return "Audio";
        if (packet_id >= 768) return "Data/Captions";
    }
    
    return "Media";
}

/**
 * @brief Parses an MMT MP_Table XML document.
 */
MpTableData* parse_mp_table(xmlDocPtr doc) {
    MpTableData* mpt_data = calloc(1, sizeof(MpTableData));
    if (!mpt_data) return NULL;

    xmlNodePtr root = xmlDocGetRootElement(doc);
    if (!root) {
        free(mpt_data);
        return NULL;
    }
    xmlChar* prop = xmlGetProp(root, (const xmlChar *)"MPTpackageID");
    if(prop) { strncpy(mpt_data->mptPackageId, (char*)prop, sizeof(mpt_data->mptPackageId)-1); xmlFree(prop); }

    xmlNodePtr asset_node = root->children;
    MptAsset* current_asset_tail = NULL;
    
    while (asset_node != NULL) {
        if (asset_node->type == XML_ELEMENT_NODE && xmlStrcmp(asset_node->name, (const xmlChar *)"Asset") == 0) {
            MptAsset* asset = calloc(1, sizeof(MptAsset));
            if(!asset) continue;

            prop = xmlGetProp(asset_node, (const xmlChar*)"assetId");
            if(prop) { strncpy(asset->assetId, (char*)prop, sizeof(asset->assetId)-1); xmlFree(prop); }
            prop = xmlGetProp(asset_node, (const xmlChar*)"assetType");
            if(prop) { strncpy(asset->assetType, (char*)prop, sizeof(asset->assetType)-1); xmlFree(prop); }
            
            // Find the packetId in the location info
            xmlNodePtr location_node = asset_node->children;
            while(location_node != NULL && (location_node->type != XML_ELEMENT_NODE || xmlStrcmp(location_node->name, (const xmlChar*)"MPT_Location_Info") != 0)) {
                location_node = location_node->next;
            }
            if(location_node) {
                prop = xmlGetProp(location_node, (const xmlChar*)"packetId");
                if(prop) { strncpy(asset->packetId, (char*)prop, sizeof(asset->packetId)-1); xmlFree(prop); }
            }

            if(mpt_data->head_asset == NULL) {
                mpt_data->head_asset = asset;
                current_asset_tail = asset;
            } else {
                current_asset_tail->next = asset;
                current_asset_tail = asset;
            }
        }
        asset_node = asset_node->next;
    }

    return mpt_data;
}

// Helper function to parse descriptor headers
static int parse_mpt_descriptor_header(const uint8_t** data_ptr, size_t* remaining_ptr,
                                        uint16_t* tag_out, uint16_t* length_out) {
    const uint8_t* data = *data_ptr;
    size_t remaining = *remaining_ptr;
    
    if (remaining < 4) return -1;
    
    uint16_t tag = (data[0] << 8) | data[1];
    uint16_t length = (data[2] << 8) | data[3];
    
    *tag_out = tag;
    *length_out = length;
    *data_ptr += 4;
    *remaining_ptr -= 4;
    
    return 0;
}

// Parser for VSPD (Video Stream Properties Descriptor) - A/331 Section 6.6.2
// Helper function to parse H.265 profile_tier_level structure
// Based on ITU-T H.265 Section 7.3.3
// Structure is 12 bytes when maxNumSubLayersMinus1=0
static void parse_h265_profile_tier_level(const uint8_t* data, size_t length, int maxNumSubLayersMinus1, VspdData* vspd) {
    if (length < 12) {
        DBG_PRINTF("      ERROR: Not enough data for profile_tier_level\n");
        return;
    }
    
    const uint8_t* pos = data;
    
    // Byte 0: general_profile_space (2 bits), general_tier_flag (1 bit), general_profile_idc (5 bits)
    // general_profile_space = (pos[0] >> 6) & 0x03 (not used)
    uint8_t general_tier_flag = (pos[0] >> 5) & 0x01;
    uint8_t general_profile_idc = pos[0] & 0x1F;
    pos += 1;
    
    // Bytes 1-4: general_profile_compatibility_flag[32] (32 bits)
    // general_profile_compatibility = (pos[0] << 24) | (pos[1] << 16) | (pos[2] << 8) | pos[3] (not used)
    pos += 4;
    
    // Byte 5: general_progressive_source_flag, general_interlaced_source_flag, 
    //         general_non_packed_constraint_flag, general_frame_only_constraint_flag,
    //         plus 4 bits of reserved
    uint8_t general_progressive_source_flag = (pos[0] >> 7) & 0x01;
    uint8_t general_interlaced_source_flag = (pos[0] >> 6) & 0x01;
    // general_non_packed_constraint_flag = (pos[0] >> 5) & 0x01 (not used)
    // general_frame_only_constraint_flag = (pos[0] >> 4) & 0x01 (not used)
    pos += 1;
    
    // Bytes 6-10: general_reserved_zero_43bits (43 bits) + general_inbld_flag (1 bit) = 44 bits total
    // Skip 5 bytes to get to byte 11
    pos += 5;
    
    // Byte 11: general_level_idc
    uint8_t general_level_idc = pos[0];
    pos += 1;
    
    // Profile name mapping
    const char* profile_name = "Unknown";
    switch (general_profile_idc) {
        case 1: profile_name = "Main"; break;
        case 2: profile_name = "Main 10"; break;
        case 3: profile_name = "Main Still Picture"; break;
        case 4: profile_name = "Format Range Extensions"; break;
        case 9: profile_name = "Screen Content Coding"; break;
    }
    
    // Level mapping (general_level_idc / 30.0)
    float level = general_level_idc / 30.0f;
    
    DBG_PRINTF("      HEVC Profile: %s (idc=%u)\n", profile_name, general_profile_idc);
    DBG_PRINTF("      HEVC Level: %.1f (idc=%u)\n", level, general_level_idc);
    DBG_PRINTF("      Tier: %s\n", general_tier_flag ? "High" : "Main");
    DBG_PRINTF("      Progressive: %s, Interlaced: %s\n",
           general_progressive_source_flag ? "yes" : "no",
           general_interlaced_source_flag ? "yes" : "no");
    
    // Store in VspdData if provided
    if (vspd) {
        vspd->profile_idc = general_profile_idc;
        strncpy(vspd->profile_name, profile_name, sizeof(vspd->profile_name) - 1);
        vspd->profile_name[sizeof(vspd->profile_name) - 1] = '\0';
        vspd->level_idc = general_level_idc;
        vspd->level_value = level;
        vspd->tier_flag = general_tier_flag;
        vspd->progressive_flag = general_progressive_source_flag;
        vspd->interlaced_flag = general_interlaced_source_flag;
    }
    
    // Note: We're ignoring sub-layer information since maxNumSubLayersMinus1 is typically 0
}

void parse_vspd_descriptor(const uint8_t* data, uint16_t length,
                           const char* destIp, const char* destPort) {
    if (length < 4) {
        DBG_PRINTF("    ERROR: VSPD too short (%u bytes)\n", length);
        return;
    }
    
    // ========================================================================
    // VSPD RAW DATA DUMP
    // ========================================================================
    DBG_PRINTF("\n");
    DBG_PRINTF("╔══════════════════════════════════════════════════════════════╗\n");
    DBG_PRINTF("║ VSPD (Video Stream Properties Descriptor) RAW DATA          ║\n");
    DBG_PRINTF("╠══════════════════════════════════════════════════════════════╣\n");
    DBG_PRINTF("║ Destination: %s:%-5s                                  ║\n", destIp, destPort);
    DBG_PRINTF("║ Length: %-4u bytes                                          ║\n", length);
    DBG_PRINTF("╚══════════════════════════════════════════════════════════════╝\n");
    DBG_PRINTF("\n");
    
    // Hex dump with offset, hex values, and ASCII representation
    DBG_PRINTF("Offset(h)  00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F  ASCII\n");
    DBG_PRINTF("─────────  ───────────────────────────────────────────────  ────────────────\n");
    for (uint16_t i = 0; i < length; i += 16) {
        DBG_PRINTF("%08X   ", i);
        
        // Hex values
        for (int j = 0; j < 16; j++) {
            if (i + j < length) {
                DBG_PRINTF("%02X ", data[i + j]);
            } else {
                DBG_PRINTF("   ");
            }
        }
        
        DBG_PRINTF(" ");
        
        // ASCII representation
        for (int j = 0; j < 16 && i + j < length; j++) {
            uint8_t c = data[i + j];
            DBG_PRINTF("%c", (c >= 32 && c <= 126) ? c : '.');
        }
        DBG_PRINTF("\n");
    }
    DBG_PRINTF("\n");
    
    // Binary breakdown of first few bytes
    DBG_PRINTF("First 48 bytes (binary breakdown):\n");
    for (int i = 0; i < 48 && i < length; i++) {
        DBG_PRINTF("  Byte[%2d] = 0x%02X = 0b", i, data[i]);
        for (int bit = 7; bit >= 0; bit--) {
            DBG_PRINTF("%d", (data[i] >> bit) & 1);
            if (bit == 4) DBG_PRINTF("_");  // Visual separator
        }
        DBG_PRINTF(" = %3d", data[i]);
        
        // Add helpful notes for known positions
        if (i == 0 && length >= 4) {
            uint16_t first_word = (data[0] << 8) | data[1];
            if (first_word == 0x0005) {
                DBG_PRINTF("  ← Descriptor tag (high byte) = 0x0005 (VSPD)");
            }
        } else if (i == 1 && length >= 4) {
            DBG_PRINTF("  ← Descriptor tag (low byte)");
        } else if (i == 2 && length >= 4) {
            DBG_PRINTF("  ← Descriptor length (high byte)");
        } else if (i == 3 && length >= 4) {
            DBG_PRINTF("  ← Descriptor length (low byte) = %u total bytes", (data[2] << 8) | data[3]);
        } else if (i == 4 && length >= 5) {
            uint16_t first_word = (data[0] << 8) | data[1];
            if (first_word == 0x0005) {
                DBG_PRINTF("  ← number_of_assets");
            }
        }
        DBG_PRINTF("\n");
    }
    DBG_PRINTF("\n");
    DBG_PRINTF("════════════════════════════════════════════════════════════════\n");
    DBG_PRINTF("BEGIN PARSING\n");
    DBG_PRINTF("════════════════════════════════════════════════════════════════\n\n");
    
    const uint8_t* pos = data;
    size_t remaining = length;
    
    // Check if this is MMT Asset Descriptor format (starts with descriptor_tag 0x0005)
    uint16_t first_word = (pos[0] << 8) | pos[1];
    
    if (first_word == 0x0005 && remaining >= 4) {
        // MMT Asset Descriptor format (ISO/IEC 23008-1)
        // descriptor_length = (pos[2] << 8) | pos[3] (not used)
        pos += 4;
        remaining -= 4;
        
        if (remaining < 1) return;
        uint8_t number_of_assets = pos[0];
        DBG_PRINTF("    Video: %u asset(s)\n", number_of_assets);
        pos += 1;
        remaining -= 1;
        
        // Parse each asset
        for (int i = 0; i < number_of_assets && remaining >= 4; i++) {
            // asset_id_length (4 bytes)
            uint32_t asset_id_length = (pos[0] << 24) | (pos[1] << 16) | (pos[2] << 8) | pos[3];
            pos += 4;
            remaining -= 4;
            
            if (remaining < asset_id_length) {
                DBG_PRINTF("      ERROR: Not enough data for asset_id\n");
                return;
            }
            
            // asset_id (variable length string)
            DBG_PRINTF("      Asset %d ID: %.*s\n", i + 1, (int)asset_id_length, pos);
            pos += asset_id_length;
            remaining -= asset_id_length;
            
            // asset_type (4 bytes FourCC)
            if (remaining < 4) {
                DBG_PRINTF("      ERROR: Not enough data for asset_type\n");
                return;
            }
            char asset_type[5] = {pos[0], pos[1], pos[2], pos[3], 0};
            DBG_PRINTF("      Asset Type: %s\n", asset_type);
            pos += 4;
            remaining -= 4;
            
            // VSPD-specific flags (1 byte)
            if (remaining < 1) {
                DBG_PRINTF("      ERROR: Not enough data for VSPD flags\n");
                return;
            }
            uint8_t vspd_flags = pos[0];
            // temporal_scalability_present = (vspd_flags >> 7) & 0x01 (not used)
            // scalability_info_present = (vspd_flags >> 6) & 0x01 (not used)
            // multiview_info_present = (vspd_flags >> 5) & 0x01 (not used)
            uint8_t res_cf_bd_info_present = (vspd_flags >> 4) & 0x01;
            uint8_t pr_info_present = (vspd_flags >> 3) & 0x01;
            // br_info_present = (vspd_flags >> 2) & 0x01 (not used)
            // color_info_present = (vspd_flags >> 1) & 0x01 (not used)
            // bit 0 is reserved (should be 1)
            pos += 1;
            remaining -= 1;
            
            // Initialize values for storage
            uint16_t horizontal_size = 0;
            uint16_t vertical_size = 0;
            uint8_t frame_rate_code = 0;
            char frame_rate_str[16] = "";
            uint8_t chroma_format = 0;
            uint8_t bit_depth = 0;
            
            // Parse resolution/chroma/bit-depth info if present
            if (res_cf_bd_info_present && remaining >= 5) {
                DBG_PRINTF("      Resolution/Color/BitDepth info:\n");
                horizontal_size = (pos[0] << 8) | pos[1];
                vertical_size = (pos[2] << 8) | pos[3];
                chroma_format = (pos[4] >> 4) & 0x0F;
                bit_depth = pos[4] & 0x0F;
                DBG_PRINTF("        Resolution: %ux%u\n", horizontal_size, vertical_size);
                DBG_PRINTF("        Chroma format: %u, Bit depth: %u\n", chroma_format, bit_depth);
                pos += 5;
                remaining -= 5;
            }
            
            // Parse picture rate info if present
            if (pr_info_present && remaining >= 1) {
                frame_rate_code = pos[0];
                DBG_PRINTF("      Frame rate code: 0x%02x\n", frame_rate_code);
                
                // Frame rate mapping per A/331 Table 6.9
                switch (frame_rate_code) {
                    case 0x1: strcpy(frame_rate_str, "23.976 fps"); break;
                    case 0x2: strcpy(frame_rate_str, "24 fps"); break;
                    case 0x3: strcpy(frame_rate_str, "25 fps"); break;
                    case 0x4: strcpy(frame_rate_str, "29.97 fps"); break;
                    case 0x5: strcpy(frame_rate_str, "30 fps"); break;
                    case 0x6: strcpy(frame_rate_str, "50 fps"); break;
                    case 0x7: strcpy(frame_rate_str, "59.94 fps"); break;
                    case 0x8: strcpy(frame_rate_str, "60 fps"); break;
                    case 0x9: strcpy(frame_rate_str, "120 fps"); break;
                    default: strcpy(frame_rate_str, "Unknown"); break;
                }
                DBG_PRINTF("        %s\n", frame_rate_str);
                pos += 1;
                remaining -= 1;
            }
            
            // For now, we'll just parse the profile_tier_level which should follow
            // In your case, all flags are 0, so we go straight to profile_tier_level(1, 0)
            
            // Create temporary vspd to capture profile/tier/level data
            VspdData temp_vspd;
            memset(&temp_vspd, 0, sizeof(VspdData));
            
            if (remaining >= 12) {
                parse_h265_profile_tier_level(pos, remaining, 0, &temp_vspd);
                // profile_tier_level is 12 bytes when maxNumSubLayersMinus1=0
                pos += 12;
                remaining -= 12;
            }
            
            // Show remaining unparsed data
            if (remaining > 0) {
                DBG_PRINTF("\n");
                DBG_PRINTF("╔══════════════════════════════════════════════════════════════╗\n");
                DBG_PRINTF("║ VSPD: REMAINING UNPARSED DATA (%zu bytes)                    \n", remaining);
                DBG_PRINTF("╚══════════════════════════════════════════════════════════════╝\n");
                DBG_PRINTF("Offset(h)  Hex Values                                          ASCII\n");
                DBG_PRINTF("─────────  ───────────────────────────────────────────────────  ────────────────\n");
                
                size_t offset = (pos - data);
                for (size_t i = 0; i < remaining; i += 16) {
                    DBG_PRINTF("%08zX   ", offset + i);
                    
                    // Hex values
                    for (int j = 0; j < 16; j++) {
                        if (i + j < remaining) {
                            DBG_PRINTF("%02X ", pos[i + j]);
                        } else {
                            DBG_PRINTF("   ");
                        }
                    }
                    
                    DBG_PRINTF(" ");
                    
                    // ASCII representation
                    for (int j = 0; j < 16 && i + j < remaining; j++) {
                        uint8_t c = pos[i + j];
                        DBG_PRINTF("%c", (c >= 32 && c <= 126) ? c : '.');
                    }
                    DBG_PRINTF("\n");
                }
                DBG_PRINTF("\n");
            } else {
                DBG_PRINTF("\n╔══════════════════════════════════════════════════════════════╗\n");
                DBG_PRINTF("║ VSPD: ALL DATA PARSED (no remaining bytes)                  ║\n");
                DBG_PRINTF("╚══════════════════════════════════════════════════════════════╝\n\n");
            }
            
            // Store VSPD data even if incomplete - store whatever we have
            DBG_PRINTF("DEBUG: Attempting to store ATSC3 VSPD for %s:%s (resolution: %ux%u, codec: %s)\n", 
                   destIp, destPort, horizontal_size, vertical_size, asset_type);
            ServiceDescriptors* svc_desc = get_or_create_service_descriptor(destIp, destPort);
            if (svc_desc && !svc_desc->vspd) {
                svc_desc->vspd = (VspdData*)malloc(sizeof(VspdData));
                if (svc_desc->vspd) {
                    memset(svc_desc->vspd, 0, sizeof(VspdData));
                    svc_desc->vspd->codec_code = 0;
                    strncpy(svc_desc->vspd->codec_name, asset_type, sizeof(svc_desc->vspd->codec_name) - 1);
                    svc_desc->vspd->codec_name[sizeof(svc_desc->vspd->codec_name) - 1] = '\0';
                    svc_desc->vspd->horizontal_size = horizontal_size;
                    svc_desc->vspd->vertical_size = vertical_size;
                    svc_desc->vspd->aspect_ratio = 0;
                    svc_desc->vspd->frame_rate_code = frame_rate_code;
                    strncpy(svc_desc->vspd->frame_rate, frame_rate_str, sizeof(svc_desc->vspd->frame_rate) - 1);
                    svc_desc->vspd->frame_rate[sizeof(svc_desc->vspd->frame_rate) - 1] = '\0';
                    svc_desc->vspd->color_depth = bit_depth;
                    svc_desc->vspd->chroma_format = chroma_format;
                    svc_desc->vspd->hdr_info = 0;
                    // Copy profile/tier/level data from temp_vspd
                    svc_desc->vspd->profile_idc = temp_vspd.profile_idc;
                    strncpy(svc_desc->vspd->profile_name, temp_vspd.profile_name, sizeof(svc_desc->vspd->profile_name) - 1);
                    svc_desc->vspd->level_idc = temp_vspd.level_idc;
                    svc_desc->vspd->level_value = temp_vspd.level_value;
                    svc_desc->vspd->tier_flag = temp_vspd.tier_flag;
                    svc_desc->vspd->progressive_flag = temp_vspd.progressive_flag;
                    svc_desc->vspd->interlaced_flag = temp_vspd.interlaced_flag;
                    DBG_PRINTF("DEBUG: ATSC3 VSPD stored successfully for %s:%s (codec: %s, resolution: %ux%u, framerate: %s, chroma: %u, bit_depth: %u)\n", 
                           destIp, destPort, asset_type, horizontal_size, vertical_size, 
                           strlen(frame_rate_str) > 0 ? frame_rate_str : "unknown", chroma_format, bit_depth);
                }
            } else if (svc_desc && svc_desc->vspd) {
                DBG_PRINTF("DEBUG: VSPD already exists for %s:%s\n", destIp, destPort);
            }
        }
        
    } else {
        // Simple A/331 format (starts directly with video parameters)
        if (length < 8) {
            DBG_PRINTF("      ERROR: Simple VSPD too short (%u bytes)\n", length);
            return;
        }
        
        uint16_t horizontal_size = (data[0] << 8) | data[1];
        uint16_t vertical_size = (data[2] << 8) | data[3];
        uint8_t aspect_ratio = data[4] >> 4;
        uint8_t frame_rate_code = data[4] & 0x0F;
        uint8_t video_code = data[5];
        uint8_t still_picture_flag = (data[6] >> 7) & 0x01;
        
        DBG_PRINTF("    Video: %ux%u", horizontal_size, vertical_size);
        
        // Frame rate mapping per A/331 Table 6.9
        const char* frame_rate_str = "Unknown";
        switch (frame_rate_code) {
            case 0x1: frame_rate_str = "23.976 fps"; break;
            case 0x2: frame_rate_str = "24 fps"; break;
            case 0x3: frame_rate_str = "25 fps"; break;
            case 0x4: frame_rate_str = "29.97 fps"; break;
            case 0x5: frame_rate_str = "30 fps"; break;
            case 0x6: frame_rate_str = "50 fps"; break;
            case 0x7: frame_rate_str = "59.94 fps"; break;
            case 0x8: frame_rate_str = "60 fps"; break;
            case 0x9: frame_rate_str = "120 fps"; break;
            case 0xA: frame_rate_str = "119.88 fps"; break;
        }
        DBG_PRINTF(", %s", frame_rate_str);
        
        // Aspect ratio per A/331 Table 6.10
        const char* aspect_str = "Unknown";
        switch (aspect_ratio) {
            case 0x2: aspect_str = "4:3"; break;
            case 0x3: aspect_str = "16:9"; break;
            case 0x4: aspect_str = "2.21:1"; break;
        }
        DBG_PRINTF(", %s", aspect_str);
        
        // Video code per A/331 Table 6.11
        const char* video_code_str = "Unknown";
        switch (video_code) {
            case 0x01: video_code_str = "HEVC Main Profile"; break;
            case 0x02: video_code_str = "HEVC Main 10 Profile"; break;
        }
        DBG_PRINTF(", %s", video_code_str);
        
        if (still_picture_flag) {
            DBG_PRINTF(", Still Picture");
        }
        DBG_PRINTF("\n");
        
        // Store VSPD data for HTML output
        DBG_PRINTF("DEBUG: Attempting to store VSPD for %s:%s\n", destIp, destPort);
        DBG_PRINTF("DEBUG: Current g_service_descriptor_count = %d\n", g_service_descriptor_count);
        ServiceDescriptors* svc_desc = get_or_create_service_descriptor(destIp, destPort);
        if (svc_desc && !svc_desc->vspd) {
            svc_desc->vspd = (VspdData*)malloc(sizeof(VspdData));
            if (svc_desc->vspd) {
                svc_desc->vspd->codec_code = video_code;
                strncpy(svc_desc->vspd->codec_name, video_code_str, sizeof(svc_desc->vspd->codec_name) - 1);
                svc_desc->vspd->codec_name[sizeof(svc_desc->vspd->codec_name) - 1] = '\0';
                svc_desc->vspd->horizontal_size = horizontal_size;
                svc_desc->vspd->vertical_size = vertical_size;
                svc_desc->vspd->aspect_ratio = aspect_ratio;
                svc_desc->vspd->frame_rate_code = frame_rate_code;
                strncpy(svc_desc->vspd->frame_rate, frame_rate_str, sizeof(svc_desc->vspd->frame_rate) - 1);
                svc_desc->vspd->frame_rate[sizeof(svc_desc->vspd->frame_rate) - 1] = '\0';
                svc_desc->vspd->color_depth = 0;  // Not in simple format
                svc_desc->vspd->hdr_info = 0;      // Not in simple format
                DBG_PRINTF("DEBUG: VSPD stored successfully for %s:%s (%ux%u, %s)\n", 
                       destIp, destPort, horizontal_size, vertical_size, frame_rate_str);
            } else {
                printf("ERROR: Failed to allocate memory for VSPD\n");
            }
        } else if (svc_desc && svc_desc->vspd) {
            DBG_PRINTF("DEBUG: VSPD already exists for %s:%s, skipping\n", destIp, destPort);
        } else {
            printf("ERROR: Could not get service descriptor storage for %s:%s\n", destIp, destPort);
        }
    }
}

void parse_spd_descriptor(const uint8_t* data, uint16_t length,
                          const char* destIp, const char* destPort) {
    if (length < 5) {
        DBG_PRINTF("    ERROR: SPD too short (%u bytes)\n", length);
        return;
    }
    
    const uint8_t* pos = data;
    size_t remaining = length;
    
    // descriptor_tag (2 bytes) - should be 0x000c
    // descriptor_tag = (pos[0] << 8) | pos[1] (not used)
    pos += 2;
    remaining -= 2;
    
    // descriptor_length (2 bytes)
    // descriptor_length = (pos[0] << 8) | pos[1] (not used)
    pos += 2;
    remaining -= 2;
    
    if (remaining < 1) {
        DBG_PRINTF("    ERROR: SPD missing number_of_assets\n");
        return;
    }
    
    // number_of_assets (1 byte)
    uint8_t number_of_assets = pos[0];
    pos += 1;
    remaining -= 1;
    
    DBG_PRINTF("    Security Properties Descriptor: %u asset(s)\n", number_of_assets);
    
    if (number_of_assets == 0) {
        DBG_PRINTF("    ✓ No DRM/encryption configured (unencrypted content)\n");
        return;
    }
    
    // Parse each asset
    for (int i = 0; i < number_of_assets && remaining >= 4; i++) {
        DBG_PRINTF("    Asset %d:\n", i + 1);
        
        // asset_id_length (4 bytes)
        uint32_t asset_id_length = (pos[0] << 24) | (pos[1] << 16) | (pos[2] << 8) | pos[3];
        pos += 4;
        remaining -= 4;
        
        if (remaining < asset_id_length) {
            DBG_PRINTF("      ERROR: Not enough data for asset_id\n");
            break;
        }
        
        // asset_id_byte (variable length)
        DBG_PRINTF("      Asset ID: ");
        for (uint32_t j = 0; j < asset_id_length && j < 32; j++) {
            DBG_PRINTF("%02x", pos[j]);
        }
        if (asset_id_length > 32) DBG_PRINTF("...");
        DBG_PRINTF("\n");
        pos += asset_id_length;
        remaining -= asset_id_length;
        
        if (remaining < 1) break;
        
        // flags byte: scheme_code_present(1) | default_KID_present(1) | reserved(6)
        uint8_t flags = pos[0];
        uint8_t scheme_code_present = (flags >> 7) & 0x1;
        uint8_t default_KID_present = (flags >> 6) & 0x1;
        pos += 1;
        remaining -= 1;
        
        // scheme_code (4 bytes if present)
        if (scheme_code_present && remaining >= 4) {
            char scheme_code[5];
            memcpy(scheme_code, pos, 4);
            scheme_code[4] = '\0';
            DBG_PRINTF("      Scheme Code: %s (0x%02x%02x%02x%02x)\n", 
                   scheme_code, pos[0], pos[1], pos[2], pos[3]);
            pos += 4;
            remaining -= 4;
        }
        
        // default_KID (16 bytes if present)
        if (default_KID_present && remaining >= 16) {
            DBG_PRINTF("      Default KID: ");
            for (int j = 0; j < 16; j++) {
                DBG_PRINTF("%02x", pos[j]);
                if (j == 3 || j == 5 || j == 7 || j == 9) DBG_PRINTF("-");
            }
            DBG_PRINTF("\n");
            pos += 16;
            remaining -= 16;
        }
        
        if (remaining < 1) break;
        
        // number_of_systems (1 byte)
        uint8_t number_of_systems = pos[0];
        pos += 1;
        remaining -= 1;
        
        DBG_PRINTF("      DRM Systems: %u\n", number_of_systems);
        
        // Parse each system (simplified - just skip the data for now)
        for (int j = 0; j < number_of_systems && remaining > 0; j++) {
            if (remaining < 1) break;
            
            uint8_t sys_flags = pos[0];
            uint8_t system_UUID_present = (sys_flags >> 7) & 0x1;
            uint8_t license_info_present = (sys_flags >> 6) & 0x1;
            uint8_t pssh_present = (sys_flags >> 5) & 0x1;
            pos += 1;
            remaining -= 1;
            
            if (system_UUID_present && remaining >= 16) {
                DBG_PRINTF("        System UUID: ");
                for (int k = 0; k < 16; k++) {
                    DBG_PRINTF("%02x", pos[k]);
                    if (k == 3 || k == 5 || k == 7 || k == 9) DBG_PRINTF("-");
                }
                DBG_PRINTF("\n");
                pos += 16;
                remaining -= 16;
            }
            
            if (license_info_present && remaining >= 1) {
                uint8_t num_license_info = pos[0];
                pos += 1;
                remaining -= 1;
                
                for (int k = 0; k < num_license_info && remaining >= 2; k++) {
                    // license_type = pos[0] (not used)
                    uint8_t la_url_length = pos[1];
                    pos += 2;
                    remaining -= 2;
                    
                    if (remaining >= la_url_length) {
                        DBG_PRINTF("        License Server URL: %.*s\n", la_url_length, pos);
                        pos += la_url_length;
                        remaining -= la_url_length;
                    }
                }
            }
            
            if (pssh_present && remaining >= 4) {
                uint32_t pssh_length = (pos[0] << 24) | (pos[1] << 16) | (pos[2] << 8) | pos[3];
                pos += 4;
                remaining -= 4;
                
                if (remaining >= pssh_length) {
                    DBG_PRINTF("        PSSH box: %u bytes\n", pssh_length);
                    pos += pssh_length;
                    remaining -= pssh_length;
                }
            }
        }
    }
}

/**
 * @brief Map AC-4 audio_channel_config value to actual channel count
 * Based on ETSI TS 103 190-2 V1.2.1 Table 79
 */
static uint8_t map_ac4_channel_config_to_count(uint8_t config) {
    switch (config) {
        case 0: return 1;   // Mono
        case 1: return 2;   // Stereo (L, R)
        case 2: return 3;   // LCR (L, C, R)
        case 3: return 4;   // LCRLrs (L, C, R, LsRs)
        case 4: return 5;   // LCRLrsLFE (5.0)
        case 5: return 6;   // LCRLrsLFE (5.1)
        case 6: return 7;   // LCRLrsLbRb (7.0)
        case 7: return 8;   // LCRLrsLbRbLFE (7.1)
        default: return 0;  // Unknown
    }
}

/**
 * @brief Map channel config to surround format string (e.g., "5.1", "7.1")
 */
static void map_ac4_channel_config_to_string(uint8_t config, char* output, size_t output_size) {
    switch (config) {
        case 0: snprintf(output, output_size, "1.0"); break;
        case 1: snprintf(output, output_size, "2.0"); break;
        case 2: snprintf(output, output_size, "3.0"); break;
        case 3: snprintf(output, output_size, "4.0"); break;
        case 4: snprintf(output, output_size, "5.0"); break;
        case 5: snprintf(output, output_size, "5.1"); break;
        case 6: snprintf(output, output_size, "7.0"); break;
        case 7: snprintf(output, output_size, "7.1"); break;
        default: snprintf(output, output_size, "%d ch", config); break;
    }
}

/**
 * @brief Count total audio streams in service from MPT tables
 */
static int count_audio_streams_in_service(const char* dest_ip, const char* dest_port) {
    int audio_count = 0;
    MptTable* mpt = get_mpt_tables();
    int mpt_count = get_mpt_table_count();
    
    // Track packet_ids we've already counted to avoid duplicates
    uint16_t counted_packet_ids[256];  // Should be enough for most cases
    int counted_count = 0;
    
    DBG_PRINTF("DEBUG AUDIO COUNT: Checking %d MPT tables for %s:%s\n", mpt_count, dest_ip, dest_port);
    
    for (int i = 0; i < mpt_count; i++) {
        if (strcmp(mpt[i].source_ip, dest_ip) == 0 &&
            strcmp(mpt[i].source_port, dest_port) == 0) {
            
            DBG_PRINTF("DEBUG AUDIO COUNT:   MPT[%d] matches - checking %d assets\n", i, mpt[i].num_assets);
            
            for (int j = 0; j < mpt[i].num_assets; j++) {
                MptAssetInfo* asset = &mpt[i].assets[j];
                DBG_PRINTF("DEBUG AUDIO COUNT:     Asset[%d]: type='%s', packet_id=%u\n", 
                       j, asset->asset_type, asset->packet_id);
                
                if (asset->asset_type[0] && (
                    strcmp(asset->asset_type, "audio") == 0 ||
                    strcmp(asset->asset_type, "ac-4") == 0 ||
                    strcmp(asset->asset_type, "mp4a") == 0 ||
                    strcmp(asset->asset_type, "ac-3") == 0 ||
                    strcmp(asset->asset_type, "ec-3") == 0)) {
                    
                    // Check if we've already counted this packet_id
                    bool already_counted = false;
                    for (int k = 0; k < counted_count; k++) {
                        if (counted_packet_ids[k] == asset->packet_id) {
                            already_counted = true;
                            DBG_PRINTF("DEBUG AUDIO COUNT:       ✗ DUPLICATE packet_id %u - already counted\n", asset->packet_id);
                            break;
                        }
                    }
                    
                    if (!already_counted) {
                        audio_count++;
                        if (counted_count < 256) {
                            counted_packet_ids[counted_count++] = asset->packet_id;
                        }
                        DBG_PRINTF("DEBUG AUDIO COUNT:       ✓ COUNTED as audio (total now: %d)\n", audio_count);
                    }
                } else {
                    DBG_PRINTF("DEBUG AUDIO COUNT:       ✗ Not audio\n");
                }
            }
        }
    }
    
    DBG_PRINTF("DEBUG: Found %d audio stream(s) in MPT for %s:%s\n", audio_count, dest_ip, dest_port);
    return audio_count;
}

void parse_aspd_descriptor(const uint8_t* data, uint16_t length,
                           const char* destIp, const char* destPort) {
    if (length < 4) {
        DBG_PRINTF("    ERROR: ASPD too short (%u bytes)\n", length);
        return;
    }
    
    // ========================================================================
    // ASPD RAW DATA DUMP
    // ========================================================================
    DBG_PRINTF("\n");
    DBG_PRINTF("╔══════════════════════════════════════════════════════════════╗\n");
    DBG_PRINTF("║ ASPD (Audio Stream Properties Descriptor) RAW DATA          ║\n");
    DBG_PRINTF("╠══════════════════════════════════════════════════════════════╣\n");
    DBG_PRINTF("║ Destination: %s:%-5s                                  ║\n", destIp, destPort);
    DBG_PRINTF("║ Length: %-4u bytes                                          ║\n", length);
    DBG_PRINTF("╚══════════════════════════════════════════════════════════════╝\n");
    DBG_PRINTF("\n");
    
    // Hex dump with offset, hex values, and ASCII representation
    DBG_PRINTF("Offset(h)  00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F  ASCII\n");
    DBG_PRINTF("─────────  ───────────────────────────────────────────────  ────────────────\n");
    for (uint16_t i = 0; i < length; i += 16) {
        DBG_PRINTF("%08X   ", i);
        
        // Hex values
        for (int j = 0; j < 16; j++) {
            if (i + j < length) {
                DBG_PRINTF("%02X ", data[i + j]);
            } else {
                DBG_PRINTF("   ");
            }
        }
        
        DBG_PRINTF(" ");
        
        // ASCII representation
        for (int j = 0; j < 16 && i + j < length; j++) {
            uint8_t c = data[i + j];
            DBG_PRINTF("%c", (c >= 32 && c <= 126) ? c : '.');
        }
        DBG_PRINTF("\n");
    }
    DBG_PRINTF("\n");
    
    // Binary breakdown of first few bytes
    DBG_PRINTF("First 48 bytes (binary breakdown):\n");
    for (int i = 0; i < 48 && i < length; i++) {
        DBG_PRINTF("  Byte[%2d] = 0x%02X = 0b", i, data[i]);
        for (int bit = 7; bit >= 0; bit--) {
            DBG_PRINTF("%d", (data[i] >> bit) & 1);
            if (bit == 4) DBG_PRINTF("_");  // Visual separator
        }
        DBG_PRINTF(" = %3d", data[i]);
        
        // Add helpful notes for known positions
        if (i == 0 && length >= 4) {
            uint16_t first_word = (data[0] << 8) | data[1];
            if (first_word == 0x0009) {
                DBG_PRINTF("  ← Descriptor tag (high byte) = 0x0009 (ASPD)");
            } else if (first_word < 0x100) {
                DBG_PRINTF("  ← Audio code (simple format)");
            }
        } else if (i == 1 && length >= 4) {
            uint16_t first_word = (data[0] << 8) | data[1];
            if (first_word == 0x0009) {
                DBG_PRINTF("  ← Descriptor tag (low byte)");
            } else {
                DBG_PRINTF("  ← Number of channels (simple format)");
            }
        } else if (i == 2 && length >= 4) {
            uint16_t first_word = (data[0] << 8) | data[1];
            if (first_word == 0x0009) {
                DBG_PRINTF("  ← Descriptor length (high byte)");
            }
        } else if (i == 3 && length >= 4) {
            uint16_t first_word = (data[0] << 8) | data[1];
            if (first_word == 0x0009) {
                DBG_PRINTF("  ← Descriptor length (low byte) = %u total bytes", (data[2] << 8) | data[3]);
            }
        } else if (i == 4 && length >= 5) {
            uint16_t first_word = (data[0] << 8) | data[1];
            if (first_word == 0x0009) {
                DBG_PRINTF("  ← number_of_assets");
            }
        }
        DBG_PRINTF("\n");
    }
    DBG_PRINTF("\n");
    DBG_PRINTF("════════════════════════════════════════════════════════════════\n");
    DBG_PRINTF("BEGIN PARSING\n");
    DBG_PRINTF("════════════════════════════════════════════════════════════════\n\n");
    
    const uint8_t* pos = data;
    size_t remaining = length;
    
    // Check if this is MMT Asset Descriptor format (starts with descriptor_tag 0x0009)
    uint16_t first_word = (pos[0] << 8) | pos[1];
    
    if (first_word == 0x0009 && remaining >= 4) {
        // MMT Asset Descriptor format - A/331 Table 7.32
        // descriptor_length = (pos[2] << 8) | pos[3] (not used)
        pos += 4;
        remaining -= 4;
        
        if (remaining < 1) return;
        uint8_t number_of_assets = pos[0];
        DBG_PRINTF("    Audio: %u asset(s)\n", number_of_assets);
        pos += 1;
        remaining -= 1;
        
        // Parse each asset
        for (int i = 0; i < number_of_assets && remaining >= 4; i++) {
            // asset_id_length (4 bytes)
            uint32_t asset_id_length = (pos[0] << 24) | (pos[1] << 16) | (pos[2] << 8) | pos[3];
            pos += 4;
            remaining -= 4;
            
            if (remaining < asset_id_length) {
                DBG_PRINTF("      ERROR: Not enough data for asset_id\n");
                return;
            }
            
            // asset_id (variable length string)
            DBG_PRINTF("      Asset %d ID: %.*s\n", i + 1, (int)asset_id_length, pos);
            pos += asset_id_length;
            remaining -= asset_id_length;
            
            // asset_type (4 bytes FourCC)
            if (remaining < 4) {
                DBG_PRINTF("      ERROR: Not enough data for asset_type\n");
                return;
            }
            char asset_type[5] = {pos[0], pos[1], pos[2], pos[3], 0};
            DBG_PRINTF("      Asset Type: %s\n", asset_type);
            pos += 4;
            remaining -= 4;
            
            // num_presentations (1 byte)
            if (remaining < 1) {
                DBG_PRINTF("      ERROR: Not enough data for num_presentations\n");
                return;
            }
            uint8_t num_presentations = pos[0];
            DBG_PRINTF("      Presentations: %u\n", num_presentations);
            pos += 1;
            remaining -= 1;
            
            // Flags byte
            if (remaining < 1) {
                DBG_PRINTF("      ERROR: Not enough data for flags\n");
                return;
            }
            uint8_t flags = pos[0];
            uint8_t multi_stream_info_present = (flags >> 7) & 0x01;
            uint8_t emergency_info_time_present = (flags >> 6) & 0x01;
            pos += 1;
            remaining -= 1;
            
            // Variable to capture first language for storage
            char first_language[64] = "";
            
            // Variables to capture channel config
            uint8_t first_audio_channel_config = 0;
            bool found_channel_config = false;
            
            // Parse each presentation
            for (int j = 0; j < num_presentations && remaining >= 2; j++) {
                DBG_PRINTF("      Presentation %d:\n", j + 1);
                
                // presentation_id (1 byte)
                uint8_t presentation_id = pos[0];
                DBG_PRINTF("        ID: %u\n", presentation_id);
                pos += 1;
                remaining -= 1;
                
                // Presentation flags (1 byte)
                if (remaining < 1) break;
                uint8_t pres_flags = pos[0];
                // interactivity_enabled = (pres_flags >> 7) & 0x01 (not used)
                uint8_t profile_channel_config_present = (pres_flags >> 6) & 0x01;
                uint8_t profile_long = (pres_flags >> 5) & 0x01;
                uint8_t channel_config_long = (pres_flags >> 4) & 0x01;
                uint8_t audio_rendering_info_present = (pres_flags >> 3) & 0x01;
                uint8_t language_present = (pres_flags >> 2) & 0x01;
                uint8_t accessibility_role_present = (pres_flags >> 1) & 0x01;
                uint8_t label_present = pres_flags & 0x01;
                pos += 1;
                remaining -= 1;
                
                // profile_channel_config
                if (profile_channel_config_present) {
                    // profile_level_indication
                    if (remaining < 1) break;
                    uint8_t profile_level_indication;
                    if (profile_long == 1) {
                        // 8 bits
                        profile_level_indication = pos[0];
                        pos += 1;
                        remaining -= 1;
                    } else {
                        // 3 bits (packed with channel_config)
                        profile_level_indication = (pos[0] >> 5) & 0x07;
                        // Don't advance pos yet, channel_config is in same byte
                    }
                    
                    // audio_channel_config
                    uint8_t audio_channel_config;
                    if (channel_config_long == 1) {
                        if (remaining < 1) break;
                        // 8 bits
                        audio_channel_config = pos[0];
                        pos += 1;
                        remaining -= 1;
                    } else {
                        if (remaining < 1) break;
                        // 3 bits (lower 3 bits of byte with profile)
                        audio_channel_config = pos[0] & 0x07;
                        pos += 1;
                        remaining -= 1;
                    }
                    
                    DBG_PRINTF("        Profile level: %u, Channel config: %u\n", 
                           profile_level_indication, audio_channel_config);
                
                    // Capture first channel config for storage
                    if (!found_channel_config) {
                        first_audio_channel_config = audio_channel_config;
                        found_channel_config = true;
                        DBG_PRINTF("        *** Captured channel config: %u ***\n", audio_channel_config);
                    }
                }
                
                // audio_rendering_indication
                if (audio_rendering_info_present) {
                    if (remaining < 1) break;
                    uint8_t audio_rendering_indication = pos[0];
                    DBG_PRINTF("        Audio rendering indication: 0x%02x\n", audio_rendering_indication);
                    pos += 1;
                    remaining -= 1;
                }
                
                // Languages - capture the first one for storage
                uint8_t num_languages = 0;
                if (language_present) {
                    if (remaining < 1) break;
                    uint8_t num_languages_minus1 = pos[0];
                    num_languages = num_languages_minus1 + 1;
                    pos += 1;
                    remaining -= 1;
                    
                    for (int k = 0; k < num_languages && remaining >= 1; k++) {
                        uint8_t language_length = pos[0];
                        pos += 1;
                        remaining -= 1;
                        
                        if (remaining < language_length) break;
                        DBG_PRINTF("        Language %d: %.*s\n", k + 1, language_length, pos);
                        
                        // Save first language for storage
                        if (k == 0 && language_length > 0) {
                            int copy_len = language_length < sizeof(first_language) - 1 ? language_length : sizeof(first_language) - 1;
                            memcpy(first_language, pos, copy_len);
                            first_language[copy_len] = '\0';
                        }
                        
                        pos += language_length;
                        remaining -= language_length;
                    }
                }
                
                // Accessibility roles
                if (accessibility_role_present) {
                    for (int k = 0; k < num_languages && remaining >= 1; k++) {
                        uint8_t accessibility_role = pos[0];
                        DBG_PRINTF("        Accessibility role %d: 0x%02x\n", k + 1, accessibility_role);
                        pos += 1;
                        remaining -= 1;
                    }
                }
                
                // Label
                if (label_present) {
                    if (remaining < 1) break;
                    uint8_t label_length = pos[0];
                    pos += 1;
                    remaining -= 1;
                    
                    if (remaining < label_length) break;
                    DBG_PRINTF("        Label: %.*s\n", label_length, pos);
                    pos += label_length;
                    remaining -= label_length;
                }
            }
            
            // multi_stream_info (if present)
            if (multi_stream_info_present && remaining > 0) {
                DBG_PRINTF("      Multi-stream info present (%zu bytes)\n", remaining);
                // Skip for now - presentation_aux_stream_info() structure not shown
            }
            
            // emergency_info_time (if present)
            if (emergency_info_time_present && remaining >= 8) {
                DBG_PRINTF("      Emergency info time present\n");
                // Skip the 8 bytes
                pos += 8;
                remaining -= 8;
            }
            
            // Store ASPD data for this asset - store asset_type as codec
            DBG_PRINTF("DEBUG: Attempting to store ATSC3 ASPD for %s:%s (codec: %s, lang: %s)\n", 
                   destIp, destPort, asset_type, first_language);
            ServiceDescriptors* svc_desc = get_or_create_service_descriptor(destIp, destPort);
            if (svc_desc && !svc_desc->aspd) {
                svc_desc->aspd = (AspdData*)malloc(sizeof(AspdData));
                if (svc_desc->aspd) {
                    memset(svc_desc->aspd, 0, sizeof(AspdData));
                    svc_desc->aspd->codec_code = 0;
                    strncpy(svc_desc->aspd->codec_name, asset_type, sizeof(svc_desc->aspd->codec_name) - 1);
                    svc_desc->aspd->codec_name[sizeof(svc_desc->aspd->codec_name) - 1] = '\0';
                    
                    // Use captured channel config instead of hardcoded 0
                    if (found_channel_config) {
                        svc_desc->aspd->num_channels = map_ac4_channel_config_to_count(first_audio_channel_config);
                        map_ac4_channel_config_to_string(first_audio_channel_config, 
                                                        svc_desc->aspd->channel_config,
                                                        sizeof(svc_desc->aspd->channel_config));
                        DBG_PRINTF("DEBUG: Mapped channel config %u to %u channels (%s)\n",
                               first_audio_channel_config, svc_desc->aspd->num_channels,
                               svc_desc->aspd->channel_config);
                    } else {
                        svc_desc->aspd->num_channels = 0;
                        svc_desc->aspd->channel_config[0] = '\0';
                    }
                    
                    // Sample rate is typically 48kHz for ATSC 3.0
                    svc_desc->aspd->sample_rate = 48000;
                    
                    strncpy(svc_desc->aspd->language, first_language, sizeof(svc_desc->aspd->language) - 1);
                    svc_desc->aspd->language[sizeof(svc_desc->aspd->language) - 1] = '\0';
                    svc_desc->aspd->num_presentations = num_presentations;
                    DBG_PRINTF("DEBUG: ATSC3 ASPD stored successfully for %s:%s (codec: %s, %u channels, lang: %s)\n", 
                           destIp, destPort, asset_type, svc_desc->aspd->num_channels, first_language);
                }
            } else if (svc_desc && svc_desc->aspd) {
                DBG_PRINTF("DEBUG: ASPD already exists for %s:%s\n", destIp, destPort);
            }
        }
        
        // Remaining bytes are reserved
        if (remaining > 0) {
            DBG_PRINTF("\n");
            DBG_PRINTF("╔══════════════════════════════════════════════════════════════╗\n");
            DBG_PRINTF("║ ASPD: REMAINING/RESERVED DATA (%zu bytes)                    \n", remaining);
            DBG_PRINTF("╚══════════════════════════════════════════════════════════════╝\n");
            DBG_PRINTF("Offset(h)  Hex Values                                          ASCII\n");
            DBG_PRINTF("─────────  ───────────────────────────────────────────────────  ────────────────\n");
            
            size_t offset = (pos - data);
            for (size_t i = 0; i < remaining; i += 16) {
                DBG_PRINTF("%08zX   ", offset + i);
                
                // Hex values
                for (int j = 0; j < 16; j++) {
                    if (i + j < remaining) {
                        DBG_PRINTF("%02X ", pos[i + j]);
                    } else {
                        DBG_PRINTF("   ");
                    }
                }
                
                DBG_PRINTF(" ");
                
                // ASCII representation
                for (int j = 0; j < 16 && i + j < remaining; j++) {
                    uint8_t c = pos[i + j];
                    DBG_PRINTF("%c", (c >= 32 && c <= 126) ? c : '.');
                }
                DBG_PRINTF("\n");
            }
            DBG_PRINTF("\n");
        } else {
            DBG_PRINTF("\n╔══════════════════════════════════════════════════════════════╗\n");
            DBG_PRINTF("║ ASPD: ALL DATA PARSED (no remaining bytes)                  ║\n");
            DBG_PRINTF("╚══════════════════════════════════════════════════════════════╝\n\n");
        }
        
    } else {
        // Simple A/331 format (starts directly with audio parameters - Table 6.12)
        if (length < 2) {
            DBG_PRINTF("    ERROR: Simple ASPD too short (%u bytes)\n", length);
            return;
        }
        
        uint8_t audio_code = data[0];
        uint8_t num_channels = data[1];
        
        // Audio code per A/331 Table 6.13
        const char* audio_code_str = "Unknown";
        uint32_t sample_rate = 48000;  // Default for ATSC 3.0
        switch (audio_code) {
            case 0x01: audio_code_str = "AC-4"; break;
            case 0x06: audio_code_str = "HE-AAC"; break;
        }
        
        DBG_PRINTF("    Audio: %s, %u channels\n", audio_code_str, num_channels);
        
        // Parse full_channel_audio_descriptor if present
        if (length >= 3) {
            uint8_t fca_desc_length = data[2];
            if (length >= 3 + fca_desc_length && fca_desc_length > 0) {
                DBG_PRINTF("    Full channel audio descriptor present (%u bytes)\n", fca_desc_length);
            }
        }
        
        // Store ASPD data for HTML output
        DBG_PRINTF("DEBUG: Attempting to store ASPD for %s:%s\n", destIp, destPort);
        ServiceDescriptors* svc_desc = get_or_create_service_descriptor(destIp, destPort);
        if (svc_desc && !svc_desc->aspd) {
            svc_desc->aspd = (AspdData*)malloc(sizeof(AspdData));
            if (svc_desc->aspd) {
                svc_desc->aspd->codec_code = audio_code;
                strncpy(svc_desc->aspd->codec_name, audio_code_str, sizeof(svc_desc->aspd->codec_name) - 1);
                svc_desc->aspd->codec_name[sizeof(svc_desc->aspd->codec_name) - 1] = '\0';
                svc_desc->aspd->num_channels = num_channels;
                svc_desc->aspd->sample_rate = sample_rate;
                // Format channel configuration
                snprintf(svc_desc->aspd->channel_config, sizeof(svc_desc->aspd->channel_config), 
                        "%u.%u", num_channels > 5 ? 5 : num_channels, num_channels > 5 ? 1 : 0);
                DBG_PRINTF("DEBUG: ASPD stored successfully for %s:%s (%s, %u channels)\n", 
                       destIp, destPort, audio_code_str, num_channels);
            } else {
                printf("ERROR: Failed to allocate memory for ASPD\n");
            }
        } else if (svc_desc && svc_desc->aspd) {
            DBG_PRINTF("DEBUG: ASPD already exists for %s:%s, skipping\n", destIp, destPort);
        } else {
            printf("ERROR: Could not get service descriptor storage for %s:%s\n", destIp, destPort);
        }
    }
}

void parse_cad_descriptor(const uint8_t* data, uint16_t length,
                          const char* destIp, const char* destPort) {
    if (length < 4) {
        DBG_PRINTF("    ERROR: CAD too short (%u bytes)\n", length);
        return;
    }
    
    // ========================================================================
    // CAD RAW DATA DUMP
    // ========================================================================
    DBG_PRINTF("\n");
    DBG_PRINTF("╔══════════════════════════════════════════════════════════════╗\n");
    DBG_PRINTF("║ CAD (Caption Asset Descriptor) RAW DATA                     ║\n");
    DBG_PRINTF("╠══════════════════════════════════════════════════════════════╣\n");
    DBG_PRINTF("║ Destination: %s:%-5s                                  ║\n", destIp, destPort);
    DBG_PRINTF("║ Length: %-4u bytes                                          ║\n", length);
    DBG_PRINTF("╚══════════════════════════════════════════════════════════════╝\n");
    DBG_PRINTF("\n");
    
    // Hex dump with offset, hex values, and ASCII representation
    DBG_PRINTF("Offset(h)  00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F  ASCII\n");
    DBG_PRINTF("─────────  ───────────────────────────────────────────────  ────────────────\n");
    for (uint16_t i = 0; i < length; i += 16) {
        DBG_PRINTF("%08X   ", i);
        
        // Hex values
        for (int j = 0; j < 16; j++) {
            if (i + j < length) {
                DBG_PRINTF("%02X ", data[i + j]);
            } else {
                DBG_PRINTF("   ");
            }
        }
        
        DBG_PRINTF(" ");
        
        // ASCII representation
        for (int j = 0; j < 16 && i + j < length; j++) {
            uint8_t c = data[i + j];
            DBG_PRINTF("%c", (c >= 32 && c <= 126) ? c : '.');
        }
        DBG_PRINTF("\n");
    }
    DBG_PRINTF("\n");
    
    // Binary breakdown of first few bytes
    DBG_PRINTF("First 48 bytes (binary breakdown):\n");
    for (int i = 0; i < 48 && i < length; i++) {
        DBG_PRINTF("  Byte[%2d] = 0x%02X = 0b", i, data[i]);
        for (int bit = 7; bit >= 0; bit--) {
            DBG_PRINTF("%d", (data[i] >> bit) & 1);
            if (bit == 4) DBG_PRINTF("_");  // Visual separator
        }
        DBG_PRINTF(" = %3d", data[i]);
        
        // Add helpful notes for known positions
        if (i == 0 && length >= 4) {
            uint16_t first_word = (data[0] << 8) | data[1];
            if (first_word == 0x0008) {
                DBG_PRINTF("  ← Descriptor tag (high byte) = 0x0008 (CAD)");
            }
        } else if (i == 1 && length >= 4) {
            DBG_PRINTF("  ← Descriptor tag (low byte)");
        } else if (i == 2 && length >= 4) {
            DBG_PRINTF("  ← Descriptor length (high byte)");
        } else if (i == 3 && length >= 4) {
            DBG_PRINTF("  ← Descriptor length (low byte) = %u total bytes", (data[2] << 8) | data[3]);
        } else if (i == 4 && length >= 5) {
            uint16_t first_word = (data[0] << 8) | data[1];
            if (first_word == 0x0008) {
                DBG_PRINTF("  ← number_of_assets");
            }
        }
        DBG_PRINTF("\n");
    }
    DBG_PRINTF("\n");
    DBG_PRINTF("════════════════════════════════════════════════════════════════\n");
    DBG_PRINTF("BEGIN PARSING\n");
    DBG_PRINTF("════════════════════════════════════════════════════════════════\n\n");
    
    const uint8_t* pos = data;
    size_t remaining = length;
    
    // Check if this is MMT Asset Descriptor format (starts with descriptor_tag 0x0008)
    uint16_t first_word = (pos[0] << 8) | pos[1];
    
    if (first_word == 0x0008 && remaining >= 4) {
        // MMT Asset Descriptor format - A/331 Table 7.33
        // descriptor_length = (pos[2] << 8) | pos[3] (not used)
        pos += 4;
        remaining -= 4;
        
        if (remaining < 1) return;
        uint8_t number_of_assets = pos[0];
        DBG_PRINTF("    Captions: %u asset(s)\n", number_of_assets);
        pos += 1;
        remaining -= 1;
        
        // Initialize storage for CAD data
        DBG_PRINTF("DEBUG: Attempting to store ATSC3 CAD for %s:%s\n", destIp, destPort);
        ServiceDescriptors* svc_desc = get_or_create_service_descriptor(destIp, destPort);
        if (svc_desc && !svc_desc->cad) {
            svc_desc->cad = (CadData*)malloc(sizeof(CadData));
            if (svc_desc->cad) {
                svc_desc->cad->head = NULL;
            }
        }
        
        CadEntry** tail = svc_desc && svc_desc->cad ? &(svc_desc->cad->head) : NULL;
        int cad_entry_count = 0;
        
        // Parse each asset
        for (int i = 0; i < number_of_assets && remaining >= 4; i++) {
            // asset_id_length (4 bytes)
            uint32_t asset_id_length = (pos[0] << 24) | (pos[1] << 16) | (pos[2] << 8) | pos[3];
            pos += 4;
            remaining -= 4;
            
            if (remaining < asset_id_length) {
                DBG_PRINTF("      ERROR: Not enough data for asset_id\n");
                return;
            }
            
            // asset_id (variable length string)
            DBG_PRINTF("      Asset %d ID: %.*s\n", i + 1, (int)asset_id_length, pos);
            pos += asset_id_length;
            remaining -= asset_id_length;
            
            // language_length (1 byte)
            if (remaining < 1) {
                DBG_PRINTF("      ERROR: Not enough data for language_length\n");
                return;
            }
            uint8_t language_length = pos[0];
            pos += 1;
            remaining -= 1;
            
            if (remaining < language_length) {
                DBG_PRINTF("      ERROR: Not enough data for language\n");
                return;
            }
            
            // language (variable length string) - save this for storage
            char language[64];
            int lang_copy_len = language_length < sizeof(language) - 1 ? language_length : sizeof(language) - 1;
            memcpy(language, pos, lang_copy_len);
            language[lang_copy_len] = '\0';
            DBG_PRINTF("      Language: %s\n", language);
            pos += language_length;
            remaining -= language_length;
            
            // role, aspect_ratio (1 byte total)
            if (remaining < 1) {
                DBG_PRINTF("      ERROR: Not enough data for role/aspect_ratio\n");
                return;
            }
            uint8_t role_aspect = pos[0];
            uint8_t role = (role_aspect >> 4) & 0x0F;
            uint8_t aspect_ratio = role_aspect & 0x0F;
            pos += 1;
            remaining -= 1;
            
            // Role mapping per A/331 Table 7.34
            const char* role_str = "Reserved";
            switch (role) {
                case 0x0: role_str = "main"; break;
                case 0x1: role_str = "alternate"; break;
                case 0x2: role_str = "commentary"; break;
            }
            
            // Aspect ratio mapping per A/331 Table 7.35
            const char* aspect_str = "Reserved";
            switch (aspect_ratio) {
                case 0x0: aspect_str = "16:9"; break;
                case 0x1: aspect_str = "4:3"; break;
                case 0x2: aspect_str = "21:9"; break;
            }
            
            DBG_PRINTF("      Role: %s, Aspect: %s\n", role_str, aspect_str);
            
            // easy_reader, profile, 3d_support, reserved (1 byte total)
            if (remaining < 1) {
                DBG_PRINTF("      ERROR: Not enough data for flags\n");
                return;
            }
            uint8_t flags = pos[0];
            uint8_t easy_reader = (flags >> 7) & 0x01;
            uint8_t profile = (flags >> 5) & 0x03;
            uint8_t support_3d = (flags >> 4) & 0x01;
            pos += 1;
            remaining -= 1;
            
            const char* profile_str = "Reserved";
            if (profile == 0x00) profile_str = "text";
            else if (profile == 0x01) profile_str = "image";
            
            DBG_PRINTF("      Profile: %s, Easy reader: %s, 3D support: %s\n",
                   profile_str,
                   easy_reader ? "yes" : "no",
                   support_3d ? "yes" : "no");
            
            // Store this caption asset
            if (tail) {
                CadEntry* entry = (CadEntry*)malloc(sizeof(CadEntry));
                if (entry) {
                    memset(entry, 0, sizeof(CadEntry));
                    strncpy(entry->language, language, sizeof(entry->language) - 1);
                    entry->language[sizeof(entry->language) - 1] = '\0';
                    entry->easy_reader = easy_reader;
                    entry->wide_aspect_ratio = (aspect_ratio == 0); // 16:9
                    entry->service_number = 0;
                    entry->role = role;
                    strncpy(entry->role_str, role_str, sizeof(entry->role_str) - 1);
                    entry->aspect_ratio = aspect_ratio;
                    strncpy(entry->aspect_str, aspect_str, sizeof(entry->aspect_str) - 1);
                    entry->profile = profile;
                    strncpy(entry->profile_str, profile_str, sizeof(entry->profile_str) - 1);
                    entry->support_3d = support_3d;
                    entry->next = NULL;
                    *tail = entry;
                    tail = &(entry->next);
                    cad_entry_count++;
                }
            }
        }
        
        // Remaining bytes are reserved
        if (remaining > 0) {
            DBG_PRINTF("\n");
            DBG_PRINTF("╔══════════════════════════════════════════════════════════════╗\n");
            DBG_PRINTF("║ CAD: REMAINING/RESERVED DATA (%zu bytes)                     \n", remaining);
            DBG_PRINTF("╚══════════════════════════════════════════════════════════════╝\n");
            DBG_PRINTF("Offset(h)  Hex Values                                          ASCII\n");
            DBG_PRINTF("─────────  ───────────────────────────────────────────────────  ────────────────\n");
            
            size_t offset = (pos - data);
            for (size_t i = 0; i < remaining; i += 16) {
                DBG_PRINTF("%08zX   ", offset + i);
                
                // Hex values
                for (int j = 0; j < 16; j++) {
                    if (i + j < remaining) {
                        DBG_PRINTF("%02X ", pos[i + j]);
                    } else {
                        DBG_PRINTF("   ");
                    }
                }
                
                DBG_PRINTF(" ");
                
                // ASCII representation
                for (int j = 0; j < 16 && i + j < remaining; j++) {
                    uint8_t c = pos[i + j];
                    DBG_PRINTF("%c", (c >= 32 && c <= 126) ? c : '.');
                }
                DBG_PRINTF("\n");
            }
            DBG_PRINTF("\n");
        } else {
            DBG_PRINTF("\n╔══════════════════════════════════════════════════════════════╗\n");
            DBG_PRINTF("║ CAD: ALL DATA PARSED (no remaining bytes)                   ║\n");
            DBG_PRINTF("╚══════════════════════════════════════════════════════════════╝\n\n");
        }
        
        if (svc_desc && svc_desc->cad && cad_entry_count > 0) {
            DBG_PRINTF("DEBUG: ATSC3 CAD stored successfully for %s:%s (%d entries)\n", 
                   destIp, destPort, cad_entry_count);
        }
        
    } else {
        // Simple A/331 format (different structure - Table 6.14)
        uint8_t caption_service_count = data[0];
        
        DBG_PRINTF("    Captions: %u service(s)\n", caption_service_count);
        
        // Store CAD data for HTML output
        DBG_PRINTF("DEBUG: Attempting to store CAD for %s:%s\n", destIp, destPort);
        ServiceDescriptors* svc_desc = get_or_create_service_descriptor(destIp, destPort);
        if (svc_desc && !svc_desc->cad) {
            svc_desc->cad = (CadData*)malloc(sizeof(CadData));
            if (svc_desc->cad) {
                svc_desc->cad->head = NULL;
                CadEntry** tail = &(svc_desc->cad->head);
                int cad_entry_count = 0;
                
                size_t offset = 1;
                for (int i = 0; i < caption_service_count && offset + 3 < length; i++) {
                    uint8_t lang_code_1 = data[offset];
                    uint8_t lang_code_2 = data[offset + 1];
                    uint8_t lang_code_3 = data[offset + 2];
                    uint8_t flags = data[offset + 3];
                    
                    uint8_t digital_cc = (flags >> 7) & 0x01;
                    uint8_t line21_field = (flags >> 6) & 0x01;
                    uint8_t cc_type = flags & 0x3F;
                    
                    char lang[4] = {lang_code_1, lang_code_2, lang_code_3, 0};
                    
                    DBG_PRINTF("      Service %d: Language=%s, ", i + 1, lang);
                    if (digital_cc) {
                        DBG_PRINTF("Digital CC (type=%u)\n", cc_type);
                    } else {
                        DBG_PRINTF("Line 21 (field=%u)\n", line21_field);
                    }
                    
                    // Create CAD entry
                    CadEntry* entry = (CadEntry*)malloc(sizeof(CadEntry));
                    if (entry) {
                        strncpy(entry->language, lang, sizeof(entry->language) - 1);
                        entry->language[sizeof(entry->language) - 1] = '\0';
                        entry->easy_reader = 0;
                        entry->wide_aspect_ratio = digital_cc;
                        entry->service_number = digital_cc ? cc_type : line21_field;
                        entry->next = NULL;
                        *tail = entry;
                        tail = &(entry->next);
                        cad_entry_count++;
                    }
                    
                    offset += 4;
                    
                    // Handle easy_reader field if present
                    if (offset < length) {
                        uint8_t easy_reader = data[offset];
                        if (easy_reader > 0) {
                            DBG_PRINTF("        Easy reader: %u\n", easy_reader);
                            if (entry) {
                                entry->easy_reader = easy_reader;
                            }
                        }
                        offset++;
                    }
                }
                DBG_PRINTF("DEBUG: CAD stored successfully for %s:%s (%d entries)\n", 
                       destIp, destPort, cad_entry_count);
            } else {
                printf("ERROR: Failed to allocate memory for CAD\n");
            }
        } else if (svc_desc && svc_desc->cad) {
            DBG_PRINTF("DEBUG: CAD already exists for %s:%s, skipping storage\n", destIp, destPort);
        } else {
            // Just parse without storing (already have CAD for this service)
            size_t offset = 1;
            for (int i = 0; i < caption_service_count && offset + 3 < length; i++) {
                uint8_t lang_code_1 = data[offset];
                uint8_t lang_code_2 = data[offset + 1];
                uint8_t lang_code_3 = data[offset + 2];
                uint8_t flags = data[offset + 3];
                
                uint8_t digital_cc = (flags >> 7) & 0x01;
                uint8_t line21_field = (flags >> 6) & 0x01;
                uint8_t cc_type = flags & 0x3F;
                
                char lang[4] = {lang_code_1, lang_code_2, lang_code_3, 0};
                
                DBG_PRINTF("      Service %d: Language=%s, ", i + 1, lang);
                if (digital_cc) {
                    DBG_PRINTF("Digital CC (type=%u)\n", cc_type);
                } else {
                    DBG_PRINTF("Line 21 (field=%u)\n", line21_field);
                }
                
                offset += 4;
                
                // Handle easy_reader field if present
                if (offset < length) {
                    uint8_t easy_reader = data[offset];
                    if (easy_reader > 0) {
                        DBG_PRINTF("        Easy reader: %u\n", easy_reader);
                    }
                    offset++;
                }
            }
        }
    }
}

/**
 * @brief Logs a seen MMT Packet ID and increments its count.
 */
void log_mmt_packet_id(uint16_t packet_id) {
    // Only log the first occurrence of each packet ID
    if (!packet_id_seen[packet_id]) {
        DBG_PRINTF("First occurrence of MMT Packet ID: %u\n", packet_id);
        packet_id_seen[packet_id] = true;
    }
    
    // Still maintain the count for statistics
    for (int i = 0; i < g_packet_id_log_count; i++) {
        if (g_packet_id_log[i].id == packet_id) {
            g_packet_id_log[i].count++;
            return;
        }
    }

    if (g_packet_id_log_count < MAX_UNIQUE_PIDS) {
        g_packet_id_log[g_packet_id_log_count].id = packet_id;
        g_packet_id_log[g_packet_id_log_count].count = 1;
        g_packet_id_log_count++;
    }
}

/**
 * @brief Prints the summary of all unique MMT packet IDs and their counts.
 */
void print_packet_id_log() {
    DBG_PRINTF("\n--- MMT Packet ID Summary ---\n");
    if (g_packet_id_log_count == 0) {
        DBG_PRINTF("No MMT packets were found on the monitored streams.\n");
        return;
    }
    DBG_PRINTF("Found %d unique Packet IDs:\n", g_packet_id_log_count);
    DBG_PRINTF("----------------------------------\n");
    DBG_PRINTF("| Packet ID   |  Packet Count  |\n");
    DBG_PRINTF("----------------------------------\n");
    for (int i = 0; i < g_packet_id_log_count; i++) {
        DBG_PRINTF("| %-11u | %-14d |\n", g_packet_id_log[i].id, g_packet_id_log[i].count);
    }
    DBG_PRINTF("----------------------------------\n");
    DBG_PRINTF("Tip: The signaling packet ID (for the MP Table) usually has a very low count compared to media packets.\n\n");
}

void track_mmt_message(uint16_t message_id, const char* destIp, const char* destPort, bool was_parsed) {
    // Find or create entry for this message_id
    MmtMessageStats* stats = NULL;
    for (int i = 0; i < g_mmt_message_stats_count; i++) {
        if (g_mmt_message_stats[i].message_id == message_id) {
            stats = &g_mmt_message_stats[i];
            break;
        }
    }
    
    if (!stats && g_mmt_message_stats_count < MAX_MESSAGE_TYPES) {
        stats = &g_mmt_message_stats[g_mmt_message_stats_count++];
        stats->message_id = message_id;
        stats->count = 0;
        stats->parsed_count = 0;
        strncpy(stats->first_seen_ip, destIp, sizeof(stats->first_seen_ip) - 1);
        strncpy(stats->first_seen_port, destPort, sizeof(stats->first_seen_port) - 1);
    }
    
    if (stats) {
        stats->count++;
        if (was_parsed) {
            stats->parsed_count++;
        }
    }
}

void print_mmt_message_stats() {
    if (g_mmt_message_stats_count == 0) {
        return;
    }
    
    DBG_PRINTF("\n=== MMT Signaling Message Statistics ===\n");
    DBG_PRINTF("%-10s %-30s %-10s %-10s %s\n", "Msg ID", "Type", "Count", "Parsed", "Status");
    DBG_PRINTF("%-10s %-30s %-10s %-10s %s\n", "----------", "------------------------------", "----------", "----------", "----------");
    
    for (int i = 0; i < g_mmt_message_stats_count; i++) {
        MmtMessageStats* stats = &g_mmt_message_stats[i];
        
        // Determine message type name
        const char* msg_type = "Unknown";
        if (stats->message_id == 0x0000) {
            msg_type = "PA (Package Access)";
        } else if (stats->message_id >= 0x0001 && stats->message_id <= 0x0010) {
            msg_type = "MPI (Package Info)";
        } else if (stats->message_id >= 0x0011 && stats->message_id <= 0x0020) {
            msg_type = "MPT (Package Table)";
        } else if (stats->message_id == 0x8100) {
            msg_type = "ATSC3 Signaling";
        } else if (stats->message_id == 0x8101) {
            msg_type = "ATSC3 (Reserved)";
        }
        
        // Determine status
        const char* status;
        if (stats->parsed_count == stats->count) {
            status = "FULLY PARSED";
        } else if (stats->parsed_count > 0) {
            status = "PARTIALLY PARSED";
        } else {
            status = "NOT PARSED";
        }
        
        DBG_PRINTF("0x%04x     %-30s %-10d %-10d %s\n",
               stats->message_id, msg_type, stats->count, stats->parsed_count, status);
        
        // If not fully parsed, show where first seen
        if (stats->parsed_count < stats->count) {
            DBG_PRINTF("           First seen at %s:%s\n", stats->first_seen_ip, stats->first_seen_port);
        }
    }
    DBG_PRINTF("\n");
}

int is_likely_mmt_packet(const uint8_t* payload, int len) {
    if (len < 12) return 0;
    
    // Check for MMT packet header patterns
    uint8_t version = (payload[0] >> 6) & 0x3;
    uint16_t packet_id = ntohs(*(uint16_t*)(payload + 10));
    
    // MMT version should be 0, packet ID should be reasonable
    if (version == 0 && packet_id < 8192) {
        return 1;
    }
    
    return 0;
}

// Enhanced completion detection for MMT signaling
int is_mmt_signaling_complete(const uint8_t* buffer, size_t size) {
    if (size < 10) return 0;
    
    // Check for GZIP header
    const uint8_t gzip_magic[] = {0x1f, 0x8b};
    if (size > 2 && memcmp(buffer, gzip_magic, 2) == 0) {
        return is_gzip_complete(buffer, size);
    }
    
    // Check for uncompressed binary MP table
    // Look for FE 01 00 pattern (various formats)
    for (size_t i = 0; i < size - 10; i++) {
        if (buffer[i] == 0xFE && buffer[i+1] == 0x01) {
            // Found potential MP table start - assume complete if we have reasonable size
            if (size > 100) return 1;
        }
    }
    
    // Check for XML patterns
    if (memmem(buffer, size, "<?xml", 5)) {
        return is_xml_complete((char*)buffer, size);
    }
    
    // For small buffers, require more data
    if (size < 50) return 0;
    
    // Default: assume complete if we have a reasonable amount of data
    return (size > 200);
}

void display_mmt_stream_parameters(FILE* f, ServiceInfo* service, int* total_audio_streams) {
    DBG_PRINTF("\n");
    DBG_PRINTF("╔══════════════════════════════════════════════════════════════╗\n");
    DBG_PRINTF("║ display_mmt_stream_parameters CALLED                        ║\n");
    DBG_PRINTF("╚══════════════════════════════════════════════════════════════╝\n");
    DBG_PRINTF("DEBUG: display_mmt_stream_parameters called for service %s at %s:%s\n",
           service->serviceId, service->slsDestinationIpAddress, service->slsDestinationUdpPort);
    DBG_PRINTF("DEBUG: Total stored descriptors: %d\n", g_service_descriptor_count);
    
    // Print cache for debugging
    print_mmt_params_cache();
    
    // Find descriptors for this service
    ServiceDescriptors* svc_descriptors = NULL;
    for (int desc_idx = 0; desc_idx < g_service_descriptor_count; desc_idx++) {
        DBG_PRINTF("DEBUG:   Checking [%d] %s:%s against %s:%s\n", desc_idx,
               g_service_descriptors[desc_idx].destinationIp,
               g_service_descriptors[desc_idx].destinationPort,
               service->slsDestinationIpAddress, service->slsDestinationUdpPort);
        if (strcmp(g_service_descriptors[desc_idx].destinationIp, service->slsDestinationIpAddress) == 0 &&
            strcmp(g_service_descriptors[desc_idx].destinationPort, service->slsDestinationUdpPort) == 0) {
            svc_descriptors = &g_service_descriptors[desc_idx];
            DBG_PRINTF("DEBUG: MATCH! Found descriptors - VSPD=%p, ASPD=%p, CAD=%p\n",
                   (void*)svc_descriptors->vspd, (void*)svc_descriptors->aspd, (void*)svc_descriptors->cad);
            break;
        }
    }
    
    // Find MPU-derived media parameters
    MptTable* mpt = get_mpt_tables();
    int mpt_count = get_mpt_table_count();
    MmtMediaParams* video_params = NULL;
    MmtMediaParams* audio_params = NULL;
    
    DBG_PRINTF("DEBUG: Searching for MPU-derived params in %d MPT tables\n", mpt_count);
    
    for (int mpt_idx = 0; mpt_idx < mpt_count; mpt_idx++) {
        if (strcmp(mpt[mpt_idx].source_ip, service->slsDestinationIpAddress) == 0 &&
            strcmp(mpt[mpt_idx].source_port, service->slsDestinationUdpPort) == 0) {
            
            DBG_PRINTF("DEBUG: Found matching MPT with %d assets\n", mpt[mpt_idx].num_assets);
            
            for (int asset_idx = 0; asset_idx < mpt[mpt_idx].num_assets; asset_idx++) {
                MptAssetInfo* asset = &mpt[mpt_idx].assets[asset_idx];
                
                DBG_PRINTF("DEBUG MPT: Asset[%d] type='%s', packet_id=%u\n",
                       asset_idx, asset->asset_type, asset->packet_id);
                
                MmtMediaParams* cached = get_cached_mmt_params(
                    service->slsDestinationIpAddress,
                    service->slsDestinationUdpPort,
                    asset->packet_id);
                
                if (cached) {
                    if (strlen(cached->resolution) > 0 && !video_params) {
                        video_params = cached;
                        DBG_PRINTF("DEBUG: Found video params from MPU: %s, codec=%s\n", 
                               cached->resolution, asset->asset_type);
                    }
                    if (strlen(cached->audio_codec) > 0 && !audio_params) {
                        audio_params = cached;
                        DBG_PRINTF("DEBUG: Found audio params from MPU: %s, codec=%s\n", 
                               cached->audio_codec, asset->asset_type);
                    }
                }
            }
            break;
        }
    }
    
    // If we didn't find video/audio from MPT, search cache directly by IP:port
    if (!video_params || !audio_params) {
        DBG_PRINTF("DEBUG: MPT search incomplete, searching cache directly for %s:%s\n",
               service->slsDestinationIpAddress, service->slsDestinationUdpPort);
        
        for (int i = 0; i < g_mmt_params_cache_count; i++) {
            if (strcmp(g_mmt_params_cache[i].destIp, service->slsDestinationIpAddress) == 0 &&
                strcmp(g_mmt_params_cache[i].destPort, service->slsDestinationUdpPort) == 0) {
                
                MmtMediaParams* cached = &g_mmt_params_cache[i].params;
                
                if (!video_params && (strlen(cached->resolution) > 0 || strlen(cached->video_codec) > 0)) {
                    video_params = cached;
                    DBG_PRINTF("DEBUG: Found video params from direct cache search: resolution='%s', codec='%s'\n", 
                           cached->resolution, cached->video_codec);
                }
                
                if (!audio_params && strlen(cached->audio_codec) > 0) {
                    audio_params = cached;
                    DBG_PRINTF("DEBUG: Found audio params from direct cache search: %s\n", cached->audio_codec);
                }
            }
        }
    }
    
    // ========================================================================
    // DISPLAY VIDEO/AUDIO SUMMARY (inline, matching ROUTE style)
    // No divs, no dropdowns - just inline display
    // ========================================================================
    DBG_PRINTF("DEBUG: Starting summary generation\n");
    
    // Video - combine VSPD and MPU data for best results
    bool has_video = false;
    DBG_PRINTF("DEBUG: Checking for video - svc_descriptors=%p\n", (void*)svc_descriptors);
    if (svc_descriptors) DBG_PRINTF("DEBUG:   vspd=%p\n", (void*)svc_descriptors->vspd);
    
    // Dump VSPD contents for debugging
    if (svc_descriptors && svc_descriptors->vspd) {
        VspdData* vspd = svc_descriptors->vspd;
        DBG_PRINTF("DEBUG VSPD CONTENTS:\n");
        DBG_PRINTF("  horizontal_size=%u\n", vspd->horizontal_size);
        DBG_PRINTF("  vertical_size=%u\n", vspd->vertical_size);
        DBG_PRINTF("  codec_name='%s' (len=%zu)\n", vspd->codec_name, strlen(vspd->codec_name));
        DBG_PRINTF("  profile_idc=%u\n", vspd->profile_idc);
        DBG_PRINTF("  level_idc=%u\n", vspd->level_idc);
        DBG_PRINTF("  tier_flag=%u\n", vspd->tier_flag);
        DBG_PRINTF("  frame_rate='%s'\n", vspd->frame_rate);
        DBG_PRINTF("  aspect_ratio=%u\n", vspd->aspect_ratio);
        DBG_PRINTF("  progressive_flag=%u\n", vspd->progressive_flag);
        DBG_PRINTF("  interlaced_flag=%u\n", vspd->interlaced_flag);
    }
    
    // Check if we have VSPD with complete resolution info
    bool vspd_has_full_info = (svc_descriptors && svc_descriptors->vspd && 
                               svc_descriptors->vspd->horizontal_size > 0);
    
    if (vspd_has_full_info) {
        // VSPD has complete info including resolution
        DBG_PRINTF("DEBUG: Using VSPD for video summary (has resolution)\n");
        VspdData* vspd = svc_descriptors->vspd;
        
        DBG_PRINTF("DEBUG: VSPD flags - progressive_flag=%d, interlaced_flag=%d\n", 
               vspd->progressive_flag, vspd->interlaced_flag);
        
        // Format resolution nicely (e.g., "1920x1080p", "1920x1080i")
        char formatted_res[32];
        char resolution[32];
        char scan_type[16] = "";
        snprintf(resolution, sizeof(resolution), "%ux%u", vspd->horizontal_size, vspd->vertical_size);
        if (vspd->progressive_flag) {
            strcpy(scan_type, "progressive");
            DBG_PRINTF("DEBUG: Set scan_type to 'progressive'\n");
        } else if (vspd->interlaced_flag) {
            strcpy(scan_type, "interlaced");
            DBG_PRINTF("DEBUG: Set scan_type to 'interlaced'\n");
        } else {
            DBG_PRINTF("DEBUG: WARNING - Neither progressive nor interlaced flag is set!\n");
        }
        
        DBG_PRINTF("DEBUG: Before format_video_resolution - resolution='%s', scan_type='%s'\n", 
               resolution, scan_type);
        format_video_resolution(resolution, scan_type, formatted_res, sizeof(formatted_res));
        DBG_PRINTF("DEBUG: After format_video_resolution - formatted_res='%s'\n", formatted_res);
        
        fprintf(f, "<div><strong>Video:</strong> %s", formatted_res);
        
        if (vspd->aspect_ratio > 0) {
            const char* aspect = NULL;
            switch (vspd->aspect_ratio) {
                case 0x2: aspect = "4:3"; break;
                case 0x3: aspect = "16:9"; break;
                case 0x4: aspect = "2.21:1"; break;
            }
            if (aspect) fprintf(f, " (%s)", aspect);
        }
        
        if (strlen(vspd->frame_rate) > 0) {
            // Remove " fps" suffix if present since we'll add it back in parentheses
            char frame_rate_clean[32];
            strncpy(frame_rate_clean, vspd->frame_rate, sizeof(frame_rate_clean) - 1);
            frame_rate_clean[sizeof(frame_rate_clean) - 1] = '\0';
            char* fps_pos = strstr(frame_rate_clean, " fps");
            if (fps_pos) *fps_pos = '\0';
            
            fprintf(f, " (%s fps)", frame_rate_clean);
        }
        
        // Add codec string if available (enhanced format with profile/tier/level)
        if (vspd->profile_idc > 0 && vspd->level_idc > 0 && strlen(vspd->codec_name) > 0) {
            // Build enhanced codec string with profile, tier, level
            char tier_char = vspd->tier_flag ? 'H' : 'L';
            fprintf(f, "<br />\n<strong>Codec:</strong> %s.%u.X.%c%u.X", 
                    vspd->codec_name, vspd->profile_idc, tier_char, vspd->level_idc);
            DBG_PRINTF("DEBUG: Added enhanced codec string from VSPD: %s.%u.X.%c%u.X\n",
                   vspd->codec_name, vspd->profile_idc, tier_char, vspd->level_idc);
        } else if (strlen(vspd->codec_name) > 0) {
            // Fallback to basic codec name
            fprintf(f, "<br />\n<strong>Codec:</strong> %s", vspd->codec_name);
            DBG_PRINTF("DEBUG: Added basic codec string from VSPD: %s\n", vspd->codec_name);
        }
        
        fprintf(f, "</div>\n");
        has_video = true;
        DBG_PRINTF("DEBUG: Video summary written from VSPD\n");
    } else if (video_params && strlen(video_params->resolution) > 0) {
        // Use MPU-derived resolution, but check if VSPD has scan type info
        DBG_PRINTF("DEBUG: Using MPU-derived for video summary, checking VSPD for scan type\n");
        
        char scan_type_to_use[16] = "";
        
        // Check if VSPD exists and has progressive/interlaced info (even without resolution)
        if (svc_descriptors && svc_descriptors->vspd) {
            VspdData* vspd = svc_descriptors->vspd;
            DBG_PRINTF("DEBUG: VSPD exists - progressive_flag=%d, interlaced_flag=%d\n",
                   vspd->progressive_flag, vspd->interlaced_flag);
            
            if (vspd->progressive_flag) {
                strcpy(scan_type_to_use, "progressive");
                DBG_PRINTF("DEBUG: Using VSPD progressive flag\n");
            } else if (vspd->interlaced_flag) {
                strcpy(scan_type_to_use, "interlaced");
                DBG_PRINTF("DEBUG: Using VSPD interlaced flag\n");
            }
        }
        
        // Fallback to MPU scan type if VSPD didn't provide it
        if (strlen(scan_type_to_use) == 0 && strlen(video_params->scan_type) > 0) {
            strcpy(scan_type_to_use, video_params->scan_type);
            DBG_PRINTF("DEBUG: Falling back to MPU scan_type='%s'\n", scan_type_to_use);
        }
        
        DBG_PRINTF("DEBUG:   video_params=%p, resolution='%s', codec='%s', scan_type='%s'\n", 
               (void*)video_params, video_params->resolution, video_params->video_codec, scan_type_to_use);
        
        // Format resolution with scan type
        char formatted_res[32];
        format_video_resolution(video_params->resolution, scan_type_to_use, 
                               formatted_res, sizeof(formatted_res));
        
        fprintf(f, "<div><strong>Video:</strong> %s", formatted_res);
        
        if (strlen(video_params->frame_rate) > 0) {
            // Remove " fps" suffix if present
            char frame_rate_clean[32];
            strncpy(frame_rate_clean, video_params->frame_rate, sizeof(frame_rate_clean) - 1);
            frame_rate_clean[sizeof(frame_rate_clean) - 1] = '\0';
            char* fps_pos = strstr(frame_rate_clean, " fps");
            if (fps_pos) *fps_pos = '\0';
            
            fprintf(f, " (%s fps)", frame_rate_clean);
        }
        
        // Show codec if available
        if (strlen(video_params->video_codec) > 0) {
            fprintf(f, "<br />\n<strong>Codec:</strong> %s", video_params->video_codec);
        }
        
        fprintf(f, "</div>\n");
        has_video = true;
        DBG_PRINTF("DEBUG: Video summary written from combined MPU+VSPD\n");
    } else if (svc_descriptors && svc_descriptors->vspd) {
        // VSPD exists but may have incomplete info
        // Show whatever codec info we have, even if minimal
        VspdData* vspd = svc_descriptors->vspd;
        
        DBG_PRINTF("DEBUG: Attempting VSPD codec-only path\n");
        DBG_PRINTF("DEBUG:   codec_name='%s' (len=%zu)\n", vspd->codec_name, strlen(vspd->codec_name));
        DBG_PRINTF("DEBUG:   profile_idc=%u, level_idc=%u, tier_flag=%u\n", 
               vspd->profile_idc, vspd->level_idc, vspd->tier_flag);
        
        // Show video line even if codec info is minimal
        bool has_codec_info = (strlen(vspd->codec_name) > 0) || 
                              (vspd->profile_idc > 0) || 
                              (vspd->level_idc > 0);
        
        if (has_codec_info) {
            fprintf(f, "<div><strong>Video:</strong>");
            
            // Show codec info on separate line with "Codec:" label
            if (strlen(vspd->codec_name) > 0) {
                if (vspd->profile_idc > 0 && vspd->level_idc > 0) {
                    // Build enhanced codec string with profile, tier, level
                    char tier_char = vspd->tier_flag ? 'H' : 'L';
                    fprintf(f, "<br />\n<strong>Codec:</strong> %s.%u.X.%c%u.X", 
                            vspd->codec_name, vspd->profile_idc, tier_char, vspd->level_idc);
                    DBG_PRINTF("DEBUG: Added enhanced codec string from VSPD: %s.%u.X.%c%u.X\n",
                           vspd->codec_name, vspd->profile_idc, tier_char, vspd->level_idc);
                } else {
                    // Fallback to basic codec name
                    fprintf(f, "<br />\n<strong>Codec:</strong> %s", vspd->codec_name);
                    DBG_PRINTF("DEBUG: Added basic codec string from VSPD: %s\n", vspd->codec_name);
                }
            } else if (vspd->profile_idc > 0 || vspd->level_idc > 0) {
                // We have profile/level but no codec name - show what we have
                fprintf(f, "<br />\n<strong>Codec:</strong> Profile %u, Level %u", vspd->profile_idc, vspd->level_idc);
                DBG_PRINTF("DEBUG: Added profile/level info without codec name\n");
            }
            
            fprintf(f, "</div>\n");
            has_video = true;
            DBG_PRINTF("DEBUG: Video codec-only summary written from VSPD\n");
        } else {
            DBG_PRINTF("DEBUG: VSPD exists but has no codec info to display\n");
        }
    } else if (video_params && strlen(video_params->video_codec) > 0) {
        // We have cached video codec but no resolution
        DBG_PRINTF("DEBUG: Using cached video codec without resolution\n");
        fprintf(f, "<div><strong>Video:</strong>");
        fprintf(f, "<br />\n<strong>Codec:</strong> %s", video_params->video_codec);
        fprintf(f, "</div>\n");
        has_video = true;
        DBG_PRINTF("DEBUG: Video codec-only summary written from cache\n");
    } else {
        DBG_PRINTF("DEBUG: NO VIDEO DATA AVAILABLE\n");
        DBG_PRINTF("DEBUG:   svc_descriptors=%p\n", (void*)svc_descriptors);
        if (svc_descriptors) {
            DBG_PRINTF("DEBUG:   vspd=%p\n", (void*)svc_descriptors->vspd);
            if (svc_descriptors->vspd) {
                VspdData* vspd = svc_descriptors->vspd;
                DBG_PRINTF("DEBUG:   vspd->codec_name='%s' (len=%zu)\n", 
                       vspd->codec_name, strlen(vspd->codec_name));
                DBG_PRINTF("DEBUG:   vspd->horizontal_size=%u\n", vspd->horizontal_size);
                DBG_PRINTF("DEBUG:   vspd->profile_idc=%u, level_idc=%u\n", 
                       vspd->profile_idc, vspd->level_idc);
            }
        }
        DBG_PRINTF("DEBUG:   video_params=%p\n", (void*)video_params);
        if (video_params) {
            DBG_PRINTF("DEBUG:   resolution='%s' (length=%zu)\n", 
                   video_params->resolution, strlen(video_params->resolution));
            DBG_PRINTF("DEBUG:   video_codec='%s' (length=%zu)\n",
                   video_params->video_codec, strlen(video_params->video_codec));
        }
    }
    
    // Audio - prefer ASPD, fallback to MPU
    bool has_audio = false;
    DBG_PRINTF("DEBUG: Checking for audio - svc_descriptors=%p\n", (void*)svc_descriptors);
    if (svc_descriptors) DBG_PRINTF("DEBUG:   aspd=%p\n", (void*)svc_descriptors->aspd);
    
    if (svc_descriptors && svc_descriptors->aspd) {
        DBG_PRINTF("DEBUG: Using ASPD for audio summary\n");
        AspdData* aspd = svc_descriptors->aspd;
        fprintf(f, "<div><strong>Audio:</strong> ");
        
        // Prefer MPU channels over ASPD if available
        if (audio_params && strlen(audio_params->audio_channels) > 0) {
            int ch_count = 0;
            if (strcmp(audio_params->audio_channels, "5.1") == 0) {
                ch_count = 6;
            } else if (strcmp(audio_params->audio_channels, "7.1") == 0) {
                ch_count = 8;
            } else if (strcmp(audio_params->audio_channels, "7.1.4") == 0) {
                ch_count = 12;
            } else {
                ch_count = atoi(audio_params->audio_channels);
            }
            if (ch_count > 0) {
                fprintf(f, "%d ch", ch_count);
            }
        } else if (aspd->num_channels > 0) {
            fprintf(f, "%u channels", aspd->num_channels);
        }
        
        // Show bitrate if available
        if (audio_params && audio_params->audio_bitrate_kbps > 0) {
            // Only add @ separator if we showed channels
            if (aspd->num_channels > 0 || (audio_params && strlen(audio_params->audio_channels) > 0)) {
                fprintf(f, " @ ");
            }
            fprintf(f, "%d kbps", audio_params->audio_bitrate_kbps);
        }
        
        if (total_audio_streams) {
            int count = count_audio_streams_in_service(service->slsDestinationIpAddress, 
                                                       service->slsDestinationUdpPort);
            *total_audio_streams = (count > 0) ? count : 1;
            
            DBG_PRINTF("DEBUG AUDIO ICON [ASPD path]: count=%d, showing icon=%s\n", 
                   count, (count > 1) ? "YES" : "NO");
            
            if (count > 1) {
                fprintf(f, "<svg width='16' height='16' viewBox='0 0 24 24' fill='none' "
                       "style='display:inline;vertical-align:middle;margin-left:4px;'>"
                       "<circle cx='12' cy='12' r='10' fill='#4CAF50'/>"
                       "<path d='M12 6v12M6 12h12' stroke='white' stroke-width='2' "
                       "stroke-linecap='round'/>"
                       "<title>+%d additional audio stream%s</title></svg>",
                       count - 1, (count - 1 > 1) ? "s" : "");
            }
        }
        
        // Show codec on separate line
        DBG_PRINTF("DEBUG CODEC: audio_params=%p, aspd=%p\n", (void*)audio_params, (void*)aspd);
        if (audio_params) {
            DBG_PRINTF("DEBUG CODEC: audio_params->audio_codec='%s' (len=%zu)\n", 
                   audio_params->audio_codec, strlen(audio_params->audio_codec));
        }
        DBG_PRINTF("DEBUG CODEC: aspd->codec_name='%s' (len=%zu)\n", 
               aspd->codec_name, strlen(aspd->codec_name));
        
        if (audio_params && strlen(audio_params->audio_codec) > 0) {
            fprintf(f, "<br />\n<strong>Codec:</strong> %s", audio_params->audio_codec);
            DBG_PRINTF("DEBUG CODEC: Wrote codec from audio_params: %s\n", audio_params->audio_codec);
        } else if (strlen(aspd->codec_name) > 0) {
            fprintf(f, "<br />\n<strong>Codec:</strong> %s", aspd->codec_name);
            DBG_PRINTF("DEBUG CODEC: Wrote codec from aspd: %s\n", aspd->codec_name);
        } else {
            DBG_PRINTF("DEBUG CODEC: WARNING - No codec available to display!\n");
        }
        
        fprintf(f, "</div>\n");
        has_audio = true;
        DBG_PRINTF("DEBUG: Audio summary written from ASPD+MPU\n");
        
    } else if (audio_params && (strlen(audio_params->audio_codec) > 0 || 
                               strlen(audio_params->audio_channels) > 0 ||
                               audio_params->audio_bitrate_kbps > 0)) {
        // We have some audio params from MPU but no ASPD
        DBG_PRINTF("DEBUG: Using MPU-derived for audio summary\n");
        fprintf(f, "<div><strong>Audio:</strong> ");
        
        // Show channel count first if available
        if (strlen(audio_params->audio_channels) > 0) {
            int ch_count = 0;
            if (strcmp(audio_params->audio_channels, "5.1") == 0) {
                ch_count = 6;
            } else if (strcmp(audio_params->audio_channels, "7.1") == 0) {
                ch_count = 8;
            } else if (strcmp(audio_params->audio_channels, "7.1.4") == 0) {
                ch_count = 12;
            } else {
                ch_count = atoi(audio_params->audio_channels);
            }
            if (ch_count > 0) {
                fprintf(f, "%d ch", ch_count);
            }
        }
        
        // Show bitrate if available
        if (audio_params->audio_bitrate_kbps > 0) {
            if (strlen(audio_params->audio_channels) > 0) {
                fprintf(f, " @ ");
            }
            fprintf(f, "%d kbps", audio_params->audio_bitrate_kbps);
        }
        
        if (total_audio_streams) {
            int count = count_audio_streams_in_service(service->slsDestinationIpAddress, 
                                                       service->slsDestinationUdpPort);
            *total_audio_streams = (count > 0) ? count : 1;
            
            DBG_PRINTF("DEBUG AUDIO ICON [MPU path]: count=%d, showing icon=%s\n", 
                   count, (count > 1) ? "YES" : "NO");
            
            if (count > 1) {
                fprintf(f, "<svg width='16' height='16' viewBox='0 0 24 24' fill='none' "
                       "style='display:inline;vertical-align:middle;margin-left:4px;'>"
                       "<circle cx='12' cy='12' r='10' fill='#4CAF50'/>"
                       "<path d='M12 6v12M6 12h12' stroke='white' stroke-width='2' "
                       "stroke-linecap='round'/>"
                       "<title>+%d additional audio stream%s</title></svg>",
                       count - 1, (count - 1 > 1) ? "s" : "");
            }
        }
        
        // Show codec on separate line
        DBG_PRINTF("DEBUG CODEC [MPU path]: audio_params=%p\n", (void*)audio_params);
        if (audio_params) {
            DBG_PRINTF("DEBUG CODEC [MPU path]: audio_params->audio_codec='%s' (len=%zu)\n",
                   audio_params->audio_codec, strlen(audio_params->audio_codec));
        }
        
        if (strlen(audio_params->audio_codec) > 0) {
            fprintf(f, "<br />\n<strong>Codec:</strong> %s", audio_params->audio_codec);
            DBG_PRINTF("DEBUG CODEC [MPU path]: Wrote codec: %s\n", audio_params->audio_codec);
        } else {
            DBG_PRINTF("DEBUG CODEC [MPU path]: WARNING - No codec available to display!\n");
        }
        
        fprintf(f, "</div>\n");
        has_audio = true;
        DBG_PRINTF("DEBUG: Audio summary written from MPU-derived\n");
    }
    
    DBG_PRINTF("DEBUG: Summary complete - has_video=%d, has_audio=%d\n", has_video, has_audio);
}
    

void generate_mmt_descriptor_details(FILE* f, ServiceInfo* service, int instance_num) {
    // Find descriptors for this service
    ServiceDescriptors* svc_descriptors = NULL;
    for (int desc_idx = 0; desc_idx < g_service_descriptor_count; desc_idx++) {
        if (strcmp(g_service_descriptors[desc_idx].destinationIp, service->slsDestinationIpAddress) == 0 &&
            strcmp(g_service_descriptors[desc_idx].destinationPort, service->slsDestinationUdpPort) == 0) {
            svc_descriptors = &g_service_descriptors[desc_idx];
            break;
        }
    }
    
    if (!svc_descriptors || (!svc_descriptors->vspd && !svc_descriptors->aspd && !svc_descriptors->cad)) {
        return;  // No descriptors to display
    }
    
    // Look up cached video parameters to get enhanced codec string
    MmtMediaParams* video_params = NULL;
    MptTable* mpt = get_mpt_tables();
    int mpt_count = get_mpt_table_count();
    
    for (int mpt_idx = 0; mpt_idx < mpt_count; mpt_idx++) {
        if (strcmp(mpt[mpt_idx].source_ip, service->slsDestinationIpAddress) == 0 &&
            strcmp(mpt[mpt_idx].source_port, service->slsDestinationUdpPort) == 0) {
            
            for (int asset_idx = 0; asset_idx < mpt[mpt_idx].num_assets; asset_idx++) {
                MptAssetInfo* asset = &mpt[mpt_idx].assets[asset_idx];
                
                MmtMediaParams* cached = get_cached_mmt_params(
                    service->slsDestinationIpAddress,
                    service->slsDestinationUdpPort,
                    asset->packet_id);
                
                if (cached && strlen(cached->video_codec) > 0 && !video_params) {
                    video_params = cached;
                    break;
                }
            }
            if (video_params) break;
        }
    }
    
    fprintf(f, "<details><summary>MMT Stream Descriptors Instance %d</summary>\n", instance_num);
    fprintf(f, "<div class='details-content'>\n");
    
    // Video Stream Properties Descriptor (VSPD)
    if (svc_descriptors->vspd) {
        VspdData* vspd = svc_descriptors->vspd;
        fprintf(f, "<h4>Video Stream Properties Descriptor (VSPD)</h4>\n<ul>\n");
        
        // Try to use enhanced codec string from video_params first (has profile/tier/level)
        // Fall back to basic codec_name from VSPD if not available
        if (video_params && strlen(video_params->video_codec) > 0) {
            fprintf(f, "<li><strong>Codec:</strong> %s", video_params->video_codec);
            if (strncmp(video_params->video_codec, "hev", 3) == 0 || 
                strncmp(video_params->video_codec, "hvc", 3) == 0) {
                fprintf(f, " (HEVC/H.265)");
            } else if (strncmp(video_params->video_codec, "avc", 3) == 0) {
                fprintf(f, " (AVC/H.264)");
            }
            fprintf(f, "</li>\n");
        } else if (strlen(vspd->codec_name) > 0) {
            fprintf(f, "<li><strong>Codec:</strong> %s", vspd->codec_name);
            if (strcmp(vspd->codec_name, "hev1") == 0 || strcmp(vspd->codec_name, "hvc1") == 0) {
                fprintf(f, " (HEVC/H.265)");
            } else if (strcmp(vspd->codec_name, "avc1") == 0) {
                fprintf(f, " (AVC/H.264)");
            }
            fprintf(f, "</li>\n");
        }
        
        if (vspd->horizontal_size > 0 && vspd->vertical_size > 0) {
            fprintf(f, "<li><strong>Resolution:</strong> %ux%u", 
                    vspd->horizontal_size, vspd->vertical_size);
            // Add common resolution names
            if (vspd->horizontal_size == 1920 && vspd->vertical_size == 1080) {
                fprintf(f, " (1080p/Full HD)");
            } else if (vspd->horizontal_size == 3840 && vspd->vertical_size == 2160) {
                fprintf(f, " (4K UHD)");
            } else if (vspd->horizontal_size == 1280 && vspd->vertical_size == 720) {
                fprintf(f, " (720p/HD)");
            }
            fprintf(f, "</li>\n");
        } else {
            // Try to get resolution from SPS if VSPD doesn't have it
            MptTable* mpt = get_mpt_tables();
            int mpt_count = get_mpt_table_count();
            uint32_t sps_width = 0, sps_height = 0;
            
            for (int mpt_idx = 0; mpt_idx < mpt_count; mpt_idx++) {
                if (strcmp(mpt[mpt_idx].source_ip, service->slsDestinationIpAddress) == 0 &&
                    strcmp(mpt[mpt_idx].source_port, service->slsDestinationUdpPort) == 0) {
                    
                    for (int asset_idx = 0; asset_idx < mpt[mpt_idx].num_assets; asset_idx++) {
                        MptAssetInfo* asset = &mpt[mpt_idx].assets[asset_idx];
                        
                        if (strcmp(asset->asset_type, "hev1") == 0 || 
                            strcmp(asset->asset_type, "hvc1") == 0 ||
                            strcmp(asset->asset_type, "avc1") == 0 ||
                            strcmp(asset->asset_type, "avc3") == 0) {
                            
                            MmtMediaParams* cached = get_cached_mmt_params(
                                service->slsDestinationIpAddress,
                                service->slsDestinationUdpPort,
                                asset->packet_id);
                            
                            if (cached && strlen(cached->resolution) > 0) {
                                if (sscanf(cached->resolution, "%ux%u", &sps_width, &sps_height) == 2) {
                                    fprintf(f, "<li><strong>Resolution:</strong> %ux%u", 
                                            sps_width, sps_height);
                                    
                                    // Add common resolution names
                                    if (sps_width == 1920 && sps_height == 1080) {
                                        fprintf(f, " (1080p/Full HD)");
                                    } else if (sps_width == 3840 && sps_height == 2160) {
                                        fprintf(f, " (4K UHD)");
                                    } else if (sps_width == 1280 && sps_height == 720) {
                                        fprintf(f, " (720p/HD)");
                                    }
                                    
                                    fprintf(f, " <em style=\"color:#666;\">(from HEVC SPS)</em></li>\n");
                                    break;
                                }
                            }
                        }
                    }
                    if (sps_width > 0) break;
                }
            }
        }
        
        if (strlen(vspd->frame_rate) > 0) {
            fprintf(f, "<li><strong>Frame Rate:</strong> %s</li>\n", vspd->frame_rate);
        }
        
        // Display aspect ratio only if available in VSPD
        if (vspd->aspect_ratio > 0) {
            const char* aspect_str = NULL;
            switch (vspd->aspect_ratio) {
                case 0x2: aspect_str = "4:3"; break;
                case 0x3: aspect_str = "16:9"; break;
                case 0x4: aspect_str = "2.21:1"; break;
            }
            
            if (aspect_str) {
                fprintf(f, "<li><strong>Aspect Ratio:</strong> %s", aspect_str);
                if (strcmp(aspect_str, "16:9") == 0) {
                    fprintf(f, " <em>(widescreen)</em>");
                } else if (strcmp(aspect_str, "4:3") == 0) {
                    fprintf(f, " <em>(standard/legacy)</em>");
                } else if (strcmp(aspect_str, "2.21:1") == 0) {
                    fprintf(f, " <em>(cinematic)</em>");
                }
                fprintf(f, "</li>\n");
            }
        }
        
        if (strlen(vspd->profile_name) > 0 && vspd->profile_idc > 0) {
            fprintf(f, "<li><strong>HEVC Profile:</strong> %s", vspd->profile_name);
            if (strcmp(vspd->profile_name, "Main 10") == 0) {
                fprintf(f, " <em>(supports 10-bit color depth for HDR content)</em>");
            } else if (strcmp(vspd->profile_name, "Main") == 0) {
                fprintf(f, " <em>(standard 8-bit color)</em>");
            }
            fprintf(f, "</li>\n");
        }
        
        if (vspd->level_value > 0) {
            fprintf(f, "<li><strong>HEVC Level:</strong> %.1f", vspd->level_value);
            fprintf(f, " <em>(defines maximum resolution, frame rate, and bitrate capabilities)</em>");
            fprintf(f, "</li>\n");
        }
        
        if (vspd->tier_flag == 0 || vspd->tier_flag == 1) {
            fprintf(f, "<li><strong>Tier:</strong> %s", vspd->tier_flag ? "High" : "Main");
            fprintf(f, " <em>(Main tier: standard bitrates, High tier: allows higher bitrates)</em>");
            fprintf(f, "</li>\n");
        }
        
        if (vspd->progressive_flag || vspd->interlaced_flag) {
            fprintf(f, "<li><strong>Scan Type:</strong> ");
            if (vspd->progressive_flag && !vspd->interlaced_flag) {
                fprintf(f, "Progressive <em>(full frames, better quality)</em>");
            } else if (!vspd->progressive_flag && vspd->interlaced_flag) {
                fprintf(f, "Interlaced <em>(fields, legacy format)</em>");
            } else {
                fprintf(f, "Mixed (Progressive: %s, Interlaced: %s)", 
                        vspd->progressive_flag ? "yes" : "no",
                        vspd->interlaced_flag ? "yes" : "no");
            }
            fprintf(f, "</li>\n");
        }
        
        // Display chroma format if available
        if (vspd->chroma_format > 0) {
            fprintf(f, "<li><strong>Chroma Format:</strong> ");
            switch (vspd->chroma_format) {
                case 0: fprintf(f, "Monochrome"); break;
                case 1: fprintf(f, "4:2:0 <em>(standard for most video, half color resolution)</em>"); break;
                case 2: fprintf(f, "4:2:2 <em>(professional/broadcast, better color detail)</em>"); break;
                case 3: fprintf(f, "4:4:4 <em>(no color subsampling, maximum quality)</em>"); break;
                default: fprintf(f, "Unknown (%u)", vspd->chroma_format); break;
            }
            fprintf(f, "</li>\n");
        }
        
        // Display bit depth if available
        if (vspd->color_depth > 0) {
            fprintf(f, "<li><strong>Bit Depth:</strong> %u-bit", vspd->color_depth);
            if (vspd->color_depth == 8) {
                fprintf(f, " <em>(standard color depth, 16.7 million colors)</em>");
            } else if (vspd->color_depth == 10) {
                fprintf(f, " <em>(higher color depth, 1.07 billion colors, supports HDR)</em>");
            } else if (vspd->color_depth == 12) {
                fprintf(f, " <em>(professional color depth, 68.7 billion colors)</em>");
            }
            fprintf(f, "</li>\n");
        }
        
        // Add HDR/WCG information from cached params if available
        MptTable* mpt = get_mpt_tables();
        int mpt_count = get_mpt_table_count();
        const char* hdr_wcg_info = NULL;
        
        for (int mpt_idx = 0; mpt_idx < mpt_count && !hdr_wcg_info; mpt_idx++) {
            if (strcmp(mpt[mpt_idx].source_ip, service->slsDestinationIpAddress) == 0 &&
                strcmp(mpt[mpt_idx].source_port, service->slsDestinationUdpPort) == 0) {
                
                for (int asset_idx = 0; asset_idx < mpt[mpt_idx].num_assets; asset_idx++) {
                    MptAssetInfo* asset = &mpt[mpt_idx].assets[asset_idx];
                    
                    if (strcmp(asset->asset_type, "hev1") == 0 || 
                        strcmp(asset->asset_type, "hvc1") == 0 ||
                        strcmp(asset->asset_type, "avc1") == 0 ||
                        strcmp(asset->asset_type, "avc3") == 0) {
                        
                        MmtMediaParams* cached = get_cached_mmt_params(
                            service->slsDestinationIpAddress,
                            service->slsDestinationUdpPort,
                            asset->packet_id);
                        
                        if (cached && strlen(cached->hdr_wcg_info) > 0 && 
                            strcmp(cached->hdr_wcg_info, "Unknown") != 0) {
                            hdr_wcg_info = cached->hdr_wcg_info;
                            break;
                        }
                    }
                }
            }
        }
        
        if (hdr_wcg_info) {
            fprintf(f, "<li><strong>Dynamic Range:</strong> %s", hdr_wcg_info);
            if (strstr(hdr_wcg_info, "HDR10")) {
                fprintf(f, " <em>(High Dynamic Range with PQ transfer function)</em>");
            } else if (strstr(hdr_wcg_info, "HLG")) {
                fprintf(f, " <em>(Hybrid Log-Gamma HDR, backward compatible)</em>");
            } else if (strcmp(hdr_wcg_info, "SDR") == 0) {
                fprintf(f, " <em>(Standard Dynamic Range)</em>");
            }
            
            if (strstr(hdr_wcg_info, "WCG")) {
                fprintf(f, "<br/><strong>Color Gamut:</strong> Wide Color Gamut (BT.2020) <em>(billions of colors, richer than standard BT.709)</em>");
            }
            fprintf(f, "</li>\n");
        }
        
        fprintf(f, "</ul>\n");
    }
    
    // Audio Stream Properties Descriptor (ASPD)
    if (svc_descriptors->aspd) {
        AspdData* aspd = svc_descriptors->aspd;
        fprintf(f, "<h4>Audio Stream Properties Descriptor (ASPD)</h4>\n<ul>\n");
        
        if (strlen(aspd->codec_name) > 0) {
            fprintf(f, "<li><strong>Codec:</strong> %s", aspd->codec_name);
            if (strcmp(aspd->codec_name, "ac-4") == 0) {
                fprintf(f, " (Dolby AC-4 - next-generation audio codec)");
            } else if (strcmp(aspd->codec_name, "mp4a") == 0) {
                fprintf(f, " (AAC)");
            } else if (strcmp(aspd->codec_name, "ac-3") == 0) {
                fprintf(f, " (Dolby Digital)");
            } else if (strcmp(aspd->codec_name, "ec-3") == 0) {
                fprintf(f, " (Dolby Digital Plus)");
            }
            fprintf(f, "</li>\n");
        }
        
        if (strlen(aspd->language) > 0) {
            fprintf(f, "<li><strong>Language:</strong> %s</li>\n", aspd->language);
        }
        
        if (aspd->num_presentations > 0) {
            fprintf(f, "<li><strong>Presentations:</strong> %u", aspd->num_presentations);
            fprintf(f, " <em>(separate audio mixes, e.g., main, commentary, descriptive)</em>");
            fprintf(f, "</li>\n");
        }
        
        if (aspd->num_channels > 0) {
            fprintf(f, "<li><strong>Channels:</strong> %u</li>\n", aspd->num_channels);
        }
        
        if (aspd->sample_rate > 0) {
            fprintf(f, "<li><strong>Sample Rate:</strong> %u Hz</li>\n", aspd->sample_rate);
        }
        
        fprintf(f, "</ul>\n");
    }
    
    // Caption Asset Descriptor (CAD)
    if (svc_descriptors->cad && svc_descriptors->cad->head) {
        fprintf(f, "<h4>Caption Asset Descriptor (CAD)</h4>\n<ul>\n");
        
        CadEntry* entry = svc_descriptors->cad->head;
        int caption_num = 1;
        while (entry) {
            fprintf(f, "<li><strong>Caption Track %d:</strong><ul style='margin: 5px 0; padding-left: 20px;'>\n", caption_num);
            
            if (strlen(entry->language) > 0) {
                fprintf(f, "<li><strong>Language:</strong> %s</li>\n", entry->language);
            }
            
            if (strlen(entry->role_str) > 0) {
                fprintf(f, "<li><strong>Role:</strong> %s", entry->role_str);
                if (strcmp(entry->role_str, "main") == 0) {
                    fprintf(f, " <em>(primary captions)</em>");
                } else if (strcmp(entry->role_str, "alternate") == 0) {
                    fprintf(f, " <em>(alternative captions)</em>");
                } else if (strcmp(entry->role_str, "commentary") == 0) {
                    fprintf(f, " <em>(descriptive/commentary captions)</em>");
                }
                fprintf(f, "</li>\n");
            }
            
            if (strlen(entry->aspect_str) > 0) {
                fprintf(f, "<li><strong>Aspect Ratio:</strong> %s</li>\n", entry->aspect_str);
            }
            
            if (strlen(entry->profile_str) > 0) {
                fprintf(f, "<li><strong>Profile:</strong> %s", entry->profile_str);
                if (strcmp(entry->profile_str, "text") == 0) {
                    fprintf(f, " <em>(text-based captions)</em>");
                } else if (strcmp(entry->profile_str, "image") == 0) {
                    fprintf(f, " <em>(bitmap/image-based captions)</em>");
                }
                fprintf(f, "</li>\n");
            }
            
            if (entry->easy_reader) {
                fprintf(f, "<li><strong>Easy Reader:</strong> Yes <em>(simplified captions for accessibility)</em></li>\n");
            }
            
            if (entry->support_3d) {
                fprintf(f, "<li><strong>3D Support:</strong> Yes</li>\n");
            }
            
            fprintf(f, "</ul></li>\n");
            entry = entry->next;
            caption_num++;
        }
        
        fprintf(f, "</ul>\n");
    }
    
    fprintf(f, "</div></details>\n");
}

ServiceDescriptors* get_or_create_service_descriptor(const char* dest_ip, const char* dest_port) {
    // Check if already exists
    for (int i = 0; i < g_service_descriptor_count; i++) {
        if (strcmp(g_service_descriptors[i].destinationIp, dest_ip) == 0 &&
            strcmp(g_service_descriptors[i].destinationPort, dest_port) == 0) {
            return &g_service_descriptors[i];
        }
    }
    
    // Create new entry if there's space
    if (g_service_descriptor_count < MAX_SERVICE_DESCRIPTORS) {
        ServiceDescriptors* desc = &g_service_descriptors[g_service_descriptor_count];
        
        // Initialize the new descriptor
        strncpy(desc->destinationIp, dest_ip, sizeof(desc->destinationIp) - 1);
        desc->destinationIp[sizeof(desc->destinationIp) - 1] = '\0';
        
        strncpy(desc->destinationPort, dest_port, sizeof(desc->destinationPort) - 1);
        desc->destinationPort[sizeof(desc->destinationPort) - 1] = '\0';
        
        desc->vspd = NULL;
        desc->aspd = NULL;
        desc->cad = NULL;
        
        g_service_descriptor_count++;
        
        return desc;
    }
    
    return NULL;  // No space available
}



ServiceDescriptors* get_service_descriptors(void) {
    return g_service_descriptors;
}

int get_service_descriptor_count(void) {
    return g_service_descriptor_count;
}

MptTable* get_mpt_tables(void) {
    return g_mpt_tables;
}

int get_mpt_table_count(void) {
    return g_mpt_table_count;
}

void increment_mpt_table_count(void) {
    g_mpt_table_count++;
}

// Debug helper function to diagnose service info issues
void debug_dump_service_info(ServiceInfo* service) {
    if (!service) {
        DBG_PRINTF("DEBUG SERVICE: service is NULL\n");
        return;
    }
    
    DBG_PRINTF("\n=== DEBUG SERVICE INFO ===\n");
    DBG_PRINTF("Service ID: %s\n", service->serviceId);
    DBG_PRINTF("Channel: %s.%s\n", service->majorChannelNo, service->minorChannelNo);
    DBG_PRINTF("Name: %s\n", service->shortServiceName);
    DBG_PRINTF("Destination: %s:%s\n", service->slsDestinationIpAddress, service->slsDestinationUdpPort);
    DBG_PRINTF("Protocol: %s\n", service->slsProtocol);
    DBG_PRINTF("Category: %s\n", service->serviceCategory);
    
    // Check MPT tables
    MptTable* mpt = get_mpt_tables();
    int mpt_count = get_mpt_table_count();
    DBG_PRINTF("Total MPT tables: %d\n", mpt_count);
    
    for (int i = 0; i < mpt_count; i++) {
        if (strcmp(mpt[i].source_ip, service->slsDestinationIpAddress) == 0 &&
            strcmp(mpt[i].source_port, service->slsDestinationUdpPort) == 0) {
            DBG_PRINTF("Found matching MPT[%d]: %d assets\n", i, mpt[i].num_assets);
            for (int j = 0; j < mpt[i].num_assets; j++) {
                MptAssetInfo* asset = &mpt[i].assets[j];
                DBG_PRINTF("  Asset[%d]: type='%s', packet_id=%u\n", 
                       j, asset->asset_type, asset->packet_id);
                
                // Check cache for this asset
                MmtMediaParams* cached = get_cached_mmt_params(
                    service->slsDestinationIpAddress,
                    service->slsDestinationUdpPort,
                    asset->packet_id);
                
                if (cached) {
                    DBG_PRINTF("    CACHED: res='%s', v_codec='%s', a_codec='%s', a_ch='%s'\n",
                           cached->resolution, cached->video_codec, 
                           cached->audio_codec, cached->audio_channels);
                } else {
                    DBG_PRINTF("    NOT CACHED\n");
                }
            }
        }
    }
    
    // Check descriptors
    ServiceDescriptors* desc = NULL;
    for (int i = 0; i < get_service_descriptor_count(); i++) {
        ServiceDescriptors* d = &get_service_descriptors()[i];
        if (strcmp(d->destinationIp, service->slsDestinationIpAddress) == 0 &&
            strcmp(d->destinationPort, service->slsDestinationUdpPort) == 0) {
            desc = d;
            break;
        }
    }
    
    if (desc) {
        DBG_PRINTF("Found service descriptors:\n");
        DBG_PRINTF("  VSPD: %s\n", desc->vspd ? "YES" : "NO");
        DBG_PRINTF("  ASPD: %s\n", desc->aspd ? "YES" : "NO");
        DBG_PRINTF("  CAD: %s\n", desc->cad ? "YES" : "NO");
    } else {
        DBG_PRINTF("No service descriptors found\n");
    }
    
    DBG_PRINTF("=========================\n\n");
}
