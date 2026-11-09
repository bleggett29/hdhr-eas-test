#ifndef DIRECT_PARSERS_H
#define DIRECT_PARSERS_H

#include "structures.h"
#include <stdint.h>
#include <stddef.h>

/**
 * AC-4 audio parameters structure
 */
typedef struct AC4AudioParams {
    /* Basic parameters */
    int version;              /* AC-4 bitstream version (0-3+) */
    int sample_rate;          /* Sample rate in Hz */
    int channels;             /* Number of channels (1-24) */
    int frame_length;         /* Frame length in samples */
    
    /* Optional parameters */
    int bitrate;              /* Bitrate in kbps (0 if not present) */
    int channel_mode;         /* Channel mode index (0-16+) */
    
    /* Additional info */
    int iframe;               /* 1 if I-frame, 0 otherwise */
    int sequence_counter;     /* Sequence counter value */
    int fs_index;             /* Sample rate family (0=44.1k, 1=48k) */
    int frame_rate_index;     /* Frame rate configuration index */
    int nb_presentations;     /* Number of presentations */
    
    /* Channel layout description (null-terminated string) */
    char channel_layout[64];
    
    /* Codec string (null-terminated, e.g., "ac4.00.48000.6ch.256k") */
    char codec_string[64];
    
    /* Error flag and message */
    int error;                /* 0 on success, negative on error */
    char error_msg[128];      /* Error description if error != 0 */
} AC4AudioParams;

/**
 * Parse AC-4 packet and extract audio parameters
 * 
 * @param data       Pointer to AC-4 packet data
 * @param data_size  Size of data in bytes
 * @param params     Pointer to structure to fill with parsed parameters
 * @return           0 on success, negative error code on failure
 */
int ac4_parse_packet(const uint8_t *data, size_t data_size, AC4AudioParams *params);

/**
 * Initialize AC4AudioParams structure with default values
 * 
 * @param params  Pointer to structure to initialize
 */
void ac4_params_init(AC4AudioParams *params);

/**
 * Get channel layout description for a channel mode
 * 
 * @param channel_mode  Channel mode index
 * @return              String description of channel layout
 */
const char *ac4_get_channel_layout(int channel_mode);

/**
 * Get number of channels for a channel mode
 * 
 * @param channel_mode  Channel mode index
 * @return              Number of channels
 */
int ac4_get_channel_count(int channel_mode);

/**
 * Parse AC-4 from MP4 dac4 atom (Decoder Configuration Record)
 * 
 * This is used when AC-4 is containerized in MP4/ISOBMFF format.
 * The dac4 atom contains AC4Dsi (Decoder Specific Information).
 * 
 * @param data       Pointer to dac4 atom payload (after box header)
 * @param data_size  Size of dac4 atom payload
 * @param params     Pointer to structure to fill with parsed parameters
 * @return           0 on success, negative error code on failure
 */
int ac4_parse_dac4(const uint8_t *data, size_t data_size, AC4AudioParams *params);

/**
 * Find and parse AC-4 configuration from MP4 data
 * 
 * Searches for dac4 atom in MP4 structure and parses it.
 * Useful when you have raw MP4 data and need to extract AC-4 config.
 * 
 * @param data       Pointer to MP4 data
 * @param data_size  Size of MP4 data
 * @param params     Pointer to structure to fill with parsed parameters
 * @return           0 on success, negative error code on failure
 */
int ac4_parse_from_mp4(const uint8_t *data, size_t data_size, AC4AudioParams *params);

void extract_hevc_params(const uint8_t* data, size_t len, MmtMediaParams* params);
void trim_hex_zeros(char* s);

#endif /* DIRECT_PARSERS_H */
 
