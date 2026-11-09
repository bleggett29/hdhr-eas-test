#include "direct_parsers.h"
#include "debug_log.h"
#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>

/* Error codes */
#define AC4_ERROR_INVALID_DATA    -1
#define AC4_ERROR_TRUNCATED       -2
#define AC4_ERROR_UNSUPPORTED     -3

/* AC-4 Constants */
static const uint8_t channel_mode_nb_channels[] = {
    1, 2, 3, 5, 6, 7, 8, 7, 8, 7, 8, 11, 12, 13, 14, 24, 0
};

static const char *channel_layout_names[] = {
    "mono",
    "stereo",
    "3.0 (L, R, C)",
    "5.0 (L, R, C, Ls, Rs)",
    "5.1 (L, R, C, LFE, Ls, Rs)",
    "7.0 (L, R, C, Ls, Rs, Lrs, Rrs)",
    "7.1 (L, R, C, LFE, Ls, Rs, Lrs, Rrs)",
    "7.0 front",
    "7.0+LFE",
    "reserved",
    "reserved",
    "11 channels",
    "12 channels",
    "13 channels",
    "14 channels",
    "24 channels",
    "reserved"
};

static const uint16_t frame_len_base_48khz[] = {
    1920, 1920, 2048, 1536, 1536, 960, 960, 1024,
    768, 768, 512, 384, 384, 2048, 0, 0
};

/* VLC tables for channel_mode */
static const uint8_t channel_mode_bits[] = {
    1, 2, 4, 4, 4, 7, 7, 7, 7, 7, 7, 8, 8, 9, 9, 9, 9
};

static const uint16_t channel_mode_codes[] = {
    0, 2, 12, 13, 14, 120, 121, 122, 123, 124, 125, 252, 253, 508, 509, 510, 511
};

/* VLC tables for bitrate_indicator */
static const uint8_t bitrate_indicator_bits[] = {
    3, 3, 3, 3, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5
};

static const uint16_t bitrate_indicator_codes[] = {
    0, 2, 4, 6, 4, 5, 6, 7, 12, 13, 14, 15, 20, 21, 22, 23, 28, 29, 30, 31
};

/**
 * Bitstream reader structure
 */
typedef struct BitstreamReader {
    const uint8_t *data;
    size_t data_size;
    size_t byte_pos;
    int bit_pos;
    int error;
} BitstreamReader;

/* Initialize bitstream reader */
static void br_init(BitstreamReader *br, const uint8_t *data, size_t size)
{
    br->data = data;
    br->data_size = size;
    br->byte_pos = 0;
    br->bit_pos = 0;
    br->error = 0;
}

/* Read n bits from bitstream */
static uint32_t br_read_bits(BitstreamReader *br, int n)
{
    uint32_t result = 0;
    int i;
    
    if (br->error)
        return 0;
    
    for (i = 0; i < n; i++) {
        if (br->byte_pos >= br->data_size) {
            br->error = 1;
            return 0;
        }
        
        /* Get current bit */
        uint8_t byte_val = br->data[br->byte_pos];
        int bit = (byte_val >> (7 - br->bit_pos)) & 1;
        result = (result << 1) | bit;
        
        /* Advance position */
        br->bit_pos++;
        if (br->bit_pos == 8) {
            br->bit_pos = 0;
            br->byte_pos++;
        }
    }
    
    return result;
}

/* Read a single bit */
static int br_read_bit(BitstreamReader *br)
{
    return (int)br_read_bits(br, 1);
}

/* Read variable-length integer */
static uint32_t br_read_variable_bits(BitstreamReader *br, int bits)
{
    uint32_t value = 0;
    int read_more;
    
    do {
        value += br_read_bits(br, bits);
        read_more = br_read_bit(br);
        if (read_more) {
            value <<= bits;
            value += 1 << bits;
        }
    } while (read_more && !br->error);
    
    return value;
}

/* Read unary coded value */
static int br_read_unary(BitstreamReader *br, int max_val)
{
    int count = 0;
    
    while (count < max_val) {
        if (br_read_bit(br))
            break;
        count++;
    }
    
    return count;
}

/* Decode VLC (Variable Length Code) */
static int vlc_decode(BitstreamReader *br, const uint8_t *bits, 
                      const uint16_t *codes, int num_entries)
{
    int i, j;
    uint32_t accumulated = 0;
    int max_bits = 0;
    
    /* Find max bits */
    for (i = 0; i < num_entries; i++) {
        if (bits[i] > max_bits)
            max_bits = bits[i];
    }
    
    /* Try to decode progressively */
    for (j = 1; j <= max_bits; j++) {
        if (j == 1) {
            accumulated = br_read_bit(br);
        } else {
            accumulated = (accumulated << 1) | br_read_bit(br);
        }
        
        if (br->error)
            return -1;
        
        /* Check if current value matches any code */
        for (i = 0; i < num_entries; i++) {
            if (bits[i] == j && accumulated == codes[i]) {
                return i;
            }
        }
    }
    
    return -1;
}

/* Calculate sample rate from fs_index and frame_rate_index */
static int get_sample_rate(int fs_index, int frame_rate_index)
{
    int base_rate = (fs_index == 0) ? 44100 : 48000;
    
    /* Frame rate adjustments for pull-down */
    if (frame_rate_index == 0 || frame_rate_index == 3 || 
        frame_rate_index == 5 || frame_rate_index == 8) {
        /* 23.976, 29.97 fps, etc. - apply 1000/1001 pull-down */
        return (base_rate * 1000) / 1001;
    }
    
    return base_rate;
}

/* Generate codec string */
static void generate_codec_string(AC4AudioParams *params)
{
    if (params->bitrate > 0) {
        snprintf(params->codec_string, sizeof(params->codec_string),
                 "ac4.%02d.%d.%dch.%dk",
                 params->version, params->sample_rate, 
                 params->channels, params->bitrate);
    } else {
        snprintf(params->codec_string, sizeof(params->codec_string),
                 "ac4.%02d.%d.%dch",
                 params->version, params->sample_rate, params->channels);
    }
}

/* Parse AC-4 Table of Contents */
static int parse_toc(BitstreamReader *br, AC4AudioParams *params)
{
    int wait_frames, nb_wait_frames;
    
    /* Bitstream version */
    params->version = br_read_bits(br, 2);
    if (params->version == 3)
        params->version += br_read_variable_bits(br, 2);
    
    /* Sequence counter */
    params->sequence_counter = br_read_bits(br, 10);
    
    /* Wait frames */
    wait_frames = br_read_bit(br);
    if (wait_frames) {
        nb_wait_frames = br_read_bits(br, 3);
        if (nb_wait_frames > 0)
            br_read_bits(br, 2);  /* skip */
    }
    
    /* Sample rate */
    params->fs_index = br_read_bit(br);
    
    /* Frame rate */
    params->frame_rate_index = br_read_bits(br, 4);
    params->sample_rate = get_sample_rate(params->fs_index, params->frame_rate_index);
    params->frame_length = frame_len_base_48khz[params->frame_rate_index];
    
    /* I-frame flag */
    params->iframe = br_read_bit(br);
    
    /* Number of presentations */
    if (br_read_bit(br)) {
        params->nb_presentations = 1;
    } else {
        if (br_read_bit(br)) {
            params->nb_presentations = 2 + br_read_variable_bits(br, 2);
        } else {
            params->nb_presentations = 0;
        }
    }
    
    /* Payload base */
    if (br_read_bit(br)) {
        int payload_base = br_read_bits(br, 5) + 1;
        if (payload_base == 0x20)
            payload_base += br_read_variable_bits(br, 3);
    }
    
    return br->error ? AC4_ERROR_TRUNCATED : 0;
}

/* Parse substream info to extract channel configuration */
static int parse_substream_info(BitstreamReader *br, AC4AudioParams *params)
{
    int sf_multiplier;
    int bitrate_idx;
    
    /* Channel mode (VLC coded) */
    params->channel_mode = vlc_decode(br, channel_mode_bits, channel_mode_codes, 17);
    if (params->channel_mode < 0)
        return AC4_ERROR_INVALID_DATA;
    
    if (params->channel_mode == 16)
        params->channel_mode += br_read_variable_bits(br, 2);
    
    /* Get number of channels and layout */
    if (params->channel_mode < 17) {
        params->channels = channel_mode_nb_channels[params->channel_mode];
        strncpy(params->channel_layout, 
                channel_layout_names[params->channel_mode],
                sizeof(params->channel_layout) - 1);
        params->channel_layout[sizeof(params->channel_layout) - 1] = '\0';
    }
    
    /* Additional channel info for certain modes */
    if (params->channel_mode == 11 || params->channel_mode == 12 ||
        params->channel_mode == 13 || params->channel_mode == 14) {
        br_read_bit(br);  /* back_channels_present */
        br_read_bit(br);  /* centre_present */
        br_read_bits(br, 2);  /* top_channels_present */
    }
    
    /* Sample rate multiplier */
    if (params->fs_index && br_read_bit(br)) {
        sf_multiplier = 1 + br_read_bit(br);
        params->sample_rate *= sf_multiplier;
    }
    
    /* Bitrate indicator (VLC coded) - often unreliable, so we ignore it */
    /* However, we still need to read it to maintain correct bitstream position */
    if (br_read_bit(br)) {
        /* Bitrate indicator present - read but ignore */
        bitrate_idx = vlc_decode(br, bitrate_indicator_bits, 
                                 bitrate_indicator_codes, 20);
        /* Don't use this value - bitrate stays at 0 (initialized in ac4_params_init) */
        (void)bitrate_idx;  /* Suppress unused variable warning */
    }
    
    return br->error ? AC4_ERROR_TRUNCATED : 0;
}

/* Parse presentation information */
static int parse_presentation(BitstreamReader *br, AC4AudioParams *params)
{
    int single_substream;
    int presentation_config;
    int ret;
    
    /* Single substream flag */
    single_substream = br_read_bit(br);
    
    if (!single_substream) {
        presentation_config = br_read_bits(br, 3);
        if (presentation_config == 0x7)
            presentation_config += br_read_variable_bits(br, 2);
    }
    
    /* Presentation version */
    br_read_unary(br, 31);
    
    /* Try to parse substream info */
    ret = parse_substream_info(br, params);
    
    return ret;
}

/* Public API functions */

void ac4_params_init(AC4AudioParams *params)
{
    memset(params, 0, sizeof(AC4AudioParams));
    params->version = -1;
    params->sample_rate = -1;
    params->channels = -1;
    params->frame_length = -1;
    params->bitrate = 0;
    params->channel_mode = -1;
}

int ac4_parse_packet(const uint8_t *data, size_t data_size, AC4AudioParams *params)
{
    BitstreamReader br;
    int ret;
    
    if (!data || !params) {
        if (params) {
            params->error = AC4_ERROR_INVALID_DATA;
            strncpy(params->error_msg, "Invalid input parameters", 
                    sizeof(params->error_msg) - 1);
        }
        return AC4_ERROR_INVALID_DATA;
    }
    
    /* Initialize parameters */
    ac4_params_init(params);
    
    /* Initialize bitstream reader */
    br_init(&br, data, data_size);
    
    /* Parse TOC */
    ret = parse_toc(&br, params);
    if (ret < 0) {
        params->error = ret;
        strncpy(params->error_msg, "Failed to parse AC-4 TOC", 
                sizeof(params->error_msg) - 1);
        return ret;
    }
    
    /* Parse presentations if available */
    if (params->nb_presentations > 0) {
        ret = parse_presentation(&br, params);
        if (ret < 0 && params->channels < 0) {
            /* Non-fatal: we got TOC but not full presentation info */
            /* Set some defaults */
            params->channels = 2;
            strncpy(params->channel_layout, "stereo", 
                    sizeof(params->channel_layout) - 1);
        }
    } else {
        /* No presentation info, set defaults */
        params->channels = 2;
        strncpy(params->channel_layout, "stereo", 
                sizeof(params->channel_layout) - 1);
    }
    
    /* Generate codec string */
    if (params->channels > 0) {
        generate_codec_string(params);
    }
    
    params->error = 0;
    return 0;
}

const char *ac4_get_channel_layout(int channel_mode)
{
    if (channel_mode < 0 || channel_mode >= 17)
        return "unknown";
    return channel_layout_names[channel_mode];
}

int ac4_get_channel_count(int channel_mode)
{
    if (channel_mode < 0 || channel_mode >= 17)
        return 0;
    return channel_mode_nb_channels[channel_mode];
}

/* Parse AC-4 DSI (Decoder Specific Information) from dac4 atom */
int ac4_parse_dac4(const uint8_t *data, size_t data_size, AC4AudioParams *params)
{
    BitstreamReader br;
    int ac4_dsi_version;
    int bitstream_version;
    int n_presentations;
    int ret;
    
    if (!data || !params) {
        if (params) {
            params->error = AC4_ERROR_INVALID_DATA;
            strncpy(params->error_msg, "Invalid input parameters", 
                    sizeof(params->error_msg) - 1);
        }
        return AC4_ERROR_INVALID_DATA;
    }
    
    /* Initialize parameters */
    ac4_params_init(params);
    
    /* Initialize bitstream reader */
    br_init(&br, data, data_size);
    
    /* Parse AC4Dsi structure */
    ac4_dsi_version = br_read_bits(&br, 3);
    bitstream_version = br_read_bits(&br, 7);
    params->version = bitstream_version;
    
    params->fs_index = br_read_bit(&br);
    params->frame_rate_index = br_read_bits(&br, 4);
    params->sample_rate = get_sample_rate(params->fs_index, params->frame_rate_index);
    params->frame_length = frame_len_base_48khz[params->frame_rate_index];
    
    n_presentations = br_read_bits(&br, 9);
    params->nb_presentations = n_presentations;
    
    if (br.error) {
        params->error = AC4_ERROR_TRUNCATED;
        strncpy(params->error_msg, "Truncated dac4 data", 
                sizeof(params->error_msg) - 1);
        return AC4_ERROR_TRUNCATED;
    }
    
    /* Handle different DSI versions */
    if (ac4_dsi_version == 1) {
        /* DSI version 1 has a different, more complex structure */
        int b_program_id = br_read_bit(&br);
        if (b_program_id) {
            br_read_bits(&br, 16);  /* short_program_id */
            int b_uuid = br_read_bit(&br);
            if (b_uuid) {
                /* Skip UUID (128 bits) */
                for (int i = 0; i < 4; i++)
                    br_read_bits(&br, 32);
            }
        }
        
        /* ac4_bitrate_dsi */
        int bit_rate_mode = br_read_bits(&br, 2);
        int bit_rate = br_read_bits(&br, 32);
        int bit_rate_precision = br_read_bits(&br, 32);
        
        (void)bit_rate_mode;
        (void)bit_rate_precision;
        (void)bit_rate;  /* Read but ignore - often unreliable */
        
        /* Don't use DSI bit_rate - calculate from actual frames if needed */
        
        /* DSI v1 has a complex structure with substream groups.
         * We attempt a simplified parse that may work for common cases.
         * Full implementation would require parsing ac4_sgi_specifier and
         * ac4_substream_group_info structures per AC-4 spec.
         */
        if (n_presentations > 0) {
            int pres_version;
            int pres_bytes;
            int single_substream_group;
            
            /* Try to parse first presentation */
            pres_version = br_read_bits(&br, 8);
            
            if (pres_version == 0 || pres_version == 1 || pres_version == 2) {
                pres_bytes = br_read_bits(&br, 8);
                if (pres_bytes == 0xff)
                    pres_bytes += br_read_variable_bits(&br, 2);
                
                /* In DSI v1, presentations may have single_substream_group */
                single_substream_group = br_read_bit(&br);
                
                if (!single_substream_group) {
                    /* Multiple substream groups - read presentation_config */
                    int presentation_config = br_read_bits(&br, 3);
                    if (presentation_config == 0x7)
                        presentation_config += br_read_variable_bits(&br, 2);
                    
                    /* Read group_index */
                    int group_index = br_read_bits(&br, 3);
                    if (group_index == 7)
                        group_index += br_read_variable_bits(&br, 2);
                    
                    (void)group_index;
                    
                    /* For multi-group presentations, structure is complex */
                    /* Parse substream group info */
                    int substreams_present = br_read_bit(&br);
                    int hsf_ext = br_read_bit(&br);
                    int n_lf_substreams;
                    
                    if (br_read_bit(&br)) {
                        n_lf_substreams = 1;
                    } else {
                        n_lf_substreams = br_read_bits(&br, 2) + 2;
                        if (n_lf_substreams == 5)
                            n_lf_substreams += br_read_variable_bits(&br, 2);
                    }
                    
                    int channel_coded = br_read_bit(&br);
                    
                    (void)substreams_present;
                    (void)hsf_ext;
                    (void)n_lf_substreams;
                    
                    if (channel_coded) {
                        /* Channel-coded */
                        int sus_ver = br_read_bit(&br);
                        (void)sus_ver;
                        
                        ret = parse_substream_info(&br, params);
                        if (ret < 0 || params->channels < 0) {
                            params->channels = 2;
                            params->channel_mode = 1;
                            strncpy(params->channel_layout, "stereo",
                                    sizeof(params->channel_layout) - 1);
                        }
                    } else {
                        /* Object-based audio */
                        params->channels = 2;
                        params->channel_mode = 1;
                        strncpy(params->channel_layout, "stereo (object-based)",
                                sizeof(params->channel_layout) - 1);
                        ret = 0;
                    }
                } else {
                    /* Single substream group - embedded inline */
                    /* Read group_index (always present in DSI v1) */
                    int group_index = br_read_bits(&br, 3);
                    if (group_index == 7)
                        group_index += br_read_variable_bits(&br, 2);
                    
                    /* Read substream group info fields */
                    int substreams_present = br_read_bit(&br);
                    int hsf_ext = br_read_bit(&br);
                    int n_lf_substreams;
                    
                    if (br_read_bit(&br)) {
                        n_lf_substreams = 1;
                    } else {
                        n_lf_substreams = br_read_bits(&br, 2) + 2;
                        if (n_lf_substreams == 5)
                            n_lf_substreams += br_read_variable_bits(&br, 2);
                    }
                    
                    (void)group_index;
                    (void)substreams_present;
                    (void)hsf_ext;
                    (void)n_lf_substreams;
                    
                    /* KEY FIX: Don't read channel_coded or sus_ver here
                     * The channel_mode VLC starts immediately at current position
                     * This saves 2 bits and aligns us correctly */
                    
                    ret = parse_substream_info(&br, params);
                    if (ret < 0 || params->channels < 0) {
                        /* VLC decode failed - default to stereo */
                        params->channels = 2;
                        params->channel_mode = 1;
                        strncpy(params->channel_layout, "stereo",
                                sizeof(params->channel_layout) - 1);
                    }
                }
            } else {
                /* Unknown presentation version - use safer default */
                params->channels = 2;
                params->channel_mode = 1;
                strncpy(params->channel_layout, "stereo",
                        sizeof(params->channel_layout) - 1);
            }
        } else {
            /* No presentations - use safer default */
            params->channels = 2;
            params->channel_mode = 1;
            strncpy(params->channel_layout, "stereo",
                    sizeof(params->channel_layout) - 1);
        }
    } else {
        /* DSI version 0 */
        /* Parse presentations */
        if (n_presentations > 0) {
            int pres_version;
            int pres_bytes;
            
            /* Parse first presentation */
            pres_version = br_read_bits(&br, 8);
            
            if (pres_version == 0) {
                /* Presentation v0 */
                int single_substream;
                
                pres_bytes = br_read_bits(&br, 8);
                
                if (pres_bytes == 0xff)
                    pres_bytes += br_read_variable_bits(&br, 2);
                
                single_substream = br_read_bit(&br);
                
                if (single_substream) {
                    /* Parse substream info */
                    ret = parse_substream_info(&br, params);
                    if (ret < 0 && params->channels < 0) {
                        params->channels = 2;
                        strncpy(params->channel_layout, "stereo", 
                                sizeof(params->channel_layout) - 1);
                    }
                } else {
                    /* Multiple substreams */
                    int presentation_config = br_read_bits(&br, 3);
                    if (presentation_config == 0x7)
                        presentation_config += br_read_variable_bits(&br, 2);
                    
                    ret = parse_substream_info(&br, params);
                    if (ret < 0 && params->channels < 0) {
                        params->channels = 2;
                        strncpy(params->channel_layout, "stereo", 
                                sizeof(params->channel_layout) - 1);
                    }
                }
            }
        }
    }
    
    /* Set defaults if we couldn't parse */
    if (params->channels < 0) {
        params->channels = 2;
        strncpy(params->channel_layout, "stereo", 
                sizeof(params->channel_layout) - 1);
    }
    
    /* Generate codec string */
    generate_codec_string(params);
    
    params->error = 0;
    return 0;
}

/* Find dac4 atom in MP4 data - simplified search */
static int find_dac4_atom(const uint8_t *data, size_t data_size, 
                          const uint8_t **dac4_data, size_t *dac4_size)
{
    /* Simple approach: search for 'dac4' signature anywhere in the data */
    for (size_t i = 0; i + 12 < data_size; i++) {
        /* Look for box size + 'dac4' pattern */
        if (data[i+4] == 'd' && data[i+5] == 'a' && 
            data[i+6] == 'c' && data[i+7] == '4') {
            /* Found 'dac4' - extract size from preceding 4 bytes */
            uint32_t box_size = (data[i] << 24) | (data[i+1] << 16) | 
                                (data[i+2] << 8) | data[i+3];
            
            /* Sanity check the size */
            if (box_size >= 8 && box_size <= 1024 && i + box_size <= data_size) {
                *dac4_data = data + i + 8;  /* Skip size + type */
                *dac4_size = box_size - 8;
                return 0;
            }
        }
    }
    
    return -1;  /* Not found */
}

/* Parse AC-4 from MP4 container */
int ac4_parse_from_mp4(const uint8_t *data, size_t data_size, AC4AudioParams *params)
{
    const uint8_t *dac4_data = NULL;
    size_t dac4_size = 0;
    
    if (!data || !params) {
        if (params) {
            params->error = AC4_ERROR_INVALID_DATA;
            strncpy(params->error_msg, "Invalid input parameters", 
                    sizeof(params->error_msg) - 1);
        }
        return AC4_ERROR_INVALID_DATA;
    }
    
    /* Initialize params */
    ac4_params_init(params);
    
    /* Find dac4 atom */
    if (find_dac4_atom(data, data_size, &dac4_data, &dac4_size) < 0) {
        params->error = AC4_ERROR_INVALID_DATA;
        strncpy(params->error_msg, "dac4 atom not found in MP4 data", 
                sizeof(params->error_msg) - 1);
        return AC4_ERROR_INVALID_DATA;
    }
    
    /* Parse the dac4 atom */
    return ac4_parse_dac4(dac4_data, dac4_size, params);
}

void trim_hex_zeros(char* s) {
    if (s == NULL) return;
    int len = strlen(s);
    if (len == 0) return;

    char* end = s + len - 1;
    while (end > s && *end == '0') {
        end--;
    }
    *(end + 1) = '\0';
}

void extract_hevc_params(const uint8_t* data, size_t len, MmtMediaParams* params) {
    DBG_PRINTF("DEBUG extract_hevc_params: len=%zu\n", len);
    DBG_PRINTF("  First 40 bytes: ");
    for (size_t i = 0; i < 40 && i < len; i++) {
        DBG_PRINTF("%02x ", data[i]);
    }
    DBG_PRINTF("\n");

    const uint8_t* hvcc_pos = NULL;
    const char* codec_fourcc_str = NULL;

    // Refined hvcC Detection Logic
    DBG_PRINTF("DEBUG: Starting hvcC search...\n");
    for (size_t i = 0; i <= len - 8; i++) {
        if (data[i] == 'h' && data[i+1] == 'v' && (data[i+2] == 'c' || data[i+2] == 'e') && data[i+3] == '1') {
            codec_fourcc_str = (const char*)&data[i];
            size_t search_end = (i + 200 < len - 4) ? (i + 200) : (len - 4);
            for (size_t j = i + 4; j <= search_end; j++) {
                if (data[j] == 'h' && data[j+1] == 'v' && data[j+2] == 'c' && data[j+3] == 'C') {
                    hvcc_pos = data + j;
                    DBG_PRINTF("DEBUG: Found hvcC after codec fourcc at offset %zu\n", j);
                    goto found_hvcc;
                }
            }
            codec_fourcc_str = NULL; 
        }
    }
    if (!hvcc_pos) {
        for (size_t i = 0; i <= len - 4; i++) {
            if (data[i] == 'h' && data[i+1] == 'v' && data[i+2] == 'c' && data[i+3] == 'C') {
                hvcc_pos = data + i;
                DBG_PRINTF("DEBUG: Found hvcC via fallback search at offset %zu\n", i);
                for(int k = (int)i - 8; k >= 0 && k > (int)i - 200; k-=4) {
                    if (data[k] == 'h' && data[k+1] == 'v' && (data[k+2] == 'c' || data[k+2] == 'e') && data[k+3] == '1') {
                        codec_fourcc_str = (const char*)&data[k];
                        DBG_PRINTF("DEBUG: Found preceding codec fourcc '%.4s' at offset %d for fallback hvcC\n", codec_fourcc_str, k);
                        break;
                    }
                }
                goto found_hvcc;
            }
        }
    }

found_hvcc:

    if (hvcc_pos && (hvcc_pos - data) >= 4) {
        DBG_PRINTF("DEBUG: Proceeding with hvcC parse at offset %ld.\n", (long)(hvcc_pos - data));
        const uint8_t* box_start = hvcc_pos - 4;
        uint32_t box_size_be = 0;
        memcpy(&box_size_be, box_start, 4); 
        uint32_t box_size = ntohl(box_size_be); 

        DBG_PRINTF("DEBUG: hvcC box size = %u\n", box_size);

        size_t hvcc_offset = hvcc_pos - data;
        if (box_size >= 8 && box_size <= len - (hvcc_offset - 4) ) {

            const uint8_t* hvcc_data = hvcc_pos + 4;
            size_t hvcc_len = box_size - 8;
            DBG_PRINTF("DEBUG: hvcC data length = %zu\n", hvcc_len);

            if (hvcc_len >= 23) {
                
                // Codec String Logic
                uint8_t profile_byte = hvcc_data[1];
                uint8_t tier_flag = (profile_byte >> 5) & 0x1;
                uint8_t profile_idc = profile_byte & 0x1f;
                uint32_t profile_compatibility_be = 0;
                memcpy(&profile_compatibility_be, &hvcc_data[2], 4);
                uint32_t profile_compatibility = ntohl(profile_compatibility_be);
                uint64_t constraint_flags_be = 0;
                for (int cf = 0; cf < 6; cf++) {
                    constraint_flags_be = (constraint_flags_be << 8) | hvcc_data[6 + cf];
                }
                uint64_t constraint_flags = constraint_flags_be;
                uint8_t level_idc = hvcc_data[12];
                const char* fourcc_to_use = codec_fourcc_str ? codec_fourcc_str : "hev1";
                char tier_level_str[16];
                snprintf(tier_level_str, sizeof(tier_level_str), "%c%d", tier_flag ? 'H' : 'L', level_idc);
                
                char constraint_hex[13] = "";
                snprintf(constraint_hex, sizeof(constraint_hex), "%llX", (unsigned long long)constraint_flags);
                
                char profile_compat_hex[9] = "";
                snprintf(profile_compat_hex, sizeof(profile_compat_hex), "%X", profile_compatibility);
                
                trim_hex_zeros(constraint_hex);
                trim_hex_zeros(profile_compat_hex);
                
                snprintf(params->video_codec, sizeof(params->video_codec),
                         "%.4s.%d.%s.%s.%s",
                         fourcc_to_use, profile_idc, profile_compat_hex,
                         tier_level_str, constraint_hex);
                DBG_PRINTF("DEBUG: Built codec string: %s\n", params->video_codec);

#if DIRECT_PARSING
                DBG_PRINTF("DEBUG: Attempting parse with libavcodec...\n");
                
                AVCodecParameters *codec_params = avcodec_parameters_alloc();
                if (!codec_params) {
                    printf("ERROR: avcodec_parameters_alloc failed\n");
                    return;
                }

                codec_params->codec_type = AVMEDIA_TYPE_VIDEO;
                codec_params->codec_id = AV_CODEC_ID_HEVC;
                codec_params->extradata_size = hvcc_len;
                codec_params->extradata = av_mallocz(hvcc_len + AV_INPUT_BUFFER_PADDING_SIZE);
                if (!codec_params->extradata) {
                    printf("ERROR: av_mallocz for extradata failed\n");
                    avcodec_parameters_free(&codec_params);
                    return;
                }
                memcpy(codec_params->extradata, hvcc_data, hvcc_len);

                const AVCodec *codec = avcodec_find_decoder(codec_params->codec_id);
                if (!codec) {
                    printf("ERROR: avcodec_find_decoder failed for HEVC (codec_id: %d)\n", codec_params->codec_id);
                    av_freep(&codec_params->extradata);
                    avcodec_parameters_free(&codec_params);
                    return;
                }
                DBG_PRINTF("DEBUG: Found codec: %s\n", codec->name);

                AVCodecContext *codec_ctx = avcodec_alloc_context3(codec);
                if (!codec_ctx) {
                    printf("ERROR: avcodec_alloc_context3 failed\n");
                    av_freep(&codec_params->extradata);
                    avcodec_parameters_free(&codec_params);
                    return;
                }
                
                codec_ctx->flags |= AV_CODEC_FLAG_GLOBAL_HEADER;

                int ret = avcodec_parameters_to_context(codec_ctx, codec_params);
                if (ret < 0) {
                    char err_buf[AV_ERROR_MAX_STRING_SIZE] = {0};
                    av_strerror(ret, err_buf, sizeof(err_buf));
                    printf("ERROR: avcodec_parameters_to_context failed: %d (%s)\n", ret, err_buf);
                } else {
                    DBG_PRINTF("DEBUG: Trying avcodec_open2 to force parse...\n");
                    ret = avcodec_open2(codec_ctx, codec, NULL);
                    if (ret < 0) {
                        char err_buf[AV_ERROR_MAX_STRING_SIZE] = {0};
                        av_strerror(ret, err_buf, sizeof(err_buf));
                        DBG_PRINTF("WARN: avcodec_open2 failed: %d (%s) - params may be incomplete\n", ret, err_buf);
                    } else {
                        DBG_PRINTF("DEBUG: avcodec_open2 succeeded!\n");
                    }
                    
                    // Resolution
                    if (codec_ctx->width > 0 && codec_ctx->height > 0) {
                        snprintf(params->resolution, sizeof(params->resolution), 
                                "%dx%d", codec_ctx->width, codec_ctx->height);
                        DBG_PRINTF("DEBUG libavcodec: Resolution: %s\n", params->resolution);
                    }
                    
                    // Frame Rate
                    if (codec_ctx->framerate.num > 0 && codec_ctx->framerate.den > 0) {
                        double fps = (double)codec_ctx->framerate.num / codec_ctx->framerate.den;
                        snprintf(params->frame_rate, sizeof(params->frame_rate), "%.3f", fps);
                        
                        char* p_decimal = strchr(params->frame_rate, '.');
                        if (p_decimal) {
                            char* end = params->frame_rate + strlen(params->frame_rate) - 1;
                            while (end > p_decimal && *end == '0') {
                                *end-- = '\0';
                            }
                            if (end == p_decimal) {
                            *end = '\0';
                            }
                        }
                    }
                    
                    DBG_PRINTF("DEBUG libavcodec: Framerate: %s\n", params->frame_rate);
                    
                    // Scan Type
                    switch (codec_ctx->field_order) {
                        case AV_FIELD_PROGRESSIVE:
                            strcpy(params->scan_type, "progressive");
                            break;
                        case AV_FIELD_TT:
                        case AV_FIELD_BB:
                        case AV_FIELD_TB:
                        case AV_FIELD_BT:
                            strcpy(params->scan_type, "interlaced");
                            break;
                        default:
                            strcpy(params->scan_type, "unknown");
                            break;
                    }
                    DBG_PRINTF("DEBUG libavcodec: Scan Type: %s\n", params->scan_type);
                    
                    // Color Space and HDR Information
                    const char* color_primaries_str = "Unknown";
                    bool is_wcg = false;
                    switch (codec_ctx->color_primaries) {
                        case AVCOL_PRI_BT709:
                            color_primaries_str = "BT.709 (SDR)";
                            break;
                        case AVCOL_PRI_BT2020:
                            color_primaries_str = "BT.2020 (WCG)";
                            is_wcg = true;
                            break;
                        case AVCOL_PRI_SMPTE170M:
                            color_primaries_str = "SMPTE 170M (SDR)";
                            break;
                        case AVCOL_PRI_SMPTE240M:
                            color_primaries_str = "SMPTE 240M";
                            break;
                        case AVCOL_PRI_BT470BG:
                            color_primaries_str = "BT.470 BG (PAL/SECAM)";
                            break;
                        default:
                            color_primaries_str = "Unspecified";
                            break;
                    }
                    
                    const char* transfer_str = "Unknown";
                    bool is_hdr = false;
                    const char* hdr_type = NULL;
                    switch (codec_ctx->color_trc) {
                        case AVCOL_TRC_BT709:
                            transfer_str = "BT.709 (SDR)";
                            break;
                        case AVCOL_TRC_SMPTE2084:
                            transfer_str = "SMPTE 2084 (PQ)";
                            is_hdr = true;
                            hdr_type = "HDR10";
                            break;
                        case AVCOL_TRC_ARIB_STD_B67:
                            transfer_str = "ARIB STD-B67 (HLG)";
                            is_hdr = true;
                            hdr_type = "HLG";
                            break;
                        case AVCOL_TRC_SMPTE428:
                            transfer_str = "SMPTE 428 (DCI-P3)";
                            break;
                        case AVCOL_TRC_LINEAR:
                            transfer_str = "Linear";
                            break;
                        case AVCOL_TRC_GAMMA22:
                            transfer_str = "Gamma 2.2";
                            break;
                        case AVCOL_TRC_GAMMA28:
                            transfer_str = "Gamma 2.8";
                            break;
                        default:
                            transfer_str = "Unspecified";
                            break;
                    }
                    
                    if (is_hdr && hdr_type) {
                        if (is_wcg) {
                            snprintf(params->hdr_wcg_info, sizeof(params->hdr_wcg_info), 
                                    "%s/WCG", hdr_type);
                        } else {
                            snprintf(params->hdr_wcg_info, sizeof(params->hdr_wcg_info), 
                                    "%s", hdr_type);
                        }
                    } else if (is_wcg) {
                        strcpy(params->hdr_wcg_info, "SDR/WCG");
                    } else {
                        strcpy(params->hdr_wcg_info, "SDR");
                    }
                    
                    DBG_PRINTF("DEBUG libavcodec: Color Primaries: %s (WCG=%d)\n", 
                           color_primaries_str, is_wcg);
                    DBG_PRINTF("DEBUG libavcodec: Transfer Characteristics: %s (HDR=%d)\n", 
                           transfer_str, is_hdr);
                    DBG_PRINTF("DEBUG libavcodec: HDR/WCG Summary: %s\n", params->hdr_wcg_info);
                }

                avcodec_free_context(&codec_ctx);
                avcodec_parameters_free(&codec_params);
#else
                DBG_PRINTF("DEBUG: DIRECT_PARSING disabled - relying on VSPD descriptor for video parameters\n");
#endif
                
                DBG_PRINTF("DEBUG: Returning from hvcC path execution.\n");
                return;

            } else { 
                DBG_PRINTF("DEBUG: hvcC length check failed (len %zu < 23)\n", hvcc_len); 
            }
        } else { 
            DBG_PRINTF("DEBUG: hvcC box size check failed (box_size %u vs buffer len %zu)\n", box_size, len); 
        }
    } else { 
        DBG_PRINTF("DEBUG: hvcC box was not found or position invalid.\n"); 
    }
}
