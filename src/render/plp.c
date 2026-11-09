#include <stdio.h>
#include "debug_log.h"
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include "plp.h"
#include "l1_detail_parser.h"

static L1SignalingData* g_l1_signaling_data = NULL;
static EnhancedL1SignalingData* g_enhanced_l1_signaling_data = NULL;

L1SignalingData* get_l1_signaling_data(void) {
    return g_l1_signaling_data;
}

void set_l1_signaling_data(L1SignalingData* data) {
    g_l1_signaling_data = data;
}

EnhancedL1SignalingData* get_enhanced_l1_signaling_data(void) {
    return g_enhanced_l1_signaling_data;
}

void set_enhanced_l1_signaling_data(EnhancedL1SignalingData* data) {
    g_enhanced_l1_signaling_data = data;
}

/**
 * @brief Generate txt filename from input filename by replacing extension
 */
char* get_txt_filename_from_input(const char* input_filename) {
    if (!input_filename) return NULL;
    
    char* txt_filename = malloc(strlen(input_filename) + 5); // +5 for potential ".txt\0"
    if (!txt_filename) return NULL;
    
    strcpy(txt_filename, input_filename);
    
    // Find the last dot
    char* last_dot = strrchr(txt_filename, '.');
    if (last_dot) {
        strcpy(last_dot, ".txt");
    } else {
        strcat(txt_filename, ".txt");
    }
    
    return txt_filename;
}

/**
 * @brief Parse a PLP line like "0: sfi=0 mod=qam64 cod=11/15 layer=core ti=hti lls=1 lock=1"
 */
PlpInfo* parse_plp_line(const char* line) {
    if (!line) return NULL;
    
    PlpInfo* plp = calloc(1, sizeof(PlpInfo));
    if (!plp) return NULL;
    
    // Parse PLP ID (number before colon)
    if (sscanf(line, "%d:", &plp->plp_id) != 1) {
        free(plp);
        return NULL;
    }
    
    // Parse sfi
    const char* sfi_pos = strstr(line, "sfi=");
    if (sfi_pos && sscanf(sfi_pos, "sfi=%d", &plp->sfi) != 1) {
        plp->sfi = 0;
    }
    
    // Parse modulation
    const char* mod_pos = strstr(line, "mod=");
    if (mod_pos) {
        if (sscanf(mod_pos, "mod=%15s", plp->modulation) == 1) {
            // Remove any trailing non-alphanumeric characters
            char* end = plp->modulation;
            while (*end && (isalnum(*end))) end++;
            *end = '\0';
        }
    }
    
    // Parse code rate
    const char* cod_pos = strstr(line, "cod=");
    if (cod_pos) {
        if (sscanf(cod_pos, "cod=%15s", plp->code_rate) == 1) {
            // Remove any trailing non-alphanumeric/slash characters
            char* end = plp->code_rate;
            while (*end && (isalnum(*end) || *end == '/')) end++;
            *end = '\0';
        }
    }
    
    // Parse layer
    const char* layer_pos = strstr(line, "layer=");
    if (layer_pos) {
        if (sscanf(layer_pos, "layer=%15s", plp->layer) == 1) {
            char* end = plp->layer;
            while (*end && isalnum(*end)) end++;
            *end = '\0';
        }
    }
    
    // Parse TI mode
    const char* ti_pos = strstr(line, "ti=");
    if (ti_pos) {
        if (sscanf(ti_pos, "ti=%7s", plp->ti_mode) == 1) {
            char* end = plp->ti_mode;
            while (*end && isalnum(*end)) end++;
            *end = '\0';
        }
    }
    
    // Parse LLS flag
    const char* lls_pos = strstr(line, "lls=");
    if (lls_pos) {
        sscanf(lls_pos, "lls=%d", &plp->lls_flag);
    }
    
    // Parse lock flag
    const char* lock_pos = strstr(line, "lock=");
    if (lock_pos) {
        sscanf(lock_pos, "lock=%d", &plp->lock_flag);
    }
    
    return plp;
}

/**
 * @brief Parse L1 field lines and SNR values with context tracking
 */
void parse_l1_field_line(const char* line, L1SignalingData* data) {
    if (!line || !data) return;
    
    char field_name[64];
    char field_value[256];
    static int current_plp_id = -1; // Track which PLP we're currently parsing details for
    
    // Check for PLP section headers like "    PLP #0:" or "      L1D_plp_id: 0"
    if (strstr(line, "PLP #")) {
        sscanf(line, "%*[^#]#%d", &current_plp_id);
        return;
    }
    
    if (strstr(line, "L1D_plp_id:")) {
        sscanf(line, "%*[^:]: %d", &current_plp_id);
        return;
    }
    
    // Handle SNR lines like "  -> Required SNR: AWGN 14.52 dB, Rayleigh 17.87 dB"
    if (strstr(line, "-> Required SNR:")) {
        // Find the most recent PLP to attach SNR to
        PlpInfo* current_plp = data->plp_head;
        while (current_plp && current_plp->next) {
            current_plp = current_plp->next;
        }
        
        if (current_plp) {
            const char* awgn_pos = strstr(line, "AWGN");
            if (awgn_pos) {
                sscanf(awgn_pos, "AWGN %lf", &current_plp->required_snr_awgn);
            }
            
            const char* rayleigh_pos = strstr(line, "Rayleigh");
            if (rayleigh_pos) {
                sscanf(rayleigh_pos, "Rayleigh %lf", &current_plp->required_snr_rayleigh);
            }
        }
        return;
    }
    
    // Handle bitrate lines like "      -> PLP Bitrate: 16.456 Mbps"
    if (strstr(line, "-> PLP Bitrate:")) {
        double bitrate = 0.0;
        if (sscanf(line, "%*[^0-9]%lf", &bitrate) == 1 && bitrate > 0) {
            // Find the PLP with the current ID we're parsing
            PlpInfo* target_plp = data->plp_head;
            if (current_plp_id >= 0) {
                while (target_plp) {
                    if (target_plp->plp_id == current_plp_id) {
                        target_plp->bitrate_mbps = bitrate;
                        break;
                    }
                    target_plp = target_plp->next;
                }
            } else {
                // Fallback: use the most recently added PLP
                while (target_plp && target_plp->next) {
                    target_plp = target_plp->next;
                }
                if (target_plp) {
                    target_plp->bitrate_mbps = bitrate;
                }
            }
        }
        return;
    }
    
    // Handle BSID lines
    if (sscanf(line, "L1D BSID: %15s", field_value) == 1) {
        if (strcmp(field_value, "Not") != 0) { // Skip "Not set"
            strncpy(data->l1_bsid, field_value, sizeof(data->l1_bsid) - 1);
        }
        return;
    }
    
    if (sscanf(line, "bsid=%15s", field_value) == 1) {
        //strncpy(data->l1_bsid, field_value, sizeof(data->l1_bsid) - 1);
        long bsid_val = strtol(field_value, NULL, 0);
        snprintf(data->l1_bsid, sizeof(data->l1_bsid), "%ld", bsid_val);
        return;
    }
    
    // Handle base64 lines (long lines without colons, likely base64)
    if (strlen(line) > 50 && !strchr(line, ':') && 
        strspn(line, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/= \t") == strlen(line)) {
        // Find start of non-whitespace
        const char* start = line;
        while (*start == ' ' || *start == '\t') start++;
        
        // Find end of non-whitespace
        const char* end = line + strlen(line) - 1;
        while (end > start && (*end == ' ' || *end == '\t')) end--;
        
        // Copy trimmed string
        size_t trimmed_len = end - start + 1;
        if (trimmed_len < sizeof(data->l1_base64)) {
            strncpy(data->l1_base64, start, trimmed_len);
            data->l1_base64[trimmed_len] = '\0';
        }
        return;
    }
    
    // Handle L1Basic and L1Detail field lines (rest of the function remains the same)
    if (sscanf(line, "%63[^:]: %255[^\r\n]", field_name, field_value) == 2) {
        // Map field names to struct members
        if (strcmp(field_name, "L1B_version") == 0) {
            strncpy(data->l1b_version, field_value, sizeof(data->l1b_version) - 1);
        } else if (strcmp(field_name, "L1B_mimo_scattered_pilot_encoding") == 0) {
            strncpy(data->l1b_mimo_pilot_encoding, field_value, sizeof(data->l1b_mimo_pilot_encoding) - 1);
        } else if (strcmp(field_name, "L1B_lls_flag") == 0) {
            strncpy(data->l1b_lls_flag, field_value, sizeof(data->l1b_lls_flag) - 1);
        } else if (strcmp(field_name, "L1B_time_info_flag") == 0) {
            strncpy(data->l1b_time_info_flag, field_value, sizeof(data->l1b_time_info_flag) - 1);
        } else if (strcmp(field_name, "L1B_return_channel_flag") == 0) {
            strncpy(data->l1b_return_channel_flag, field_value, sizeof(data->l1b_return_channel_flag) - 1);
        } else if (strcmp(field_name, "L1B_papr_reduction") == 0) {
            strncpy(data->l1b_papr_reduction, field_value, sizeof(data->l1b_papr_reduction) - 1);
        } else if (strcmp(field_name, "L1B_frame_length_mode") == 0) {
            strncpy(data->l1b_frame_length_mode, field_value, sizeof(data->l1b_frame_length_mode) - 1);
        } else if (strcmp(field_name, "L1B_time_offset") == 0) {
            strncpy(data->l1b_time_offset, field_value, sizeof(data->l1b_time_offset) - 1);
        } else if (strcmp(field_name, "L1B_additional_samples") == 0) {
            strncpy(data->l1b_additional_samples, field_value, sizeof(data->l1b_additional_samples) - 1);
        } else if (strcmp(field_name, "L1B_num_subframes") == 0) {
            strncpy(data->l1b_num_subframes, field_value, sizeof(data->l1b_num_subframes) - 1);
        } else if (strcmp(field_name, "L1B_preamble_num_symbols") == 0) {
            strncpy(data->l1b_preamble_num_symbols, field_value, sizeof(data->l1b_preamble_num_symbols) - 1);
        } else if (strcmp(field_name, "L1B_preamble_reduced_carriers") == 0) {
            strncpy(data->l1b_preamble_reduced_carriers, field_value, sizeof(data->l1b_preamble_reduced_carriers) - 1);
        } else if (strcmp(field_name, "L1B_L1_Detail_content_tag") == 0) {
            strncpy(data->l1b_l1_detail_content_tag, field_value, sizeof(data->l1b_l1_detail_content_tag) - 1);
        } else if (strcmp(field_name, "L1B_L1_Detail_size_bytes") == 0) {
            strncpy(data->l1b_l1_detail_size_bytes, field_value, sizeof(data->l1b_l1_detail_size_bytes) - 1);
        } else if (strcmp(field_name, "L1B_L1_Detail_fec_type") == 0) {
            strncpy(data->l1b_l1_detail_fec_type, field_value, sizeof(data->l1b_l1_detail_fec_type) - 1);
        } else if (strcmp(field_name, "L1B_L1_additional_parity_mode") == 0) {
            strncpy(data->l1b_l1_additional_parity_mode, field_value, sizeof(data->l1b_l1_additional_parity_mode) - 1);
        } else if (strcmp(field_name, "L1B_L1_Detail_total_cells") == 0) {
            strncpy(data->l1b_l1_detail_total_cells, field_value, sizeof(data->l1b_l1_detail_total_cells) - 1);
        } else if (strcmp(field_name, "L1B_first_sub_mimo") == 0) {
            strncpy(data->l1b_first_sub_mimo, field_value, sizeof(data->l1b_first_sub_mimo) - 1);
        } else if (strcmp(field_name, "L1B_first_sub_miso") == 0) {
            strncpy(data->l1b_first_sub_miso, field_value, sizeof(data->l1b_first_sub_miso) - 1);
        } else if (strcmp(field_name, "L1B_first_sub_fft_size") == 0) {
            strncpy(data->l1b_first_sub_fft_size, field_value, sizeof(data->l1b_first_sub_fft_size) - 1);
        } else if (strcmp(field_name, "L1B_first_sub_reduced_carriers") == 0) {
            strncpy(data->l1b_first_sub_reduced_carriers, field_value, sizeof(data->l1b_first_sub_reduced_carriers) - 1);
        } else if (strcmp(field_name, "L1B_first_sub_guard_interval") == 0) {
            strncpy(data->l1b_first_sub_guard_interval, field_value, sizeof(data->l1b_first_sub_guard_interval) - 1);
        } else if (strcmp(field_name, "L1B_first_sub_num_ofdm_symbols") == 0) {
            strncpy(data->l1b_first_sub_num_ofdm_symbols, field_value, sizeof(data->l1b_first_sub_num_ofdm_symbols) - 1);
        } else if (strcmp(field_name, "L1B_first_sub_scattered_pilot_pattern") == 0) {
            strncpy(data->l1b_first_sub_scattered_pilot_pattern, field_value, sizeof(data->l1b_first_sub_scattered_pilot_pattern) - 1);
        } else if (strcmp(field_name, "L1B_first_sub_scattered_pilot_boost") == 0) {
            strncpy(data->l1b_first_sub_scattered_pilot_boost, field_value, sizeof(data->l1b_first_sub_scattered_pilot_boost) - 1);
        } else if (strcmp(field_name, "L1B_first_sub_sbs_first") == 0) {
            strncpy(data->l1b_first_sub_sbs_first, field_value, sizeof(data->l1b_first_sub_sbs_first) - 1);
        } else if (strcmp(field_name, "L1B_first_sub_sbs_last") == 0) {
            strncpy(data->l1b_first_sub_sbs_last, field_value, sizeof(data->l1b_first_sub_sbs_last) - 1);
        } else if (strcmp(field_name, "L1B_crc") == 0) {
            strncpy(data->l1b_crc, field_value, sizeof(data->l1b_crc) - 1);
        }
        // L1Detail fields
        else if (strcmp(field_name, "L1D_version") == 0) {
            strncpy(data->l1d_version, field_value, sizeof(data->l1d_version) - 1);
        } else if (strcmp(field_name, "L1D_num_rf") == 0) {
            strncpy(data->l1d_num_rf, field_value, sizeof(data->l1d_num_rf) - 1);
        } else if (strcmp(field_name, "L1D_time_sec") == 0) {
            strncpy(data->l1d_time_sec, field_value, sizeof(data->l1d_time_sec) - 1);
        } else if (strcmp(field_name, "L1D_time_msec") == 0) {
            strncpy(data->l1d_time_msec, field_value, sizeof(data->l1d_time_msec) - 1);
        } else if (strcmp(field_name, "L1D_time_usec") == 0) {
            strncpy(data->l1d_time_usec, field_value, sizeof(data->l1d_time_usec) - 1);
        } else if (strcmp(field_name, "L1D_time_nsec") == 0) {
            strncpy(data->l1d_time_nsec, field_value, sizeof(data->l1d_time_nsec) - 1);
        } else if (strcmp(field_name, "L1D_crc") == 0) {
            strncpy(data->l1d_crc, field_value, sizeof(data->l1d_crc) - 1);
        }
    }
}

/**
 * @brief Parse L1 signaling file
 */
L1SignalingData* parse_l1_signaling_file(const char* txt_filename) {
    FILE* f = fopen(txt_filename, "r");
    if (!f) {
        return NULL; // File doesn't exist, which is fine
    }
    
    DBG_PRINTF("Found L1 signaling file: %s\n", txt_filename);
    
    L1SignalingData* data = calloc(1, sizeof(L1SignalingData));
    if (!data) {
        fclose(f);
        return NULL;
    }
    
    char line[1024];
    PlpInfo* plp_tail = NULL;
    
    while (fgets(line, sizeof(line), f)) {
        // Remove trailing newline
        line[strcspn(line, "\r\n")] = '\0';
        
        // Skip empty lines and separator lines
        if (strlen(line) == 0 || strstr(line, "__HLINE__")) {
            continue;
        }
        
        // Check if this is a PLP line (starts with digit followed by colon)
        if (isdigit(line[0]) && strchr(line, ':') && strchr(line, '=')) {
            PlpInfo* plp = parse_plp_line(line);
            if (plp) {
                if (!data->plp_head) {
                    data->plp_head = plp;
                    plp_tail = plp;
                } else {
                    plp_tail->next = plp;
                    plp_tail = plp;
                }
            }
        } else {
            // Handle other types of lines
            parse_l1_field_line(line, data);
        }
    }
    
    fclose(f);
    
    // Count PLPs found
    int plp_count = 0;
    PlpInfo* count_plp = data->plp_head;
    while (count_plp) {
        plp_count++;
        count_plp = count_plp->next;
    }
    
    DBG_PRINTF("Parsed L1 signaling data: %d PLPs", plp_count);
    if (strlen(data->l1_bsid) > 0) {
        DBG_PRINTF(", L1 BSID: %s", data->l1_bsid);
    }
    if (strlen(data->l1_base64) > 0) {
        DBG_PRINTF(", L1Basic/Detail base64 (%zu chars)", strlen(data->l1_base64));
    }
    DBG_PRINTF("\n");
    
    return data;
}

/**
 * @brief Free L1 signaling data
 */
void free_l1_signaling_data(L1SignalingData* data) {
    if (!data) return;
    
    PlpInfo* current = data->plp_head;
    while (current) {
        PlpInfo* next = current->next;
        free(current);
        current = next;
    }
    
    free(data);
}

// Function to parse simple PLP info line (like "0: sfi=0 mod=qam64 cod=11/15 layer=core ti=hti lls=1 lock=1")
EnhancedPlpInfo* parse_simple_plp_line(const char* line) {
    if (!line) return NULL;
    
    EnhancedPlpInfo* plp = calloc(1, sizeof(EnhancedPlpInfo));
    if (!plp) return NULL;
    
    // Parse PLP ID (number before colon)
    if (sscanf(line, "%d:", &plp->plp_id) != 1) {
        free(plp);
        return NULL;
    }
    
    // Parse sfi
    const char* sfi_pos = strstr(line, "sfi=");
    if (sfi_pos && sscanf(sfi_pos, "sfi=%d", &plp->sfi) != 1) {
        plp->sfi = 0;
    }
    
    // Parse modulation
    const char* mod_pos = strstr(line, "mod=");
    if (mod_pos) {
        if (sscanf(mod_pos, "mod=%15s", plp->modulation) == 1) {
            char* end = plp->modulation;
            while (*end && (isalnum(*end))) end++;
            *end = '\0';
        }
    }
    
    // Parse code rate
    const char* cod_pos = strstr(line, "cod=");
    if (cod_pos) {
        if (sscanf(cod_pos, "cod=%15s", plp->code_rate) == 1) {
            char* end = plp->code_rate;
            while (*end && (isalnum(*end) || *end == '/')) end++;
            *end = '\0';
        }
    }
    
    // Parse layer
    const char* layer_pos = strstr(line, "layer=");
    if (layer_pos) {
        if (sscanf(layer_pos, "layer=%15s", plp->layer) == 1) {
            char* end = plp->layer;
            while (*end && isalnum(*end)) end++;
            *end = '\0';
        }
    }
    
    // Parse TI mode
    const char* ti_pos = strstr(line, "ti=");
    if (ti_pos) {
        if (sscanf(ti_pos, "ti=%7s", plp->ti_mode) == 1) {
            char* end = plp->ti_mode;
            while (*end && isalnum(*end)) end++;
            *end = '\0';
        }
    }
    
    // Parse LLS flag
    const char* lls_pos = strstr(line, "lls=");
    if (lls_pos) {
        sscanf(lls_pos, "lls=%d", &plp->lls_flag);
    }
    
    // Parse lock flag - if present, use it; if not present, default to 0 (not locked)
    // calloc already initialized lock_flag to 0, so we only need to update if found
    const char* lock_pos = strstr(line, "lock=");
    if (lock_pos) {
        sscanf(lock_pos, "lock=%d", &plp->lock_flag);
    }
    // If lock_pos is NULL, lock_flag stays at 0 (not locked)
    
    return plp;
}

// Function to compute SNR values if not present
void compute_snr_values(EnhancedPlpInfo* plp) {
    if (!plp || strlen(plp->modulation) == 0 || strlen(plp->code_rate) == 0) return;
    
    char normalized_mod[16];
    normalize_mod_str_l1(plp->modulation, normalized_mod, sizeof(normalized_mod));
    
    struct snr_pair_result snr_result = get_snr_pair_for_modcod_l1(normalized_mod, plp->code_rate, -1);
    
    if (snr_result.found) {
        if (snr_result.ldpc_length_known) {
            plp->required_snr_awgn = snr_result.awgn_min;
            plp->required_snr_rayleigh = snr_result.rayleigh_min;
            plp->snr_range_available = 0;
        } else {
            // Store range
            plp->required_snr_awgn_min = snr_result.awgn_min;
            plp->required_snr_awgn_max = snr_result.awgn_max;
            plp->required_snr_rayleigh_min = snr_result.rayleigh_min;
            plp->required_snr_rayleigh_max = snr_result.rayleigh_max;
            plp->snr_range_available = 1;
        }
    }
}

// Function to parse PLP info with SNR values already included
EnhancedPlpInfo* parse_plp_with_snr(const char* line, const char* next_line) {
    EnhancedPlpInfo* plp = parse_simple_plp_line(line);
    if (!plp || !next_line) return plp;
    
    // Check if next line contains SNR info
    if (strstr(next_line, "Required SNR:") && strstr(next_line, "AWGN") && strstr(next_line, "Rayleigh")) {
        float awgn, rayleigh;
        
        // Parse AWGN value
        const char* awgn_pos = strstr(next_line, "AWGN");
        if (awgn_pos && sscanf(awgn_pos, "AWGN %f", &awgn) == 1) {
            plp->required_snr_awgn = awgn;
        }
        
        // Parse Rayleigh value
        const char* rayleigh_pos = strstr(next_line, "Rayleigh");
        if (rayleigh_pos && sscanf(rayleigh_pos, "Rayleigh %f", &rayleigh) == 1) {
            plp->required_snr_rayleigh = rayleigh;
        }
    }
    
    return plp;
}

// Function to parse full L1 detail from base64
EnhancedL1SignalingData* parse_l1_detail_from_base64(const char* base64_data) {
    if (!base64_data || strlen(base64_data) == 0) return NULL;
    
    // Decode base64
    size_t decoded_len = b64_decoded_size_l1(base64_data);
    unsigned char *decoded_data = malloc(decoded_len);
    if (!decoded_data) return NULL;
    
    if (!b64_decode_l1(base64_data, decoded_data, decoded_len)) {
        free(decoded_data);
        return NULL;
    }
    
    // Create L1 detail info structure
    struct l1_detail_info* detail_info = create_l1_detail_info(MAX_DISPLAY_LINES);
    if (!detail_info) {
        free(decoded_data);
        return NULL;
    }
    
    // Parse L1 data
    parse_l1_data_l1(decoded_data, decoded_len, detail_info->display_lines, 
                     &detail_info->line_count, detail_info->max_lines, &detail_info->context);
    
    // Create enhanced L1 signaling data
    EnhancedL1SignalingData* enhanced_data = calloc(1, sizeof(EnhancedL1SignalingData));
    if (!enhanced_data) {
        free_l1_detail_info(detail_info);
        free(decoded_data);
        return NULL;
    }
    
    // Copy base64 data
    strncpy(enhanced_data->l1_base64, base64_data, sizeof(enhanced_data->l1_base64) - 1);
    
    // Parse PLP information from display lines
    EnhancedPlpInfo* plp_tail = NULL;
    int current_plp_id = -1; // Track the current PLP ID being processed
    
    // First pass: look for BSID in display lines
    for (int i = 0; i < detail_info->line_count; i++) {
        char* line = detail_info->display_lines[i];
        
        // Look for BSID - try multiple formats that might appear in parsed output
        if (strstr(line, "L1D_bsid:")) {
            char* bsid_start = strchr(line, ':');
            if (bsid_start) {
                bsid_start++; // Skip the colon
                while (*bsid_start == ' ') bsid_start++; // Skip spaces
                long bsid_val = strtol(bsid_start, NULL, 0);
                snprintf(enhanced_data->l1_bsid, sizeof(enhanced_data->l1_bsid), "%ld", bsid_val);
            }
            break; // Found BSID, no need to continue this search
        }
    }
    
    for (int i = 0; i < detail_info->line_count; i++) {
        char* line = detail_info->display_lines[i];
        
        // NEW: Track current subframe
        static int current_subframe = 0;
        if (strstr(line, "Subframe #") && strchr(line, ':')) {
            sscanf(line, "Subframe #%d:", &current_subframe);
        }
        
        // Look for PLP ID lines first to establish context
        if (strstr(line, "L1D_plp_id:")) {
            continue;
        }
        
        // Look for PLP lines (format: "PLP #0:")
        if (strstr(line, "PLP #") && strchr(line, ':')) {
            EnhancedPlpInfo* plp = calloc(1, sizeof(EnhancedPlpInfo));
            if (!plp) {
                // FIX: Clean up on allocation failure
                free_enhanced_l1_signaling_data(enhanced_data);
                free_l1_detail_info(detail_info);
                free(decoded_data);
                return NULL;
            }
            
            // Set SFI to current subframe
            plp->sfi = current_subframe;
            
            // Extract PLP number from header (this is just section numbering, not the actual ID)
            int section_number;
            if (sscanf(line, "%*[^#]#%d:", &section_number) != 1) {
                free(plp);
                continue;
            }
            
            // The actual PLP ID will be found in the following L1D_plp_id line
            // For now, use current_plp_id if we have it, otherwise default to section number
            plp->plp_id = (current_plp_id >= 0) ? current_plp_id : section_number;
            
            // Required SNR as computed by the L1 parser (per-PLP LDPC length,
            // LDM-adjusted). When present it replaces the plain modcod lookup.
            int have_l1_snr = 0;

            // Parse subsequent lines for PLP details AND bitrate
            for (int j = i + 1; j < detail_info->line_count && j < i + 40; j++) {
                char* detail_line = detail_info->display_lines[j];
                
                // Stop if we hit another PLP or section
                if (strstr(detail_line, "PLP #") || strstr(detail_line, "Subframe #") || 
                    strstr(detail_line, "L1D_crc:")) break;
                
                // Parse PLP ID from the detail section
                if (strstr(detail_line, "L1D_plp_id:")) {
                    int actual_plp_id;
                    if (sscanf(detail_line, "%*[^:]: %d", &actual_plp_id) == 1) {
                        plp->plp_id = actual_plp_id;
                    }
                }
                
                // Parse modulation
                if (strstr(detail_line, "L1D_plp_mod:")) {
                    if (strstr(detail_line, "QPSK")) strcpy(plp->modulation, "QPSK");
                    else if (strstr(detail_line, "16QAM")) strcpy(plp->modulation, "16QAM");
                    else if (strstr(detail_line, "64QAM")) strcpy(plp->modulation, "64QAM");
                    else if (strstr(detail_line, "256QAM")) strcpy(plp->modulation, "256QAM");
                    else if (strstr(detail_line, "1024QAM")) strcpy(plp->modulation, "1024QAM");
                    else if (strstr(detail_line, "4096QAM")) strcpy(plp->modulation, "4096QAM");
                }
                
                // Parse code rate
                if (strstr(detail_line, "L1D_plp_cod:")) {
                    char* cod_start = strchr(detail_line, ':');
                    if (cod_start) {
                        cod_start += 2; // Skip ": "
                        sscanf(cod_start, "%15s", plp->code_rate);
                    }
                }
                
                // Parse layer
                if (strstr(detail_line, "L1D_plp_layer:")) {
                    if (strstr(detail_line, "Core")) strcpy(plp->layer, "core");
                    else if (strstr(detail_line, "Enhanced")) strcpy(plp->layer, "enhanced");
                }
                
                // Parse TI mode
                if (strstr(detail_line, "L1D_plp_TI_mode:")) {
                    if (strstr(detail_line, "No TI")) strcpy(plp->ti_mode, "no");
                    else if (strstr(detail_line, "CTI")) strcpy(plp->ti_mode, "cti");
                    else if (strstr(detail_line, "HTI")) strcpy(plp->ti_mode, "hti");
                }
                
                // Parse LLS flag
                if (strstr(detail_line, "L1D_plp_lls_flag:")) {
                    char* flag_start = strchr(detail_line, ':');
                    if (flag_start) {
                        plp->lls_flag = atoi(flag_start + 1);
                    }
                }
                
                // Parse FEC type
                if (strstr(detail_line, "L1D_plp_fec_type:")) {
                    char* fec_start = strchr(detail_line, ':');
                    if (fec_start) {
                        strncpy(plp->fec_type, fec_start + 2, sizeof(plp->fec_type) - 1);
                        // Clean up string
                        char* end = strchr(plp->fec_type, '\n');
                        if (end) *end = '\0';
                    }
                }
                
                // "-> PLP Required SNR: AWGN 1.23 dB, Rayleigh 4.56 dB [(LDM, ...)]"
                // A value of "not decodable" leaves that field at 0 (shown as N/A).
                if (strstr(detail_line, "-> PLP Required SNR:")) {
                    char* awgn_pos = strstr(detail_line, "AWGN ");
                    char* ray_pos = strstr(detail_line, "Rayleigh ");
                    double v;
                    have_l1_snr = 1;
                    plp->snr_range_available = 0;
                    if (awgn_pos && sscanf(awgn_pos, "AWGN %lf", &v) == 1) plp->required_snr_awgn = v;
                    if (ray_pos && sscanf(ray_pos, "Rayleigh %lf", &v) == 1) plp->required_snr_rayleigh = v;
                }

                // Parse bitrate - look for the specific format
                if (strstr(detail_line, "-> PLP Bitrate:")) {
                    float bitrate;
                    // Try different parsing patterns
                    if (sscanf(detail_line, "%*[^0-9]%f", &bitrate) == 1) {
                        plp->bitrate_mbps = bitrate;
                    } else {
                        // Try alternate pattern - look for number after colon
                        char* bitrate_start = strstr(detail_line, "-> PLP Bitrate:");
                        if (bitrate_start) {
                            bitrate_start += 15; // Skip "-> PLP Bitrate:"
                            while (*bitrate_start && !isdigit(*bitrate_start) && *bitrate_start != '.') {
                                bitrate_start++; // Skip spaces and non-numeric chars
                            }
                        }
                    }
                }
            }
            
            // Determine LDPC length from FEC type
            int ldpc_length = -1;
            if (strlen(plp->fec_type) > 0) {
                if (strstr(plp->fec_type, "16K")) {
                    ldpc_length = 0;  // Short
                } else if (strstr(plp->fec_type, "64K")) {
                    ldpc_length = 1;  // Long
                }
            }
            
            // Fall back to a plain modcod lookup only if the parser gave no value
            if (!have_l1_snr && strlen(plp->modulation) > 0 && strlen(plp->code_rate) > 0) {
                // Use the determined LDPC length
                char normalized_mod[16];
                normalize_mod_str_l1(plp->modulation, normalized_mod, sizeof(normalized_mod));
                
                struct snr_pair_result snr_result = get_snr_pair_for_modcod_l1(normalized_mod, plp->code_rate, ldpc_length);
                
                if (snr_result.found) {
                    if (snr_result.ldpc_length_known) {
                        plp->required_snr_awgn = snr_result.awgn_min;
                        plp->required_snr_rayleigh = snr_result.rayleigh_min;
                        plp->snr_range_available = 0;
                    } else {
                        plp->required_snr_awgn_min = snr_result.awgn_min;
                        plp->required_snr_awgn_max = snr_result.awgn_max;
                        plp->required_snr_rayleigh_min = snr_result.rayleigh_min;
                        plp->required_snr_rayleigh_max = snr_result.rayleigh_max;
                        plp->snr_range_available = 1;
                    }
                }
            }
            
            // Add to linked list
            if (enhanced_data->plp_head == NULL) {
                enhanced_data->plp_head = plp;
                plp_tail = plp;
            } else {
                plp_tail->next = plp;
                plp_tail = plp;
            }
        }
    }
    
    free_l1_detail_info(detail_info);
    free(decoded_data);
    return enhanced_data;
}

// Modified parse_enhanced_l1_signaling_file to correctly populate l1_base64 for display
EnhancedL1SignalingData* parse_enhanced_l1_signaling_file(const char* txt_filename) {
    FILE* f = fopen(txt_filename, "r");
    if (!f) {
        return NULL; // File doesn't exist
    }
    
    DBG_PRINTF("Found L1 signaling file: %s\n", txt_filename);
    
    // Read entire file content to pre-scan for Base64
    fseek(f, 0, SEEK_END);
    long file_size = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    char* file_content = malloc(file_size + 1);
    if (!file_content) {
        fclose(f);
        return NULL;
    }
    
    size_t bytes_read = fread(file_content, 1, file_size, f);
    file_content[bytes_read] = '\0';
    fseek(f, 0, SEEK_SET); // Reset for line-by-line parsing
    
    EnhancedL1SignalingData* data = calloc(1, sizeof(EnhancedL1SignalingData));
    if (!data) {
        fclose(f);
        free(file_content);
        return NULL;
    }
    
    data->original_text_content = file_content;
    
    int prefer_base64 = 0;
    if (strstr(file_content, "Raw L1 Detail (Base64):")) {
        prefer_base64 = 1;
        DBG_PRINTF("Base64 L1 section found. PLP details will be parsed directly from Base64.\n");
    }

    char line[1024];
    EnhancedPlpInfo* plp_tail = NULL;
    char* base64_buffer = NULL;
    size_t base64_size = 0;
    int in_base64_section = 0;
    
    // NEW: Store simple PLP info (with lock status) before parsing base64
    EnhancedPlpInfo* simple_plp_head = NULL;
    EnhancedPlpInfo* simple_plp_tail = NULL;
    
    while (fgets(line, sizeof(line), f)) {
        line[strcspn(line, "\r\n")] = '\0';
        
        if (strlen(line) == 0 || strstr(line, "__HLINE__") || strstr(line, "====")) {
            continue;
        }
        
        if (strstr(line, "Raw L1 Detail (Base64):")) {
            in_base64_section = 1;
            continue;
        }
        
        if (in_base64_section) {
            int is_base64_line = 1;
            for (int i = 0; line[i] && i < 100; i++) {
                char c = line[i];
                if (!(isalnum(c) || c == '+' || c == '/' || c == '=' || isspace(c))) {
                    is_base64_line = 0;
                    break;
                }
            }
            if (is_base64_line && strlen(line) > 10) {
                size_t line_len = strlen(line);
                base64_buffer = realloc(base64_buffer, base64_size + line_len + 1);
                if (base64_buffer) {
                    strcpy(base64_buffer + base64_size, line);
                    base64_size += line_len;
                }
            }
            continue;
        }
        
        if (isdigit(line[0]) && strchr(line, ':') && strchr(line, '=')) {
            EnhancedPlpInfo* simple_plp = parse_simple_plp_line(line);
            if (simple_plp) {
                if (!simple_plp_head) {
                    simple_plp_head = simple_plp;
                    simple_plp_tail = simple_plp;
                } else {
                    simple_plp_tail->next = simple_plp;
                    simple_plp_tail = simple_plp;
                }
            }
        }
        
        if (!prefer_base64 && isdigit(line[0]) && strchr(line, ':') && strchr(line, '=')) {
            char next_line[1024] = "";
            long pos = ftell(f);
            if (fgets(next_line, sizeof(next_line), f)) {
                next_line[strcspn(next_line, "\r\n")] = '\0';
                fseek(f, pos, SEEK_SET);
            }
            
            EnhancedPlpInfo* plp = NULL;
            if (strstr(next_line, "Required SNR:")) {
                plp = parse_plp_with_snr(line, next_line);
                fgets(next_line, sizeof(next_line), f);
            } else {
                plp = parse_simple_plp_line(line);
                if (plp) compute_snr_values(plp);
            }
            
            if (plp) {
                if (!data->plp_head) {
                    data->plp_head = plp;
                    plp_tail = plp;
                } else {
                    plp_tail->next = plp;
                    plp_tail = plp;
                }
            }
        } else {
            parse_l1_field_line(line, (L1SignalingData*)data);
        }
    }
    
    char* base64_to_parse = NULL;
    if (base64_buffer && base64_size > 0) {
        base64_to_parse = base64_buffer;
    } else if (strlen(data->l1_base64) > 0) {
        base64_to_parse = data->l1_base64;
    }
    
    // *** FIX IS HERE: Copy the discovered Base64 string to the main data struct ***
    if (base64_to_parse) {
        // Clean up the string by removing whitespace and copy it to data->l1_base64
        size_t dest_idx = 0;
        for (size_t i = 0; base64_to_parse[i] && dest_idx < sizeof(data->l1_base64) - 1; i++) {
            if (!isspace(base64_to_parse[i])) {
                data->l1_base64[dest_idx++] = base64_to_parse[i];
            }
        }
        data->l1_base64[dest_idx] = '\0';
        
        // Now use this cleaned string for parsing PLPs
        EnhancedL1SignalingData* base64_data = parse_l1_detail_from_base64(data->l1_base64);
        
        if (base64_data && base64_data->plp_head) {
            // Count PLPs for single-PLP special case
            int total_plp_count = 0;
            EnhancedPlpInfo* count_plp = base64_data->plp_head;
            while (count_plp) {
                total_plp_count++;
                count_plp = count_plp->next;
            }
            
            // Merge lock status from simple_plp_head into base64_data PLPs
            EnhancedPlpInfo* base64_plp = base64_data->plp_head;
            while (base64_plp) {
                // Find matching PLP in simple list by ID
                int found_simple = 0;
                EnhancedPlpInfo* simple_plp = simple_plp_head;
                while (simple_plp) {
                    if (simple_plp->plp_id == base64_plp->plp_id) {
                        // Copy lock status from simple PLP (0 or 1)
                        base64_plp->lock_flag = simple_plp->lock_flag;
                        found_simple = 1;
                        break;
                    }
                    simple_plp = simple_plp->next;
                }
                
                // If no matching simple PLP found, set to unknown (-1)
                // UNLESS there's only one PLP, in which case it must be locked (1)
                if (!found_simple) {
                    if (total_plp_count == 1) {
                        base64_plp->lock_flag = 1;  // Single PLP must be locked
                    } else {
                        base64_plp->lock_flag = -1;  // Unknown for multi-PLP
                    }
                }
                
                base64_plp = base64_plp->next;
            }
            
            data->plp_head = base64_data->plp_head;
            base64_data->plp_head = NULL;
            
            // Also copy BSID if we found one in base64 parsing and don't already have one
            if (strlen(data->l1_bsid) == 0 && strlen(base64_data->l1_bsid) > 0) {
                strncpy(data->l1_bsid, base64_data->l1_bsid, sizeof(data->l1_bsid) - 1);
                data->l1_bsid[sizeof(data->l1_bsid) - 1] = '\0';
            }
        }
        
        if (base64_data) {
            free_enhanced_l1_signaling_data(base64_data);
        }
    }
    
    // NEW: Free the simple PLP list
    EnhancedPlpInfo* current = simple_plp_head;
    while (current) {
        EnhancedPlpInfo* next = current->next;
        free(current);
        current = next;
    }
    
    if (base64_buffer) {
        free(base64_buffer);
    }
    
    fclose(f);
    
    int plp_count = 0;
    EnhancedPlpInfo* count_plp = data->plp_head;
    while (count_plp) {
        plp_count++;
        count_plp = count_plp->next;
    }
    
    DBG_PRINTF("Parsed enhanced L1 signaling data: %d PLPs", plp_count);
    if (strlen(data->l1_bsid) > 0) DBG_PRINTF(", L1 BSID: %s", data->l1_bsid);
    if (strlen(data->l1_base64) > 0) DBG_PRINTF(", L1Basic/Detail base64 (%zu chars)", strlen(data->l1_base64));
    DBG_PRINTF("\n");
    
    return data;
}

// Function to free enhanced L1 signaling data
void free_enhanced_l1_signaling_data(EnhancedL1SignalingData* data) {
    if (!data) return;
    
    EnhancedPlpInfo* current = data->plp_head;
    while (current) {
        EnhancedPlpInfo* next = current->next;
        free(current);
        current = next;
    }
    
    if (data->original_text_content) {
        free(data->original_text_content);
    }
    
    free(data);
}

void generate_enhanced_l1_section(FILE *f, EnhancedL1SignalingData* data, const char* slt_bsid) {
    if (!data) return;
    
    // Count PLPs for the summary
    int plp_count_summary = 0;
    EnhancedPlpInfo* count_plp = data->plp_head;
    while (count_plp) {
        plp_count_summary++;
        count_plp = count_plp->next;
    }
    
    // Create BSID display - only highlight if it differs from SLT BSID
    char bsid_display[128] = "";
    if (strlen(data->l1_bsid) > 0) {
        int bsid_mismatch = (slt_bsid && strlen(slt_bsid) > 0 && strcmp(data->l1_bsid, slt_bsid) != 0);
        if (bsid_mismatch) {
            snprintf(bsid_display, sizeof(bsid_display), " <span style='background:#ffff00;' title='L1 BSID does not match SLT BSID (%s)'>(L1 BSID: %s)</span>", 
                     slt_bsid, data->l1_bsid);
        } else {
            snprintf(bsid_display, sizeof(bsid_display), " (L1 BSID: %s)", data->l1_bsid);
        }
    } else {
        snprintf(bsid_display, sizeof(bsid_display), " <span style='background:#ffff00;'>(L1 BSID: Not Set)</span>");
    }
    
    fprintf(f, "<h2>Physical Layer Pipes - %d PLP%s%s</h2>\n", 
            plp_count_summary, (plp_count_summary == 1) ? "" : "s", bsid_display);
    
    // Display PLP information as an uncollapsed table (similar to SLT section)
    if (data->plp_head) {
        // Count PLPs first for sorting
        int plp_count = 0;
        EnhancedPlpInfo* count_plp = data->plp_head;
        while (count_plp) {
            plp_count++;
            count_plp = count_plp->next;
        }
        
        // Create array for sorting
        EnhancedPlpInfo** plp_array = malloc(plp_count * sizeof(EnhancedPlpInfo*));
        if (plp_array) {
            // Fill array
            EnhancedPlpInfo* plp = data->plp_head;
            int idx = 0;
            while (plp && idx < plp_count) {
                plp_array[idx++] = plp;
                plp = plp->next;
            }
            
            // Sort by PLP ID
            for (int i = 0; i < plp_count - 1; i++) {
                for (int j = i + 1; j < plp_count; j++) {
                    if (plp_array[i]->plp_id > plp_array[j]->plp_id) {
                        EnhancedPlpInfo* temp = plp_array[i];
                        plp_array[i] = plp_array[j];
                        plp_array[j] = temp;
                    }
                }
            }
            
            fprintf(f, "<table>\n<thead><tr><th>PLP ID</th><th>SFI</th><th>Modulation</th><th>Code Rate</th><th>Layer</th><th>TI Mode</th><th>LLS</th><th>Lock</th><th>Required SNR</th><th>Bitrate</th>");
            
            // Add enhanced columns if we have the data
            /*int has_enhanced_data = 0;
            for (int i = 0; i < plp_count; i++) {
                if (strlen(plp_array[i]->fec_type) > 0 || plp_array[i]->plp_size > 0) {
                    has_enhanced_data = 1;
                    break;
                }
            }
            
            if (has_enhanced_data) {
                fprintf(f, "<th>FEC Type</th><th>PLP Size</th><th>PLP Type</th>");
            }*/
            
            fprintf(f, "</tr></thead>\n<tbody>\n");
            
            for (int i = 0; i < plp_count; i++) {
                EnhancedPlpInfo* plp = plp_array[i];
                fprintf(f, "<tr><td>%d</td><td>%d</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td>", 
                        plp->plp_id, plp->sfi, plp->modulation, plp->code_rate, plp->layer, plp->ti_mode);
                fprintf(f, "<td>%s</td><td>%s</td>", 
                        plp->lls_flag ? "Yes" : "No", plp->lock_flag ? "Yes" : "No");
                
                // SNR values
                fprintf(f, "<td>");
                if (plp->snr_range_available) {
                    if (plp->required_snr_awgn_min < 0.0 || plp->required_snr_awgn_max < 0.0) {
                        fprintf(f, "AWGN: (%.2f)-(%.2f) dB", plp->required_snr_awgn_min, plp->required_snr_awgn_max);
                    } else {
                        fprintf(f, "AWGN: %.2f-%.2f dB", plp->required_snr_awgn_min, plp->required_snr_awgn_max);
                    }
                    fprintf(f, "<br>");
                    if (plp->required_snr_rayleigh_min < 0.0 || plp->required_snr_rayleigh_max < 0.0) {
                        fprintf(f, "Rayleigh: (%.2f)-(%.2f) dB", plp->required_snr_rayleigh_min, plp->required_snr_rayleigh_max);
                    } else {
                        fprintf(f, "Rayleigh: %.2f-%.2f dB", plp->required_snr_rayleigh_min, plp->required_snr_rayleigh_max);
                    }
                } else if (plp->required_snr_awgn != 0.0 || plp->required_snr_rayleigh != 0.0) {
                    if (plp->required_snr_awgn != 0.0) {
                        if (plp->required_snr_awgn < 0.0) {
                            fprintf(f, "AWGN: (%.2f) dB", plp->required_snr_awgn);
                        } else {
                            fprintf(f, "AWGN: %.2f dB", plp->required_snr_awgn);
                        }
                    }
                    if (plp->required_snr_rayleigh != 0.0) {
                        if (plp->required_snr_awgn != 0.0) fprintf(f, "<br>");
                        if (plp->required_snr_rayleigh < 0.0) {
                            fprintf(f, "Rayleigh: (%.2f) dB", plp->required_snr_rayleigh);
                        } else {
                            fprintf(f, "Rayleigh: %.2f dB", plp->required_snr_rayleigh);
                        }
                    }
                } else {
                    fprintf(f, "N/A");
                }
                fprintf(f, "</td>");
                
                // Bitrate
                fprintf(f, "<td>");
                if (plp->bitrate_mbps != 0.0) {
                    fprintf(f, "%.3f Mbps", plp->bitrate_mbps);
                } else {
                    fprintf(f, "N/A");
                }
                fprintf(f, "</td>");
                
                fprintf(f, "</tr>\n");
            }
            fprintf(f, "</tbody></table>\n");
            
            free(plp_array);
        }
    }
    
    // Now add the detailed L1 signaling information as a collapsible section
    // Check if we have any detailed L1 information to display
    int has_l1_details = 0;
    
    // Check if we have base64 data
    int has_base64 = (strlen(data->l1_base64) > 0);
    
    // Check if we have parsed L1Basic/L1Detail fields
    int has_l1basic = (strlen(data->l1b_version) > 0 || strlen(data->l1b_mimo_pilot_encoding) > 0 || 
                      strlen(data->l1b_lls_flag) > 0 || strlen(data->l1b_frame_length_mode) > 0);
    
    int has_l1detail = (strlen(data->l1d_version) > 0 || strlen(data->l1d_num_rf) > 0 || 
                       strlen(data->l1d_time_sec) > 0 || strlen(data->l1d_crc) > 0);
    
    // Check if any PLP has detailed information
    EnhancedPlpInfo* check_plp = data->plp_head;
    int has_plp_details = 0;
    while (check_plp) {
        if (strlen(check_plp->fec_type) > 0 || check_plp->plp_size > 0 || 
            strlen(check_plp->plp_type) > 0) {
            has_plp_details = 1;
            break;
        }
        check_plp = check_plp->next;
    }
    
    has_l1_details = has_base64 || has_l1basic || has_l1detail || has_plp_details;
    
    if (has_l1_details) {
        // Parse the L1 data first (if base64 available) so we can extract the timestamp for the header
        struct l1_detail_info* detail_info = NULL;
        unsigned char *decoded_data = NULL;
        char l1d_time_str[64] = "";
        
        if (has_base64) {
            size_t decoded_len = b64_decoded_size_l1(data->l1_base64);
            decoded_data = malloc(decoded_len);
            
            if (decoded_data && b64_decode_l1(data->l1_base64, decoded_data, decoded_len)) {
                detail_info = create_l1_detail_info(MAX_DISPLAY_LINES);
                if (detail_info) {
                    // Parse the L1 data
                    parse_l1_data_l1(decoded_data, decoded_len, detail_info->display_lines, 
                                     &detail_info->line_count, detail_info->max_lines, &detail_info->context);
                    
                    // Search display lines for L1D_time_sec to extract timestamp
                    for (int i = 0; i < detail_info->line_count; i++) {
                        char* time_pos = strstr(detail_info->display_lines[i], "L1D_time_sec:");
                        if (time_pos) {
                            long unix_time = 0;
                            if (sscanf(time_pos, "L1D_time_sec: %ld", &unix_time) == 1 && unix_time > 0) {
                                time_t time_val = (time_t)unix_time;
                                struct tm *tm_info = localtime(&time_val);
                                if (tm_info) {
                                    strftime(l1d_time_str, sizeof(l1d_time_str), "%Y-%m-%d %H:%M:%S %Z", tm_info);
                                }
                            }
                            break;
                        }
                    }
                }
            }
        }
        
        // Now write the header with timestamp if we found one
        fprintf(f, "<details><summary>L1 Signaling Details ");
        if (has_base64) { fprintf(f, "(From L1Detail)"); }
        else { fprintf(f, "(From Text File)"); }
        
        if (strlen(l1d_time_str) > 0) {
            fprintf(f, " - %s", l1d_time_str);
        }
        
        fprintf(f, "</summary>\n");
        fprintf(f, "<div class='details-content'>\n");
        
        // If we have parsed base64 data, display it
        if (detail_info) {
            // Display the parsed data
            fprintf(f, "<div style='font-family: monospace; font-size: 12px; background-color: #f8f9fa; padding: 10px; border-radius: 4px; margin: 10px 0;'>\n");
            for (int i = 0; i < detail_info->line_count; i++) {
                if (strcmp(detail_info->display_lines[i], "__HLINE__") == 0) {
                    fprintf(f, "<strong style='color: #0066cc;'>================================================================================</strong><br>\n");
                } else {
                    fprintf_escaped_xml(f, detail_info->display_lines[i]);
                    fprintf(f, "<br>\n");
                }
            }
            fprintf(f, "</div>\n");
            
            free_l1_detail_info(detail_info);
        }
        
        if (decoded_data) {
            free(decoded_data);
        }
        
        if (!has_base64) {
            // No base64 data available, show original text file content
            fprintf(f, "<div style='font-family: monospace; font-size: 12px; background-color: #f8f9fa; padding: 10px; border-radius: 4px; margin: 10px 0;'>\n");
            
            if (data->original_text_content) {
                // Find the __HLINE__ or ==== separator and start from after it
                char* content = data->original_text_content;
                char* separator_pos = NULL;
                
                // Look for __HLINE__ first
                separator_pos = strstr(content, "__HLINE__");
                if (!separator_pos) {
                    // If not found, look for a line starting with ====
                    char* line_start = content;
                    char* line_end;
                    
                    while ((line_end = strchr(line_start, '\n')) != NULL) {
                        if (line_end - line_start >= 4 && strncmp(line_start, "====", 4) == 0) {
                            separator_pos = line_start;
                            break;
                        }
                        line_start = line_end + 1;
                    }
                    
                    // Check the last line if no newline at end
                    if (!separator_pos && *line_start && strlen(line_start) >= 4 && strncmp(line_start, "====", 4) == 0) {
                        separator_pos = line_start;
                    }
                }

                if (separator_pos) {
                    // Find the next newline after the separator to start content from there
                    char* content_start = strchr(separator_pos, '\n');
                    if (content_start) {
                        content_start++; // Skip the newline
                        
                        // Find where to stop - look for "Raw L1 Detail (Base64):" or end of content
                        char* content_end = strstr(content_start, "Raw L1 Detail (Base64):");
                        if (!content_end) {
                            content_end = content_start + strlen(content_start); // End of string
                        }
                        
                        // Display content from after the separator up to base64 section
                        char* line_start = content_start;
                        char* line_end;
                        
                        while (line_start < content_end && (line_end = strchr(line_start, '\n')) != NULL && line_end < content_end) {
                            // Check if this line is a separator line (starts with ====)
                            char* trimmed_start = line_start;
                            while (trimmed_start < line_end && (*trimmed_start == ' ' || *trimmed_start == '\t')) {
                                trimmed_start++; // Skip leading whitespace
                            }
                            
                            // Skip separator lines (lines that start with ====)
                            if (line_end - trimmed_start >= 4 && strncmp(trimmed_start, "====", 4) == 0) {
                                line_start = line_end + 1;
                                continue;
                            }
                            
                            // Print line up to newline, escaping for HTML
                            int line_len = (int)(line_end - line_start);
                            for (int i = 0; i < line_len; i++) {
                                char c = line_start[i];
                                switch (c) {
                                    case '<': fprintf(f, "&lt;"); break;
                                    case '>': fprintf(f, "&gt;"); break;
                                    case '&': fprintf(f, "&amp;"); break;
                                    default: fputc(c, f); break;
                                }
                            }
                            fprintf(f, "<br>\n");
                            
                            line_start = line_end + 1;
                        }
                        
                        // Print any remaining content before base64 section (if not a separator)
                        if (line_start < content_end && *line_start) {
                            char* trimmed_start = line_start;
                            while (trimmed_start < content_end && (*trimmed_start == ' ' || *trimmed_start == '\t')) {
                                trimmed_start++; // Skip leading whitespace
                            }
                            
                            // Only print if it's not a separator line
                            if (!(content_end - trimmed_start >= 4 && strncmp(trimmed_start, "====", 4) == 0)) {
                                int remaining_len = (int)(content_end - line_start);
                                for (int i = 0; i < remaining_len && line_start[i]; i++) {
                                    char c = line_start[i];
                                    switch (c) {
                                        case '<': fprintf(f, "&lt;"); break;
                                        case '>': fprintf(f, "&gt;"); break;
                                        case '&': fprintf(f, "&amp;"); break;
                                        default: fputc(c, f); break;
                                    }
                                }
                                fprintf(f, "<br>\n");
                            }
                        }
                    } else {
                        fprintf(f, "<em>No content found after separator line</em><br>\n");
                    }
                } else {
                    fprintf(f, "<em>No __HLINE__ or ==== separator found in text file</em><br>\n");
                }
                            } else {
                                fprintf(f, "<em>Original text file content not available</em><br>\n");
                            }
                            
                            fprintf(f, "</div>\n");
                        }
                        
                        fprintf(f, "</div></details>\n");
                    } else {
                        // No L1 details available at all
                        fprintf(f, "<div class='details-content' style='margin-top: 1em; padding: 10px; border-radius: 5px; background-color: #f8d7da; border: 1px solid #f5c6cb; color: #721c24;'>\n");
                        fprintf(f, "<strong>L1 Detail Information Not Available</strong>\n");
                        fprintf(f, "</div>\n");
                    }
                }

void generate_basic_l1_section(FILE *f, L1SignalingData* data, const char* slt_bsid) {
    if (!data) return;
    
    int plp_count = 0;
    PlpInfo* count_plp = data->plp_head;
    while (count_plp) {
        plp_count++;
        count_plp = count_plp->next;
    }
    
    // Create summary text for the collapsible header - only highlight if BSID differs from SLT
    char l1_summary[256] = "";
    if (strlen(data->l1_bsid) > 0) {
        int bsid_mismatch = (slt_bsid && strlen(slt_bsid) > 0 && strcmp(data->l1_bsid, slt_bsid) != 0);
        if (bsid_mismatch) {
            snprintf(l1_summary, sizeof(l1_summary), " <span style='background:#ffff00;' title='L1 BSID does not match SLT BSID (%s)'>(L1 BSID: %s)</span>", 
                     slt_bsid, data->l1_bsid);
        } else {
            snprintf(l1_summary, sizeof(l1_summary), " (L1 BSID: %s)", data->l1_bsid);
        }
    } else {
        snprintf(l1_summary, sizeof(l1_summary), " <span style='background:#ffff00;'>(L1 BSID: Not Set)</span>");
    }
    
    fprintf(f, "<details><summary>L1 Information - %d PLP%s%s</summary>\n", 
            plp_count, (plp_count == 1) ? "" : "s", l1_summary);
    fprintf(f, "<div class='details-content'>\n");
    
    if (data->plp_head) {
        fprintf(f, "<h3>Physical Layer Pipes (PLPs)</h3>\n");
        fprintf(f, "<table>\n<thead><tr><th>PLP ID</th><th>SFI</th><th>Modulation</th><th>Code Rate</th><th>Layer</th><th>TI Mode</th><th>LLS</th><th>Lock</th><th>Required SNR (dB)</th><th>Bitrate</th></tr></thead>\n<tbody>\n");
        
        PlpInfo* plp = data->plp_head;
        while (plp) {
            fprintf(f, "<tr><td>%d</td><td>%d</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td>", 
                    plp->plp_id, plp->sfi, plp->modulation, plp->code_rate, plp->layer, plp->ti_mode);
            fprintf(f, "<td>%s</td><td>%s</td>", 
                    plp->lls_flag ? "Yes" : "No", plp->lock_flag ? "Yes" : "No");
            
            // SNR values
            fprintf(f, "<td>");
            if (plp->required_snr_awgn != 0.0 || plp->required_snr_rayleigh != 0.0) {
                if (plp->required_snr_awgn != 0.0) {
                    fprintf(f, "AWGN: %.2f", plp->required_snr_awgn);
                }
                if (plp->required_snr_rayleigh != 0.0) {
                    if (plp->required_snr_awgn != 0.0) fprintf(f, "<br>");
                    fprintf(f, "Rayleigh: %.2f", plp->required_snr_rayleigh);
                }
            } else {
                fprintf(f, "N/A");
            }
            fprintf(f, "</td>");
            
            // Bitrate
            fprintf(f, "<td>");
            if (plp->bitrate_mbps != 0.0) {
                fprintf(f, "%.3f Mbps", plp->bitrate_mbps);
            } else {
                fprintf(f, "N/A");
            }
            fprintf(f, "</td>");
            
            fprintf(f, "</tr>\n");
            plp = plp->next;
        }
        fprintf(f, "</tbody></table>\n");
    }
    
    fprintf(f, "</div></details>\n");
}
