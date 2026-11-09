#ifndef PLP_H
#define PLP_H

#include <stdint.h>
#include <time.h>

// Forward declarations
struct l1_detail_info;

// PLP data structures
typedef struct PlpInfo {
    int plp_id;
    int sfi;
    char modulation[16];
    char code_rate[16];
    char layer[16];
    char ti_mode[8];
    int lls_flag;
    int lock_flag;
    double required_snr_awgn;
    double required_snr_rayleigh;
    double bitrate_mbps;
    struct PlpInfo* next;
} PlpInfo;

typedef struct EnhancedPlpInfo {
    int plp_id;
    int sfi;
    char modulation[16];
    char code_rate[16];
    char layer[16];
    char ti_mode[8];
    int lls_flag;
    int lock_flag;
    double required_snr_awgn;
    double required_snr_rayleigh;
    double required_snr_awgn_min;
    double required_snr_awgn_max;
    double required_snr_rayleigh_min;
    double required_snr_rayleigh_max;
    int snr_range_available;  
    double bitrate_mbps;
    
    // Enhanced fields from L1 detail
    int plp_start;
    int plp_size;
    char fec_type[32];
    char scrambler_type[16];
    int mimo_stream_combining;
    int mimo_iq_interleaving;
    int mimo_ph;
    char plp_type[16];
    int num_subslices;
    int subslice_interval;
    
    struct EnhancedPlpInfo* next;
} EnhancedPlpInfo;

// L1 signaling data structures
typedef struct L1SignalingData {
    char l1_bsid[16];
    char l1_base64[1024];
    PlpInfo* plp_head;
    
    // L1Basic fields
    char l1b_version[8];
    char l1b_mimo_pilot_encoding[32];
    char l1b_lls_flag[16];
    char l1b_time_info_flag[16];
    char l1b_return_channel_flag[8];
    char l1b_papr_reduction[16];
    char l1b_frame_length_mode[32];
    char l1b_time_offset[16];
    char l1b_additional_samples[16];
    char l1b_num_subframes[8];
    char l1b_preamble_num_symbols[8];
    char l1b_preamble_reduced_carriers[8];
    char l1b_l1_detail_content_tag[8];
    char l1b_l1_detail_size_bytes[8];
    char l1b_l1_detail_fec_type[16];
    char l1b_l1_additional_parity_mode[8];
    char l1b_l1_detail_total_cells[16];
    char l1b_first_sub_mimo[16];
    char l1b_first_sub_miso[8];
    char l1b_first_sub_fft_size[8];
    char l1b_first_sub_reduced_carriers[8];
    char l1b_first_sub_guard_interval[16];
    char l1b_first_sub_num_ofdm_symbols[8];
    char l1b_first_sub_scattered_pilot_pattern[8];
    char l1b_first_sub_scattered_pilot_boost[8];
    char l1b_first_sub_sbs_first[8];
    char l1b_first_sub_sbs_last[8];
    char l1b_crc[16];
    
    // L1Detail fields
    char l1d_version[8];
    char l1d_num_rf[8];
    char l1d_time_sec[16];
    char l1d_time_msec[8];
    char l1d_time_usec[8];
    char l1d_time_nsec[8];
    char l1d_crc[16];
} L1SignalingData;

typedef struct EnhancedL1SignalingData {
    char l1_bsid[16];
    char l1_base64[1024];
    EnhancedPlpInfo* plp_head;
    
    // L1Basic fields (same as L1SignalingData)
    char l1b_version[8];
    char l1b_mimo_pilot_encoding[32];
    char l1b_lls_flag[16];
    char l1b_time_info_flag[16];
    char l1b_return_channel_flag[8];
    char l1b_papr_reduction[16];
    char l1b_frame_length_mode[32];
    char l1b_time_offset[16];
    char l1b_additional_samples[16];
    char l1b_num_subframes[8];
    char l1b_preamble_num_symbols[8];
    char l1b_preamble_reduced_carriers[8];
    char l1b_l1_detail_content_tag[8];
    char l1b_l1_detail_size_bytes[8];
    char l1b_l1_detail_fec_type[16];
    char l1b_l1_additional_parity_mode[8];
    char l1b_l1_detail_total_cells[16];
    char l1b_first_sub_mimo[16];
    char l1b_first_sub_miso[8];
    char l1b_first_sub_fft_size[8];
    char l1b_first_sub_reduced_carriers[8];
    char l1b_first_sub_guard_interval[16];
    char l1b_first_sub_num_ofdm_symbols[8];
    char l1b_first_sub_scattered_pilot_pattern[8];
    char l1b_first_sub_scattered_pilot_boost[8];
    char l1b_first_sub_sbs_first[8];
    char l1b_first_sub_sbs_last[8];
    char l1b_crc[16];
    
    // L1Detail fields (same as L1SignalingData)
    char l1d_version[8];
    char l1d_num_rf[8];
    char l1d_time_sec[16];
    char l1d_time_msec[8];
    char l1d_time_usec[8];
    char l1d_time_nsec[8];
    char l1d_crc[16];
    
    char* original_text_content;
} EnhancedL1SignalingData;

// Function declarations
void fprintf_escaped_xml(FILE* f, const char* str);
char* get_txt_filename_from_input(const char* input_filename);
PlpInfo* parse_plp_line(const char* line);
void parse_l1_field_line(const char* line, L1SignalingData* data);
L1SignalingData* parse_l1_signaling_file(const char* txt_filename);
void free_l1_signaling_data(L1SignalingData* data);

EnhancedPlpInfo* parse_simple_plp_line(const char* line);
void compute_snr_values(EnhancedPlpInfo* plp);
EnhancedPlpInfo* parse_plp_with_snr(const char* line, const char* next_line);
EnhancedL1SignalingData* parse_enhanced_l1_signaling_file(const char* txt_filename);
EnhancedL1SignalingData* parse_l1_detail_from_base64(const char* base64_data);
void free_enhanced_l1_signaling_data(EnhancedL1SignalingData* data);

L1SignalingData* get_l1_signaling_data(void);
void set_l1_signaling_data(L1SignalingData* data);
EnhancedL1SignalingData* get_enhanced_l1_signaling_data(void);
void set_enhanced_l1_signaling_data(EnhancedL1SignalingData* data);

void generate_enhanced_l1_section(FILE *f, EnhancedL1SignalingData* data, const char* slt_bsid);
void generate_basic_l1_section(FILE *f, L1SignalingData* data, const char* slt_bsid);

#endif // PLP_H
