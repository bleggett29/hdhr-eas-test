#ifndef BPS_H
#define BPS_H

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

// BPS (Broadcast Positioning System) structures

typedef struct BpsTimingSource {
    uint8_t version;
    uint16_t length;
    uint8_t type;
    uint16_t tx_id;
    uint16_t tx_freq_mhz;
    uint32_t fac_id;
    uint8_t sync_hierarchy;
    uint16_t expected_accuracy_ns;
    uint8_t timing_source_used;
    uint8_t num_timing_sources;
    uint16_t timing_sources;
} BpsTimingSource;

typedef struct BpsMeasurement {
    uint8_t version;
    uint16_t length;
    uint8_t type;
    uint16_t tx_id;
    uint16_t tx_freq_mhz;
    uint32_t fac_id;
    uint8_t forward_flag;
    
    // Reported bootstrap time (only if forward_flag = 1)
    uint32_t reported_bootstrap_time_sec;
    uint16_t reported_bootstrap_time_msec;
    uint16_t reported_bootstrap_time_usec;
    uint16_t reported_bootstrap_time_nsec;
    uint32_t bootstrap_toa_offset;
    
    // Previous bootstrap time (always present)
    uint32_t prev_bootstrap_time_sec;
    uint16_t prev_bootstrap_time_msec;
    uint16_t prev_bootstrap_time_usec;
    uint16_t prev_bootstrap_time_nsec;
    uint32_t prev_bootstrap_time_error_nsec;
} BpsMeasurement;

typedef struct BpsDescription {
    uint8_t version;
    uint16_t length;
    uint8_t type;
    uint16_t tx_id;
    uint16_t tx_freq_mhz;
    uint32_t fac_id;
    uint8_t gain_flag;
    uint8_t pos_flag;
    uint8_t pow_flag;
    uint8_t pattern_flag;
    uint16_t max_gain_dir;
    double latitude;
    double longitude;
    double height;
    float power_kw;
    uint8_t antenna_pattern[36];
} BpsDescription;

typedef struct BpsData {
    uint8_t version;
    uint8_t num_segments;
    BpsTimingSource* timing;
    BpsMeasurement* measurement;
    BpsDescription* description;
    uint32_t crc;
} BpsData;

// Function declarations
BpsData* parse_bps_packet(const uint8_t* payload, size_t len);
void free_bps_data(BpsData* bps);
int is_bps_service(const char* dest_ip, const char* dest_port);
void generate_bps_html_section(FILE* f, BpsData* bps_data);

#endif // BPS_H 
