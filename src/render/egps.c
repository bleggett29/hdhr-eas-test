/**
 * @file egps.c
 * @brief eGPS (Enhanced GPS) packet parsing and rendering for ATSC 3.0
 * 
 * Handles Cambium-style binary GPS packets transmitted via ROUTE protocol.
 */

#include "egps.h"

// Global eGPS data storage
EgpsData* g_egps_data[MAX_EGPS_STREAMS];
int g_egps_data_count = 0;

/**
 * @brief Parse a single eGPS Cambium-style packet
 */
EgpsLocationFix* parse_egps_packet(const uint8_t* data, size_t len) {
    if (!data || len < 8) return NULL;
    
    // Check magic bytes (0xBCA1)
    uint16_t magic = (data[0] << 8) | data[1];
    if (magic != EGPS_MAGIC) return NULL;
    
    // Parse header
    uint16_t pkt_length = (data[2] << 8) | data[3];
    uint16_t id = (data[4] << 8) | data[5];
    uint8_t encrypted = (data[6] & 0x80) != 0;
    uint16_t remaining_len = ((data[6] & 0x7F) << 8) | data[7];
    
    size_t total_pkt_len = 4 + pkt_length;
    if (total_pkt_len > len) total_pkt_len = len;
    
    EgpsLocationFix* fix = calloc(1, sizeof(EgpsLocationFix));
    if (!fix) return NULL;
    
    // Store header fields
    fix->magic = magic;
    fix->length = pkt_length;
    fix->msg_type = id;
    fix->flag = encrypted;
    fix->payload_len = remaining_len;
    fix->is_valid = !encrypted;  // Encrypted packets can't be validated
    
    // Store raw packet data
    fix->misc_data_len = (total_pkt_len > sizeof(fix->misc_data)) ? sizeof(fix->misc_data) : total_pkt_len;
    memcpy(fix->misc_data, data, fix->misc_data_len);
    
    // Parse GPS payload (0x0806 packets only, unencrypted)
    if (id == EGPS_ID_GPS && !encrypted && len >= 8 + 14) {
        const uint8_t* gps = data + 8;
        
        // Status is always first 2 bytes
        fix->status = (gps[0] << 8) | gps[1];
        
        // Determine packet format based on remaining length
        // Short packets (~18-28 bytes): No timestamp, lat/lon starts at offset 2
        // Long packets (~39+ bytes): Has timestamp, lat/lon starts at offset 6
        
        if (remaining_len >= 39) {
            // LONG format: Status(2) + Timestamp(4) + Lat(4) + Lon(4) + Bias(4)
            fix->tow = ((uint32_t)gps[2] << 24) | ((uint32_t)gps[3] << 16) | 
                       ((uint32_t)gps[4] << 8) | gps[5];
            
            uint32_t lat_raw = ((uint32_t)gps[6] << 24) | ((uint32_t)gps[7] << 16) | 
                               ((uint32_t)gps[8] << 8) | gps[9];
            fix->latitude = (int32_t)lat_raw;
            
            uint32_t lon_raw = ((uint32_t)gps[10] << 24) | ((uint32_t)gps[11] << 16) | 
                               ((uint32_t)gps[12] << 8) | gps[13];
            fix->longitude = (int32_t)lon_raw;
            
            if (remaining_len >= 18 && len >= 8 + 18) {
                uint32_t bias_raw = ((uint32_t)gps[14] << 24) | ((uint32_t)gps[15] << 16) | 
                                    ((uint32_t)gps[16] << 8) | gps[17];
                fix->altitude = (int32_t)bias_raw;  // Actually clock bias
            }
        } else {
            // SHORT format: Status(2) + Lat(4) + Lon(4) + Bias(4) - no timestamp
            fix->tow = 0;  // No timestamp in short packets
            
            uint32_t lat_raw = ((uint32_t)gps[2] << 24) | ((uint32_t)gps[3] << 16) | 
                               ((uint32_t)gps[4] << 8) | gps[5];
            fix->latitude = (int32_t)lat_raw;
            
            uint32_t lon_raw = ((uint32_t)gps[6] << 24) | ((uint32_t)gps[7] << 16) | 
                               ((uint32_t)gps[8] << 8) | gps[9];
            fix->longitude = (int32_t)lon_raw;
            
            if (remaining_len >= 14 && len >= 8 + 14) {
                uint32_t bias_raw = ((uint32_t)gps[10] << 24) | ((uint32_t)gps[11] << 16) | 
                                    ((uint32_t)gps[12] << 8) | gps[13];
                fix->altitude = (int32_t)bias_raw;  // Actually clock bias
            }
        }
        
        // Convert to degrees
        fix->lat_degrees = fix->latitude / 10000000.0;
        fix->lon_degrees = fix->longitude / 10000000.0;
        fix->alt_meters = (double)fix->altitude;  // This is clock bias, not altitude
        
        // Validate coordinates
        if (fix->lat_degrees < -90.0 || fix->lat_degrees > 90.0 ||
            fix->lon_degrees < -180.0 || fix->lon_degrees > 180.0) {
            fix->is_valid = 0;
        }
    }
    
    fix->receive_time = time(NULL);
    fix->next = NULL;
    
    return fix;
}

/**
 * @brief Parse multiple eGPS packets from a data stream
 */
EgpsData* parse_egps_stream(const uint8_t* data, size_t len, const char* dest_ip, const char* dest_port) {
    if (!data || len < 8) return NULL;
    
    EgpsData* egps = calloc(1, sizeof(EgpsData));
    if (!egps) return NULL;
    
    if (dest_ip) strncpy(egps->dest_ip, dest_ip, sizeof(egps->dest_ip) - 1);
    if (dest_port) strncpy(egps->dest_port, dest_port, sizeof(egps->dest_port) - 1);
    egps->timestamp = time(NULL);
    
    // Store raw data
    egps->raw_size = len;
    egps->raw_data = malloc(len);
    if (egps->raw_data) {
        memcpy(egps->raw_data, data, len);
    }
    
    // Parse packets
    size_t offset = 0;
    EgpsLocationFix* tail = NULL;
    
    while (offset + 4 <= len) {
        if (data[offset] != 0xBC || data[offset + 1] != 0xA1) {
            offset++;
            continue;
        }
        
        uint16_t pkt_content_len = (data[offset + 2] << 8) | data[offset + 3];
        size_t total_pkt_len = 4 + pkt_content_len;
        
        if (pkt_content_len < 4 || total_pkt_len > 1000) {
            offset++;
            continue;
        }
        
        size_t avail_len = (offset + total_pkt_len <= len) ? total_pkt_len : (len - offset);
        EgpsLocationFix* fix = parse_egps_packet(data + offset, avail_len);
        if (fix) {
            if (!egps->location_fixes) {
                egps->location_fixes = fix;
            } else {
                tail->next = fix;
            }
            tail = fix;
            egps->location_fix_count++;
            
            // Track latest valid GPS fix (0x0806 with valid coords)
            if (fix->msg_type == EGPS_ID_GPS && fix->is_valid) {
                egps->latest_fix = fix;
            }
        }
        
        offset += total_pkt_len;
    }
    
    egps->parse_status = (egps->location_fix_count > 0) ? 0 : -1;
    
    return egps;
}

/**
 * @brief Free eGPS data structure
 */
void free_egps_data(EgpsData* data) {
    if (!data) return;
    
    // Free location fixes
    EgpsLocationFix* fix = data->location_fixes;
    while (fix) {
        EgpsLocationFix* next = fix->next;
        free(fix);
        fix = next;
    }
    
    // Free satellite info (legacy)
    EgpsSatelliteInfo* sat = data->satellites;
    while (sat) {
        EgpsSatelliteInfo* next = sat->next;
        free(sat);
        sat = next;
    }
    
    // Free raw data
    if (data->raw_data) {
        free(data->raw_data);
    }
    
    free(data);
}

/**
 * @brief Render eGPS data as HTML
 */
int render_egps_html(FILE* f, EgpsData* egps) {
    if (!f || !egps || !egps->raw_data || egps->raw_size == 0) {
        return 0;
    }
    
    // Count total packets by scanning raw data
    int packet_count = 0;
    size_t scan = 0;
    while (scan + 6 < egps->raw_size) {
        if (egps->raw_data[scan] == 0xBC && egps->raw_data[scan + 1] == 0xA1) {
            uint16_t pkt_len = (egps->raw_data[scan + 2] << 8) | egps->raw_data[scan + 3];
            packet_count++;
            scan += 4 + pkt_len;
            if (pkt_len < 4) scan += 4;
        } else {
            scan++;
        }
    }
    
    fprintf(f, "<details><summary>eGPS Data (%d packets, %zu bytes)</summary>\n",
            packet_count, egps->raw_size);
    fprintf(f, "<div class='details-content'>\n");
    
    // All Packets
    if (packet_count > 0) {
        fprintf(f, "<table>\n<thead><tr><th style='white-space:nowrap;'>#</th><th style='white-space:nowrap;'>Offset</th><th style='white-space:nowrap;'>ID</th><th style='white-space:nowrap;'>Encrypted</th><th>Hex</th></tr></thead>\n<tbody>\n");
        
        int pkt_num = 1;
        size_t offset = 0;
        while (offset + 6 < egps->raw_size) {
            if (egps->raw_data[offset] != 0xBC || egps->raw_data[offset + 1] != 0xA1) {
                offset++;
                continue;
            }
            uint16_t pkt_len = (egps->raw_data[offset + 2] << 8) | egps->raw_data[offset + 3];
            uint16_t pkt_id = (egps->raw_data[offset + 4] << 8) | egps->raw_data[offset + 5];
            uint8_t pkt_encrypted = 0;
            if (offset + 7 < egps->raw_size) {
                pkt_encrypted = (egps->raw_data[offset + 6] & 0x80) != 0;
            }
            size_t total_len = 4 + pkt_len;
            
            fprintf(f, "<tr><td style='white-space:nowrap;'>%d</td><td style='white-space:nowrap;'>%zu</td><td style='white-space:nowrap;'>0x%04X</td><td style='white-space:nowrap;'>%s</td><td style='font-family:monospace;font-size:10px;word-spacing:0.3em;'>",
                    pkt_num++, offset, pkt_id, pkt_encrypted ? "Y" : "N");
            size_t show = (offset + total_len <= egps->raw_size) ? total_len : (egps->raw_size - offset);
            // Limit display to first 64 bytes for large packets
            int truncated = 0;
            if (show > 64) {
                show = 64;
                truncated = 1;
            }
            for (size_t i = 0; i < show; i++) {
                fprintf(f, "%02X ", egps->raw_data[offset + i]);
            }
            if (truncated) fprintf(f, "...");
            fprintf(f, "</td></tr>\n");
            
            offset += (total_len > 4) ? total_len : 4;
        }
        fprintf(f, "</tbody></table>\n");
    }
    
    // Full raw hex dump
    fprintf(f, "<details><summary>Full Raw Data (%zu bytes)</summary>\n", egps->raw_size);
    fprintf(f, "<pre style='font-size:11px;background:#f5f5f5;padding:10px;overflow-x:auto;'>");
    for (size_t i = 0; i < egps->raw_size; i++) {
        if (i > 0 && i % 16 == 0) fprintf(f, "\n");
        else if (i > 0 && i % 8 == 0) fprintf(f, " ");
        fprintf(f, "%02X ", egps->raw_data[i]);
    }
    fprintf(f, "</pre></details>\n");
    
    fprintf(f, "</div></details>\n");
    
    return 1;
}

/**
 * @brief Find eGPS data for a given destination
 */
EgpsData* find_egps_data(const char* dest_ip, const char* dest_port) {
    if (!dest_ip || !dest_port) return NULL;
    
    for (int i = 0; i < g_egps_data_count; i++) {
        if (g_egps_data[i] && 
            strcmp(g_egps_data[i]->dest_ip, dest_ip) == 0 &&
            strcmp(g_egps_data[i]->dest_port, dest_port) == 0) {
            return g_egps_data[i];
        }
    }
    return NULL;
}

/**
 * @brief Store or append eGPS data to global storage
 */
int store_egps_data(EgpsData* egps) {
    if (!egps) return 0;
    
    // Check if we already have data for this destination
    EgpsData* existing = find_egps_data(egps->dest_ip, egps->dest_port);
    
    if (existing) {
        // Append to existing data
        EgpsLocationFix* tail = existing->location_fixes;
        if (tail) {
            while (tail->next) tail = tail->next;
            tail->next = egps->location_fixes;
        } else {
            existing->location_fixes = egps->location_fixes;
        }
        existing->location_fix_count += egps->location_fix_count;
        
        if (egps->latest_fix && egps->latest_fix->is_valid) {
            existing->latest_fix = egps->latest_fix;
        }
        
        // Transfer raw data if existing doesn't have it
        if (!existing->raw_data && egps->raw_data) {
            existing->raw_data = egps->raw_data;
            existing->raw_size = egps->raw_size;
            egps->raw_data = NULL;  // Prevent double-free
        }
        
        // Prevent double-free of transferred fixes
        egps->location_fixes = NULL;
        free_egps_data(egps);
        return 1;
    }
    
    // Add new entry
    if (g_egps_data_count < MAX_EGPS_STREAMS) {
        g_egps_data[g_egps_data_count++] = egps;
        return 1;
    }
    
    return 0;  // No space
}

/**
 * @brief Free all global eGPS data
 */
void free_all_egps_data(void) {
    for (int i = 0; i < g_egps_data_count; i++) {
        if (g_egps_data[i]) {
            free_egps_data(g_egps_data[i]);
            g_egps_data[i] = NULL;
        }
    }
    g_egps_data_count = 0;
}
