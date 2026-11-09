#include "bps.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

BpsData* parse_bps_packet(const uint8_t* payload, size_t len) {
    if (len < 4) return NULL;
    
    BpsData* bps = calloc(1, sizeof(BpsData));
    if (!bps) return NULL;
    
    const uint8_t* pos = payload;
    
    // Parse header
    uint8_t header = *pos++;
    bps->version = (header >> 4) & 0x0F;
    bps->num_segments = header & 0x0F;
    
    //printf("BPS: version=%d, segments=%d\n", bps->version, bps->num_segments);
    
    // Parse each segment
    for (int i = 0; i < bps->num_segments && pos < payload + len - 4; i++) {
        uint16_t seg_header = ntohs(*(uint16_t*)pos);
        pos += 2;
        
        uint8_t seg_version = (seg_header >> 12) & 0x0F;
        uint16_t seg_length = seg_header & 0x0FFF;
        
        if (pos + seg_length > payload + len) {
            printf("BPS: segment %d exceeds packet length\n", i);
            break;
        }
        
        // Parse type/tx_id
        uint16_t type_txid = ntohs(*(uint16_t*)pos);
        pos += 2;
        uint8_t type = (type_txid >> 13) & 0x07;
        uint16_t tx_id = type_txid & 0x1FFF;
        
        // Common fields
        uint16_t tx_freq = ntohs(*(uint16_t*)pos);
        pos += 2;
        uint32_t fac_id = ntohl(*(uint32_t*)pos);
        pos += 4;
        
        //printf("  Segment %d: type=%d, tx_id=%d, freq=%d MHz, fac_id=0x%08X\n", 
        //       i, type, tx_id, tx_freq, fac_id);
        
        switch (type) {
            case 1: { // Timing Source
                if (!bps->timing) {
                    bps->timing = calloc(1, sizeof(BpsTimingSource));
                    if (!bps->timing) break;
                    
                    bps->timing->version = seg_version;
                    bps->timing->length = seg_length;
                    bps->timing->type = type;
                    bps->timing->tx_id = tx_id;
                    bps->timing->tx_freq_mhz = tx_freq;
                    bps->timing->fac_id = fac_id;
                    
                    bps->timing->sync_hierarchy = *pos++;
                    bps->timing->expected_accuracy_ns = ntohs(*(uint16_t*)pos);
                    pos += 2;
                    
                    uint8_t timing_byte = *pos++;
                    bps->timing->timing_source_used = (timing_byte >> 4) & 0x0F;
                    bps->timing->num_timing_sources = timing_byte & 0x0F;
                    
                    bps->timing->timing_sources = ntohs(*(uint16_t*)pos);
                    pos += 2;
                    
                    //printf("    Timing: hierarchy=%d, accuracy=%d ns, sources=0x%04X\n",
                    //       bps->timing->sync_hierarchy, 
                    //       bps->timing->expected_accuracy_ns,
                    //       bps->timing->timing_sources);
                }
                break;
            }
            
            case 0: { // Measurement
                if (!bps->measurement) {
                    bps->measurement = calloc(1, sizeof(BpsMeasurement));
                    if (!bps->measurement) break;
                    
                    bps->measurement->version = seg_version;
                    bps->measurement->length = seg_length;
                    bps->measurement->type = type;
                    bps->measurement->tx_id = tx_id;
                    bps->measurement->tx_freq_mhz = tx_freq;
                    bps->measurement->fac_id = fac_id;
                    
                    uint8_t flags = *pos++;
                    bps->measurement->forward_flag = (flags >> 7) & 0x01;
                    
                    // Read reported bootstrap time if forward_flag is set (96 bits = 12 bytes)
                    if (bps->measurement->forward_flag) {
                        bps->measurement->reported_bootstrap_time_sec = ntohl(*(uint32_t*)pos);
                        pos += 4;
                        
                        uint32_t reported_time_frac = ntohl(*(uint32_t*)pos);
                        pos += 4;
                        bps->measurement->reported_bootstrap_time_msec = (reported_time_frac >> 22) & 0x3FF;
                        bps->measurement->reported_bootstrap_time_usec = (reported_time_frac >> 12) & 0x3FF;
                        bps->measurement->reported_bootstrap_time_nsec = (reported_time_frac >> 2) & 0x3FF;
                        // 2 reserved bits
                        
                        bps->measurement->bootstrap_toa_offset = ntohl(*(uint32_t*)pos);
                        pos += 4;
                    }
                    
                    // Always read previous bootstrap time (96 bits = 12 bytes)
                    bps->measurement->prev_bootstrap_time_sec = ntohl(*(uint32_t*)pos);
                    pos += 4;
                    
                    uint32_t prev_time_frac = ntohl(*(uint32_t*)pos);
                    pos += 4;
                    bps->measurement->prev_bootstrap_time_msec = (prev_time_frac >> 22) & 0x3FF;
                    bps->measurement->prev_bootstrap_time_usec = (prev_time_frac >> 12) & 0x3FF;
                    bps->measurement->prev_bootstrap_time_nsec = (prev_time_frac >> 2) & 0x3FF;
                    // 2 reserved bits
                    
                    bps->measurement->prev_bootstrap_time_error_nsec = ntohl(*(uint32_t*)pos);
                    pos += 4;
                }
                break;
            }
            
            case 2: { // Description
                if (!bps->description) {
                    bps->description = calloc(1, sizeof(BpsDescription));
                    if (!bps->description) break;
                    
                    bps->description->version = seg_version;
                    bps->description->length = seg_length;
                    bps->description->type = type;
                    bps->description->tx_id = tx_id;
                    bps->description->tx_freq_mhz = tx_freq;
                    bps->description->fac_id = fac_id;
                    
                    uint16_t flags = ntohs(*(uint16_t*)pos);
                    pos += 2;
                    
                    bps->description->gain_flag = (flags >> 15) & 0x01;
                    bps->description->pos_flag = (flags >> 14) & 0x01;
                    bps->description->pow_flag = (flags >> 13) & 0x01;
                    bps->description->pattern_flag = (flags >> 12) & 0x01;
                    bps->description->max_gain_dir = flags & 0x03FF;
                    
                    if (bps->description->pos_flag) {
                        // Read as big-endian doubles
                        uint64_t lat_bits = ((uint64_t)ntohl(*(uint32_t*)pos) << 32) | ntohl(*(uint32_t*)(pos + 4));
                        memcpy(&bps->description->latitude, &lat_bits, sizeof(double));
                        pos += 8;
                        
                        uint64_t lon_bits = ((uint64_t)ntohl(*(uint32_t*)pos) << 32) | ntohl(*(uint32_t*)(pos + 4));
                        memcpy(&bps->description->longitude, &lon_bits, sizeof(double));
                        pos += 8;
                        
                        uint64_t height_bits = ((uint64_t)ntohl(*(uint32_t*)pos) << 32) | ntohl(*(uint32_t*)(pos + 4));
                        memcpy(&bps->description->height, &height_bits, sizeof(double));
                        pos += 8;
                    }
                    
                    if (bps->description->pow_flag) {
                        uint32_t power_bits = ntohl(*(uint32_t*)pos);
                        memcpy(&bps->description->power_kw, &power_bits, sizeof(float));
                        pos += 4;
                    }
                    
                    if (bps->description->pattern_flag) {
                        memcpy(bps->description->antenna_pattern, pos, 36);
                        pos += 36;
                    }
                    
                    /*printf("    Description: lat=%.6f, lon=%.6f, height=%.1fm, power=%.1fkW\n",
                           bps->description->latitude,
                           bps->description->longitude,
                           bps->description->height,
                           bps->description->power_kw);*/
                }
                break;
            }
        }
    }
    
    // Read CRC (last 4 bytes)
    if (pos + 4 <= payload + len) {
        bps->crc = ntohl(*(uint32_t*)pos);
    }
    
    return bps;
}

void free_bps_data(BpsData* bps) {
    if (!bps) return;
    free(bps->timing);
    free(bps->measurement);
    free(bps->description);
    free(bps);
}

int is_bps_service(const char* dest_ip, const char* dest_port) {
    // BPS uses multicast address 239.66.80.84 port 6062
    if (strcmp(dest_ip, "239.66.80.84") == 0 && strcmp(dest_port, "6062") == 0) {
        return 1;
    }
    return 0;
}

void generate_bps_html_section(FILE* f, BpsData* bps_data) {
    if (!bps_data) return;
    
    fprintf(f, "<details><summary>Broadcast Positioning System (BPS) - 239.66.80.84:6062</summary>\n");
    fprintf(f, "<div class='details-content'>\n");
    
    if (bps_data->timing) {
        BpsTimingSource* t = bps_data->timing;
        fprintf(f, "<h3>Timing Source Information</h3>\n");
        fprintf(f, "<table><tr><th>Parameter</th><th>Value</th></tr>\n");
        fprintf(f, "<tr><td><strong>TxID</strong></td><td>%u</td></tr>\n", t->tx_id);
        fprintf(f, "<tr><td><strong>Center Frequency</strong></td><td>%u MHz</td></tr>\n", t->tx_freq_mhz);
        fprintf(f, "<tr><td><strong>Facility ID</strong></td><td>%u</td></tr>\n", t->fac_id);
        fprintf(f, "<tr><td><strong>Sync Hierarchy</strong></td><td>%u</td></tr>\n", t->sync_hierarchy);
        fprintf(f, "<tr><td><strong>Expected Accuracy</strong></td><td>Within %u ns of UTC</td></tr>\n", 
                t->expected_accuracy_ns);
        
        // Decode timing sources
        fprintf(f, "<tr><td><strong>Timing Sources <u>Used</u></strong></td><td>");
        const char* source_names[] = {
            "NIST/USNO", "GPS", "Other Stations", "Local Clock", "eLORAN",
            "Reserved (5)", "Reserved (6)", "Reserved (7)", "Reserved (8)",
            "Reserved (9)", "Reserved (10)", "Reserved (11)", "Reserved (12)",
            "Reserved (13)", "Reserved (14)", "Ensemble"
        };

        int source_ids[16];
        int num_sources = t->num_timing_sources;
        if (num_sources > 16) num_sources = 16;

        for (int nibble_pos = 0; nibble_pos < num_sources; nibble_pos++) {
            source_ids[nibble_pos] = (t->timing_sources >> (nibble_pos * 4)) & 0x0F;
        }

        // Simple bubble sort
        for (int i = 0; i < num_sources - 1; i++) {
            for (int j = 0; j < num_sources - 1 - i; j++) {
                if (source_ids[j] > source_ids[j + 1]) {
                    int temp = source_ids[j];
                    source_ids[j] = source_ids[j + 1];
                    source_ids[j + 1] = temp;
                }
            }
        }

        int first = 1;
        for (int i = 0; i < num_sources; i++) {
            if (!first) fprintf(f, ", ");
            if (source_ids[i] == t->timing_source_used) {
                fprintf(f, "<strong><u>");
            }
            fprintf(f, "%s", source_names[source_ids[i]]);
            if (source_ids[i] == t->timing_source_used) {
                fprintf(f, "</u></strong>");
            }
            first = 0;
        }
        fprintf(f, "</td></tr>\n");
        fprintf(f, "</table>\n");
    }
    
    if (bps_data->measurement) {
        BpsMeasurement* m = bps_data->measurement;
        fprintf(f, "<h3>Measurement Information</h3>\n");
        fprintf(f, "<table><tr><th>Parameter</th><th>Value</th></tr>\n");
        fprintf(f, "<tr><td><strong>Forward Flag</strong></td><td>%s</td></tr>\n", 
                m->forward_flag ? "Yes (neighboring station data)" : "No (self measurement)");
        
        if (m->forward_flag) {
            fprintf(f, "<tr><td colspan='2'><strong>Reported Bootstrap Time (from neighbor)</strong></td></tr>\n");
            fprintf(f, "<tr><td style='padding-left: 20px;'>Timestamp</td><td>%u.%03u%03u%03u seconds</td></tr>\n",
                    m->reported_bootstrap_time_sec,
                    m->reported_bootstrap_time_msec,
                    m->reported_bootstrap_time_usec,
                    m->reported_bootstrap_time_nsec);
            fprintf(f, "<tr><td style='padding-left: 20px;'>TOA Offset</td><td>%d ns</td></tr>\n",
                    (int32_t)m->bootstrap_toa_offset);
        }
        
        fprintf(f, "<tr><td colspan='2'><strong>Previous Bootstrap Time (self)</strong></td></tr>\n");
        fprintf(f, "<tr><td style='padding-left: 20px;'>Timestamp</td><td>%u.%03u%03u%03u seconds</td></tr>\n",
                m->prev_bootstrap_time_sec,
                m->prev_bootstrap_time_msec,
                m->prev_bootstrap_time_usec,
                m->prev_bootstrap_time_nsec);
        fprintf(f, "<tr><td style='padding-left: 20px;'>Time Error</td><td>%d ns</td></tr>\n",
                (int32_t)m->prev_bootstrap_time_error_nsec);
        
        fprintf(f, "</table>\n");
    }
    
    if (bps_data->description) {
        BpsDescription* d = bps_data->description;
        fprintf(f, "<h3>Transmitter Description</h3>\n");
        fprintf(f, "<table><tr><th>Parameter</th><th>Value</th></tr>\n");
        
        if (d->pos_flag) {
            fprintf(f, "<tr><td><strong>Latitude</strong></td><td>%.4f°</td></tr>\n", d->latitude);
            fprintf(f, "<tr><td><strong>Longitude</strong></td><td>%.4f°</td></tr>\n", d->longitude);
            fprintf(f, "<tr><td><strong>Height AMSL</strong></td><td>%.1f m</td></tr>\n", d->height);
            fprintf(f, "<tr><td><strong>Map</strong></td><td><a href='https://www.google.com/maps?q=%.6f,%.6f' target='_blank'>View on Google Maps</a></td></tr>\n",
                    d->latitude, d->longitude);
        }
        
        if (d->pow_flag) {
            fprintf(f, "<tr><td><strong>Transmitter Power</strong></td><td>%.1f kW</td></tr>\n", d->power_kw);
        }
        
        fprintf(f, "</table>\n");
        
        if (d->pattern_flag) {
            fprintf(f, "<details style='margin-top: 10px;'><summary><strong>Antenna Pattern (View Data)</strong></summary>\n");
            fprintf(f, "<table style='margin: 10px; width: 100%%;'><tr><th>Azimuth</th><th>Value</th></tr>\n");
            
            uint64_t bit_buffer = 0;
            int bits_in_buffer = 0;
            int byte_pos = 0;
            
            for (int i = 0; i < 36; i++) {
                while (bits_in_buffer < 7 && byte_pos < 36) {
                    bit_buffer = (bit_buffer << 8) | d->antenna_pattern[byte_pos++];
                    bits_in_buffer += 8;
                }
                
                uint8_t value = (bit_buffer >> (bits_in_buffer - 7)) & 0x7F;
                bits_in_buffer -= 7;
                
                int azimuth = i * 10;
                fprintf(f, "<tr><td>%d°</td><td>%u</td></tr>\n", azimuth, value);
            }
            
            fprintf(f, "</table></details>\n");
        }
    }
    
    fprintf(f, "</div></details>\n");
}
