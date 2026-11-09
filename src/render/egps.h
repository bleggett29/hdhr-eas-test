/**
 * @file egps.h
 * @brief eGPS (Enhanced GPS) packet parsing and rendering for ATSC 3.0
 * 
 * Handles Cambium-style binary GPS packets transmitted via ROUTE protocol.
 * Packet IDs:
 *   0x0806 - GPS position/status data
 *   0x07DF - Almanac/bulk orbital data
 */

#ifndef EGPS_H
#define EGPS_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

// Include structures.h for EgpsData and related struct definitions
#include "structures.h"

// Constants
#define MAX_EGPS_STREAMS 100
#define EGPS_MAGIC 0xBCA1
#define EGPS_ID_GPS 0x0806
#define EGPS_ID_ALMANAC 0x07DF

// Global eGPS data storage - defined in egps.c
extern EgpsData* g_egps_data[MAX_EGPS_STREAMS];
extern int g_egps_data_count;

/**
 * @brief Parse a single eGPS Cambium-style packet
 * 
 * Packet structure:
 * Header (8 bytes):
 *   0x00: Magic (0xBCA1)
 *   0x02: Length (UINT16) - bytes following this field
 *   0x04: ID (proprietary, e.g. 0x0806 = GPS, 0x07DF = Almanac)
 *   0x06 bit 7: Encryption flag (1 = encrypted)
 *   0x06 bits 6-0 + 0x07: Remaining length (15 bits)
 * 
 * @param data Raw packet data
 * @param len Length of data
 * @return Parsed location fix or NULL on error
 */
EgpsLocationFix* parse_egps_packet(const uint8_t* data, size_t len);

/**
 * @brief Parse multiple eGPS packets from a data stream
 * 
 * @param data Raw data stream containing one or more packets
 * @param len Length of data
 * @param dest_ip Destination IP address (for identification)
 * @param dest_port Destination port (for identification)
 * @return EgpsData structure with parsed packets, or NULL on error
 */
EgpsData* parse_egps_stream(const uint8_t* data, size_t len, 
                            const char* dest_ip, const char* dest_port);

/**
 * @brief Free eGPS data structure and all associated memory
 * 
 * @param data EgpsData structure to free
 */
void free_egps_data(EgpsData* data);

/**
 * @brief Render eGPS data as HTML
 * 
 * Generates HTML output showing:
 * - Packets with ID, encryption flag, offset, length, and hex dump
 * - Full raw hex dump (collapsed)
 * 
 * @param f Output file handle
 * @param egps eGPS data to render
 * @return 1 if content was rendered, 0 if no data
 */
int render_egps_html(FILE* f, EgpsData* egps);

/**
 * @brief Find eGPS data for a given destination
 * 
 * @param dest_ip Destination IP to search for
 * @param dest_port Destination port to search for
 * @return EgpsData pointer if found, NULL otherwise
 */
EgpsData* find_egps_data(const char* dest_ip, const char* dest_port);

/**
 * @brief Store or append eGPS data to global storage
 * 
 * If data for this destination already exists, appends to it.
 * Otherwise creates a new entry.
 * 
 * @param egps EgpsData to store (ownership transferred on success)
 * @return 1 on success, 0 on failure (caller must free egps on failure)
 */
int store_egps_data(EgpsData* egps);

/**
 * @brief Free all global eGPS data
 */
void free_all_egps_data(void);

#endif /* EGPS_H */
