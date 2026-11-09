#ifndef MMT_H
#define MMT_H

#include "structures.h"
#include <stdio.h>
#include <stdbool.h>
#include <libavcodec/avcodec.h>
#include <libavutil/mem.h>
#include <libavutil/avutil.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <libxml/parser.h>
#include <libxml/tree.h>

// Debug flag
#define DEBUG_MMT 0

// MMT packet types
#define MMT_PACKET_TYPE_IPV4 0x0
#define MMT_PACKET_TYPE_IPV6 0x1
#define MMT_PACKET_TYPE_GFP  0x2
#define MMT_PACKET_TYPE_HEADER_COMPRESSION 0x3

// MMT payload types
#define MMT_PAYLOAD_TYPE_MPU 0x0
#define MMT_PAYLOAD_TYPE_GENERIC_OBJECT 0x1
#define MMT_PAYLOAD_TYPE_SIGNALING_MESSAGE 0x2

// MMT Descriptor Tags (ATSC A/331 and ISO/IEC 23008-1)
#define MMT_DESCRIPTOR_USD      0x8001
#define MMT_DESCRIPTOR_MPD      0x8002
#define MMT_DESCRIPTOR_HELD     0x8003
#define MMT_DESCRIPTOR_AEI      0x8004
#define MMT_DESCRIPTOR_VSPD     0x8005
#define MMT_DESCRIPTOR_INED     0x8007
#define MMT_DESCRIPTOR_CAD      0x8008
#define MMT_DESCRIPTOR_ASPD     0x8009

// Array size limits
#define MAX_SERVICE_DESCRIPTORS 32
#define MAX_MPT_TABLES 16
#define MAX_MESSAGE_TYPES 256

extern int g_packet_count;
extern int g_lls_table_count;
extern LlsTable g_lls_tables[];

// Packet parsing
int parse_mmt_packet_header(const uint8_t* buffer, size_t length, mmt_packet_header_t* header);
int parse_mpu_header(const uint8_t* buffer, size_t length, MpuHeader* header);
void free_mmt_packet_header(mmt_packet_header_t* header);

// Payload processing
void process_enhanced_mmt_payload(const u_char* payload, int len, ServiceDestination* dest_info);
void process_enhanced_mmt_signaling_payload(const uint8_t* buffer, size_t size, 
                                            const char* destIp, const char* destPort);
void process_mmt_signaling_payload(const uint8_t* buffer, size_t size, 
                                    const char* destIp, const char* destPort);

// Binary message parsing
int parse_binary_mmt_messages(const uint8_t* buffer, size_t size, 
                               const char* destIp, const char* destPort);

// Media parameter extraction
void extract_hevc_params(const uint8_t* data, size_t len, MmtMediaParams* params);
void extract_ac4_params(const uint8_t* data, size_t len, MmtMediaParams* params);
void extract_mmt_media_params_from_mpu(const uint8_t* payload, size_t length, 
                                        const char* asset_type, MmtMediaParams* params,
                                        const char* dest_ip, const char* dest_port);

// Parameter caching
void cache_mmt_params(const char* dest_ip, const char* dest_port, 
                      uint16_t packet_id, MmtMediaParams* params);
MmtMediaParams* get_cached_mmt_params(const char* dest_ip, const char* dest_port, 
                                       uint16_t packet_id);
void print_mmt_params_cache(void);

// Packet ID tracking
void log_mmt_packet_id(uint16_t packet_id);
void print_packet_id_log(void);

// Message tracking
void track_mmt_message(uint16_t message_id, const char* destIp, 
                       const char* destPort, bool was_parsed);
void print_mmt_message_stats(void);

// Utilities
int is_likely_mmt_packet(const uint8_t* payload, int len);
int is_mmt_signaling_complete(const uint8_t* buffer, size_t size);

// HTML report generation
void display_mmt_stream_parameters(FILE* f, ServiceInfo* service, int* total_audio_streams);
void generate_mmt_descriptor_details(FILE* f, ServiceInfo* service, int instance_num);

// Global accessors (for accessing module-level state)
ServiceDescriptors* get_service_descriptors(void);
int get_service_descriptor_count(void);
MptTable* get_mpt_tables(void);
int get_mpt_table_count(void);
void increment_mpt_table_count(void);

ServiceDescriptors* get_service_descriptors(void);
int get_service_descriptor_count(void);
ServiceDescriptors* get_or_create_service_descriptor(const char* dest_ip, const char* dest_port);

void parse_mpi_message_improved(const uint8_t* pos, size_t msg_length, 
                                const char* destIp, const char* destPort);



// Functions from a3render.c that mmt.c needs to call
const char* get_stream_description(const char* destIp, const char* destPort, uint32_t tsi_or_pid);
void record_data_usage(const char* dest_ip, const char* dest_port, uint32_t tsi_or_packet_id,
                       uint32_t packet_bytes, const char* description, const struct timeval* timestamp,
                       const uint8_t* payload, int payload_len);
const char* get_media_type_from_mpt(const char* dest_ip, const char* dest_port, uint32_t packet_id);
char* decompress_gzip(const u_char *compressed_data, int len, int *decompressed_size, int* consumed_size);
int parse_xml(const char* xml_data, int len, TableType* type, void** parsed_data, const char* source_id);
void store_unique_table(const char* content, int len, TableType type, void* parsed_data, 
                        const char* destIp, const char* destPort, int is_in_smt, int smt_sig_index);
char* extract_node_as_xml(xmlNodePtr node);
int is_gzip_complete(const uint8_t* buffer, size_t size);
int is_xml_complete(const char* buffer, size_t size);

#endif // MMT_H
