#ifndef ESG_H
#define ESG_H

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <stdio.h>
#include <time.h>

// ESG data structures
typedef struct EsgMediaAsset {
    char uri[512];
    char contentType[64];
    char usage[32];
    char width[16];
    char height[16];
    struct EsgMediaAsset* next;
} EsgMediaAsset;

typedef struct EsgContentRating {
    char scheme[64];
    char value[128];
    struct EsgContentRating* next;
} EsgContentRating;

typedef struct EsgProgramInfo {
    char id[128];
    char title[256];
    char description[1024];
    char startTime[32];
    char duration[32];
    char genre[128];
    char serviceRef[256];
    EsgContentRating* ratings;
    EsgMediaAsset* icons;
    struct EsgProgramInfo* next;
} EsgProgramInfo;

typedef struct EsgScheduleEvent {
    char startTime[32];
    char duration[32];
    char programId[128];
    struct EsgScheduleEvent* next;
} EsgScheduleEvent;

typedef struct EsgServiceInfo {
    char id[128];
    char name[256];
    char serviceStatus[16];
    char majorChannel[16];
    char minorChannel[16];
    char genre[128];
    char description[512];
    EsgMediaAsset* icons;
    EsgScheduleEvent* schedule;
    struct EsgServiceInfo* next;
} EsgServiceInfo;

typedef struct {
    EsgServiceInfo* services;
    EsgProgramInfo* programs;
} EsgFragmentData;

// SGDD structures
typedef struct SgddFragment {
    char transportId[32];
    char fragmentId[512];
    char version[32];
    char fragmentEncoding[16];
    char fragmentType[16];
    struct SgddFragment* next;
} SgddFragment;

typedef struct SgddDeliveryUnit {
    char contentLocation[256];
    char transportObjectId[32];
    SgddFragment* fragments;
    struct SgddDeliveryUnit* next;
} SgddDeliveryUnit;

typedef struct SgddEntry {
    char startTime[32];
    char endTime[32];
    char serviceCriteria[512];
    char ipAddress[64];
    char port[16];
    char transmissionSessionId[32];
    char hasFdt[16];
    SgddDeliveryUnit* deliveryUnits;
    struct SgddEntry* next;
} SgddEntry;

typedef struct {
    char id[128];
    char version[32];
    SgddEntry* entries;
} SgddData;

// ============================================================================
// ESG DISPLAY FUNCTIONS AND STRUCTURES
// ============================================================================

// LLS table reference structure for ESG display
typedef struct EsgLlsTableRef {
    int type;
    void* parsed_data;
    char* content_id;       // Raw XML content for display
    char destinationIp[40];
    char destinationPort[16];
} EsgLlsTableRef;

// ESG display result structure
typedef struct EsgDisplayResult {
    int fragment_count;
    int service_count;
    int program_count;
    int success;
} EsgDisplayResult;

// Structure to track raw XML by service (for "Raw XML" display feature)
typedef struct EsgServiceXmlTracker {
    char service_id[256];
    char** service_xmls;
    int service_xml_count;
    char** schedule_xmls;
    int schedule_xml_count;
    char** content_xmls;
    int content_xml_count;
} EsgServiceXmlTracker;

// Extended merged ESG data structure
typedef struct EsgMergedData {
    EsgServiceInfo* services;
    EsgProgramInfo* programs;
    int fragment_count;
    EsgServiceXmlTracker* xml_trackers;
    int xml_tracker_count;
    // Track orphaned/unmatched fragments for diagnostic display
    char** orphaned_xmls;
    char* orphaned_types;  // 'S'=Service, 'C'=Content, 'H'=Schedule, 'U'=Unknown
    int orphaned_xml_count;
} EsgMergedData;

// Function prototypes - parsing
EsgFragmentData* parse_esg_service_fragment(xmlDocPtr doc);
SgddData* parse_sgdd(xmlDocPtr doc);
void parse_esg_content(xmlNodePtr content_node, EsgFragmentData* esg_data);
void parse_esg_service(xmlNodePtr service_node, EsgFragmentData* esg_data);
void parse_esg_program(xmlNodePtr program_node, EsgFragmentData* esg_data);
void parse_esg_schedule(xmlNodePtr schedule_node, EsgFragmentData* esg_data);
void parse_esg_service_bundle(xmlNodePtr bundle_node, EsgFragmentData* esg_data);
EsgMediaAsset* parse_esg_media_asset(xmlNodePtr asset_node, const char* usage_type);
EsgContentRating* parse_esg_content_rating(xmlNodePtr rating_node);
void parse_esg_schedule_events(xmlNodePtr schedule_node, EsgScheduleEvent** head, EsgScheduleEvent** tail);
EsgFragmentData* correlate_esg_fragments(const char* destIp, const char* destPort, 
                                          void* lls_tables, int lls_table_count);
EsgContentRating* parse_atsc3_content_advisory(xmlNodePtr advisory_node);
int count_services(EsgServiceInfo* head);
int count_programs(EsgProgramInfo* head);
void free_esg_data(EsgFragmentData* data);

// Function prototypes - display
EsgDisplayResult render_esg_to_html(FILE* f, 
                                     const char* service_sls_ip, 
                                     const char* service_sls_port,
                                     EsgLlsTableRef* lls_tables, 
                                     int lls_table_count,
                                     void (*fprintf_escaped_xml_fn)(FILE*, const char*));

SgddData* find_sgdd_for_service(const char* service_ip, 
                                 const char* service_port,
                                 EsgLlsTableRef* lls_tables, 
                                 int lls_table_count);

EsgMergedData* merge_esg_fragments_for_display(const char* service_ip,
                                                const char* service_port,
                                                EsgLlsTableRef* lls_tables,
                                                int lls_table_count);

void free_esg_merged_data(EsgMergedData* data);

#endif // ESG_H
