#ifndef STRUCTURES_H
#define STRUCTURES_H

#include <stdint.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <stdbool.h>

// Maximum limits
#define MAX_PAYLOAD_SIZE 65536
#define MAX_TABLES 100000
#define MAX_SERVICES 5000
#define MAX_UNIQUE_PIDS 2000
#define MAX_DATA_STREAMS 1000

// Table type enumeration
typedef enum {
    TABLE_TYPE_UNKNOWN,
    TABLE_TYPE_SLT,
    TABLE_TYPE_SYSTEM_TIME,
    TABLE_TYPE_RRT,
    TABLE_TYPE_UCT,
    TABLE_TYPE_CDT,
    TABLE_TYPE_UDST,
    TABLE_TYPE_SIGNATURE,
    TABLE_TYPE_FDT,
    TABLE_TYPE_EFDT,
    TABLE_TYPE_MPD,
    TABLE_TYPE_MP_TABLE_XML,
    TABLE_TYPE_MP_TABLE_BINARY,
    TABLE_TYPE_MP_TABLE_PATTERN_MATCHED,
    TABLE_TYPE_HELD,
    TABLE_TYPE_ESG_FRAGMENT,
    TABLE_TYPE_SGDD,
    TABLE_TYPE_USER_SERVICE_DESCRIPTION,
    TABLE_TYPE_SERVICE_SIGNALING,
    TABLE_TYPE_STSID,
    TABLE_TYPE_USBD,
    TABLE_TYPE_USD,
    TABLE_TYPE_DWD,
    TABLE_TYPE_LMT,
    TABLE_TYPE_EGPS,
    TABLE_TYPE_UDS,
    TABLE_TYPE_AEAT,
    TABLE_TYPE_UNHANDLED
} TableType;

// Service destination structure
typedef struct {
    struct in_addr ip_addr;
    uint16_t port;
    char destinationIpStr[40];
    char destinationPortStr[16];
    char protocol[8];
    uint16_t mmtSignalingPacketId;
    char serviceCategory[8];
    int isEsgService;
    int isEgpsService;
    char egpsContextId[128];      // appContextIdList for eGPS identification
} ServiceDestination;

// Data usage tracking
typedef struct DataUsageEntry {
    char destinationIp[40];
    char destinationPort[16];
    uint32_t tsi_or_packet_id;
    uint64_t total_bytes;
    uint32_t packet_count;
    char description[128];
    char stream_type[16];
    int is_lls;
    int is_signaling;
    // Per-stream timing for bitrate calculation (ALP-PCAP only)
    struct timeval first_packet_time;
    struct timeval last_packet_time;
    int timing_valid;
    // Sample payload for unknown stream analysis
    uint8_t sample_payload[512];
    int sample_payload_len;
    int sample_collected;
    // Bytes per fixed time window since capture start (for min/max bitrate and
    // the sparkline). Owned by the entry; merged on consolidation.
    uint32_t* rate_bins;
    uint32_t rate_bin_count;
    uint32_t rate_bin_cap;
} DataUsageEntry;

// Packet ID logging
typedef struct {
    uint16_t id;
    int count;
} PacketIdLog;

// For SLT: A single service entry
typedef struct ServiceInfo {
    char serviceId[16];
    char majorChannelNo[16];
    char minorChannelNo[16];
    char shortServiceName[64];
    char globalServiceID[128];
    char slsDestinationIpAddress[40];
    char slsDestinationUdpPort[16];
    char slsSourceIpAddress[40];
    char slsProtocol[8];
    char slsMmtpPacketId[16];
    char slsMajorProtocolVersion[8];
    char slsMinorProtocolVersion[8];
    char serviceCategory[8];
    char sltSvcSeqNum[8];
    int protected;
    int broadbandAccessRequired;
    int hidden;
    int hideInGuide;
    struct ServiceInfo* next;
} ServiceInfo;

// MMT media parameters
typedef struct {
    char resolution[32];
    char scan_type[16];
    char frame_rate[16];
    char audio_channels[16];
    char audio_codec[64];   // Increased for full codec strings like "ac-4.02.01.01.02.03"
    char video_codec[64];   // Increased for full codec strings like "hev1.2.3.L240.BA10"
    char hdr_wcg_info[32];
    int audio_bitrate_kbps;  // Bitrate in kbps (0 if unknown)
} MmtMediaParams;

typedef struct {
    char destIp[40];
    char destPort[16];
    uint16_t packet_id;
    MmtMediaParams params;
} MmtMediaParamsCache;

// Generic table storage
typedef struct {
    char* content_id;
    void* parsed_data;
    TableType type;
    char destinationIp[40];
    char destinationPort[16];
    // SMT (Signed Multi-Table) support
    int is_in_smt;              // 1 if this table was extracted from an SMT
    int smt_signature_index;    // Index of associated TABLE_TYPE_SIGNATURE entry (-1 if none)
} LlsTable;

// Signature algorithm identifiers (for SMT)
typedef enum {
    SIG_ALG_UNKNOWN = 0,
    SIG_ALG_RSA_SHA256 = 1,
    SIG_ALG_RSA_SHA384 = 2,
    SIG_ALG_RSA_SHA512 = 3,
    SIG_ALG_ECDSA_SHA256 = 4,
    SIG_ALG_ECDSA_SHA384 = 5
} SignatureAlgorithm;

// Enhanced signature data for SMT
typedef struct {
    int signature_len;              // Total signature block length
    SignatureAlgorithm algorithm;   // Detected signature algorithm
    char algorithm_name[32];        // Human-readable: "RSA-SHA256", etc.
    int tables_covered;             // Number of tables covered by this signature
    int is_cms_valid;               // 1 if structure looks like valid CMS
} SignatureData;

// Video Stream Properties Descriptor (VSPD) - A/331 Section 7.2.3.2
typedef struct {
    uint8_t codec_code;
    char codec_name[64];
    uint16_t horizontal_size;
    uint16_t vertical_size;
    uint8_t aspect_ratio;
    uint8_t frame_rate_code;
    char frame_rate[16];
    uint8_t color_depth;
    uint8_t  chroma_format;        // Chroma subsampling (0=mono, 1=4:2:0, 2=4:2:2, 3=4:4:4)
    uint8_t hdr_info;
    uint8_t profile_idc;
    char profile_name[64];
    uint8_t level_idc;
    float level_value;
    uint8_t tier_flag;
    uint8_t progressive_flag;
    uint8_t interlaced_flag;
} VspdData;

// Audio Stream Properties Descriptor (ASPD) - A/331 Section 7.2.3.4
typedef struct {
    uint8_t codec_code;
    char codec_name[64];
    uint8_t num_channels;
    uint32_t sample_rate;
    char channel_config[64];
    char language[64];
    uint8_t num_presentations;
} AspdData;

// Caption Asset Descriptor (CAD) - A/331 Section 7.2.3.5
typedef struct CadEntry {
    char language[64];
    uint8_t easy_reader;
    uint8_t wide_aspect_ratio;
    uint16_t service_number;
    uint8_t role;
    char role_str[32];
    uint8_t aspect_ratio;
    char aspect_str[16];
    uint8_t profile;
    char profile_str[16];
    uint8_t support_3d;
    struct CadEntry* next;
} CadEntry;

typedef struct {
    CadEntry* head;
} CadData;

// Storage for per-service descriptors
typedef struct ServiceDescriptors {
    char destinationIp[40];
    char destinationPort[16];
    VspdData* vspd;
    AspdData* aspd;
    CadData* cad;
} ServiceDescriptors;

typedef struct {
    uint8_t version;
    uint8_t packet_counter_flag;
    uint8_t fec_type;
    uint8_t extension_flag;
    uint8_t rap_flag;
    uint8_t qos_flag;
    uint16_t packet_id;
    uint32_t timestamp;
    uint32_t packet_sequence_number;
    uint16_t packet_counter;
    uint8_t qos_classifier;
    uint8_t payload_type;
    uint32_t payload_length;
    uint16_t extension_type;
    uint16_t extension_length;
    uint8_t* extension_data;
} mmt_packet_header_t;

// MPU header structure
typedef struct {
    uint32_t mpu_sequence_number;
    uint8_t fragmentation_indicator;
    uint8_t fragment_type;
    const uint8_t* mfu_data;
    size_t mfu_data_length;
} MpuHeader;

// For MMT-specific USD data (BundleDescriptionMMT)
typedef struct UsdEntryMmt {
    char id[128];
    char contentType[128];
    char version[16];
    struct UsdEntryMmt* next;
} UsdEntryMmt;

typedef struct {
    UsdEntryMmt* head;
} UsdbData;

// For MMT MP Table
typedef struct MptAsset {
    char assetId[256];
    char assetType[64];
    char packetId[16];
    struct MptAsset* next;
} MptAsset;

typedef struct {
    char mptPackageId[256];
    MptAsset* head_asset;
} MpTableData;

typedef struct BinaryMptAsset {
    char assetId[256];
    char assetType[64];
    char codec[64];
    uint16_t packetId;
    struct BinaryMptAsset* next;
} BinaryMptAsset;

typedef struct {
    BinaryMptAsset* head_asset;
} BinaryMptData;

typedef struct {
    char asset_id[128];
    char asset_type[5];      // FourCC like "hvc1", "ac-4"
    uint16_t packet_id;
    bool is_default;
    uint32_t asset_id_scheme;  // 0=UUID, 1=URI
} MptAssetInfo;

typedef struct {
    char package_id[128];
    uint8_t version;
    uint8_t table_id;
    uint8_t num_assets;
    MptAssetInfo assets[32];
    char source_ip[64];
    char source_port[16];
    time_t last_updated;
    bool is_complete;
} MptTable;

// For USD (User Service Description)
typedef struct UsdAsset {
    char assetId[128];
    char assetType[64];
    char role[64];
    char lang[16];
    struct UsdAsset* next;
} UsdAsset;

typedef struct UsdComponent {
    char componentId[128];
    int componentType;
    int componentRole;
    char description[256];
    struct UsdComponent* next;
} UsdComponent;

typedef struct UsdData {
    char serviceId[64];
    char serviceName[256];
    char serviceDescription[512];
    char serviceCategory[16];
    char globalServiceId[128];
    char mmtPackageId[128];
    UsdComponent* components;
    UsdAsset* assets;
} UsdData;

typedef struct {
    uint16_t message_id;
    int count;
    int parsed_count;
    char first_seen_ip[64];
    char first_seen_port[16];
} MmtMessageStats;

// RRT (Rating Region Table) structures - A/331 Section 6.4
typedef struct RrtRatingValue {
    char abbrev_name[32];           // Abbreviated rating name (e.g., "TV-MA")
    char full_name[128];            // Full rating name (e.g., "Mature Audience Only")
    struct RrtRatingValue* next;
} RrtRatingValue;

typedef struct RrtDimension {
    char dimension_name[64];        // e.g., "TV Rating", "MPAA"
    int graduated_scale;            // 1 if ratings are in order of increasing restriction
    int num_values;
    RrtRatingValue* values;
    struct RrtDimension* next;
} RrtDimension;

typedef struct RrtRegion {
    int region_id;                  // Rating region (1=US, 2=Canada, etc.)
    char region_name[128];          // Human-readable region name
    int num_dimensions;
    RrtDimension* dimensions;
    struct RrtRegion* next;
} RrtRegion;

typedef struct {
    int num_regions;
    RrtRegion* regions;
} RrtData;

// Unhandled/unrecognized table data - stores basic info for tables we don't fully parse
typedef struct {
    char root_element[64];      // XML root element name (e.g., "AEAT", "OnscreenMessageNotification")
    char namespace_uri[256];    // XML namespace if present
} UnhandledTableData;

// eGPS Location Fix - individual position report from Cambium-style packets
typedef struct EgpsLocationFix {
    // Header fields
    uint16_t magic;               // Should be 0xBCA1 (Basic Cambium 1)
    uint16_t length;              // Number of bytes following
    uint16_t msg_type;            // 0x0806 = GPS Status/Geolocation
    uint8_t flag;                 // 0x80 = Valid, 0x00 = Invalid
    uint8_t payload_len;          // Length of GPS payload
    
    // GPS Payload fields
    uint16_t status;              // Status/fix type (e.g., 0x0708)
    uint32_t tow;                 // Time of Week (internal tick counter)
    int32_t latitude;             // Latitude × 10^7 (e.g., 268066080 = 26.806608°)
    int32_t longitude;            // Longitude × 10^7 (e.g., -908955290 = -90.895529°)
    int32_t altitude;             // Height (in centimeters or decimeters)
    
    // Derived/parsed values
    double lat_degrees;           // Parsed latitude in degrees
    double lon_degrees;           // Parsed longitude in degrees
    double alt_meters;            // Parsed altitude in meters
    int is_valid;                 // 1 if fix is valid
    
    // Additional tracking data (if available)
    uint8_t misc_data[64];        // Variable tracking data, visible sats, DOP
    int misc_data_len;
    
    time_t receive_time;          // When this fix was received
    struct EgpsLocationFix* next;
} EgpsLocationFix;

// eGPS (enhanced GPS / GNSS Assistance Data) structures - A/331 App-Based Service
typedef struct EgpsSatelliteInfo {
    uint8_t gnss_system_id;          // GNSS constellation (e.g., 0=GPS, 1=GLONASS, etc.)
    uint8_t satellite_id;             // PRN/SV number
    uint32_t reference_time;          // GPS Time of Week (seconds)
    uint16_t validity_duration;       // Duration in seconds
    // Ephemeris parameters (scaled integers from binary)
    uint32_t semi_major_axis;         // a - orbital semi-major axis
    uint32_t eccentricity;            // e - orbital eccentricity  
    uint32_t inclination;             // i - inclination angle
    uint32_t raan;                    // Right Ascension of Ascending Node
    uint32_t arg_perigee;             // Argument of perigee
    int has_ephemeris;                // Flag indicating ephemeris data present
    struct EgpsSatelliteInfo* next;
} EgpsSatelliteInfo;

typedef struct {
    uint32_t toi;                     // Transport Object Identifier
    uint32_t tsi;                     // Transport Session Identifier
    size_t raw_size;                  // Size of raw binary data
    uint8_t* raw_data;                // Copy of raw binary (for hex dump display)
    int satellite_count;              // Number of satellites parsed
    EgpsSatelliteInfo* satellites;    // Linked list of satellite info (legacy)
    
    // New geolocation data from Cambium-style packets
    int location_fix_count;           // Number of location fixes parsed
    EgpsLocationFix* location_fixes;  // Linked list of location fixes
    EgpsLocationFix* latest_fix;      // Most recent valid fix (for quick access)
    
    time_t timestamp;                 // When this data was received
    int parse_status;                 // 0=success, 1=partial, -1=failed
    char content_type[64];            // From FDT if available
    char app_context_id[32];          // appContextIdList value
    char dest_ip[40];                 // Destination IP for this eGPS stream
    char dest_port[16];               // Destination port
} EgpsData;

// User Defined Stream (UDS) - LLS table for broadcaster-defined data streams
typedef struct UdsData {
    char contextId[128];              // Application/vendor identifier
    char destIP[40];                  // Destination IP address
    char destPort[16];                // Destination port
    char maxBitrate[32];              // Maximum bitrate
    char name[128];                   // Human-readable name
    // Sample payload from the stream (if found)
    uint8_t sample_payload[256];
    int sample_payload_len;
    int sample_collected;
    struct UdsData* next;             // For linked list in UDST
} UdsData;

// AEAT Media entry
typedef struct AeatMedia {
    char url[512];
    char contentType[64];
    char contentLength[32];
    char mediaType[64];               // e.g., "AEAtextAudio"
    char mediaDesc[256];
    char lang[16];
    struct AeatMedia* next;
} AeatMedia;

// AEAT AEA (Alert Entry) structure
typedef struct AeaEntry {
    char aeaId[128];
    char aeaType[32];                 // "alert", "update", "cancel"
    char audience[32];                // "public", "private"
    char category[64];                // "Weather", "Security", etc.
    char issuer[128];
    char priority[8];                 // 1-5
    char wakeup[8];                   // "true"/"false"
    // Header info
    char effective[64];               // ISO datetime
    char expires[64];                 // ISO datetime
    char eventCode[16];               // SAME code like "FFW"
    char eventCodeType[16];           // "SAME"
    char eventDesc[256];              // Human-readable event description
    char eventDescLang[16];
    char location[64];                // FIPS code or other location
    char locationType[32];            // "FIPS", "PSID", etc.
    // Alert text
    char aeaText[2048];
    char aeaTextLang[16];
    // Media attachments
    AeatMedia* head_media;
    struct AeaEntry* next;
} AeaEntry;

// AEAT (Advanced Emergency Alert Table) data
typedef struct {
    AeaEntry* head_aea;
    int aea_count;
} AeatData;

#endif // STRUCTURES_H
