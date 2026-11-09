#ifndef CRYPTO_H
#define CRYPTO_H

#include <stdio.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/asn1.h>
#include <openssl/bn.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include "structures.h"
#include "utility.h"

// DRM key ID structure
typedef struct DrmKeyId {
    char keyId[64];  // Hex representation of key ID
    struct DrmKeyId* next;
} DrmKeyId;

// DRM information structure
typedef struct DrmInfo {
    char schemeIdUri[128];
    char systemName[32];  // "Widevine", "PlayReady", etc.
    char contentId[128];
    char licenseUrl[256];
    char groupLicenseUrl[256];
    char psshData[1024];  // Base64 PSSH data
    int keyCount;
    DrmKeyId* keyIds;
    struct DrmInfo* next;
} DrmInfo;

// Certificate information structure
typedef struct CertificateInfo {
    char subject[512];
    char issuer[512];
    char serial_number[64];
    char not_before[32];
    char not_after[32];
    char signature_algorithm[64];
    char public_key_algorithm[64];
    int key_size;
    char fingerprint_sha1[64];
    char fingerprint_sha256[96];
    int is_ca;
    int is_self_signed;
    struct CertificateInfo* next;
} CertificateInfo;

// CDT data structure
typedef struct {
    char ocspRefresh[32];
    int certificate_count;
    CertificateInfo* certificates;
} CdtData;

// Function prototypes
CertificateInfo* parse_x509_certificate(const char* cert_data, size_t cert_len);
void free_certificate_info(CertificateInfo* cert);
int check_ca_certificate(X509* cert);
void calculate_fingerprint(X509* cert, const EVP_MD* md, char* output, size_t output_size);
DrmInfo* parse_drm_content_protection(xmlNodePtr cp_node);
CdtData* parse_cdt(xmlDocPtr doc);
void generate_cdt_html_section(FILE *f, int g_lls_table_count, LlsTable* g_lls_tables);

#endif // CRYPTO_H
