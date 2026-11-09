#include "crypto.h"
#include "structures.h"
#include "utility.h"  
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <libxml/parser.h>
#include <libxml/tree.h>

CertificateInfo* parse_x509_certificate(const char* cert_data, size_t cert_len) {
    if (!cert_data || cert_len == 0) {
        return NULL;
    }
    
    CertificateInfo* cert_info = calloc(1, sizeof(CertificateInfo));
    if (!cert_info) {
        return NULL;
    }
    
    // Check if this looks like base64 data (common in XML)
    int is_base64 = 1;
    for (size_t i = 0; i < cert_len && i < 100; i++) {
        char c = cert_data[i];
        if (!(isalnum(c) || c == '+' || c == '/' || c == '=' || isspace(c))) {
            is_base64 = 0;
            break;
        }
    }
    
    // If it's base64, we need to decode it first
    BIO* bio = NULL;
    BIO* b64 = NULL;
    
    if (is_base64) {
        bio = BIO_new_mem_buf((void*)cert_data, cert_len);
        b64 = BIO_new(BIO_f_base64());
        BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
        bio = BIO_push(b64, bio);
    } else {
        bio = BIO_new_mem_buf((void*)cert_data, cert_len);
    }
    
    if (!bio) {
        free(cert_info);
        return NULL;
    }
    
    X509* cert = NULL;
    
    // Try DER format first (more common for base64 decoded data)
    cert = d2i_X509_bio(bio, NULL);
    if (!cert) {
        // Reset BIO and try PEM format
        (void)BIO_reset(bio);
        cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    }
    
    if (!cert) {
        BIO_free_all(bio);
        free(cert_info);
        return NULL;
    }
    
    // Extract subject
    X509_NAME* subject = X509_get_subject_name(cert);
    if (subject) {
        char* subject_str = X509_NAME_oneline(subject, NULL, 0);
        if (subject_str) {
            strncpy(cert_info->subject, subject_str, sizeof(cert_info->subject) - 1);
            cert_info->subject[sizeof(cert_info->subject) - 1] = '\0';
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
            OPENSSL_free(subject_str);
#else
            free(subject_str);
#endif
        }
    }
    
    // Extract issuer
    X509_NAME* issuer = X509_get_issuer_name(cert);
    if (issuer) {
        char* issuer_str = X509_NAME_oneline(issuer, NULL, 0);
        if (issuer_str) {
            strncpy(cert_info->issuer, issuer_str, sizeof(cert_info->issuer) - 1);
            cert_info->issuer[sizeof(cert_info->issuer) - 1] = '\0';
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
            OPENSSL_free(issuer_str);
#else
            free(issuer_str);
#endif
        }
    }
    
    // Extract serial number
    ASN1_INTEGER* serial = X509_get_serialNumber(cert);
    if (serial) {
        BIGNUM* bn = ASN1_INTEGER_to_BN(serial, NULL);
        if (bn) {
            char* serial_str = BN_bn2hex(bn);
            if (serial_str) {
                strncpy(cert_info->serial_number, serial_str, sizeof(cert_info->serial_number) - 1);
                cert_info->serial_number[sizeof(cert_info->serial_number) - 1] = '\0';
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
                OPENSSL_free(serial_str);
#else
                free(serial_str);
#endif
            }
            BN_free(bn);
        }
    }
    
    // Extract validity dates
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    const ASN1_TIME* not_before = X509_get0_notBefore(cert);
    const ASN1_TIME* not_after = X509_get0_notAfter(cert);
#else
    ASN1_TIME* not_before = X509_get_notBefore(cert);
    ASN1_TIME* not_after = X509_get_notAfter(cert);
#endif
    
    if (not_before) {
        BIO* date_bio = BIO_new(BIO_s_mem());
        if (date_bio) {
            ASN1_TIME_print(date_bio, not_before);
            int len = BIO_read(date_bio, cert_info->not_before, sizeof(cert_info->not_before) - 1);
            if (len > 0) cert_info->not_before[len] = '\0';
            BIO_free(date_bio);
        }
    }
    
    if (not_after) {
        BIO* date_bio = BIO_new(BIO_s_mem());
        if (date_bio) {
            ASN1_TIME_print(date_bio, not_after);
            int len = BIO_read(date_bio, cert_info->not_after, sizeof(cert_info->not_after) - 1);
            if (len > 0) cert_info->not_after[len] = '\0';
            BIO_free(date_bio);
        }
    }
    
    // Extract signature algorithm
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    const X509_ALGOR* sig_alg;
    X509_get0_signature(NULL, &sig_alg, cert);
    if (sig_alg) {
        int nid = OBJ_obj2nid(sig_alg->algorithm);
        const char* sig_name = OBJ_nid2ln(nid);
        if (sig_name) {
            strncpy(cert_info->signature_algorithm, sig_name, sizeof(cert_info->signature_algorithm) - 1);
            cert_info->signature_algorithm[sizeof(cert_info->signature_algorithm) - 1] = '\0';
        }
    }
#else
    // For older versions, extract signature algorithm differently
    strcpy(cert_info->signature_algorithm, "Unknown");
#endif
    
    // Extract public key information
    EVP_PKEY* pkey = X509_get_pubkey(cert);
    if (pkey) {
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
        int key_type = EVP_PKEY_get_base_id(pkey);
#else
        int key_type = EVP_PKEY_type(pkey->type);
#endif
        switch(key_type) {
            case EVP_PKEY_RSA:
                strcpy(cert_info->public_key_algorithm, "RSA");
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
                cert_info->key_size = EVP_PKEY_get_bits(pkey);
#else
                cert_info->key_size = EVP_PKEY_bits(pkey);
#endif
                break;
            case EVP_PKEY_EC:
                strcpy(cert_info->public_key_algorithm, "EC");
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
                cert_info->key_size = EVP_PKEY_get_bits(pkey);
#else
                cert_info->key_size = EVP_PKEY_bits(pkey);
#endif
                break;
            case EVP_PKEY_DSA:
                strcpy(cert_info->public_key_algorithm, "DSA");
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
                cert_info->key_size = EVP_PKEY_get_bits(pkey);
#else
                cert_info->key_size = EVP_PKEY_bits(pkey);
#endif
                break;
            default:
                strcpy(cert_info->public_key_algorithm, "Unknown");
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
                cert_info->key_size = EVP_PKEY_get_bits(pkey);
#else
                cert_info->key_size = EVP_PKEY_bits(pkey);
#endif
                break;
        }
        EVP_PKEY_free(pkey);
    }
    
    // Calculate fingerprints
    calculate_fingerprint(cert, EVP_sha1(), cert_info->fingerprint_sha1, sizeof(cert_info->fingerprint_sha1));
    calculate_fingerprint(cert, EVP_sha256(), cert_info->fingerprint_sha256, sizeof(cert_info->fingerprint_sha256));
    
    // Check if it's a CA certificate
    cert_info->is_ca = (check_ca_certificate(cert) > 0);
    
    // Check if self-signed
    cert_info->is_self_signed = (X509_NAME_cmp(subject, issuer) == 0);
    
    X509_free(cert);
    BIO_free(bio);
    
    return cert_info;
}

/**
 * @brief Check if a certificate is a CA certificate (compatible across OpenSSL versions)
 */
int check_ca_certificate(X509* cert) {
    // Try the newer function first
#if defined(X509_check_ca)
    return X509_check_ca(cert);
#else
    // Fallback: check Basic Constraints extension
    BASIC_CONSTRAINTS* bc = X509_get_ext_d2i(cert, NID_basic_constraints, NULL, NULL);
    if (bc) {
        int is_ca = bc->ca;
        BASIC_CONSTRAINTS_free(bc);
        return is_ca;
    }
    return 0;
#endif
}

/**
 * @brief Calculates certificate fingerprint
 */
void calculate_fingerprint(X509* cert, const EVP_MD* md, char* output, size_t output_size) {
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len;
    
    if (X509_digest(cert, md, digest, &digest_len) == 1) {
        char* ptr = output;
        size_t remaining = output_size - 1;
        
        for (unsigned int i = 0; i < digest_len && remaining > 2; i++) {
            int written = snprintf(ptr, remaining, "%02X", digest[i]);
            if (i < digest_len - 1 && remaining > written + 1) {
                ptr[written] = ':';
                ptr += written + 1;
                remaining -= written + 1;
            } else {
                ptr += written;
                remaining -= written;
            }
        }
        *ptr = '\0';
    } else {
        strcpy(output, "Unable to calculate");
    }
}

/**
 * @brief Frees certificate information
 */
void free_certificate_info(CertificateInfo* cert) {
    while (cert) {
        CertificateInfo* next = cert->next;
        free(cert);
        cert = next;
    }
}

DrmInfo* parse_drm_content_protection(xmlNodePtr cp_node) {
    DrmInfo* drm = calloc(1, sizeof(DrmInfo));
    if (!drm) return NULL;

    xmlChar* prop = xmlGetProp(cp_node, (const xmlChar*)"schemeIdUri");
    if (prop) {
        strncpy(drm->schemeIdUri, (char*)prop, sizeof(drm->schemeIdUri)-1);
        
        // Identify DRM system
        if (strstr((char*)prop, "edef8ba9-79d6-4ace-a3c8-27dcd51d21ed")) {
            strcpy(drm->systemName, "Widevine");
        } else if (strstr((char*)prop, "9a04f079-9840-4286-ab92-e65be0885f95")) {
            strcpy(drm->systemName, "PlayReady");
        } else if (strstr((char*)prop, "1077efec-c0b2-4d02-ace3-3c1e52e2fb4b")) {
            strcpy(drm->systemName, "ClearKey");
        } else {
            strcpy(drm->systemName, "Unknown");
        }
        xmlFree(prop);
    }

    // Parse child elements
    xmlNodePtr child = cp_node->children;
    while (child != NULL) {
        if (child->type == XML_ELEMENT_NODE) {
            if (xmlStrcmp(child->name, (const xmlChar*)"pssh") == 0) {
                xmlChar* pssh_content = xmlNodeGetContent(child);
                if (pssh_content) {
                    strncpy(drm->psshData, (char*)pssh_content, sizeof(drm->psshData)-1);
                    
                    // Parse content ID from PSSH if possible
                    // This is a simplified extraction - full PSSH parsing is complex
                    if (strstr((char*)pssh_content, "kdfw_")) {
                        char* content_start = strstr((char*)pssh_content, "kdfw_");
                        if (content_start) {
                            int i = 0;
                            while (content_start[i] && content_start[i] != '"' && content_start[i] != ' ' && i < 127) {
                                drm->contentId[i] = content_start[i];
                                i++;
                            }
                            drm->contentId[i] = '\0';
                        }
                    }
                    xmlFree(pssh_content);
                }
            } else if (xmlStrcmp(child->name, (const xmlChar*)"Laurl") == 0) {
                xmlChar* license_type = xmlGetProp(child, (const xmlChar*)"licenseType");
                xmlChar* url_content = xmlNodeGetContent(child);
                
                if (url_content) {
                    if (license_type && strstr((char*)license_type, "group")) {
                        strncpy(drm->groupLicenseUrl, (char*)url_content, sizeof(drm->groupLicenseUrl)-1);
                    } else {
                        strncpy(drm->licenseUrl, (char*)url_content, sizeof(drm->licenseUrl)-1);
                    }
                    xmlFree(url_content);
                }
                if (license_type) xmlFree(license_type);
            }
        }
        child = child->next;
    }

    return drm;
}

CdtData* parse_cdt(xmlDocPtr doc) {
    CdtData* cdt_data = calloc(1, sizeof(CdtData));
    if (!cdt_data) {
        return NULL;
    }
    
    xmlNodePtr root = xmlDocGetRootElement(doc);
    if (!root) {
        free(cdt_data);
        return NULL;
    }
    
    xmlNodePtr to_be_signed_node = root->children;

    while(to_be_signed_node != NULL && (to_be_signed_node->type != XML_ELEMENT_NODE || xmlStrcmp(to_be_signed_node->name, (const xmlChar *)"ToBeSignedData") != 0)) {
        to_be_signed_node = to_be_signed_node->next;
    }

    if(!to_be_signed_node) {
        free(cdt_data);
        return NULL;
    }

    if(to_be_signed_node) {
        xmlChar* prop = xmlGetProp(to_be_signed_node, (const xmlChar *)"OCSPRefresh");
        if(prop) { 
            strncpy(cdt_data->ocspRefresh, (char*)prop, sizeof(cdt_data->ocspRefresh)-1); 
            xmlFree(prop); 
        }

        xmlNodePtr cert_node = to_be_signed_node->children;
        CertificateInfo* cert_tail = NULL;
        
        while(cert_node != NULL) {
            if(cert_node->type == XML_ELEMENT_NODE) {
                if(xmlStrcmp(cert_node->name, (const xmlChar*)"Certificates") == 0) {
                    cdt_data->certificate_count++;
                    
                    // Extract certificate data
                    xmlChar* cert_content = xmlNodeGetContent(cert_node);
                    if(cert_content) {
                        size_t cert_len = strlen((char*)cert_content);
                        
                        // Parse the X.509 certificate
                        CertificateInfo* cert_info = parse_x509_certificate((char*)cert_content, cert_len);
                        if(cert_info) {
                            if(cdt_data->certificates == NULL) {
                                cdt_data->certificates = cert_info;
                                cert_tail = cert_info;
                            } else {
                                cert_tail->next = cert_info;
                                cert_tail = cert_info;
                            }
                        }
                        xmlFree(cert_content);
                    }
                }
            }
            cert_node = cert_node->next;
        }
    }
    
    return cdt_data;
}

void generate_cdt_html_section(FILE *f, int g_lls_table_count, LlsTable* g_lls_tables) {
    int cdt_present = 0;
    
    // Check if CDT is present
    for (int i = 0; i < g_lls_table_count; i++) {
        if (g_lls_tables[i].type == TABLE_TYPE_CDT) {
            cdt_present = 1;
            break;
        }
    }
    
    if (cdt_present) {
        for (int i = 0; i < g_lls_table_count; i++) {
            if (g_lls_tables[i].type == TABLE_TYPE_CDT) {
                CdtData* cdt_data = (CdtData*)g_lls_tables[i].parsed_data;
                // Green highlight applied to the summary tag for CDT presence
                fprintf(f, "<details><summary style='background-color: #d4edda; border: 1px solid #c3e6cb; color: #155724; border-radius: 4px; '>Certification Data Table (CDT) - %d Certificate(s)</summary><div class='details-content'>", cdt_data->certificate_count);
                fprintf(f, "<table>\n<thead><tr><th>Attribute</th><th>Value</th></tr></thead>\n<tbody>\n");
                fprintf(f, "<tr><td>OCSP Refresh</td><td>%s</td></tr>\n", cdt_data->ocspRefresh);
                fprintf(f, "<tr><td>Certificate Count</td><td>%d</td></tr>\n", cdt_data->certificate_count);
                fprintf(f, "</tbody></table>\n");
                
                if (cdt_data->certificates) {
                    fprintf(f, "<h4>Certificate Details</h4>\n");
                    CertificateInfo* cert = cdt_data->certificates;
                    int cert_num = 1;
                    
                    while (cert) {
                        // Extract CN from subject
                        char cn[128] = "Unknown";
                        char* cn_start = strstr(cert->subject, "CN=");
                        if (cn_start) {
                            cn_start += 3; // Skip "CN="
                            char* cn_end = strchr(cn_start, '/');
                            if (cn_end) {
                                size_t cn_len = cn_end - cn_start;
                                if (cn_len < sizeof(cn)) {
                                    strncpy(cn, cn_start, cn_len);
                                    cn[cn_len] = '\0';
                                }
                            } else {
                                // CN is at the end of the subject string
                                strncpy(cn, cn_start, sizeof(cn) - 1);
                                cn[sizeof(cn) - 1] = '\0';
                            }
                        }
                        
                        // Extract just the date part (no time) from not_after
                        char valid_until_date[32] = "Unknown";
                        if (strlen(cert->not_after) > 0) {
                            char temp_date[64];
                            strncpy(temp_date, cert->not_after, sizeof(temp_date) - 1);
                            temp_date[sizeof(temp_date) - 1] = '\0';
                            
                            // Find the year (4 digits followed by space or end of string)
                            char* year_pos = NULL;
                            for (int j = 0; j < strlen(temp_date) - 3; j++) {
                                if (isdigit(temp_date[j]) && isdigit(temp_date[j+1]) && 
                                    isdigit(temp_date[j+2]) && isdigit(temp_date[j+3]) &&
                                    (temp_date[j+4] == ' ' || temp_date[j+4] == '\0' || temp_date[j+4] == 'G')) {
                                    // Found a 4-digit year
                                    if (temp_date[j] == '2' && temp_date[j+1] == '0') { // 20xx year
                                        year_pos = &temp_date[j];
                                        break;
                                    }
                                }
                            }
                            
                            if (year_pos) {
                                // Extract year
                                char year[5];
                                strncpy(year, year_pos, 4);
                                year[4] = '\0';
                                
                                // Extract month (first 3 chars)
                                char month[4];
                                strncpy(month, temp_date, 3);
                                month[3] = '\0';
                                
                                // Find day - it's between month and time, could be single or double digit
                                char day[3] = "??";
                                char* day_start = temp_date + 3;
                                while (*day_start == ' ') day_start++; // Skip spaces
                                
                                if (isdigit(*day_start)) {
                                    if (isdigit(*(day_start + 1)) && *(day_start + 2) == ' ') {
                                        // Two digit day
                                        day[0] = *day_start;
                                        day[1] = *(day_start + 1);
                                        day[2] = '\0';
                                    } else if (*(day_start + 1) == ' ') {
                                        // Single digit day
                                        day[0] = *day_start;
                                        day[1] = '\0';
                                    }
                                }
                                
                                // Format as "MMM DD YYYY"
                                snprintf(valid_until_date, sizeof(valid_until_date), "%s %s %s", month, day, year);
                            }
                        }
                        
                        fprintf(f, "<details><summary>Certificate %d - %s (Valid Until: %s)</summary>\n", 
                                cert_num, cn, valid_until_date);
                        fprintf(f, "<div class='details-content'>\n");
                        fprintf(f, "<table>\n<thead><tr><th>Field</th><th>Value</th></tr></thead>\n<tbody>\n");
                        fprintf(f, "<tr><td><strong>Subject</strong></td><td>%s</td></tr>\n", cert->subject);
                        fprintf(f, "<tr><td><strong>Issuer</strong></td><td>%s</td></tr>\n", cert->issuer);
                        fprintf(f, "<tr><td><strong>Serial Number</strong></td><td>%s</td></tr>\n", cert->serial_number);
                        fprintf(f, "<tr><td><strong>Valid From</strong></td><td>%s</td></tr>\n", cert->not_before);
                        fprintf(f, "<tr><td><strong>Valid Until</strong></td><td>%s</td></tr>\n", cert->not_after);
                        fprintf(f, "<tr><td><strong>Signature Algorithm</strong></td><td>%s</td></tr>\n", cert->signature_algorithm);
                        fprintf(f, "<tr><td><strong>Public Key</strong></td><td>%s (%d bits)</td></tr>\n", cert->public_key_algorithm, cert->key_size);
                        fprintf(f, "<tr><td><strong>SHA-1 Fingerprint</strong></td><td style='font-family: monospace; font-size: 12px;'>%s</td></tr>\n", cert->fingerprint_sha1);
                        fprintf(f, "<tr><td><strong>SHA-256 Fingerprint</strong></td><td style='font-family: monospace; font-size: 12px;'>%s</td></tr>\n", cert->fingerprint_sha256);
                        fprintf(f, "<tr><td><strong>Certificate Authority</strong></td><td>%s</td></tr>\n", cert->is_ca ? "Yes" : "No");
                        fprintf(f, "<tr><td><strong>Self-Signed</strong></td><td>%s</td></tr>\n", cert->is_self_signed ? "Yes" : "No");
                        fprintf(f, "</tbody></table>\n");
                        fprintf(f, "</div></details>\n");
                        
                        cert = cert->next;
                        cert_num++;
                    }
                }
                
                fprintf(f, "<details><summary>Raw XML</summary><pre>");
                fprintf_escaped_xml(f, g_lls_tables[i].content_id);  // NOW USING THE UTILITY FUNCTION
                fprintf(f, "</pre></div></details>\n");
                break; // Only show first CDT
            }
        }
    } else {
        // If CDT is not present, show the red message where the table would have been.
        fprintf(f, "<div class='details-content' style='margin-top: 1em; padding: 10px; border-radius: 5px; background-color: #f8d7da; border: 1px solid #f5c6cb; color: #721c24;'>\n");
        fprintf(f, "<strong>Signal Signing Not Available</strong>\n");
        fprintf(f, "</div>\n");
    }
}
