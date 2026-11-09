#include "esg.h"
#include "structures.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Forward declare external dependencies
extern int g_lls_table_count;
extern LlsTable* g_lls_tables;

/**
 * @brief Enhanced ESG parser that extracts services, programs, schedules, and media assets
 */
EsgFragmentData* parse_esg_service_fragment(xmlDocPtr doc) {
    EsgFragmentData* esg_data = calloc(1, sizeof(EsgFragmentData));
    if (!esg_data) return NULL;

    xmlNodePtr root = xmlDocGetRootElement(doc);

    if (xmlStrcmp(root->name, (const xmlChar *)"Service") == 0) {
        parse_esg_service(root, esg_data);
    } else if (xmlStrcmp(root->name, (const xmlChar *)"Program") == 0) {
        parse_esg_program(root, esg_data);
    } else if (xmlStrcmp(root->name, (const xmlChar *)"Schedule") == 0) {
        parse_esg_schedule(root, esg_data);
    } else if (xmlStrcmp(root->name, (const xmlChar *)"ServiceBundle") == 0) {
        parse_esg_service_bundle(root, esg_data);
    } else if (xmlStrcmp(root->name, (const xmlChar *)"Content") == 0) {
        parse_esg_content(root, esg_data);
    }
    
    return esg_data;
}

void parse_esg_service(xmlNodePtr service_node, EsgFragmentData* esg_data) {
    EsgServiceInfo* service = calloc(1, sizeof(EsgServiceInfo));
    if (!service) return;

    xmlChar* prop;
    
    // Basic service attributes
    prop = xmlGetProp(service_node, (const xmlChar *)"id");
    if(prop) { strncpy(service->id, (char*)prop, sizeof(service->id)-1); xmlFree(prop); }
    
    prop = xmlGetProp(service_node, (const xmlChar *)"serviceStatus");
    if(prop) { strncpy(service->serviceStatus, (char*)prop, sizeof(service->serviceStatus)-1); xmlFree(prop); }
    
    prop = xmlGetProp(service_node, (const xmlChar *)"globalServiceID");
    if(prop) { strncpy(service->serviceStatus, (char*)prop, sizeof(service->serviceStatus)-1); xmlFree(prop); }

    // Parse child elements
    xmlNodePtr child = service_node->children;
    EsgMediaAsset* icon_tail = NULL;
    EsgScheduleEvent* schedule_tail = NULL;
    
    while(child != NULL) {
        if(child->type == XML_ELEMENT_NODE) {
            if (xmlStrcmp(child->name, (const xmlChar *)"Name") == 0) {
                // FIXED: Try "text" attribute first (OMA ESG format)
                prop = xmlGetProp(child, (const xmlChar *)"text");
                if(prop) {
                    strncpy(service->name, (char*)prop, sizeof(service->name)-1);
                    xmlFree(prop);
                } else {
                    // Fallback to element content
                    xmlChar* content = xmlNodeGetContent(child);
                    if(content) {
                        strncpy(service->name, (char*)content, sizeof(service->name)-1);
                        xmlFree(content);
                    }
                }
            } else if (xmlStrcmp(child->name, (const xmlChar *)"Description") == 0) {
                // FIXED: Try "text" attribute first
                prop = xmlGetProp(child, (const xmlChar *)"text");
                if(prop) {
                    strncpy(service->description, (char*)prop, sizeof(service->description)-1);
                    xmlFree(prop);
                } else {
                    xmlChar* content = xmlNodeGetContent(child);
                    if(content) {
                        strncpy(service->description, (char*)content, sizeof(service->description)-1);
                        xmlFree(content);
                    }
                }
            } else if (xmlStrcmp(child->name, (const xmlChar *)"Genre") == 0) {
                xmlChar* content = xmlNodeGetContent(child);
                if(content) {
                    strncpy(service->genre, (char*)content, sizeof(service->genre)-1);
                    xmlFree(content);
                }
            } else if (xmlStrcmp(child->name, (const xmlChar *)"ServiceIcon") == 0 ||
                       xmlStrcmp(child->name, (const xmlChar *)"Icon") == 0) {
                EsgMediaAsset* icon = parse_esg_media_asset(child, "serviceIcon");
                if(icon) {
                    if(!service->icons) {
                        service->icons = icon;
                        icon_tail = icon;
                    } else {
                        icon_tail->next = icon;
                        icon_tail = icon;
                    }
                }
            } else if (xmlStrcmp(child->name, (const xmlChar *)"Schedule") == 0) {
                parse_esg_schedule_events(child, &service->schedule, &schedule_tail);
            } else if (xmlStrcmp(child->name, (const xmlChar *)"PrivateExt") == 0) {
                // Look for ATSC3ServiceExtension
                xmlNodePtr ext_child = child->children;
                while (ext_child) {
                    if (ext_child->type == XML_ELEMENT_NODE &&
                        xmlStrcmp(ext_child->name, (const xmlChar *)"ATSC3ServiceExtension") == 0) {
                        xmlNodePtr channel_child = ext_child->children;
                        while (channel_child) {
                            if (channel_child->type == XML_ELEMENT_NODE) {
                                if (xmlStrcmp(channel_child->name, (const xmlChar *)"MajorChannelNum") == 0) {
                                    xmlChar* content = xmlNodeGetContent(channel_child);
                                    if (content) {
                                        strncpy(service->majorChannel, (char*)content, sizeof(service->majorChannel)-1);
                                        xmlFree(content);
                                    }
                                } else if (xmlStrcmp(channel_child->name, (const xmlChar *)"MinorChannelNum") == 0) {
                                    xmlChar* content = xmlNodeGetContent(channel_child);
                                    if (content) {
                                        strncpy(service->minorChannel, (char*)content, sizeof(service->minorChannel)-1);
                                        xmlFree(content);
                                    }
                                } else if (xmlStrcmp(channel_child->name, (const xmlChar *)"Icon") == 0) {
                                    EsgMediaAsset* icon = parse_esg_media_asset(channel_child, "serviceIcon");
                                    if (icon) {
                                        if (!service->icons) {
                                            service->icons = icon;
                                            icon_tail = icon;
                                        } else {
                                            icon_tail->next = icon;
                                            icon_tail = icon;
                                        }
                                    }
                                }
                            }
                            channel_child = channel_child->next;
                        }
                    }
                    ext_child = ext_child->next;
                }
            }
        }
        child = child->next;
    }

    // Add to service list
    service->next = esg_data->services;
    esg_data->services = service;
}

void parse_esg_program(xmlNodePtr program_node, EsgFragmentData* esg_data) {
    EsgProgramInfo* program = calloc(1, sizeof(EsgProgramInfo));
    if (!program) return;

    xmlChar* prop;
    
    prop = xmlGetProp(program_node, (const xmlChar *)"id");
    if(prop) { strncpy(program->id, (char*)prop, sizeof(program->id)-1); xmlFree(prop); }

    // Parse program details
    xmlNodePtr child = program_node->children;
    EsgMediaAsset* icon_tail = NULL;
    EsgContentRating* rating_tail = NULL;
    
    while(child != NULL) {
        if(child->type == XML_ELEMENT_NODE) {
            if (xmlStrcmp(child->name, (const xmlChar *)"Title") == 0) {
                xmlChar* content = xmlNodeGetContent(child);
                if(content) {
                    strncpy(program->title, (char*)content, sizeof(program->title)-1);
                    xmlFree(content);
                }
            } else if (xmlStrcmp(child->name, (const xmlChar *)"Description") == 0) {
                xmlChar* content = xmlNodeGetContent(child);
                if(content) {
                    strncpy(program->description, (char*)content, sizeof(program->description)-1);
                    xmlFree(content);
                }
            } else if (xmlStrcmp(child->name, (const xmlChar *)"Genre") == 0) {
                xmlChar* content = xmlNodeGetContent(child);
                if(content) {
                    strncpy(program->genre, (char*)content, sizeof(program->genre)-1);
                    xmlFree(content);
                }
            } else if (xmlStrcmp(child->name, (const xmlChar *)"ProgramIcon") == 0 ||
                       xmlStrcmp(child->name, (const xmlChar *)"Icon") == 0) {
                EsgMediaAsset* icon = parse_esg_media_asset(child, "programIcon");
                if(icon) {
                    if(!program->icons) {
                        program->icons = icon;
                        icon_tail = icon;
                    } else {
                        icon_tail->next = icon;
                        icon_tail = icon;
                    }
                }
            } else if (xmlStrcmp(child->name, (const xmlChar *)"ContentRating") == 0) {
                EsgContentRating* rating = parse_esg_content_rating(child);
                if(rating) {
                    if(!program->ratings) {
                        program->ratings = rating;
                        rating_tail = rating;
                    } else {
                        rating_tail->next = rating;
                        rating_tail = rating;
                    }
                }
            } else if (xmlStrcmp(child->name, (const xmlChar *)"ContentAdvisoryRatings") == 0) {
                EsgContentRating* rating = parse_atsc3_content_advisory(child);
                if (rating) {
                    if (!program->ratings) {
                        program->ratings = rating;
                        rating_tail = rating;
                    } else {
                        rating_tail->next = rating;
                        rating_tail = rating;
                    }
                }
            }
        }
        child = child->next;
    }

    // Add to program list
    program->next = esg_data->programs;
    esg_data->programs = program;
}

EsgMediaAsset* parse_esg_media_asset(xmlNodePtr asset_node, const char* usage_type) {
    EsgMediaAsset* asset = calloc(1, sizeof(EsgMediaAsset));
    if (!asset) return NULL;

    strcpy(asset->usage, usage_type);

    xmlChar* prop;
    prop = xmlGetProp(asset_node, (const xmlChar *)"uri");
    if(!prop) prop = xmlGetProp(asset_node, (const xmlChar *)"href");
    if(!prop) prop = xmlGetProp(asset_node, (const xmlChar *)"src");
    if(prop) { 
        strncpy(asset->uri, (char*)prop, sizeof(asset->uri)-1); 
        xmlFree(prop); 
    } else {
        // Check element content (e.g., <Icon>filename.png</Icon>)
        xmlChar* content = xmlNodeGetContent(asset_node);
        if (content && strlen((char*)content) > 0) {
            strncpy(asset->uri, (char*)content, sizeof(asset->uri)-1);
            xmlFree(content);
        }
    }

    prop = xmlGetProp(asset_node, (const xmlChar *)"contentType");
    if(!prop) prop = xmlGetProp(asset_node, (const xmlChar *)"mimeType");
    if(prop) { strncpy(asset->contentType, (char*)prop, sizeof(asset->contentType)-1); xmlFree(prop); }

    prop = xmlGetProp(asset_node, (const xmlChar *)"width");
    if(prop) { strncpy(asset->width, (char*)prop, sizeof(asset->width)-1); xmlFree(prop); }

    prop = xmlGetProp(asset_node, (const xmlChar *)"height");
    if(prop) { strncpy(asset->height, (char*)prop, sizeof(asset->height)-1); xmlFree(prop); }

    return asset;
}

void parse_esg_content(xmlNodePtr content_node, EsgFragmentData* esg_data) {
    xmlChar* prop;
    
    // Create a program entry from the Content element
    EsgProgramInfo* program = calloc(1, sizeof(EsgProgramInfo));
    if (!program) return;
    
    // Get content ID if available
    prop = xmlGetProp(content_node, (const xmlChar *)"id");
    if(prop) { 
        strncpy(program->id, (char*)prop, sizeof(program->id)-1); 
        xmlFree(prop); 
    }
    
    xmlNodePtr child = content_node->children;
    while (child) {
        if (child->type == XML_ELEMENT_NODE) {
            if (xmlStrcmp(child->name, (const xmlChar *)"Name") == 0) {
                // Try "text" attribute first (OMA ESG format)
                prop = xmlGetProp(child, (const xmlChar *)"text");
                if(prop) {
                    strncpy(program->title, (char*)prop, sizeof(program->title)-1);
                    xmlFree(prop);
                } else {
                    // Fallback to element content
                    xmlChar* content = xmlNodeGetContent(child);
                    if(content) {
                        strncpy(program->title, (char*)content, sizeof(program->title)-1);
                        xmlFree(content);
                    }
                }
            } else if (xmlStrcmp(child->name, (const xmlChar *)"Description") == 0) {
                // Try "text" attribute first (OMA ESG format)
                prop = xmlGetProp(child, (const xmlChar *)"text");
                if(prop) {
                    strncpy(program->description, (char*)prop, sizeof(program->description)-1);
                    xmlFree(prop);
                } else {
                    // Fallback to element content
                    xmlChar* content = xmlNodeGetContent(child);
                    if(content) {
                        strncpy(program->description, (char*)content, sizeof(program->description)-1);
                        xmlFree(content);
                    }
                }
            } else if (xmlStrcmp(child->name, (const xmlChar *)"Genre") == 0) {
                // Try href attribute or element content
                prop = xmlGetProp(child, (const xmlChar *)"href");
                if(prop) {
                    strncpy(program->genre, (char*)prop, sizeof(program->genre)-1);
                    xmlFree(prop);
                } else {
                    xmlChar* content = xmlNodeGetContent(child);
                    if(content) {
                        strncpy(program->genre, (char*)content, sizeof(program->genre)-1);
                        xmlFree(content);
                    }
                }
            } else if (xmlStrcmp(child->name, (const xmlChar *)"ContentAdvisoryRatings") == 0) {
                EsgContentRating* rating = parse_atsc3_content_advisory(child);
                if (rating) {
                    rating->next = program->ratings;
                    program->ratings = rating;
                }
            } else if (xmlStrcmp(child->name, (const xmlChar *)"MediaAsset") == 0 ||
                       xmlStrcmp(child->name, (const xmlChar *)"Icon") == 0) {
                EsgMediaAsset* icon = parse_esg_media_asset(child, "programIcon");
                if(icon) {
                    icon->next = program->icons;
                    program->icons = icon;
                }
            } else if (xmlStrcmp(child->name, (const xmlChar *)"PrivateExt") == 0) {
                // Look for ATSC3 ContentIcon
                xmlNodePtr ext_child = child->children;
                while (ext_child) {
                    if (ext_child->type == XML_ELEMENT_NODE) {
                        // Check for sa:ContentIcon or just ContentIcon
                        if (xmlStrcmp(ext_child->name, (const xmlChar *)"ContentIcon") == 0) {
                            EsgMediaAsset* icon = calloc(1, sizeof(EsgMediaAsset));
                            if (icon) {
                                strcpy(icon->usage, "contentIcon");
                                
                                // Get URL from element content
                                xmlChar* content = xmlNodeGetContent(ext_child);
                                if (content) {
                                    strncpy(icon->uri, (char*)content, sizeof(icon->uri)-1);
                                    xmlFree(content);
                                }
                                
                                // Get attributes
                                xmlChar* prop = xmlGetProp(ext_child, (const xmlChar *)"MIMEType");
                                if (!prop) prop = xmlGetProp(ext_child, (const xmlChar *)"contentType");
                                if (prop) {
                                    strncpy(icon->contentType, (char*)prop, sizeof(icon->contentType)-1);
                                    xmlFree(prop);
                                }
                                
                                prop = xmlGetProp(ext_child, (const xmlChar *)"width");
                                if (prop) {
                                    strncpy(icon->width, (char*)prop, sizeof(icon->width)-1);
                                    xmlFree(prop);
                                }
                                
                                prop = xmlGetProp(ext_child, (const xmlChar *)"height");
                                if (prop) {
                                    strncpy(icon->height, (char*)prop, sizeof(icon->height)-1);
                                    xmlFree(prop);
                                }
                                
                                icon->next = program->icons;
                                program->icons = icon;
                            }
                        }
                    }
                    ext_child = ext_child->next;
                }
            } else if (xmlStrcmp(child->name, (const xmlChar *)"ServiceReference") == 0) {
                prop = xmlGetProp(child, (const xmlChar *)"idRef");
                if (!prop) prop = xmlGetProp(child, (const xmlChar *)"id");
                if (prop) {
                    strncpy(program->serviceRef, (char*)prop, sizeof(program->serviceRef)-1);
                    xmlFree(prop);
                }
            }
        }
        child = child->next;
    }
    
    // Add to program list
    program->next = esg_data->programs;
    esg_data->programs = program;
}

EsgContentRating* parse_esg_content_rating(xmlNodePtr rating_node) {
    EsgContentRating* rating = calloc(1, sizeof(EsgContentRating));
    if (!rating) return NULL;

    xmlChar* prop;
    prop = xmlGetProp(rating_node, (const xmlChar *)"scheme");
    if(prop) { strncpy(rating->scheme, (char*)prop, sizeof(rating->scheme)-1); xmlFree(prop); }

    prop = xmlGetProp(rating_node, (const xmlChar *)"value");
    if(!prop) {
        xmlChar* content = xmlNodeGetContent(rating_node);
        if(content) {
            strncpy(rating->value, (char*)content, sizeof(rating->value)-1);
            xmlFree(content);
        }
    } else {
        strncpy(rating->value, (char*)prop, sizeof(rating->value)-1);
        xmlFree(prop);
    }

    return rating;
}

/**
 * Parse ATSC 3.0 ContentAdvisoryRatings element
 */
EsgContentRating* parse_atsc3_content_advisory(xmlNodePtr advisory_node) {
    EsgContentRating* rating = calloc(1, sizeof(EsgContentRating));
    if (!rating) return NULL;
    
    xmlNodePtr child = advisory_node->children;
    char sub_ratings[256] = "";
    
    while (child) {
        if (child->type == XML_ELEMENT_NODE) {
            // Check local name (ignoring namespace prefix)
            const char* name = (const char*)child->name;
            
            if (strcmp(name, "RegionIdentifier") == 0) {
                xmlChar* content = xmlNodeGetContent(child);
                if (content) {
                    // Region 1 = US, 2 = Canada, etc.
                    if (strcmp((char*)content, "1") == 0) {
                        strcpy(rating->scheme, "US");
                    } else if (strcmp((char*)content, "2") == 0) {
                        strcpy(rating->scheme, "Canada");
                    } else {
                        snprintf(rating->scheme, sizeof(rating->scheme), "Region %s", (char*)content);
                    }
                    xmlFree(content);
                }
            } else if (strcmp(name, "RatingDescription") == 0) {
                xmlChar* content = xmlNodeGetContent(child);
                if (content) {
                    strncpy(rating->value, (char*)content, sizeof(rating->value)-1);
                    xmlFree(content);
                }
            } else if (strcmp(name, "RatingDimVal") == 0) {
                // Parse sub-ratings (D, L, S, V, etc.)
                xmlNodePtr dim_child = child->children;
                while (dim_child) {
                    if (dim_child->type == XML_ELEMENT_NODE) {
                        const char* dim_name = (const char*)dim_child->name;
                        if (strcmp(dim_name, "RatingValueString") == 0) {
                            xmlChar* content = xmlNodeGetContent(dim_child);
                            if (content) {
                                // Skip if it's the same as main rating
                                if (strcmp((char*)content, rating->value) != 0) {
                                    if (strlen(sub_ratings) > 0) {
                                        strncat(sub_ratings, ",", sizeof(sub_ratings) - strlen(sub_ratings) - 1);
                                    }
                                    strncat(sub_ratings, (char*)content, sizeof(sub_ratings) - strlen(sub_ratings) - 1);
                                }
                                xmlFree(content);
                            }
                        }
                    }
                    dim_child = dim_child->next;
                }
            }
        }
        child = child->next;
    }
    
    // Append sub-ratings to value if present (e.g., "TV-14 (D,L)")
    if (strlen(sub_ratings) > 0 && strstr(rating->value, sub_ratings) == NULL) {
        size_t remaining = sizeof(rating->value) - strlen(rating->value) - 1;
        if (remaining > strlen(sub_ratings) + 3) {
            strcat(rating->value, " (");
            strcat(rating->value, sub_ratings);
            strcat(rating->value, ")");
        }
    }
    
    return rating;
}

void parse_esg_schedule_events(xmlNodePtr schedule_node, EsgScheduleEvent** head, EsgScheduleEvent** tail) {
    xmlNodePtr event_node = schedule_node->children;
    
    while(event_node != NULL) {
        if(event_node->type == XML_ELEMENT_NODE && 
           (xmlStrcmp(event_node->name, (const xmlChar *)"ScheduleEvent") == 0 ||
            xmlStrcmp(event_node->name, (const xmlChar *)"Event") == 0)) {
            
            EsgScheduleEvent* event = calloc(1, sizeof(EsgScheduleEvent));
            if(event) {
                xmlChar* prop;
                prop = xmlGetProp(event_node, (const xmlChar *)"startTime");
                if(prop) { strncpy(event->startTime, (char*)prop, sizeof(event->startTime)-1); xmlFree(prop); }
                
                prop = xmlGetProp(event_node, (const xmlChar *)"duration");
                if(prop) { strncpy(event->duration, (char*)prop, sizeof(event->duration)-1); xmlFree(prop); }
                
                prop = xmlGetProp(event_node, (const xmlChar *)"programId");
                if(prop) { strncpy(event->programId, (char*)prop, sizeof(event->programId)-1); xmlFree(prop); }

                if(!*head) {
                    *head = event;
                    *tail = event;
                } else {
                    (*tail)->next = event;
                    *tail = event;
                }
            }
        }
        event_node = event_node->next;
    }
}

void parse_esg_service_bundle(xmlNodePtr bundle_node, EsgFragmentData* esg_data) {
    xmlNodePtr child = bundle_node->children;
    
    while(child != NULL) {
        if(child->type == XML_ELEMENT_NODE) {
            if (xmlStrcmp(child->name, (const xmlChar *)"Service") == 0) {
                parse_esg_service(child, esg_data);
            } else if (xmlStrcmp(child->name, (const xmlChar *)"Program") == 0) {
                parse_esg_program(child, esg_data);
            }
        }
        child = child->next;
    }
}

void parse_esg_schedule(xmlNodePtr schedule_node, EsgFragmentData* esg_data) {
    xmlChar* prop;
    
    // Get the service ID this schedule is for
    char serviceId[128] = {0};
    
    // First try attributes on the Schedule element itself
    prop = xmlGetProp(schedule_node, (const xmlChar *)"serviceIDRef");
    if (!prop) prop = xmlGetProp(schedule_node, (const xmlChar *)"serviceId");
    if (!prop) prop = xmlGetProp(schedule_node, (const xmlChar *)"service");
    if (prop) {
        strncpy(serviceId, (char*)prop, sizeof(serviceId)-1);
        xmlFree(prop);
    }
    
    // If not found as attribute, look for ServiceRef/ServiceReference child element (OMA ESG format)
    if (strlen(serviceId) == 0) {
        xmlNodePtr ref_child = schedule_node->children;
        while (ref_child) {
            if (ref_child->type == XML_ELEMENT_NODE) {
                if (xmlStrcmp(ref_child->name, (const xmlChar *)"ServiceRef") == 0 ||
                    xmlStrcmp(ref_child->name, (const xmlChar *)"ServiceReference") == 0) {
                    prop = xmlGetProp(ref_child, (const xmlChar *)"idRef");
                    if (!prop) prop = xmlGetProp(ref_child, (const xmlChar *)"ref");
                    if (!prop) prop = xmlGetProp(ref_child, (const xmlChar *)"serviceId");
                    if (!prop) prop = xmlGetProp(ref_child, (const xmlChar *)"id");
                    if (prop) {
                        strncpy(serviceId, (char*)prop, sizeof(serviceId)-1);
                        xmlFree(prop);
                        break;
                    }
                }
            }
            ref_child = ref_child->next;
        }
    }
    
    // Find or create the service this schedule belongs to
    EsgServiceInfo* target_service = NULL;
    EsgServiceInfo* svc = esg_data->services;
    while (svc) {
        if (strcmp(svc->id, serviceId) == 0) {
            target_service = svc;
            break;
        }
        svc = svc->next;
    }
    
    // If service doesn't exist yet, create a placeholder
    if (!target_service && strlen(serviceId) > 0) {
        target_service = calloc(1, sizeof(EsgServiceInfo));
        if (target_service) {
            strncpy(target_service->id, serviceId, sizeof(target_service->id)-1);
            target_service->next = esg_data->services;
            esg_data->services = target_service;
        }
    }
    
    if (!target_service) {
        return;
    }
    
    // Parse schedule events - look for ScheduleEvent children
    EsgScheduleEvent* schedule_tail = target_service->schedule;
    while (schedule_tail && schedule_tail->next) {
        schedule_tail = schedule_tail->next;
    }
    
    xmlNodePtr child = schedule_node->children;
    while (child) {
        if (child->type == XML_ELEMENT_NODE) {
            if (xmlStrcmp(child->name, (const xmlChar *)"ScheduleEvent") == 0 ||
                xmlStrcmp(child->name, (const xmlChar *)"Event") == 0) {
                
                EsgScheduleEvent* event = calloc(1, sizeof(EsgScheduleEvent));
                if (event) {
                    prop = xmlGetProp(child, (const xmlChar *)"startTime");
                    if (prop) { 
                        strncpy(event->startTime, (char*)prop, sizeof(event->startTime)-1);
                        event->startTime[sizeof(event->startTime)-1] = '\0';
                        xmlFree(prop); 
                    }
                    
                    prop = xmlGetProp(child, (const xmlChar *)"duration");
                    if (prop) { 
                        strncpy(event->duration, (char*)prop, sizeof(event->duration)-1);
                        event->duration[sizeof(event->duration)-1] = '\0';
                        xmlFree(prop); 
                    }
                    
                    prop = xmlGetProp(child, (const xmlChar *)"endTime");
                    if (prop) { 
                        // Some formats use endTime instead of duration
                        strncpy(event->duration, (char*)prop, sizeof(event->duration)-1);
                        event->duration[sizeof(event->duration)-1] = '\0';
                        xmlFree(prop); 
                    }
                    
                    // Program reference can be in different attributes
                    prop = xmlGetProp(child, (const xmlChar *)"programIDRef");
                    if (!prop) prop = xmlGetProp(child, (const xmlChar *)"programId");
                    if (!prop) prop = xmlGetProp(child, (const xmlChar *)"contentIDRef");
                    if (prop) { 
                        strncpy(event->programId, (char*)prop, sizeof(event->programId)-1);
                        event->programId[sizeof(event->programId)-1] = '\0';
                        xmlFree(prop); 
                    }
                    
                    // Also check for nested ContentFragmentRef element
                    xmlNodePtr event_child = child->children;
                    while (event_child) {
                        if (event_child->type == XML_ELEMENT_NODE &&
                            (xmlStrcmp(event_child->name, (const xmlChar *)"ContentFragmentRef") == 0 ||
                             xmlStrcmp(event_child->name, (const xmlChar *)"ProgramRef") == 0)) {
                            prop = xmlGetProp(event_child, (const xmlChar *)"idRef");
                            if (!prop) prop = xmlGetProp(event_child, (const xmlChar *)"id");
                            if (prop) {
                                strncpy(event->programId, (char*)prop, sizeof(event->programId)-1);
                                event->programId[sizeof(event->programId)-1] = '\0';
                                xmlFree(prop);
                            }
                        }
                        event_child = event_child->next;
                    }
                    
                    // Only add event if it has valid timing data
                    if (strlen(event->startTime) > 0) {
                        if (!target_service->schedule) {
                            target_service->schedule = event;
                            schedule_tail = event;
                        } else {
                            schedule_tail->next = event;
                            schedule_tail = event;
                        }
                    } else {
                        free(event);
                    }
                }
            }
            // Handle OMA ESG ContentReference format with nested PresentationWindow
            else if (xmlStrcmp(child->name, (const xmlChar *)"ContentReference") == 0) {
                EsgScheduleEvent* event = calloc(1, sizeof(EsgScheduleEvent));
                if (event) {
                    // Get content/program ID from idRef attribute
                    prop = xmlGetProp(child, (const xmlChar *)"idRef");
                    if (!prop) prop = xmlGetProp(child, (const xmlChar *)"id");
                    if (prop) { 
                        strncpy(event->programId, (char*)prop, sizeof(event->programId)-1);
                        event->programId[sizeof(event->programId)-1] = '\0';
                        xmlFree(prop); 
                    }
                    
                    // Look for PresentationWindow child to get timing info
                    xmlNodePtr pw = child->children;
                    while (pw) {
                        if (pw->type == XML_ELEMENT_NODE &&
                            xmlStrcmp(pw->name, (const xmlChar *)"PresentationWindow") == 0) {
                            prop = xmlGetProp(pw, (const xmlChar *)"startTime");
                            if (prop) { 
                                strncpy(event->startTime, (char*)prop, sizeof(event->startTime)-1);
                                event->startTime[sizeof(event->startTime)-1] = '\0';
                                xmlFree(prop); 
                            }
                            
                            prop = xmlGetProp(pw, (const xmlChar *)"duration");
                            if (prop) { 
                                strncpy(event->duration, (char*)prop, sizeof(event->duration)-1);
                                event->duration[sizeof(event->duration)-1] = '\0';
                                xmlFree(prop); 
                            }
                            
                            prop = xmlGetProp(pw, (const xmlChar *)"endTime");
                            if (prop) { 
                                // Store endTime in duration field if no duration (can convert later)
                                if (strlen(event->duration) == 0) {
                                    strncpy(event->duration, (char*)prop, sizeof(event->duration)-1);
                                    event->duration[sizeof(event->duration)-1] = '\0';
                                }
                                xmlFree(prop); 
                            }
                            break;
                        }
                        pw = pw->next;
                    }
                    
                    // Only add event if it has valid timing data
                    if (strlen(event->startTime) > 0) {
                        if (!target_service->schedule) {
                            target_service->schedule = event;
                            schedule_tail = event;
                        } else {
                            schedule_tail->next = event;
                            schedule_tail = event;
                        }
                    } else {
                        free(event);
                    }
                }
            }
        }
        child = child->next;
    }
}

SgddData* parse_sgdd(xmlDocPtr doc) {
    SgddData* sgdd = calloc(1, sizeof(SgddData));
    if (!sgdd) return NULL;
    
    xmlNodePtr root = xmlDocGetRootElement(doc);
    
    xmlChar* prop = xmlGetProp(root, (const xmlChar *)"id");
    if (prop) {
        strncpy(sgdd->id, (char*)prop, sizeof(sgdd->id)-1);
        xmlFree(prop);
    }
    
    prop = xmlGetProp(root, (const xmlChar *)"version");
    if (prop) {
        strncpy(sgdd->version, (char*)prop, sizeof(sgdd->version)-1);
        xmlFree(prop);
    }
    
    // Parse DescriptorEntry elements
    xmlNodePtr entry_node = root->children;
    SgddEntry* entry_tail = NULL;
    
    while (entry_node) {
        if (entry_node->type == XML_ELEMENT_NODE &&
            xmlStrcmp(entry_node->name, (const xmlChar *)"DescriptorEntry") == 0) {
            
            SgddEntry* entry = calloc(1, sizeof(SgddEntry));
            if (!entry) continue;
            
            // Parse GroupingCriteria
            xmlNodePtr child = entry_node->children;
            while (child) {
                if (child->type == XML_ELEMENT_NODE) {
                    if (xmlStrcmp(child->name, (const xmlChar *)"GroupingCriteria") == 0) {
                        xmlNodePtr gc_child = child->children;
                        while (gc_child) {
                            if (gc_child->type == XML_ELEMENT_NODE) {
                                if (xmlStrcmp(gc_child->name, (const xmlChar *)"TimeGroupingCriteria") == 0) {
                                    prop = xmlGetProp(gc_child, (const xmlChar *)"startTime");
                                    if (prop) {
                                        strncpy(entry->startTime, (char*)prop, sizeof(entry->startTime)-1);
                                        xmlFree(prop);
                                    }
                                    prop = xmlGetProp(gc_child, (const xmlChar *)"endTime");
                                    if (prop) {
                                        strncpy(entry->endTime, (char*)prop, sizeof(entry->endTime)-1);
                                        xmlFree(prop);
                                    }
                                } else if (xmlStrcmp(gc_child->name, (const xmlChar *)"ServiceCriteria") == 0) {
                                    xmlChar* content = xmlNodeGetContent(gc_child);
                                    if (content) {
                                        strncpy(entry->serviceCriteria, (char*)content, sizeof(entry->serviceCriteria)-1);
                                        xmlFree(content);
                                    }
                                }
                            }
                            gc_child = gc_child->next;
                        }
                    } else if (xmlStrcmp(child->name, (const xmlChar *)"Transport") == 0) {
                        prop = xmlGetProp(child, (const xmlChar *)"ipAddress");
                        if (prop) {
                            strncpy(entry->ipAddress, (char*)prop, sizeof(entry->ipAddress)-1);
                            xmlFree(prop);
                        }
                        prop = xmlGetProp(child, (const xmlChar *)"port");
                        if (prop) {
                            strncpy(entry->port, (char*)prop, sizeof(entry->port)-1);
                            xmlFree(prop);
                        }
                        prop = xmlGetProp(child, (const xmlChar *)"transmissionSessionID");
                        if (prop) {
                            strncpy(entry->transmissionSessionId, (char*)prop, sizeof(entry->transmissionSessionId)-1);
                            xmlFree(prop);
                        }
                        prop = xmlGetProp(child, (const xmlChar *)"hasFDT");
                        if (prop) {
                            strncpy(entry->hasFdt, (char*)prop, sizeof(entry->hasFdt)-1);
                            xmlFree(prop);
                        }
                    } else if (xmlStrcmp(child->name, (const xmlChar *)"ServiceGuideDeliveryUnit") == 0) {
                        SgddDeliveryUnit* unit = calloc(1, sizeof(SgddDeliveryUnit));
                        if (unit) {
                            prop = xmlGetProp(child, (const xmlChar *)"contentLocation");
                            if (prop) {
                                strncpy(unit->contentLocation, (char*)prop, sizeof(unit->contentLocation)-1);
                                xmlFree(prop);
                            }
                            prop = xmlGetProp(child, (const xmlChar *)"transportObjectID");
                            if (prop) {
                                strncpy(unit->transportObjectId, (char*)prop, sizeof(unit->transportObjectId)-1);
                                xmlFree(prop);
                            }
                            
                            // Parse Fragment elements
                            xmlNodePtr frag_node = child->children;
                            SgddFragment* frag_tail = NULL;
                            while (frag_node) {
                                if (frag_node->type == XML_ELEMENT_NODE &&
                                    xmlStrcmp(frag_node->name, (const xmlChar *)"Fragment") == 0) {
                                    
                                    SgddFragment* frag = calloc(1, sizeof(SgddFragment));
                                    if (frag) {
                                        prop = xmlGetProp(frag_node, (const xmlChar *)"transportID");
                                        if (prop) {
                                            strncpy(frag->transportId, (char*)prop, sizeof(frag->transportId)-1);
                                            xmlFree(prop);
                                        }
                                        prop = xmlGetProp(frag_node, (const xmlChar *)"id");
                                        if (prop) {
                                            strncpy(frag->fragmentId, (char*)prop, sizeof(frag->fragmentId)-1);
                                            xmlFree(prop);
                                        }
                                        prop = xmlGetProp(frag_node, (const xmlChar *)"version");
                                        if (prop) {
                                            strncpy(frag->version, (char*)prop, sizeof(frag->version)-1);
                                            xmlFree(prop);
                                        }
                                        prop = xmlGetProp(frag_node, (const xmlChar *)"fragmentEncoding");
                                        if (prop) {
                                            strncpy(frag->fragmentEncoding, (char*)prop, sizeof(frag->fragmentEncoding)-1);
                                            xmlFree(prop);
                                        }
                                        prop = xmlGetProp(frag_node, (const xmlChar *)"fragmentType");
                                        if (prop) {
                                            strncpy(frag->fragmentType, (char*)prop, sizeof(frag->fragmentType)-1);
                                            xmlFree(prop);
                                        }
                                        
                                        // Add to list
                                        if (!unit->fragments) {
                                            unit->fragments = frag;
                                            frag_tail = frag;
                                        } else {
                                            frag_tail->next = frag;
                                            frag_tail = frag;
                                        }
                                    }
                                }
                                frag_node = frag_node->next;
                            }
                            
                            // Add unit to list
                            unit->next = entry->deliveryUnits;
                            entry->deliveryUnits = unit;
                        }
                    }
                }
                child = child->next;
            }
            
            // Add entry to list
            if (!sgdd->entries) {
                sgdd->entries = entry;
                entry_tail = entry;
            } else {
                entry_tail->next = entry;
                entry_tail = entry;
            }
        }
        entry_node = entry_node->next;
    }
    
    return sgdd;
}

/**
 * @brief Correlates ESG fragments by matching service/program IDs
 */
EsgFragmentData* correlate_esg_fragments(const char* destIp, const char* destPort, 
                             void* lls_tables_ptr, int lls_table_count) {
    LlsTable* lls_tables = (LlsTable*)lls_tables_ptr;
    
    // First pass: collect all services and programs
    EsgServiceInfo* all_services = NULL;
    EsgProgramInfo* all_programs = NULL;
    
    for (int i = 0; i < lls_table_count; i++) {
        if (lls_tables[i].type != TABLE_TYPE_ESG_FRAGMENT) continue;
        if (strcmp(lls_tables[i].destinationIp, destIp) != 0) continue;
        if (strcmp(lls_tables[i].destinationPort, destPort) != 0) continue;
        
        EsgFragmentData* frag = (EsgFragmentData*)lls_tables[i].parsed_data;
        if (!frag) continue;
        
        // Merge services
        EsgServiceInfo* svc = frag->services;
        while (svc) {
            // Check if we already have this service ID
            EsgServiceInfo* existing = all_services;
            int found = 0;
            while (existing) {
                if (strcmp(existing->id, svc->id) == 0) {
                    found = 1;
                    // Merge additional data if needed
                    if (strlen(existing->name) == 0 && strlen(svc->name) > 0) {
                        strncpy(existing->name, svc->name, sizeof(existing->name)-1);
                    }
                    if (strlen(existing->description) == 0 && strlen(svc->description) > 0) {
                        strncpy(existing->description, svc->description, sizeof(existing->description)-1);
                    }
                    // Merge schedule events from this fragment
                    if (svc->schedule) {
                        EsgScheduleEvent* existing_tail = existing->schedule;
                        if (existing_tail) {
                            while (existing_tail->next) existing_tail = existing_tail->next;
                        }
                        
                        EsgScheduleEvent* src_event = svc->schedule;
                        while (src_event) {
                            // Check for duplicate (same startTime)
                            int is_dup = 0;
                            EsgScheduleEvent* chk = existing->schedule;
                            while (chk) {
                                if (strcmp(chk->startTime, src_event->startTime) == 0) {
                                    is_dup = 1;
                                    break;
                                }
                                chk = chk->next;
                            }
                            
                            if (!is_dup) {
                                EsgScheduleEvent* new_ev = calloc(1, sizeof(EsgScheduleEvent));
                                if (new_ev) {
                                    memcpy(new_ev, src_event, sizeof(EsgScheduleEvent));
                                    new_ev->next = NULL;
                                    if (!existing->schedule) {
                                        existing->schedule = new_ev;
                                        existing_tail = new_ev;
                                    } else {
                                        existing_tail->next = new_ev;
                                        existing_tail = new_ev;
                                    }
                                }
                            }
                            src_event = src_event->next;
                        }
                    }
                    break;
                }
                existing = existing->next;
            }
            
            if (!found) {
                // Add new service (make a copy)
                EsgServiceInfo* new_svc = calloc(1, sizeof(EsgServiceInfo));
                memcpy(new_svc, svc, sizeof(EsgServiceInfo));
                new_svc->next = all_services;
                all_services = new_svc;
            }
            
            svc = svc->next;
        }
        
        // Merge programs
        EsgProgramInfo* prog = frag->programs;
        while (prog) {
            EsgProgramInfo* existing = all_programs;
            int found = 0;
            while (existing) {
                if (strcmp(existing->id, prog->id) == 0) {
                    found = 1;
                    // Merge data
                    if (strlen(existing->title) == 0 && strlen(prog->title) > 0) {
                        strncpy(existing->title, prog->title, sizeof(existing->title)-1);
                    }
                    if (strlen(existing->description) == 0 && strlen(prog->description) > 0) {
                        strncpy(existing->description, prog->description, sizeof(existing->description)-1);
                    }
                    break;
                }
                existing = existing->next;
            }
            
            if (!found) {
                EsgProgramInfo* new_prog = calloc(1, sizeof(EsgProgramInfo));
                memcpy(new_prog, prog, sizeof(EsgProgramInfo));
                new_prog->next = all_programs;
                all_programs = new_prog;
            }
            
            prog = prog->next;
        }
    }
    
    // Second pass: link schedule events to programs
    for (int i = 0; i < lls_table_count; i++) {
        if (lls_tables[i].type != TABLE_TYPE_ESG_FRAGMENT) continue;
        if (strcmp(lls_tables[i].destinationIp, destIp) != 0) continue;
        if (strcmp(lls_tables[i].destinationPort, destPort) != 0) continue;
        
        EsgFragmentData* frag = (EsgFragmentData*)lls_tables[i].parsed_data;
        if (!frag) continue;
        
        EsgServiceInfo* svc = frag->services;
        while (svc) {
            EsgScheduleEvent* event = svc->schedule;
            while (event) {
                // Find the program this schedule event refers to
                EsgProgramInfo* prog = all_programs;
                while (prog) {
                    if (strcmp(prog->id, event->programId) == 0) {
                        break;
                    }
                    prog = prog->next;
                }
                event = event->next;
            }
            svc = svc->next;
        }
    }
    
    EsgFragmentData* merged = calloc(1, sizeof(EsgFragmentData));
    if (merged) {
        merged->services = all_services;
        merged->programs = all_programs;
    }

    return merged;  // Caller now owns this data
}

int count_services(EsgServiceInfo* head) {
    int count = 0;
    while (head) {
        count++;
        head = head->next;
    }
    return count;
}

int count_programs(EsgProgramInfo* head) {
    int count = 0;
    while (head) {
        count++;
        head = head->next;
    }
    return count;
}

void free_esg_data(EsgFragmentData* data) {
    if (!data) return;
    
    // Free services
    EsgServiceInfo* current_service = data->services;
    while (current_service != NULL) {
        EsgServiceInfo* next_service = current_service->next;
        
        // Free service icons
        EsgMediaAsset* current_icon = current_service->icons;
        while(current_icon) {
            EsgMediaAsset* next_icon = current_icon->next;
            free(current_icon);
            current_icon = next_icon;
        }
        
        // Free service schedule
        EsgScheduleEvent* current_event = current_service->schedule;
        while(current_event) {
            EsgScheduleEvent* next_event = current_event->next;
            free(current_event);
            current_event = next_event;
        }
        
        free(current_service);
        current_service = next_service;
    }
    
    // Free programs
    EsgProgramInfo* current_program = data->programs;
    while(current_program != NULL) {
        EsgProgramInfo* next_program = current_program->next;
        
        // Free program icons
        EsgMediaAsset* current_icon = current_program->icons;
        while(current_icon) {
            EsgMediaAsset* next_icon = current_icon->next;
            free(current_icon);
            current_icon = next_icon;
        }
        
        // Free program ratings
        EsgContentRating* current_rating = current_program->ratings;
        while(current_rating) {
            EsgContentRating* next_rating = current_rating->next;
            free(current_rating);
            current_rating = next_rating;
        }
        
        free(current_program);
        current_program = next_program;
    }
    
    free(data);
}

// ============================================================================
// ESG DISPLAY IMPLEMENTATION
// ============================================================================

/**
 * @brief Find SGDD data for a given service IP:Port
 */
SgddData* find_sgdd_for_service(const char* service_ip, 
                                 const char* service_port,
                                 EsgLlsTableRef* lls_tables, 
                                 int lls_table_count) {
    for (int i = 0; i < lls_table_count; i++) {
        if (lls_tables[i].type == TABLE_TYPE_SGDD) {
            SgddData* sgdd = (SgddData*)lls_tables[i].parsed_data;
            if (sgdd && sgdd->entries) {
                SgddEntry* entry = sgdd->entries;
                while (entry) {
                    if (strcmp(entry->ipAddress, service_ip) == 0 &&
                        strcmp(entry->port, service_port) == 0) {
                        return sgdd;
                    }
                    entry = entry->next;
                }
            }
        }
    }
    return NULL;
}

/**
 * @brief Find or create XML tracker entry for a service
 */
static EsgServiceXmlTracker* find_or_create_xml_tracker(EsgMergedData* merged, const char* service_id) {
    // Search existing
    for (int i = 0; i < merged->xml_tracker_count; i++) {
        if (strcmp(merged->xml_trackers[i].service_id, service_id) == 0) {
            return &merged->xml_trackers[i];
        }
    }
    // Create new
    if (merged->xml_tracker_count < 100) {
        EsgServiceXmlTracker* tracker = &merged->xml_trackers[merged->xml_tracker_count++];
        strncpy(tracker->service_id, service_id, sizeof(tracker->service_id)-1);
        tracker->service_xmls = malloc(sizeof(char*) * 50);
        tracker->service_xml_count = 0;
        tracker->schedule_xmls = malloc(sizeof(char*) * 100);
        tracker->schedule_xml_count = 0;
        tracker->content_xmls = malloc(sizeof(char*) * 500);
        tracker->content_xml_count = 0;
        return tracker;
    }
    return NULL;
}

/**
 * @brief Merge all ESG fragments for a given service into unified lists (for display)
 */
EsgMergedData* merge_esg_fragments_for_display(const char* service_ip,
                                                const char* service_port,
                                                EsgLlsTableRef* lls_tables,
                                                int lls_table_count) {
    EsgMergedData* merged = calloc(1, sizeof(EsgMergedData));
    if (!merged) return NULL;
    
    merged->xml_trackers = calloc(100, sizeof(EsgServiceXmlTracker));
    merged->orphaned_xmls = malloc(sizeof(char*) * 500);
    merged->orphaned_types = malloc(sizeof(char) * 500);
    merged->orphaned_xml_count = 0;
    
    for (int k = 0; k < lls_table_count; k++) {
        if (lls_tables[k].type != TABLE_TYPE_ESG_FRAGMENT) continue;
        if (strcmp(lls_tables[k].destinationIp, service_ip) != 0) continue;
        if (strcmp(lls_tables[k].destinationPort, service_port) != 0) continue;
        
        merged->fragment_count++;
        
        EsgFragmentData* frag = (EsgFragmentData*)lls_tables[k].parsed_data;
        
        // Track fragments with no parsed data or no services/programs as orphaned
        if (!frag || (!frag->services && !frag->programs)) {
            if (lls_tables[k].content_id && merged->orphaned_xml_count < 500) {
                merged->orphaned_xmls[merged->orphaned_xml_count] = lls_tables[k].content_id;
                merged->orphaned_types[merged->orphaned_xml_count] = 'U';  // Unknown/empty
                merged->orphaned_xml_count++;
            }
            continue;
        }
        
        // Merge services (deduplicate by ID)
        EsgServiceInfo* svc = frag->services;
        while (svc) {
            EsgServiceInfo* existing = merged->services;
            int found = 0;
            while (existing) {
                if (strcmp(existing->id, svc->id) == 0) {
                    found = 1;
                    // Merge missing data
                    if (strlen(existing->name) == 0 && strlen(svc->name) > 0) {
                        strncpy(existing->name, svc->name, sizeof(existing->name)-1);
                    }
                    if (strlen(existing->description) == 0 && strlen(svc->description) > 0) {
                        strncpy(existing->description, svc->description, sizeof(existing->description)-1);
                    }
                    if (strlen(existing->majorChannel) == 0 && strlen(svc->majorChannel) > 0) {
                        strncpy(existing->majorChannel, svc->majorChannel, sizeof(existing->majorChannel)-1);
                    }
                    if (strlen(existing->minorChannel) == 0 && strlen(svc->minorChannel) > 0) {
                        strncpy(existing->minorChannel, svc->minorChannel, sizeof(existing->minorChannel)-1);
                    }
                    if (!existing->icons && svc->icons) {
                        existing->icons = svc->icons;
                    }
                    // Merge schedule events
                    if (svc->schedule) {
                        EsgScheduleEvent* src_event = svc->schedule;
                        while (src_event) {
                            int is_dup = 0;
                            EsgScheduleEvent* chk = existing->schedule;
                            while (chk) {
                                if (strcmp(chk->startTime, src_event->startTime) == 0) {
                                    is_dup = 1;
                                    break;
                                }
                                chk = chk->next;
                            }
                            if (!is_dup) {
                                EsgScheduleEvent* new_event = calloc(1, sizeof(EsgScheduleEvent));
                                if (new_event) {
                                    memcpy(new_event, src_event, sizeof(EsgScheduleEvent));
                                    new_event->next = existing->schedule;
                                    existing->schedule = new_event;
                                }
                            }
                            src_event = src_event->next;
                        }
                    }
                    break;
                }
                existing = existing->next;
            }
            
            if (!found) {
                EsgServiceInfo* copy = calloc(1, sizeof(EsgServiceInfo));
                memcpy(copy, svc, sizeof(EsgServiceInfo));
                copy->icons = svc->icons;
                copy->schedule = svc->schedule;
                copy->next = merged->services;
                merged->services = copy;
            }
            
            // Track raw XML for this service
            EsgServiceXmlTracker* tracker = find_or_create_xml_tracker(merged, svc->id);
            if (tracker && lls_tables[k].content_id) {
                if (strlen(svc->name) > 0) {
                    // Service fragment
                    if (tracker->service_xml_count < 50) {
                        tracker->service_xmls[tracker->service_xml_count++] = lls_tables[k].content_id;
                    }
                } else if (svc->schedule) {
                    // Schedule fragment
                    if (tracker->schedule_xml_count < 100) {
                        tracker->schedule_xmls[tracker->schedule_xml_count++] = lls_tables[k].content_id;
                    }
                }
            }
            
            svc = svc->next;
        }
        
        // Merge programs (deduplicate by ID)
        EsgProgramInfo* prog = frag->programs;
        while (prog) {
            // Determine service ID for this program
            char prog_service_id[256] = "";
            if (strlen(prog->serviceRef) > 0) {
                strncpy(prog_service_id, prog->serviceRef, sizeof(prog_service_id)-1);
            } else {
                const char* content_marker = strstr(prog->id, "Content-");
                if (content_marker) {
                    const char* dash = strchr(content_marker + 8, '-');
                    if (dash) {
                        size_t prefix_len = content_marker - prog->id;
                        char service_num[32] = "";
                        size_t num_len = dash - (content_marker + 8);
                        if (num_len < sizeof(service_num)) {
                            strncpy(service_num, content_marker + 8, num_len);
                            service_num[num_len] = '\0';
                            snprintf(prog_service_id, sizeof(prog_service_id), "%.*sService-%s", 
                                    (int)prefix_len, prog->id, service_num);
                        }
                    }
                }
            }
            
            // Track content XML
            if (strlen(prog_service_id) > 0 && lls_tables[k].content_id) {
                EsgServiceXmlTracker* tracker = find_or_create_xml_tracker(merged, prog_service_id);
                if (tracker && tracker->content_xml_count < 500) {
                    tracker->content_xmls[tracker->content_xml_count++] = lls_tables[k].content_id;
                }
            }
            
            EsgProgramInfo* existing = merged->programs;
            int found = 0;
            while (existing) {
                if (strcmp(existing->id, prog->id) == 0) {
                    found = 1;
                    if (strlen(existing->title) == 0 && strlen(prog->title) > 0) {
                        strncpy(existing->title, prog->title, sizeof(existing->title)-1);
                    }
                    if (strlen(existing->description) == 0 && strlen(prog->description) > 0) {
                        strncpy(existing->description, prog->description, sizeof(existing->description)-1);
                    }
                    if (!existing->icons && prog->icons) {
                        existing->icons = prog->icons;
                    }
                    if (!existing->ratings && prog->ratings) {
                        existing->ratings = prog->ratings;
                    }
                    break;
                }
                existing = existing->next;
            }
            
            if (!found) {
                EsgProgramInfo* copy = calloc(1, sizeof(EsgProgramInfo));
                memcpy(copy, prog, sizeof(EsgProgramInfo));
                copy->icons = prog->icons;
                copy->ratings = prog->ratings;
                copy->next = merged->programs;
                merged->programs = copy;
            }
            prog = prog->next;
        }
    }
    
    return merged;
}

/**
 * @brief Free merged ESG data
 */
void free_esg_merged_data(EsgMergedData* data) {
    if (!data) return;
    
    // Free service copies
    EsgServiceInfo* svc = data->services;
    while (svc) {
        EsgServiceInfo* next = svc->next;
        free(svc);
        svc = next;
    }
    
    // Free program copies
    EsgProgramInfo* prog = data->programs;
    while (prog) {
        EsgProgramInfo* next = prog->next;
        free(prog);
        prog = next;
    }
    
    // Free XML trackers
    if (data->xml_trackers) {
        for (int i = 0; i < data->xml_tracker_count; i++) {
            free(data->xml_trackers[i].service_xmls);
            free(data->xml_trackers[i].schedule_xmls);
            free(data->xml_trackers[i].content_xmls);
        }
        free(data->xml_trackers);
    }
    
    // Free orphaned fragment tracking
    if (data->orphaned_xmls) free(data->orphaned_xmls);
    if (data->orphaned_types) free(data->orphaned_types);
    
    free(data);
}

/**
 * @brief Render ESG data to HTML
 */
EsgDisplayResult render_esg_to_html(FILE* f, 
                                     const char* service_sls_ip, 
                                     const char* service_sls_port,
                                     EsgLlsTableRef* lls_tables, 
                                     int lls_table_count,
                                     void (*fprintf_escaped_xml_fn)(FILE*, const char*)) {
    EsgDisplayResult result = {0, 0, 0, 0};
    
    // Find SGDD if available
    SgddData* sgdd = find_sgdd_for_service(service_sls_ip, service_sls_port, 
                                            lls_tables, lls_table_count);
    
    // Merge all ESG fragments
    EsgMergedData* merged = merge_esg_fragments_for_display(service_sls_ip, service_sls_port,
                                                             lls_tables, lls_table_count);
    if (!merged || merged->fragment_count == 0) {
        if (merged) free_esg_merged_data(merged);
        return result;
    }
    
    result.fragment_count = merged->fragment_count;
    result.success = 1;
    
    // Handle case where we have fragments but no correlatable services
    if (!merged->services && merged->orphaned_xml_count > 0) {
        fprintf(f, "<details><summary>Electronic Service Guide (ESG) - 0 Service(s), 0 Program(s) (from %d fragments)</summary>\n",
                result.fragment_count);
        fprintf(f, "<div class='details-content'>\n");
        fprintf(f, "<p style='color:#cc6600;'><strong>⚠️ Warning:</strong> %d ESG fragment(s) received but none could be correlated to services. "
                   "This typically indicates empty or malformed fragments from the broadcaster.</p>\n",
                merged->orphaned_xml_count);
        
        // Display orphaned fragments
        if (fprintf_escaped_xml_fn) {
            fprintf(f, "<details><summary>Unmatched/Empty Fragments (%d)</summary>\n", 
                    merged->orphaned_xml_count);
            fprintf(f, "<div class='details-content'><pre style='max-height:400px; overflow:auto;'>");
            
            for (int x = 0; x < merged->orphaned_xml_count && x < 50; x++) {
                fprintf(f, "\n&lt;!-- ===== ORPHANED FRAGMENT %d ===== --&gt;\n", x + 1);
                fprintf_escaped_xml_fn(f, merged->orphaned_xmls[x]);
            }
            
            if (merged->orphaned_xml_count > 50) {
                fprintf(f, "\n\n&lt;!-- ... and %d more orphaned fragments not shown ... --&gt;\n", 
                        merged->orphaned_xml_count - 50);
            }
            
            fprintf(f, "</pre></div></details>\n");
        }
        
        fprintf(f, "</div></details>\n");
        free_esg_merged_data(merged);
        return result;
    }
    
    // Sort services by service number
    EsgServiceInfo** service_array = malloc(sizeof(EsgServiceInfo*) * 100);
    int svc_count = 0;
    EsgServiceInfo* svc = merged->services;
    while(svc && svc_count < 100) {
        service_array[svc_count++] = svc;
        svc = svc->next;
    }
    
    // Bubble sort by service number
    for (int a = 0; a < svc_count - 1; a++) {
        for (int b = 0; b < svc_count - a - 1; b++) {
            int num1 = 9999, num2 = 9999;
            const char* s1 = strstr(service_array[b]->id, "Service-");
            const char* s2 = strstr(service_array[b+1]->id, "Service-");
            if (s1) num1 = atoi(s1 + 8);
            if (s2) num2 = atoi(s2 + 8);
            if (num1 > num2) {
                EsgServiceInfo* temp = service_array[b];
                service_array[b] = service_array[b+1];
                service_array[b+1] = temp;
            }
        }
    }
    
    result.service_count = svc_count;
    result.program_count = count_programs(merged->programs);
    
    // Output HTML
    fprintf(f, "<details><summary>Electronic Service Guide (ESG) - %d Service(s), %d Program(s) (from %d fragments)</summary>\n", 
            result.service_count, result.program_count, result.fragment_count);
    fprintf(f, "<div class='details-content'>\n");
    
    // Show SGDD metadata if available
    if (sgdd) {
        fprintf(f, "<details><summary><strong>📋 Guide Delivery Information (SGDD Version %s)</strong></summary>\n", sgdd->version);
        fprintf(f, "<div style='margin-left: 20px;'>");
        
        SgddEntry* entry = sgdd->entries;
        while (entry) {
            time_t start_ts = atoll(entry->startTime) - 2208988800LL;
            time_t end_ts = atoll(entry->endTime) - 2208988800LL;
            struct tm* tm_start = localtime(&start_ts);
            struct tm* tm_end = localtime(&end_ts);
            char start_str[64], end_str[64];
            strftime(start_str, sizeof(start_str), "%Y-%m-%d %H:%M", tm_start);
            strftime(end_str, sizeof(end_str), "%Y-%m-%d %H:%M", tm_end);
            
            fprintf(f, "<h4>Coverage: %s to %s</h4>", start_str, end_str);
            fprintf(f, "<p><strong>Service:</strong> %s</p>", entry->serviceCriteria);
            
            SgddDeliveryUnit* unit = entry->deliveryUnits;
            while (unit) {
                fprintf(f, "<details><summary>Delivery Unit: %s (TOI %s)</summary>", 
                        unit->contentLocation, unit->transportObjectId);
                fprintf(f, "<table style='margin: 10px;'><tr><th>Transport ID</th><th>Fragment ID</th><th>Type</th></tr>\n");
                
                SgddFragment* frag_sgdd = unit->fragments;
                while (frag_sgdd) {
                    const char* type_desc = "Unknown";
                    if (strcmp(frag_sgdd->fragmentType, "1") == 0) type_desc = "Service";
                    else if (strcmp(frag_sgdd->fragmentType, "2") == 0) type_desc = "Content/Program";
                    else if (strcmp(frag_sgdd->fragmentType, "3") == 0) type_desc = "Schedule";
                    
                    fprintf(f, "<tr><td>%s</td><td><small>%s</small></td><td>%s</td></tr>",
                            frag_sgdd->transportId, frag_sgdd->fragmentId, type_desc);
                    frag_sgdd = frag_sgdd->next;
                }
                fprintf(f, "</table></details>");
                unit = unit->next;
            }
            
            entry = entry->next;
        }
        
        fprintf(f, "</div></details><br>\n");
    }
    
    // Track scheduled program IDs globally
    char** scheduled_program_ids = malloc(sizeof(char*) * 1000);
    int scheduled_program_count = 0;
    
    // Display each service
    for (int svc_idx = 0; svc_idx < svc_count; svc_idx++) {
        EsgServiceInfo* esg_service = service_array[svc_idx];
        
        // Extract service number
        char service_num[32] = "";
        const char* service_marker = strstr(esg_service->id, "Service-");
        if (service_marker) {
            strncpy(service_num, service_marker + 8, sizeof(service_num) - 1);
        }
        
        fprintf(f, "<details><summary><strong>Service %s: %s", 
                service_num, 
                strlen(esg_service->name) > 0 ? esg_service->name : esg_service->id);
                
        if (strlen(esg_service->majorChannel) > 0 && strlen(esg_service->minorChannel) > 0) {
            fprintf(f, " (%s.%s)", esg_service->majorChannel, esg_service->minorChannel);
        }
        fprintf(f, "</strong></summary>\n");
        fprintf(f, "<div style='margin-left: 20px;'>\n");
        
        // Service details table
        fprintf(f, "<table><tr><th>Field</th><th>Value</th></tr>");
        fprintf(f, "<tr><td><strong>ID</strong></td><td>%s</td></tr>", esg_service->id);
        if(strlen(esg_service->serviceStatus) > 0)
            fprintf(f, "<tr><td><strong>Status</strong></td><td>%s</td></tr>", esg_service->serviceStatus);
        if(strlen(esg_service->genre) > 0) 
            fprintf(f, "<tr><td><strong>Genre</strong></td><td>%s</td></tr>", esg_service->genre);
        if(strlen(esg_service->description) > 0) 
            fprintf(f, "<tr><td><strong>Description</strong></td><td>%s</td></tr>", esg_service->description);
        fprintf(f, "</table>\n");
        
        // Display service icons
        if(esg_service->icons) {
            fprintf(f, "<h5>Service Icons:</h5>");
            fprintf(f, "<div style='display: flex; gap: 10px; flex-wrap: wrap; align-items: center;'>");
            EsgMediaAsset* icon = esg_service->icons;
            while(icon) {
                char* icon_url = icon->uri;
                
                if (strncmp(icon_url, "http://", 7) == 0 || strncmp(icon_url, "https://", 8) == 0) {
                    fprintf(f, "<a href='");
                    for (char* p = icon_url; *p; p++) {
                        if (*p == '&') fprintf(f, "&amp;");
                        else fputc(*p, f);
                    }
                    fprintf(f, "' target='_blank' style='display:inline-block; background:#eee; padding:8px 12px; font-size:24px; text-decoration:none; border-radius:4px;' title='View service icon (%sx%s)'>📷</a>",
                            strlen(icon->width) > 0 ? icon->width : "?",
                            strlen(icon->height) > 0 ? icon->height : "?");
                } else {
                    fprintf(f, "<span style='background:#eee; padding:8px 12px; font-size:24px; color:#666; border-radius:4px;' title='%s (%sx%s)'>📷</span>",
                            icon_url,
                            strlen(icon->width) > 0 ? icon->width : "?",
                            strlen(icon->height) > 0 ? icon->height : "?");
                }
                icon = icon->next;
            }
            fprintf(f, "</div>");
        }
        
        // Schedule display
        if(esg_service->schedule) {
            typedef struct {
                EsgScheduleEvent* event;
                EsgProgramInfo* program;
                time_t timestamp;
            } ScheduleItem;
            
            ScheduleItem* schedule_items = malloc(sizeof(ScheduleItem) * 1000);
            int schedule_count = 0;
            
            EsgScheduleEvent* event = esg_service->schedule;
            while(event && schedule_count < 1000) {
                EsgProgramInfo* prog = merged->programs;
                EsgProgramInfo* matched_prog = NULL;
                while(prog) {
                    if (strcmp(prog->id, event->programId) == 0) {
                        matched_prog = prog;
                        break;
                    }
                    prog = prog->next;
                }
                schedule_items[schedule_count].event = event;
                schedule_items[schedule_count].program = matched_prog;
                schedule_items[schedule_count].timestamp = atoll(event->startTime) - 2208988800LL;
                schedule_count++;
                
                if (scheduled_program_count < 1000) {
                    scheduled_program_ids[scheduled_program_count++] = event->programId;
                }
                
                event = event->next;
            }
            
            // Sort by timestamp
            for (int a = 0; a < schedule_count - 1; a++) {
                for (int b = 0; b < schedule_count - a - 1; b++) {
                    if (schedule_items[b].timestamp > schedule_items[b+1].timestamp) {
                        ScheduleItem temp = schedule_items[b];
                        schedule_items[b] = schedule_items[b+1];
                        schedule_items[b+1] = temp;
                    }
                }
            }
            
            fprintf(f, "<h5>Schedule:</h5><table><tr><th>Time</th><th><nobr>Duration</nobr></th><th>Program</th></tr>\n");
            for (int s = 0; s < schedule_count; s++) {
                time_t ts = schedule_items[s].timestamp;
                struct tm* tm_info = localtime(&ts);
                char time_str[64];
                strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm_info);
                
                const char* prog_title = schedule_items[s].program ? 
                    (strlen(schedule_items[s].program->title) > 0 ? schedule_items[s].program->title : schedule_items[s].event->programId) :
                    schedule_items[s].event->programId;
                const char* prog_desc = schedule_items[s].program ? schedule_items[s].program->description : "";
                
                int dur_seconds = atoi(schedule_items[s].event->duration);
                int hours = dur_seconds / 3600;
                int minutes = (dur_seconds % 3600) / 60;
                char dur_str[32];
                if (hours > 0) {
                    snprintf(dur_str, sizeof(dur_str), "%dh %dm", hours, minutes);
                } else {
                    snprintf(dur_str, sizeof(dur_str), "%dm", minutes);
                }
                
                fprintf(f, "<tr><td><nobr>%s</nobr></td><td><nobr>%s</nobr></td><td>", 
                    time_str, dur_str);
                
                // Show program icon
                if (schedule_items[s].program && schedule_items[s].program->icons) {
                    char* icon_url = schedule_items[s].program->icons->uri;
                    
                    if (strncmp(icon_url, "http://", 7) == 0 || strncmp(icon_url, "https://", 8) == 0) {
                        fprintf(f, "<a href='");
                        for (char* p = icon_url; *p; p++) {
                            if (*p == '&') fprintf(f, "&amp;");
                            else fputc(*p, f);
                        }
                        fprintf(f, "' target='_blank' style='display:inline-block; background:#eeeeee; padding:2px 6px; font-size:16px; text-decoration:none; margin-right:8px;' title='View program image'>📷</a>");
                    } else {
                        fprintf(f, "<span style='background:#eee; padding:2px 6px; font-size:16px; color:#666666; margin-right:8px;' title='%s'>📷</span>", icon_url);
                    }
                }
                
                fprintf(f, "<strong>%s</strong>", prog_title);

                // Show content rating badge
                if (schedule_items[s].program && schedule_items[s].program->ratings) {
                    EsgContentRating* rating = schedule_items[s].program->ratings;
                    const char* badge_color = "#666";
                    if (strstr(rating->value, "TV-MA") || strstr(rating->value, "R") || strstr(rating->value, "NC-17")) {
                        badge_color = "#c41e3a";
                    } else if (strstr(rating->value, "TV-14") || strstr(rating->value, "PG-13")) {
                        badge_color = "#e67e22";
                    } else if (strstr(rating->value, "TV-PG") || strstr(rating->value, "PG")) {
                        badge_color = "#3498db";
                    } else if (strstr(rating->value, "TV-G") || strstr(rating->value, "TV-Y") || strstr(rating->value, "G")) {
                        badge_color = "#27ae60";
                    }
                    fprintf(f, " <span style='background-color:%s; color:white; padding:1px 6px; border-radius:3px; font-size:11px; font-weight:bold; margin-left:8px;'>%s</span>", 
                            badge_color, rating->value);
                }
                
                if (strlen(prog_desc) > 0) {
                    fprintf(f, "<br><small>%s</small>", prog_desc);
                }
                
                fprintf(f, "<br><small style='color:#666;'>%s</small>", schedule_items[s].event->programId);
                fprintf(f, "</td></tr>\n");
            }
            fprintf(f, "</table>");
            
            free(schedule_items);
        }
        
        // Unscheduled programs
        if (strlen(service_num) > 0) {
            typedef struct {
                EsgProgramInfo* program;
                int prog_num;
            } ProgramItem;
            
            ProgramItem* unscheduled_items = malloc(sizeof(ProgramItem) * 1000);
            int unscheduled_count = 0;
            
            char content_pattern[64];
            snprintf(content_pattern, sizeof(content_pattern), "Content-%s-", service_num);
            
            EsgProgramInfo* program = merged->programs;
            while(program) {
                if (strstr(program->id, content_pattern)) {
                    int is_scheduled = 0;
                    for (int sc = 0; sc < scheduled_program_count; sc++) {
                        if (strcmp(scheduled_program_ids[sc], program->id) == 0) {
                            is_scheduled = 1;
                            break;
                        }
                    }
                    
                    if (!is_scheduled && unscheduled_count < 1000) {
                        unscheduled_items[unscheduled_count].program = program;
                        
                        const char* last_dash = strrchr(program->id, '-');
                        if (last_dash) {
                            unscheduled_items[unscheduled_count].prog_num = atoi(last_dash + 1);
                        } else {
                            unscheduled_items[unscheduled_count].prog_num = 999999;
                        }
                        unscheduled_count++;
                    }
                }
                program = program->next;
            }
            
            if (unscheduled_count > 0) {
                for (int a = 0; a < unscheduled_count - 1; a++) {
                    for (int b = 0; b < unscheduled_count - a - 1; b++) {
                        if (unscheduled_items[b].prog_num > unscheduled_items[b+1].prog_num) {
                            ProgramItem temp = unscheduled_items[b];
                            unscheduled_items[b] = unscheduled_items[b+1];
                            unscheduled_items[b+1] = temp;
                        }
                    }
                }
                
                fprintf(f, "<h5>Unscheduled Programs (%d):</h5>", unscheduled_count);
                fprintf(f, "<table><tr><th>Program</th><th>Description</th></tr>\n");
                
                for (int p = 0; p < unscheduled_count; p++) {
                    EsgProgramInfo* prog = unscheduled_items[p].program;
                    fprintf(f, "<tr><td>");
                    
                    if (prog->icons) {
                        fprintf(f, "<img src='%s' alt='%s' style='max-width: 100px; max-height: 100px; float: left; margin-right: 10px;' onerror=\"this.style.display='none';\">",
                                prog->icons->uri, prog->title);
                    }
                    
                    fprintf(f, "<strong>%s</strong><br><small>%s</small></td><td>%s</td></tr>\n", 
                            strlen(prog->title) > 0 ? prog->title : prog->id,
                            prog->id,
                            prog->description);
                }
                fprintf(f, "</table>");
            }
            
            free(unscheduled_items);
        }
        
        // Display raw XML for this service (if function pointer provided)
        if (fprintf_escaped_xml_fn) {
            for (int t = 0; t < merged->xml_tracker_count; t++) {
                if (strcmp(merged->xml_trackers[t].service_id, esg_service->id) == 0) {
                    EsgServiceXmlTracker* tracker = &merged->xml_trackers[t];
                    int total_frags = tracker->service_xml_count + 
                                     tracker->schedule_xml_count + 
                                     tracker->content_xml_count;
                    
                    if (total_frags > 0) {
                        fprintf(f, "<details><summary>Raw XML (%d fragments: %d service, %d schedule, %d content)</summary><pre>", 
                                total_frags,
                                tracker->service_xml_count,
                                tracker->schedule_xml_count,
                                tracker->content_xml_count);
                        
                        for (int x = 0; x < tracker->service_xml_count; x++) {
                            fprintf(f, "\n\n&lt;!-- ===== SERVICE FRAGMENT %d ===== --&gt;\n", x + 1);
                            fprintf_escaped_xml_fn(f, tracker->service_xmls[x]);
                        }
                        
                        for (int x = 0; x < tracker->schedule_xml_count; x++) {
                            fprintf(f, "\n\n&lt;!-- ===== SCHEDULE FRAGMENT %d ===== --&gt;\n", x + 1);
                            fprintf_escaped_xml_fn(f, tracker->schedule_xmls[x]);
                        }
                        
                        for (int x = 0; x < tracker->content_xml_count; x++) {
                            fprintf(f, "\n\n&lt;!-- ===== CONTENT FRAGMENT %d ===== --&gt;\n", x + 1);
                            fprintf_escaped_xml_fn(f, tracker->content_xmls[x]);
                        }
                        
                        fprintf(f, "</pre></details>");
                    }
                    break;
                }
            }
        }
        
        fprintf(f, "</div></details>\n");
    }
    
    free(scheduled_program_ids);
    free(service_array);
    
    // Display orphaned/unmatched fragments for diagnostic purposes
    if (merged->orphaned_xml_count > 0 && fprintf_escaped_xml_fn) {
        fprintf(f, "<details><summary style='color:#996600;'>⚠️ Unmatched/Empty Fragments (%d)</summary>\n", 
                merged->orphaned_xml_count);
        fprintf(f, "<div class='details-content'>");
        fprintf(f, "<p style='color:#666;'>These fragments were received but could not be correlated to any service "
                   "(empty ServiceReference, missing data, or unrecognized format):</p>");
        fprintf(f, "<pre style='max-height:400px; overflow:auto;'>");
        
        for (int x = 0; x < merged->orphaned_xml_count && x < 50; x++) {
            fprintf(f, "\n&lt;!-- ===== ORPHANED FRAGMENT %d ===== --&gt;\n", x + 1);
            fprintf_escaped_xml_fn(f, merged->orphaned_xmls[x]);
        }
        
        if (merged->orphaned_xml_count > 50) {
            fprintf(f, "\n\n&lt;!-- ... and %d more orphaned fragments not shown ... --&gt;\n", 
                    merged->orphaned_xml_count - 50);
        }
        
        fprintf(f, "</pre></div></details>\n");
    }
    
    fprintf(f, "</div></details>\n");
    
    free_esg_merged_data(merged);
    
    return result;
}
