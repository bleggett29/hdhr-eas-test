#include <sys/types.h>
#include "utility.h"

/**
 * @brief Helper function to print a string to a file, escaping characters for HTML.
 */
void fprintf_escaped_xml(FILE *f, const char *xml_content) {
    if (!xml_content) return;
    while (*xml_content) {
        switch (*xml_content) {
            case '<': fprintf(f, "&lt;"); break;
            case '>': fprintf(f, "&gt;"); break;
            case '&': fprintf(f, "&amp;"); break;
            case '"': fprintf(f, "&quot;"); break;
            case '\'': fprintf(f, "&apos;"); break;
            default: fputc(*xml_content, f); break;
        }
        xml_content++;
    }
}

/**
 * @brief Prints a buffer in a hex dump format for debugging.
 */
void print_hex_dump(const char* prefix, const u_char* buffer, int len) {
    fprintf(stderr, "%s (%d bytes):\n", prefix, len);
    for (int i = 0; i < len; ++i) {
        fprintf(stderr, "%02x ", buffer[i]);
        if ((i + 1) % 16 == 0) {
            fprintf(stderr, "\n");
        } else if ((i + 1) % 8 == 0) {
             fprintf(stderr, " ");
        }
    }
    fprintf(stderr, "\n");
}
