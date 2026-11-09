#ifndef UTILITY_H
#define UTILITY_H

#include <stdio.h>
#include <sys/types.h>
#ifdef _WIN32
typedef unsigned char u_char;
#endif

/**
 * @brief Prints a string to a file, escaping characters for HTML.
 * @param f File pointer to write to
 * @param xml_content String to escape and write
 */
void fprintf_escaped_xml(FILE *f, const char *xml_content);
void print_hex_dump(const char* prefix, const u_char* buffer, int len);

#endif // UTILITY_H
