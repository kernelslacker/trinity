#pragma once

/*
 * Content-aware text payload generators for kernel string-parser fuzzing.
 *
 * Each function writes up to buflen bytes into buf and returns the number of
 * bytes written.  Callers control buffer size; generators never exceed buflen.
 */

/* Repeated single-character class: all 'A', all digits, repeating UTF-8. */
unsigned int gen_long_string(char *buf, unsigned int buflen);

/* 'A' * 100 + NUL + 'B' * 100 — tests strlen-vs-explicit-length parsers. */
unsigned int gen_embedded_nul(char *buf, unsigned int buflen);

/* Printf-style format specifiers: %s %n %d %p %x and combinations. */
unsigned int gen_format_string_attack(char *buf, unsigned int buflen);

/* Valid numeric/hex prefix followed by random garbage bytes. */
unsigned int gen_valid_prefix_garbage(char *buf, unsigned int buflen);

/* Boundary integers: INT_MAX, INT_MIN, overflow, leading zeros, etc. */
unsigned int gen_numeric_boundary_string(char *buf, unsigned int buflen);

/* Path traversal sequences: "../../../etc/passwd", "//../foo", etc. */
unsigned int gen_path_traversal(char *buf, unsigned int buflen);

/* ASCII text interspersed with binary control characters \x01-\x1f. */
unsigned int gen_binary_control_chars(char *buf, unsigned int buflen);

/* Pick one of the above generators at random. */
unsigned int gen_text_payload(char *buf, unsigned int buflen);
