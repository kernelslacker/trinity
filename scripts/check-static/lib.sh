#!/bin/bash
#
# lib.sh — shared helpers for check-static gate scripts.
#
# Source this file at the top of a gate script:
#   source "$(dirname "$0")/lib.sh"
#
# Do NOT execute this file directly.

# strip_c_comments FILE
#
# Emit FILE with all C block comments (/* ... */) and line comments (//)
# removed, preserving line count so that grep -n line numbers remain aligned
# with the original source.  The output is written to stdout.
#
# Implementation note: a block-comment opener that begins before the region
# of interest still suppresses text in that region because awk processes the
# file from byte 0.  The in_block flag carries across line boundaries so
# multi-line block comments are handled correctly.  String-literal (in_str)
# and char-literal (in_chr) state prevent /* or // inside "..." or '...'
# from being mistaken for comment openers.  Both flags are reset at
# end-of-line because C does not allow unterminated string/char literals
# to continue on the next line.
strip_c_comments() {
	awk '
		{
			line = $0; stripped = ""; i = 1; len = length(line)
			while (i <= len) {
				ch = substr(line, i, 1)
				if (in_block) {
					if (substr(line, i, 2) == "*/") { in_block = 0; i += 2 }
					else { i++ }
				} else if (in_str) {
					if (ch == "\\") {
						stripped = stripped ch substr(line, i+1, 1); i += 2
					} else if (ch == "\"") {
						in_str = 0; stripped = stripped ch; i++
					} else {
						stripped = stripped ch; i++
					}
				} else if (in_chr) {
					if (ch == "\\") {
						stripped = stripped ch substr(line, i+1, 1); i += 2
					} else if (ch == "\x27") {
						in_chr = 0; stripped = stripped ch; i++
					} else {
						stripped = stripped ch; i++
					}
				} else if (substr(line, i, 2) == "/*") {
					in_block = 1; i += 2
				} else if (substr(line, i, 2) == "//") {
					break
				} else if (ch == "\"") {
					in_str = 1; stripped = stripped ch; i++
				} else if (ch == "\x27") {
					in_chr = 1; stripped = stripped ch; i++
				} else {
					stripped = stripped ch; i++
				}
			}
			# C string/char literals do not span lines; reset per-line state.
			in_str = 0; in_chr = 0
			print stripped
		}
	' "$1" 2>/dev/null
}
