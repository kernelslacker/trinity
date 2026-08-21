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
# multi-line block comments are handled correctly.
strip_c_comments() {
	awk '
		{
			line = $0; stripped = ""; i = 1; len = length(line)
			while (i <= len) {
				if (in_block) {
					if (substr(line, i, 2) == "*/") { in_block = 0; i += 2 }
					else { i++ }
				} else if (substr(line, i, 2) == "/*") {
					in_block = 1; i += 2
				} else if (substr(line, i, 2) == "//") {
					break
				} else {
					stripped = stripped substr(line, i, 1); i++
				}
			}
			print stripped
		}
	' "$1" 2>/dev/null
}
