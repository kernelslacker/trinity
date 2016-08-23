#! /bin/sh

# This demo script will find the modified files in your project,
# and generate a ctags file and cscope database for these files.
# This script is NOT tested yet!
# by Easwy Yang, 2009/03/29

# vars
PRJ_DIR=/home/easwy/prjtest
PRJ_TAG_FILE=${PRJ_DIR}/tags
PRJ_MOD_TAG_FILE=${PRJ_DIR}/newtags
PRJ_MOD_CSCOPE_FILE=${PRJ_DIR}/newcscope.out
MOD_FILES=${PRJ_DIR}/mod_files

FIND=/usr/bin/find
CTAGS=/usr/bin/ctags
CSCOPE=/usr/bin/cscope

# find modified files
# you can modify this command to exclude the object files, etc.
${FIND} ${PRJ_DIR} -type f -newer ${PRJ_TAG_FILE} > ${MOD_FILES}

# generate tag file
${CTAGS} -f${PRJ_MOD_TAG_FILE} -L${MOD_FILES}
${CSCOPE} -bq -f${PRJ_MOD_CSCOPE_FILE} -i${MOD_FILES}
