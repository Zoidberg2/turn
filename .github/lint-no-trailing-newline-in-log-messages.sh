#!/usr/bin/env bash

#
# DO NOT EDIT THIS FILE
#
# It is automatically copied from https://github.com/pion/.goassets repository.
#
# If you want to update the shared CI config, send a PR to
# https://github.com/pion/.goassets instead of this repository.
#

set -e

# Disallow usages of functions that cause the program to exit in the library code
SCRIPT_PATH=$( cd "$(dirname "${BASH_SOURCE[0]}")" ; pwd -P )
if [ -f ${SCRIPT_PATH}/.ci.conf ]; then
  . ${SCRIPT_PATH}/.ci.conf
fi

FILES=$(
  find "${SCRIPT_PATH}/.." -name "*.go" \
    | while read FILE; do
      EXCLUDED=false
      for EXCLUDE_DIRECTORY in ${EXCLUDE_DIRECTORIES}; do
        if [[ $file == */${EXCLUDE_DIRECTORY}/* ]]; then
          EXCLUDED=true
          break
        fi
      done
      ${EXCLUDED} || echo "${FILE}"
    done
)

if grep -E '\.(Trace|Debug|Info|Warn|Error)f?\("[^"]*\\n"\)?' ${FILES} | grep -v -e 'nolint'; then
	echo "Log format strings should have trailing new-line"
	exit 1
fi