#!/bin/bash

unset VERBOSE
OUTPUT_DIR=/tmp

while getopts o:v opts; do
   case ${opts} in
      o) OUTPUT_DIR=${OPTARG} ;;
      v) VERBOSE=1 ;;
   esac
done

set -e
if [[ -n $VERBOSE ]]; then
  set -x
fi

mkdir -p "$OUTPUT_DIR"
pushd "$OUTPUT_DIR" >/dev/null 2>&1
curl --fail-early -fsSL --remote-name-all \
    https://fonts.gstatic.com/s/lato/v24/S6u_w4BMUTPHjxsI9w2_Gwfo.ttf \
    https://fonts.gstatic.com/s/lato/v24/S6u8w4BMUTPHjxsAXC-v.ttf \
    https://fonts.gstatic.com/s/lato/v24/S6u_w4BMUTPHjxsI5wq_Gwfo.ttf \
    https://fonts.gstatic.com/s/lato/v24/S6u9w4BMUTPHh7USSwiPHA.ttf \
    https://fonts.gstatic.com/s/lato/v24/S6uyw4BMUTPHjx4wWw.ttf \
    https://fonts.gstatic.com/s/lato/v24/S6u9w4BMUTPHh6UVSwiPHA.ttf \
    'https://cdn.jsdelivr.net/npm/bootstrap-icons@1.5.0/font/fonts/bootstrap-icons.woff2?856008caa5eb66df68595e734e59580d' \
    'https://cdn.jsdelivr.net/npm/bootstrap-icons@1.5.0/font/fonts/bootstrap-icons.woff?856008caa5eb66df68595e734e59580d'
popd >/dev/null 2>&1

if [[ -n $VERBOSE ]]; then
  set +x
fi
set +e
