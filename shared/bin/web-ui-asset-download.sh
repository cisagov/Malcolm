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

ASSETS=(
    "https://fonts.gstatic.com/s/lato/v24/S6u_w4BMUTPHjxsI9w2_Gwfo.ttf|"
    "https://fonts.gstatic.com/s/lato/v24/S6u8w4BMUTPHjxsAXC-v.ttf|"
    "https://fonts.gstatic.com/s/lato/v24/S6u_w4BMUTPHjxsI5wq_Gwfo.ttf|"
    "https://fonts.gstatic.com/s/lato/v24/S6u9w4BMUTPHh7USSwiPHA.ttf|"
    "https://fonts.gstatic.com/s/lato/v24/S6uyw4BMUTPHjx4wWw.ttf|"
    "https://fonts.gstatic.com/s/lato/v24/S6u9w4BMUTPHh6UVSwiPHA.ttf|"
    "https://cdn.jsdelivr.net/npm/bootstrap-icons@1.5.0/font/fonts/bootstrap-icons.woff2?856008caa5eb66df68595e734e59580d|bootstrap-icons.woff2"
    "https://cdn.jsdelivr.net/npm/bootstrap-icons@1.5.0/font/fonts/bootstrap-icons.woff?856008caa5eb66df68595e734e59580d|bootstrap-icons.woff"
    "https://use.fontawesome.com/releases/v4.7.0/fonts/fontawesome-webfont.eot|"
    "https://use.fontawesome.com/releases/v4.7.0/fonts/fontawesome-webfont.woff2|"
    "https://use.fontawesome.com/releases/v4.7.0/fonts/fontawesome-webfont.woff|"
    "https://use.fontawesome.com/releases/v4.7.0/fonts/fontawesome-webfont.ttf|"
    "https://use.fontawesome.com/releases/v4.7.0/fonts/fontawesome-webfont.svg#fontawesomeregular|"
)

mkdir -p "$OUTPUT_DIR"
pushd "$OUTPUT_DIR" >/dev/null 2>&1
for i in ${ASSETS[@]}; do
    URL="$(echo "${i}" | cut -d'|' -f1)"
    OUTPUT_FILE="$(echo "${i}" | cut -d'|' -f2)"
    if [[ -n "${URL}" ]]; then
        if [[ -n "${OUTPUT_FILE}" ]]; then
            curl --fail --silent --show-error --output "${OUTPUT_FILE}" "${URL}"
        else
            curl --fail --silent --show-error --remote-header-name --remote-name "${URL}"
        fi
    fi
done
popd >/dev/null 2>&1


if [[ -n $VERBOSE ]]; then
  set +x
fi
set +e
