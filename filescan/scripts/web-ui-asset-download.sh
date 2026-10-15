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
set -o pipefail
if [[ -n $VERBOSE ]]; then
  set -x
fi

# "URL|output filename (optional, defaults to the URL's file name)|SHA-256"
#   These are pinned versions; several are also downloaded (with the same checksums) by
#   Dockerfiles/nginx.Dockerfile, so update both places together.
ASSETS=(
    "https://fonts.gstatic.com/s/lato/v24/S6u_w4BMUTPHjxsI9w2_Gwfo.ttf||287f2b0a046343d811ae43312783880cba0e09850886d6dcdd57a73f65147f01"
    "https://fonts.gstatic.com/s/lato/v24/S6u8w4BMUTPHjxsAXC-v.ttf||218f6f647f83ceec4b0995a5186404d9fc4a5fb5c535d0cdd016bf52afbb5e7e"
    "https://fonts.gstatic.com/s/lato/v24/S6u_w4BMUTPHjxsI5wq_Gwfo.ttf||726beec7cd96f06f5b05b5af54d47321b6270f94e21f4a3bdc80cefc3b79ba69"
    "https://fonts.gstatic.com/s/lato/v24/S6u9w4BMUTPHh7USSwiPHA.ttf||b229d664a58a75e0a438fad204b292b5777e79fafd4b840cce21bac7ad2a7a28"
    "https://fonts.gstatic.com/s/lato/v24/S6uyw4BMUTPHjx4wWw.ttf||b6e055ad6056d64c89133fd73e9ee935c068d8bd3ac09366d5d99f9eee99e3f4"
    "https://fonts.gstatic.com/s/lato/v24/S6u9w4BMUTPHh6UVSwiPHA.ttf||7e15d8482756e9d79c5b14dde8cd92256fd2afe0307703d825d4e8178d416c41"
    "https://cdn.jsdelivr.net/npm/bootstrap-icons@1.13.1/font/fonts/bootstrap-icons.woff2||6c75710364a1ca5604267716f6d28997b26319fdb078cf11e0b42ab66ff2ea61"
    "https://cdn.jsdelivr.net/npm/bootstrap-icons@1.13.1/font/fonts/bootstrap-icons.woff||f55513b7b591cb84a3b87ff0e34ea24d4831d6fedc22e54b911ca64b5b544a15"
    "https://cdn.jsdelivr.net/npm/bootstrap-icons@1.13.1/font/bootstrap-icons.css||004322721c8557331759bc6ddaacbb689b0f0715d688aec82bd056d2d5b5cc3b"
    "https://use.fontawesome.com/releases/v4.7.0/fonts/fontawesome-webfont.eot||7bfcab6db99d5cfbf1705ca0536ddc78585432cc5fa41bbd7ad0f009033b2979"
    "https://use.fontawesome.com/releases/v4.7.0/fonts/fontawesome-webfont.woff2||2adefcbc041e7d18fcf2d417879dc5a09997aa64d675b7a3c4b6ce33da13f3fe"
    "https://use.fontawesome.com/releases/v4.7.0/fonts/fontawesome-webfont.woff||ba0c59deb5450f5cb41b3f93609ee2d0d995415877ddfa223e8a8a7533474f07"
    "https://use.fontawesome.com/releases/v4.7.0/fonts/fontawesome-webfont.ttf||aa58f33f239a0fb02f5c7a6c45c043d7a9ac9a093335806694ecd6d4edc0d6a8"
    "https://use.fontawesome.com/releases/v4.7.0/fonts/fontawesome-webfont.svg#fontawesomeregular||ad6157926c1622ba4e1d03d478f1541368524bfc46f51e42fe0d945f7ef323e4"
)

# download and verify everything in a scratch directory first, so a failed or tampered
#   download never leaves a partial set of assets in OUTPUT_DIR
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

for i in "${ASSETS[@]}"; do
    URL="$(echo "${i}" | cut -d'|' -f1)"
    OUTPUT_FILE="$(echo "${i}" | cut -d'|' -f2)"
    SHA256="$(echo "${i}" | cut -d'|' -f3)"
    [[ -n "${URL}" ]] || continue
    if [[ -z "${OUTPUT_FILE}" ]]; then
        # file name from the URL path, without any fragment or query string
        OUTPUT_FILE="$(basename "${URL%%[#?]*}")"
    fi
    if [[ ! "${SHA256}" =~ ^[0-9a-fA-F]{64}$ ]]; then
        echo "Missing or invalid SHA-256 for ${URL}" >&2
        exit 1
    fi
    curl --fail --silent --show-error --location --retry 3 --output "${WORK_DIR}/${OUTPUT_FILE}" "${URL}"
    echo "${SHA256}  ${WORK_DIR}/${OUTPUT_FILE}" | sha256sum -c --quiet -
done

# post-process only after verification (the checksum is of the file as published)
[[ -f "${WORK_DIR}/bootstrap-icons.css" ]] && sed -i '/bootstrap-icons\.woff/ { s|\./fonts/|./|g; s|[?][^")]*||g }' "${WORK_DIR}/bootstrap-icons.css"

mkdir -p "$OUTPUT_DIR"
cp -f "${WORK_DIR}"/* "$OUTPUT_DIR"/

if [[ -n $VERBOSE ]]; then
  set +x
fi
set +e
