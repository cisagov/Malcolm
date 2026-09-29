#!/usr/bin/env bash

# Packages a filtered snapshot of the Malcolm source tree into a zip file,
# for handing off to an LLM as debugging/development context. Strips out
# anything that's noise for that purpose: generated assets and saved objects
# (Dashboards visualizations, index-pattern exports), binary/media files,
# deployment-target subtrees not relevant to core service development
# (malcolm-iso, hedgehog-raspi, kubernetes), and per-service data/config
# files that don't carry logic (Strelka scanner configs, Suricata rule
# packs, Logstash lookup maps). Keeps actual pipeline and service code,
# plus a small allowlist of scripts/ and docs/ files that are broadly
# useful context even though the rest of those directories isn't. Also
# drops anything not tracked by git, so local scratch files and
# uncommitted work-in-progress never end up in the archive.
#
# With no arguments, packages the whole filtered tree into malcolm_src.zip.
#
# With one or more Dockerfile paths as arguments, narrows the output to just
# the files that Dockerfile's COPY/ADD instructions actually pull from the
# build context, plus the Dockerfile(s) themselves and the compose files,
# and names the output after the service(s). A Dockerfile argument can be a
# full or relative path, or just a bare filename, in which case it's looked
# up under $SCRIPT_DIR/../Dockerfiles/ before giving up:
#
#   ./malcolm_source_zip.sh api.Dockerfile
#   ./malcolm_source_zip.sh Dockerfiles/api.Dockerfile Dockerfiles/nginx.Dockerfile
#
# Assumes the Docker build context for every Dockerfile is the repo root
# (this is how Malcolm's docker-compose.yml sets each service's `context:`).
# If that ever changes for a given service, COPY sources will fail to
# resolve and print a "no tracked files matched" warning below rather than
# silently producing a wrong or empty archive.
#
# Known gaps: COPY/ADD lines built from a Dockerfile ARG (e.g. `COPY
# ${SRC}/file dest/`) aren't resolved, since that requires evaluating
# build args rather than just reading the text. Multi-stage COPY
# (`--from=`) is intentionally skipped, since that source lives in another
# build stage or image, not on the host filesystem, so nothing to package.
#
# Rebuilds the archive from scratch each run rather than updating an
# existing one, so stale entries from a prior run's exclude list (or a
# prior --service filter) can't linger silently in the zip.

set -euo pipefail

function file_list_cleanup() {
  local TF="${1}"
  [[ -n "$TF" ]] && [[ -f "$TF" ]] && rm -f "$TF" >/dev/null 2>&1
}

# Strips a single matching pair of surrounding quotes (' or ") from a token,
# if present. Dockerfile COPY/ADD arguments can be quoted in the source
# (e.g. ADD 'https://...' /dest/), and bash's `read` doesn't interpret
# quotes as syntax the way Docker's own parser does, so without this a
# quoted remote URL keeps its literal quote characters and no longer looks
# like a URL to the http(s):// check below.
function strip_quotes() {
  local s="$1"
  if [[ ( "$s" == \"*\" && "$s" == *\" ) || ( "$s" == \'*\' && "$s" == *\' ) ]]; then
    s="${s:1:-1}"
  fi
  printf '%s' "$s"
}

# Parses one Dockerfile's COPY/ADD instructions and prints each source path
# on its own line, relative to the build context root. Skips --from=
# (multi-stage/external-image) copies and ADD of remote URLs.
function extract_copy_sources() {
  local dockerfile="$1"
  awk '
    /\\[[:space:]]*$/ { sub(/\\[[:space:]]*$/, " "); printf "%s", $0; next }
    { print }
  ' "$dockerfile" \
  | grep -Ei '^[[:space:]]*(COPY|ADD)[[:space:]]' \
  | while IFS= read -r line; do
      [[ "$line" == *"--from="* ]] && continue

      # drop the instruction keyword (COPY/copy/ADD/add, any case)
      line="$(awk '{$1=""; print}' <<< "$line" | sed -E 's/^[[:space:]]+//')"

      while [[ "$line" == --* ]]; do
        line="${line#* }"
      done

      if [[ "$line" == \[*\] ]]; then
        # JSON-array form: COPY ["src", "src2", "dest"]
        mapfile -t parts < <(grep -oE '"[^"]*"' <<< "$line" | tr -d '"')
      else
        read -ra parts <<< "$line"
      fi

      local count=${#parts[@]}
      (( count < 2 )) && continue   # malformed / nothing to copy

      for ((i=0; i<count-1; i++)); do
        src="$(strip_quotes "${parts[$i]}")"
        [[ "$src" == http://* || "$src" == https://* ]] && continue   # ADD remote URL
        echo "$src"
      done
    done
}

# Prints every line from $TMP_LIST that a given COPY/ADD source resolves to:
# an exact file match, everything under it if it names a directory, or a
# glob expansion if it contains wildcard characters.
function match_source() {
  local raw="$1" f
  local exact="${raw#./}"
  local prefix="${exact%/}/"
  while IFS= read -r f; do
    if [[ "$f" == "$exact" ]]; then
      echo "$f"
    elif [[ "$f" == "$prefix"* ]]; then
      echo "$f"
    elif [[ "$exact" == *[*?]* && "$f" == $exact ]]; then
      echo "$f"
    fi
  done < "$TMP_LIST"
}

export SCRIPT_DIR="$( cd -P "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Resolve Dockerfile args to absolute paths now, before the pushd below
# changes the working directory out from under any relative path the
# caller typed (from the repo root, from scripts/, from anywhere else).
# A bare filename that doesn't exist as given (relative to the caller's
# cwd, or absolute) falls back to $SCRIPT_DIR/../Dockerfiles/<name> before
# giving up on it, so `api.Dockerfile` works without typing the full path.
declare -a DOCKERFILE_ARGS=()
for df in "$@"; do
  if [[ -f "$df" ]]; then
    :
  elif [[ -f "$SCRIPT_DIR/../Dockerfiles/$(basename "$df")" ]]; then
    df="$SCRIPT_DIR/../Dockerfiles/$(basename "$df")"
  else
    echo "warning: '$df' not found (also checked Dockerfiles/$(basename "$df")), skipping" >&2
    continue
  fi
  DOCKERFILE_ARGS+=("$(realpath "$df")")
done

TMP_LIST=$(mktemp -t malcolm-files.XXXXXXXXXX)
TMP_TRACKED=$(mktemp -t malcolm-tracked.XXXXXXXXXX)
TMP_SOURCES=$(mktemp -t malcolm-sources.XXXXXXXXXX)
TMP_FILTERED=$(mktemp -t malcolm-filtered.XXXXXXXXXX)
TMP_ZIP=$(mktemp -t malcolm-files.XXXXXXXXXX.zip)
trap "file_list_cleanup '${TMP_LIST}'; file_list_cleanup '${TMP_TRACKED}'; file_list_cleanup '${TMP_SOURCES}'; file_list_cleanup '${TMP_FILTERED}'; file_list_cleanup '${TMP_ZIP}'" SIGINT EXIT RETURN
pushd "$SCRIPT_DIR"/.. >/dev/null 2>&1

{
  fd -t f \
    -E '/_includes' \
    -E '/_layouts' \
    -E '/config' \
    -E '/docs' \
    -E '/hedgehog-raspi' \
    -E '/kubernetes' \
    -E '/malcolm-iso' \
    -E '/scripts' \
    -E '_config.yml' \
    -E 'arkime/etc' \
    -E 'arkime/parsers' \
    -E 'arkime/rules' \
    -E 'arkime/wise' \
    -E 'bootstrap.css' \
    -E 'bootstrap.min.js' \
    -E 'dashboards/dashboards' \
    -E 'dashboards/maps' \
    -E 'LICENSE.txt' \
    -E 'logstash.yml' \
    -E 'logstash/maps' \
    -E 'netbox/preload' \
    -E 'nginx/landingpage' \
    -E 'NOTICE.txt' \
    -E 'opensearch-config/config' \
    -E 'opensearch_dashboards.yml' \
    -E 'strelka/config' \
    -E 'suricata/rules-default' \
    -E '*.png' -E '*.svg' -E '*.ico' -E '.gitignore' \
    -E '*.ttf' -E '*.otf' -E '*.woff2' -E '*.md' \
    -E '*.pcap' -E '*.gz' -E '*.pack' -E '*.rev' -E '*.pb' \
    -E '*.xcf' -E '*.ai' -E '*.pdf' -E '*.odp' -E '*.odg' \
    -E '*.sample' \
    .

  fd -t f '^(malcolm_(common|constants|utils)\.py|safe-extract\.py)$' ./scripts
  fd -t f '^(README|components|contributing-(dashboards|logstash|new-log-fields|zeek))\.md$' ./docs
  fd -t f '^README\.md$' -d 1 .
} | sed 's@^\./@@' | sort -u > "$TMP_LIST"

git ls-files > "$TMP_TRACKED"
grep -Fxf "$TMP_TRACKED" "$TMP_LIST" > "${TMP_LIST}.tracked" && mv "${TMP_LIST}.tracked" "$TMP_LIST"

OUT_NAME="malcolm_src"

if (( ${#DOCKERFILE_ARGS[@]} > 0 )); then
  : > "$TMP_SOURCES"
  for abs_df in "${DOCKERFILE_ARGS[@]}"; do
    # Now that we're sitting in the repo root, put this back into the same
    # repo-relative form that $TMP_LIST is already in, or it'll never match.
    df="$(realpath --relative-to="$PWD" "$abs_df")"
    echo "$df" >> "$TMP_SOURCES"
    extract_copy_sources "$df" >> "$TMP_SOURCES"
    OUT_NAME+="_$(basename "$df" .Dockerfile)"
  done
  sort -u "$TMP_SOURCES" -o "$TMP_SOURCES"

  : > "$TMP_FILTERED"
  while IFS= read -r src; do
    m="$(match_source "$src")"
    if [[ -z "$m" ]]; then
      echo "warning: no tracked files matched COPY/ADD source '$src'" >&2
    else
      printf '%s\n' "$m" >> "$TMP_FILTERED"
    fi
  done < "$TMP_SOURCES"

  grep -Fx 'docker-compose.yml' "$TMP_LIST" >> "$TMP_FILTERED" || true
  grep -Fx 'docker-compose-dev.yml' "$TMP_LIST" >> "$TMP_FILTERED" || true

  sort -u "$TMP_FILTERED" -o "$TMP_LIST"
fi

rm -f "$TMP_ZIP"
zip -q "$TMP_ZIP" -@ < "$TMP_LIST"

popd >/dev/null 2>&1

mv "$TMP_ZIP" "./${OUT_NAME}.zip"
ls -l "./${OUT_NAME}.zip"
