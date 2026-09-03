#!/usr/bin/env bash

if [[ -z "${BASH_VERSION:-}" ]]; then
  echo "Wrong interpreter, please run \"$0\" with bash"
  exit 1
fi

# Prefer GNU tools everywhere (use g*-prefixed on macOS, plain on Linux)
if [[ "$(uname -s)" == Darwin ]]; then
  AWK=gawk
  BASENAME=gbasename
  DIRNAME=gdirname
  FIND=gfind
  REALPATH=grealpath
  SED=gsed
  SORT=gsort
else
  AWK=awk
  BASENAME=basename
  DIRNAME=dirname
  FIND=find
  REALPATH=realpath
  SED=sed
  SORT=sort
fi

required=(
  jq rg "$AWK" "$BASENAME" "$DIRNAME" "$FIND" "$REALPATH" "$SED" "$SORT"
)

missing=()
for cmd in "${required[@]}"; do
  command -v "$cmd" >/dev/null 2>&1 || missing+=("$cmd")
done
if ((${#missing[@]})); then
  echo "$("$BASENAME" "${BASH_SOURCE[0]}") requires: ${missing[*]}"
  exit 1
fi

SCRIPT_PATH="$("$DIRNAME" "$("$REALPATH" -e "${BASH_SOURCE[0]}")")"
pushd "$SCRIPT_PATH/.." >/dev/null 2>&1

function get_field_names () {
    # first get them from the giant list in ./arkime/wise/source.zeeklogs.js
    $AWK '
      /var allFields = \[/ {inlist=1; next}
      inlist && /^\s*\];/ {inlist=0; exit}
      inlist {
        gsub(/^[[:space:]]*"/, "")
        gsub(/",?[[:space:]]*$/, "")
        print
      }
    ' ./arkime/wise/source.zeeklogs.js

    # now grep them out of the logstash filters
    rg --color=never -o --no-filename \
        -P '(?<![A-Za-z0-9_@.-])(?:\[[^\[\]]+\](?:\[[^\[\]]+\])+|[A-Za-z_@][A-Za-z0-9_@-]*(?:\.[A-Za-z_@][A-Za-z0-9_@-]*)+)(?![A-Za-z0-9_@.-])' ./logstash/pipelines | \
        $SED -E '/^\[/{s/^\[//; s/\]$//; s/\]\[/./g;}' | \
        rg -v \
          -e "(^(@|zeek_cols)|^\.yaml$)" \
          -e '\.(log|rb|html|yaml|zeek|json|crt|key|pl|py|conf|bro|c)$' \
          -e '\.(org|io|com|net)(\/|$)' \
          -e '\.(nil|to_s|strip|to_i|to_a|to_f|hex|length|push|append|uniq|flatten|join|split|scan|gsub|sub|match|captures|start_with|end_with|delete_prefix|delete_suffix|reject|select|map|each|any|first|last|find|dig|compact|clone|call|kind_of|is_a|positive|zero|min|encode|bytesize|new|parse|read|empty|include)(\.|$)' \
          -e '^\s*$' \
          -e "'\s*\+" \
          -e '#\{' \
          -e '\.[0-9]+$'

    # finally, pull them out of the ./dashboards/templates themselves
    $FIND ./dashboards/templates -type f \( -name '*.json' -o -name '*.template' \) -print0 |
    while IFS= read -r -d '' file; do
      jq -r '
        def extract($path):
          if (.properties? | type) == "object" then
            .properties
            | to_entries[]
            | . as $e
            | $e.value | extract($path + [$e.key])
          else
            $path | join(".")
          end;

        (.template.mappings.properties // .mappings.properties // empty)
        | to_entries[]
        | . as $e
        | $e.value | extract([$e.key])
      ' "$file" 2>/dev/null
    done
}

# trim branches (just the leaves remain)
get_field_names | $SORT -u | $AWK '
{
  fields[NR] = $0
}

END {
  for (i = 1; i <= NR; i++) {
    is_parent = 0
    prefix = fields[i] "."
    for (j = 1; j <= NR; j++) {
      if (i != j && index(fields[j], prefix) == 1) {
        is_parent = 1
        break
      }
    }
    if (!is_parent) {
      print fields[i]
    }
  }
}'

popd >/dev/null 2>&1