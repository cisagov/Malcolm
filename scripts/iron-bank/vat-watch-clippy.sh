#!/usr/bin/env bash
# vat-watch.sh — watch clipboard; on change, look up the identifier in the
# VAT justifications doc, print the full justification to stdout, and put
# the paste-ready justification back into the clipboard.
#   - direct table rows / manual entries -> specific per-finding text
#   - Low CVEs resolved via a family batch -> the grouped J-xx section text

DOC="${1:-Malcolm-26.08.0-VAT-justifications.md}"

if command -v xclip >/dev/null; then
  getclip() { xclip -selection clipboard -o 2>/dev/null; }
  setclip() { xclip -selection clipboard    2>/dev/null; }
elif command -v xsel >/dev/null; then
  getclip() { xsel -b 2>/dev/null; }
  setclip() { xsel -b -i 2>/dev/null; }
elif command -v wl-paste >/dev/null && command -v wl-copy >/dev/null; then
  getclip() { wl-paste -n 2>/dev/null; }
  setclip() { wl-copy 2>/dev/null; }
else
  echo "need xclip, xsel, or wl-paste/wl-copy" >&2; exit 1
fi

CLIP_TEXT=""   # set by lookup(): the paste-ready justification

print_group() {
  local jref="$1"
  awk -v j="### ${jref}:" '
    index($0, j) == 1 { hit=1; print; next }
    hit && /^### /    { exit }
    hit && NF         { print }
  ' "$DOC"
}

# $1 = table row; $2 = "group" to force the clipboard to carry the grouped
# section text (### stripped) instead of the row's specific cell
print_row() {
  local row="$1" clip_mode="${2:-cell}" just jref
  just=$(awk -F'|' '{ gsub(/^[ \t]+|[ \t]+$/, "", $(NF-1)); print $(NF-1) }' <<< "$row")
  echo "$just"
  jref=$(grep -oE '^J-[0-9]+' <<< "$just")
  if [[ -n "$jref" ]]; then
    echo
    print_group "$jref"
    # use grouped text for the clipboard if forced, OR if the cell is a
    # bare J-ref with no per-finding note (nothing useful to paste)
    if [[ "$clip_mode" == "group" || "$just" == "$jref" ]]; then
      CLIP_TEXT=$(print_group "$jref" | sed 's/^### //')
      return
    fi
  fi
  CLIP_TEXT="$just"
}

lookup() {
  local id="$1" row fam
  CLIP_TEXT=""

  row=$(grep -m1 -F "| ${id} " "$DOC")
  if [[ -n "$row" ]]; then print_row "$row"; return; fi

  local manual
  manual=$(awk -v id="$id" '
    $0 ~ "`" id "`" && /^\*\*/ { hit=1; next }
    hit && /^\*Max severity/   { next }
    hit && NF                  { print; found=1 }
    hit && !NF && found        { exit }
  ' "$DOC")
  if [[ -n "$manual" ]]; then
    CLIP_TEXT="$manual"
    echo "MANUAL REVIEW ENTRY:"
    awk -v id="$id" '
      $0 ~ "`" id "`" && /^\*\*/ { hit=1; next }
      hit && /^\*Max severity/   { print "[" substr($0,2,length($0)-2) "]"; exit }
    ' "$DOC"
    echo "$manual"
    return
  fi

  fam=$(awk -v id="$id" '
    /^- \*\*/ && index($0, id) {
      sub(/^- \*\*/, ""); sub(/\*\*:.*/, ""); print; exit
    }
  ' "$DOC")
  if [[ -n "$fam" ]]; then
    row=$(grep -m1 -F "| ${fam} |" "$DOC")
    if [[ -n "$row" ]]; then
      echo "(Low — batched under family: ${fam})"
      print_row "$row" group
      return
    fi
  fi

  echo "NOT FOUND: $id"
}

prev=""
echo "watching clipboard; doc: $DOC" >&2
while sleep 0.5; do
  cur=$(getclip)
  [[ "$cur" == "$prev" || -z "$cur" ]] && continue
  prev="$cur"

  id=$(grep -oE '(CVE-[0-9]{4}-[0-9]+|GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}|GO-[0-9]+-[0-9]+|CCE-[0-9]+-[0-9]|PRISMA-[0-9]{4}-[0-9]+|[0-9a-f]{32})' <<< "$cur" | head -1)
  [[ -z "$id" ]] && continue

  echo
  echo "══ $id ═══════════════════════════════"
  lookup "$id"

  if [[ -n "$CLIP_TEXT" ]]; then
    printf '%s' "$CLIP_TEXT" | setclip
    prev=$(getclip)
  fi
done