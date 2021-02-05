#!/bin/bash

function GenerateMarkdownHeader() {
  TITLE="$1"
  SLUG="$2"
  DATE="$(date +'%Y-%m-%d %H:%M:%S UTC%:z')"
  cat <<EOF
<!--
.. title: $TITLE
.. slug: $SLUG
.. date: $DATE
.. tags:
.. category:
.. link:
.. description:
.. type: text
-->
EOF
}

if [[ -n "$1" ]]; then
  BRANCH="$1"
else
  BRANCH="master"
fi

OUTPUT_DIR=./pages
FINAL_DIR=./output

mkdir -p "$OUTPUT_DIR" "$FINAL_DIR"

# main page
OUTPUT_FILE="$OUTPUT_DIR"/index.md
> $OUTPUT_FILE
GenerateMarkdownHeader " " "index" >> $OUTPUT_FILE
curl -sSL --silent https://raw.githubusercontent.com/idaholab/Malcolm/$BRANCH/README.md \
  | sed '/name="TableOfContents"/,$d' \
  | sed 's/^# Malcolm$//' \
  | sed "s@\](https://github.com/idaholab/[Mm]alcolm/*)@\](https://malcolm.fyi/)@g" \
  | sed "s@/[Mm]alcolm/blob/master/@/Malcolm/blob/$BRANCH/@g" \
  | sed "s@\](\./@\](https://raw.githubusercontent.com/idaholab/Malcolm/$BRANCH/@g" \
  >> $OUTPUT_FILE

# documentation page
OUTPUT_FILE="$OUTPUT_DIR"/documentation.md
> $OUTPUT_FILE
GenerateMarkdownHeader "Documentation" "documentation" >> $OUTPUT_FILE
curl -sSL --silent https://raw.githubusercontent.com/idaholab/Malcolm/$BRANCH/README.md \
  | sed '0,/name="TableOfContents"/d' \
  | sed '/## Other Software/,$d' \
  | sed "s@\](https://github.com/idaholab/[Mm]alcolm/*)@\](https://malcolm.fyi/)@g" \
  | sed "s@/[Mm]alcolm/blob/master/@/Malcolm/blob/$BRANCH/@g" \
  | sed "s@\](\./@\](https://raw.githubusercontent.com/idaholab/Malcolm/$BRANCH/@g" \
  >> $OUTPUT_FILE

# hedgehog Linux page
OUTPUT_FILE="$OUTPUT_DIR"/hedgehog.md
> $OUTPUT_FILE
GenerateMarkdownHeader " " "hedgehog" >> $OUTPUT_FILE
curl -sSL --silent https://raw.githubusercontent.com/idaholab/Malcolm/$BRANCH/sensor-iso/README.md \
  | sed "s@\](https://github.com/idaholab/[Mm]alcolm/*)@\](https://malcolm.fyi/)@g" \
  | sed "s@/[Mm]alcolm/blob/master/@/Malcolm/blob/$BRANCH/@g" \
  | sed "s@\](\./docs/Notes.md@\](https://github.com/idaholab/Malcolm/blob/$BRANCH/sensor-iso/docs/Notes.md)@g" \
  | sed "s@\](\./@\](https://raw.githubusercontent.com/idaholab/Malcolm/$BRANCH/sensor-iso/@g" \
  >> $OUTPUT_FILE

# downloads page
OUTPUT_FILE="$OUTPUT_DIR"/download.md
> $OUTPUT_FILE
GenerateMarkdownHeader "Downloads" "download" >> $OUTPUT_FILE
cat ./download.md >> $OUTPUT_FILE

# build site
nikola clean -a
nikola build

# clean up some stuff we don't use
rm -rf $FINAL_DIR/archive* $FINAL_DIR/blog* $FINAL_DIR/categories* $FINAL_DIR/tags* $FINAL_DIR/rss*
sed -i -re '/<sitemap>/{:a;N;/<\/sitemap>/!ba};/rss\.xml/d' $FINAL_DIR/sitemapindex.xml
sed -i -re '/<url>/{:a;N;/<\/url>/!ba};/(archive\.html|blog|categories)/d' $FINAL_DIR/sitemap.xml
