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

OUTPUT_DIR=./pages

# main page
OUTPUT_FILE="$OUTPUT_DIR"/index.md
> $OUTPUT_FILE
GenerateMarkdownHeader "Malcolm" "index" >> $OUTPUT_FILE
curl -sSL --silent https://raw.githubusercontent.com/idaholab/Malcolm/master/README.md \
  | sed '/name="TableOfContents"/,$d' \
  | sed 's/^# Malcolm$//' \
  | sed "s@\](https://github.com/idaholab/malcolm)@\](https://malcolm.fyi/)@g" \
  | sed "s@\./docs/images/@https://raw.githubusercontent.com/idaholab/Malcolm/master/docs/images/@g" \
  >> $OUTPUT_FILE

# documentation page
OUTPUT_FILE="$OUTPUT_DIR"/documentation.md
> $OUTPUT_FILE
GenerateMarkdownHeader "Documentation" "documentation" >> $OUTPUT_FILE
curl -sSL --silent https://raw.githubusercontent.com/idaholab/Malcolm/master/README.md \
  | sed '0,/name="TableOfContents"/d' \
  | sed '/## Other Software/,$d' \
  | sed "s@\](https://github.com/idaholab/malcolm)@\](https://malcolm.fyi/)@g" \
  | sed "s@\./docs/images/@https://raw.githubusercontent.com/idaholab/Malcolm/master/docs/images/@g" \
  >> $OUTPUT_FILE

# build site
nikola clean -a
nikola build