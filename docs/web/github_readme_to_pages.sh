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

# main page
OUTPUT_FILE="$OUTPUT_DIR"/index.md
> $OUTPUT_FILE
GenerateMarkdownHeader " " "index" >> $OUTPUT_FILE
curl -sSL --silent https://raw.githubusercontent.com/idaholab/Malcolm/$BRANCH/README.md \
  | sed '/name="TableOfContents"/,$d' \
  | sed 's/^# Malcolm$//' \
  | sed "s@\](https://github.com/idaholab/[Mm])@\](https://malcolm.fyi/)@g" \
  | sed "s@\](\./@\](https://raw.githubusercontent.com/idaholab/Malcolm/$BRANCH/@g" \
  >> $OUTPUT_FILE

# documentation page
OUTPUT_FILE="$OUTPUT_DIR"/documentation.md
> $OUTPUT_FILE
GenerateMarkdownHeader "Documentation" "documentation" >> $OUTPUT_FILE
curl -sSL --silent https://raw.githubusercontent.com/idaholab/Malcolm/$BRANCH/README.md \
  | sed '0,/name="TableOfContents"/d' \
  | sed '/## Other Software/,$d' \
  | sed "s@\](https://github.com/idaholab/[Mm])@\](https://malcolm.fyi/)@g" \
  | sed "s@\](\./@\](https://raw.githubusercontent.com/idaholab/Malcolm/$BRANCH/@g" \
  >> $OUTPUT_FILE

# hedgehog Linux page
OUTPUT_FILE="$OUTPUT_DIR"/hedgehog.md
> $OUTPUT_FILE
GenerateMarkdownHeader " " "hedgehog" >> $OUTPUT_FILE
curl -sSL --silent https://raw.githubusercontent.com/idaholab/Malcolm/$BRANCH/sensor-iso/README.md \
  | sed "s@\](https://github.com/idaholab/[Mm]alcolm)@\](https://malcolm.fyi/)@g" \
  | sed "s@\](\./docs/Notes.md@\](https://github.com/idaholab/Malcolm/blob/$BRANCH/sensor-iso/docs/Notes.md)@g" \
  | sed "s@\](\./@\](https://raw.githubusercontent.com/idaholab/Malcolm/$BRANCH/sensor-iso/@g" \
  >> $OUTPUT_FILE

# build site
nikola clean -a
nikola build