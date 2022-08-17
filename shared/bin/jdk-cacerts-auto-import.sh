#!/usr/bin/env bash

# determine the location of the cacerts file we're adding to

JDK_DIR="$(find /usr -type d -name jdk | head -n 1)"

CACERTS_FILE="$JDK_DIR"/lib/security/cacerts
KEYTOOL_BIN="$JDK_DIR"/bin/keytool

if [[ ! -f "$CACERTS_FILE" ]] || [[ ! -x "$KEYTOOL_BIN" ]]; then
  echo "Unable to locate cacerts and/or keytool " >&2
  exit 1
fi

unset TRUSTED_CA_DIR
TRUSTED_CA_DIRNAME=${CA_DIR:-"ca-trust"}
CA_DIR_PARENTS=(
  "$JDK_DIR"/../"$TRUSTED_CA_DIRNAME"
  /etc/"$TRUSTED_CA_DIRNAME"
  /opt/"$TRUSTED_CA_DIRNAME"
  /var/local/"$TRUSTED_CA_DIRNAME"
  /"$TRUSTED_CA_DIRNAME"
)
for i in ${CA_DIR_PARENTS[@]}; do
  TMP_DIR="$(realpath "$i")"
  if [[ -d "$i" ]]; then
    TRUSTED_CA_DIR="$i"
    break;
  fi
done

if [[ -z $TRUSTED_CA_DIR ]] || [[ ! -d "$TRUSTED_CA_DIR" ]]; then
  echo "Unable to locate directory containing trusted CA certificates" >&2
  exit 1
fi

echo
find "$TRUSTED_CA_DIR" -type f -print0 | while read -d $'\0' CRT_FILE; do
  CRT_FILE_BASE="$(basename "$CRT_FILE" | sed 's/\.[^.]*$//')"
  if [[ -n $CRT_FILE_BASE ]] && [[ "$CRT_FILE_BASE" != \.* ]] ; then
    echo "Importing \"$CRT_FILE_BASE\"... "
    ( "$KEYTOOL_BIN" -importcert -cacerts -trustcacerts -file "$CRT_FILE" -alias "$CRT_FILE_BASE" -keypass changeit -storepass changeit -noprompt 2>&1 | grep -Pv "(already exists)" ) || true
    "$KEYTOOL_BIN" -list -cacerts -alias "$CRT_FILE_BASE" -keypass changeit -storepass changeit -noprompt
    echo
  fi
done
