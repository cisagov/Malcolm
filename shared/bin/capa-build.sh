#!/bin/bash

export CAPA_VERSION="9.3.1"
export CAPA_SRC_URL="https://github.com/mandiant/capa/archive/refs/tags/v${CAPA_VERSION}.zip"
export CAPA_RULES_URL="https://github.com/mandiant/capa-rules/archive/refs/tags/v${CAPA_VERSION}.zip"

cd /tmp
mkdir ./capa
python3 -m venv capa
. ./capa/bin/activate
cd ./capa
curl -fsSL -o ./capa.zip "${CAPA_SRC_URL}"
unzip -q ./capa.zip
cd capa-${CAPA_VERSION}
python3 -m pip install -e .[build]
curl -fsSL -o ./rules.zip "${CAPA_RULES_URL}"
unzip -q ./rules.zip
mv ./capa-rules-${CAPA_VERSION}/* ./rules/
python3 ./scripts/cache-ruleset.py rules/ cache
pyinstaller ./.github/pyinstaller/pyinstaller.spec
mv ./dist/capa /usr/local/bin/capa
chmod 755 /usr/local/bin/capa
deactivate
rm -rf /tmp/capa*