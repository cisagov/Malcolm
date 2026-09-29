# Clone all Malcolm Iron Bank repositories

```bash
IRON_BANK_PARENT_PATH=/path/to/iron-bank
mkdir -p "$IRON_BANK_PARENT_PATH"

for REPO in \
    api \
    arkime \
    dashboards \
    dashboards-helper \
    dirinit \
    filebeat \
    filescan \
    file-upload \
    freq \
    htadmin \
    keycloak \
    logstash-oss \
    netbox \
    nginx \
    opensearch \
    pcap-capture \
    pcap-monitor \
    postgresql \
    redis \
    strelka-backend \
    strelka-frontend \
    strelka-manager \
    suricata \
    zeek \
; do
    git clone https://repo1.dso.mil/dsop/afdco/malcolm/"$REPO".git
    pushd "$REPO" >/dev/null 2>&1
    for BRANCH in master development inl-26.x; do
        git checkout "$BRANCH"
    done
    popd >/dev/null 2>&1
done
```

# Perform some action in each Malcolm Iron Bank repository working copy

This example opens the Iron Bank pipeline page for each repository (requires xdg-open from xdg-utils):

```bash
IRON_BANK_PARENT_PATH=/path/to/iron-bank

for REPO_DIR in $(find "$IRON_BANK_PARENT_PATH" -mindepth 1 -maxdepth 1 -type d | sed "s@\./@@") \
; do
    pushd "$REPO_DIR" >/dev/null 2>&1
    REPO_NAME="$(basename `git config --get remote.origin.url` | sed 's/\.git$//')"
    xdg-open "https://repo1.dso.mil/dsop/afdco/malcolm/$REPO_NAME/-/pipelines" # append /new for "Run new pipeline"
    popd >/dev/null 2>&1
done
```

# Pull VAT findings for each repo

```bash
IRON_BANK_PARENT_PATH=/path/to/iron-bank
FINDINGS_PATH=/path/to/findings
mkdir -p "$FINDINGS_PATH"

for REPO_DIR in $(find "$IRON_BANK_PARENT_PATH" -mindepth 1 -maxdepth 1 -type d | sed "s@\./@@") \
; do
    pushd "$REPO_DIR" >/dev/null 2>&1
    REPO_NAME="$(basename `git config --get remote.origin.url` | sed 's/\.git$//')"
    gitlab-artifacts-download.py \
        -p "$REPO_NAME" \
        -b inl-26.x \
        -j vat \
        -L \
        -S "Needs Justification" -S "Needs Rework" -S "Needs Reverified" \
        -f json > "$FINDINGS_PATH/$REPO_NAME".json
    popd >/dev/null 2>&1
done
```

# Pull and tag the Docker images for each repo

```bash
IRON_BANK_PARENT_PATH=/path/to/iron-bank
BRANCH=inl-26.x
TAG=26.08.0-ib
CONTAINER_ENGINE=docker

for REPO_DIR in $(find "$IRON_BANK_PARENT_PATH" -mindepth 1 -maxdepth 1 -type d | sed "s@\./@@") \
; do
    pushd "$REPO_DIR" >/dev/null 2>&1
    REPO_NAME="$(basename `git config --get remote.origin.url` | sed 's/\.git$//')"
    gitlab-artifacts-download.py \
        -p "$REPO_NAME" \
        -b "$BRANCH" \
        -j create-tar \
        -t ghcr.io/idaholab/malcolm/"$REPO_NAME":"$TAG"
    popd >/dev/null 2>&1
done

for PAIR in filebeat:filebeat-oss \
            nginx:nginx-proxy \
            redis:valkey; do \
    "$CONTAINER_ENGINE" tag ghcr.io/idaholab/malcolm/${PAIR%:*}:$v ghcr.io/idaholab/malcolm/${PAIR#*:}:$v
done
```

# Open the Iron Bank VAT findings page for a repository/branch/tag:

```bash
BRANCH=inl-26.x
TAG=26.08.0
REPO_NAME=api

xdg-open "https://vat.dso.mil/vat/image?imageName=afdco/malcolm/$REPO_NAME&tag=$TAG&branch=$BRANCH"
```
