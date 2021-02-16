# Notes on Sensor Development ("Hedgehog Linux")

Hedgehog Linux is a trimmed-down Debian Linux with several common tools preinstalled for capturing and forwarding network traffic artifacts. This document outlines those tools and how they were installed and configured in the hopes that the lessons learned in this project's development are useful to others deploying these tools in other environments.

### <a name="TableOfContents"></a>Table of Contents

* [Full PCAP](#FullPCAP)
    - [netsniff-ng](#netsniff)
        + [Compiling netsniff-ng from source](#netsniffCompile)
    - [tcpdump](#tcpdump)
    - [Arkime](#Arkime)
        + [Compiling Arkime from source](#molochCompile)
        + [Arkime configuration](#molochConfig)
            * [`config.ini` and command-line parameters](#molochConfigIni)
            * [capture rules](#molochRules)
            * [Arkime viewer](#molochViewer)
* [Zeek](#Zeek)
    - [Compiling Zeek from source](#ZeekCompile)
    - [Third party plugins](#ZeekThirdParty)
        + [bash script to install third party plugins for Zeek](#ZeekThirdPartyBash)
        + [Zeek::AF_Packet configuration](#ZeekAfPacket)
    - [`local.zeek`](#ZeekLocalPolicy)
    - [File carving](#ZeekFileCarving)
* [Forwarding](#Forwarding)
    - [Forwarding Zeek logs](#ForwardingZeekLogs)
    - [Forwarding sensor system metrics](#ForwardingMetrics)
    - [Forwarding audit logs](#ForwardingAuditLogs)
    - [Forwarding syslogs](#ForwardingSyslogs)
* [System considerations](#System)
    - [NIC offloading](#nicOffloading)
    - [Performance](#Performance)
    - [Hardening](#Hardening)

* [Copyright](#Footer)

# <a name="FullPCAP"></a>Full PCAP

## <a name="netsniff"></a>netsniff-ng

[netsniff-ng](http://netsniff-ng.org/) is a high-performance packet capture utility, designed by Daniel Borkmann, which can be used to capture PCAP files on Hedgehog Linux, using a command like this:

```bash
$ /usr/sbin/netsniff-ng \
    -i enp8s0 \
    -T 0xa1b2c3d4 \
    -o /storage/pcaps \
    -P "pcap_file_prefix-" \
    -F "1024sMiB" \
    "filter-expression"
```

* Notes:
    * `-i` is the capture interface
    * `-T` is the PCAP type for storage
    * `-o` is the directory to write PCAP files
    * `-P` is a prefix to prepend to each PCAP filename
    * `-F` is a file size rotation threshold (this can also be done manually by sending `netsniff-ng` a `SIGHUP` signal)
    * `filter-expression` specifies an optional `tcpdump`-like capture filter expression

### <a name="netsniffCompile"></a>Compiling netsniff-ng from source

The following bash script was used to download, build and install [netsniff-ng](http://netsniff-ng.org/) on Hedgehog Linux:

```bash
#!/bin/bash

NETSNIFF_VER="0.6.7"
NETSNIFF_URL="https://github.com/netsniff-ng/netsniff-ng/archive/v$NETSNIFF_VER.tar.gz"

# Install netsniff-ng
cd /tmp
curl -L -o netsniff-$NETSNIFF_VER.tar.gz "$NETSNIFF_URL"
tar -xzvf netsniff-$NETSNIFF_VER.tar.gz
cd netsniff-ng-$NETSNIFF_VER
./configure --prefix=/usr --disable-geoip
make netsniff-ng
checkinstall -y -D --strip=yes --stripso=yes --install=yes --fstrans=no --pkgname="netsniff-ng" --pkgversion="$NETSNIFF_VER" --pkgarch="amd64" --pkgsource="$NETSNIFF_URL" make netsniff-ng_install
```

## <a name="tcpdump"></a>tcpdump

[tcpdump](https://www.tcpdump.org/) is another powerful command-line packet analyzer which can be used to capture PCAP files on Hedgehog Linux, using a command like this:

```bash
$ /usr/sbin/tcpdump \
    -i enp8s0 \
    -s 0 \
    -w "prefix_%Y%m%d_%H%M%S.pcap" \
    -G 600 \
    -C 1024 \
    -K \
    -n \
    "filter-expression"
```

* Notes:
    * `-i` is the capture interface
    * `-s 0` sets the `snaplen` size to `0`, meaning "capture entire packets"
    * `-w` specifies a PCAP filename to write to, in this case timestamping each PCAP file with the current date and time
    * `-G` specifies a file rotation time threshold in seconds
    * `-C` specifies a file rotation size threshold in millions of bytes
    * `-K` disables IP, TCP, and UDP checksum verification
    * `-n` disables converting addresses (host addresses, port numbers, etc.) to names
    * `filter-expression` specifies an optional `tcpdump`-like capture filter expression

`tcpdump` is generally installed via your distribution's package management system (`apt`, `yum`, etc.).

## <a name="Arkime"></a>Arkime

[Arkime](https://molo.ch/) [moloch-capture](https://github.com/arkime/arkime/tree/master/capture) is a tool for traffic capture which also performs network protocol parsing and metadata insertion into an Elasticsearch instance for review using the Arkime viewer interface.

`moloch-capture` can be [downloaded](https://molo.ch/downloads) in the form of official Arkime package builds or built from source.

### <a name="molochCompile"></a>Compiling Arkime from source

At the time of writing, the [current stable release](https://github.com/arkime/arkime/blob/master/CHANGELOG) of Arkime is [v2.7.1](https://github.com/arkime/arkime/releases/tag/v2.7.1). The following bash script was used to install Arkime's build dependencies, download Arkime, build a Debian .deb package using [fpm](https://github.com/jordansissel/fpm) and install it. In building Hedgehog Linux, the building of this .deb is done inside a Docker container dedicated to that purpose.

```bash
#!/bin/bash

ARKIME_VERSION="2.7.1"
ARKIMEDIR="/opt/moloch"

OUTPUT_DIR="/tmp"
unset VERBOSE

while getopts o:v opts; do
   case ${opts} in
      o) OUTPUT_DIR=${OPTARG} ;;
      v) VERBOSE=1 ;;
   esac
done

set -e
if [[ -n $VERBOSE ]]; then
  set -x
fi

apt-get -q update

mkdir -p /opt
curl -L -o /tmp/moloch.tar.gz "https://github.com/arkime/arkime/archive/v$ARKIME_VERSION.tar.gz"

cd /tmp
tar -xvf "moloch.tar.gz"
rm -f "moloch.tar.gz"

cd "./moloch-"$ARKIME_VERSION

export PATH="$ARKIMEDIR/bin:/tmp/moloch-$ARKIME_VERSION/node_modules/.bin:${PATH}"

./easybutton-build.sh --dir "$ARKIMEDIR"

npm -g config set user root

make install

cp -r ./capture/plugins/lua/samples "$ARKIMEDIR"/lua

npm install license-checker; release/notice.txt.pl $ARKIMEDIR NOTICE release/CAPTURENOTICE > $ARKIMEDIR/NOTICE.txt

ETC_FILES=$(shopt -s nullglob dotglob; echo /moloch-etc/*)
if (( ${#ETC_FILES} )) ; then
  mkdir -p $ARKIMEDIR/etc
  cp -r /moloch-etc/* $ARKIMEDIR/etc/
fi

fpm -s dir -t deb -n moloch -x opt/moloch/logs -x opt/moloch/raw -v $ARKIME_VERSION --iteration 1 --template-scripts --after-install "release/afterinstall.sh" --url "http://molo.ch" --description "Arkime Full Packet System" -d libwww-perl -d libjson-perl -d ethtool -d libyaml-dev "$ARKIMEDIR"

ls -l *.deb && mv -v *.deb "$OUTPUT_DIR"/

cd /tmp

if [[ -n $VERBOSE ]]; then
  set +x
fi
set +e

```

* Notes:
    - Arkime is installed to `/opt/moloch` in this configuration
    - Please read the Arkime's [documentation](https://molo.ch/learn), particularly the [FAQ](https://molo.ch/faq) and [Settings](https://molo.ch/settings) pages, for more information

### <a name="molochConfig"></a>Arkime configuration

#### <a name="molochConfigIni"></a>config.ini and command-line parameters

`moloch-capture`'s behavior is generally controlled via [`config.ini`](https://molo.ch/settings#ini-settings), although some of these options can also be overridden via command-line arguments.

Below is an example of the a `config.ini` similar to that used on Hedgehog Linux.

```
# these settings for moloch-capture will be overridden on the command-line (with "-o field=value")
# so you can (for the most part) ignore settings here that seem like dummy settings

[default]
elasticsearch=http://192.168.0.1:9200
rotateIndex=daily
passwordSecret=HZyP53ddho8ASebg
httpRealm=Arkime
interface=enp8s0
pcapDir=/tmp
maxFileSizeG=2
maxFileTimeM=180
tcpTimeout=600
tcpSaveTimeout=720
udpTimeout=30
icmpTimeout=10
maxStreams=1000000
maxPackets=10000
freeSpaceG=5%
viewPort=8005
geoLite2Country=/dummy/GeoLite2-Country.mmdb
geoLite2ASN=/dummy/GeoLite2-ASN.mmdb
rirFile=/dummy/ipv4-address-space.csv
ouiFile=/dummy/oui.txt
dropUser=sensor
dropGroup=netdev
parseSMTP=true
parseSMB=true
parseQSValue=false
supportSha256=false
maxReqBody=64
config.reqBodyOnlyUtf8=true
smtpIpHeaders=X-Originating-IP:;X-Barracuda-Apparent-Source-IP:
parsersDir=/dummy/parsers
pluginsDir=/dummy/plugins
spiDataMaxIndices=2
compressES=false
maxESConns=30
maxESRequests=500
packetsPerPoll=50000
antiSynDrop=false
logEveryXPackets=500000
logUnknownProtocols=false
logESRequests=false
logFileCreation=true
logHTTPConnections=false

### High Performance settings
# https://github.com/arkime/arkime/wiki/Settings#High_Performance_Settings
magicMode=basic
pcapReadMethod=tpacketv3
tpacketv3NumThreads=2
tpacketv3BlockSize=8388608
pcapWriteMethod=simple
pcapWriteSize=2560000
packetThreads=5
maxPacketsInQueue=300000
dbBulkSize=4000000
#compressES=true
rulesFiles=/dummy/rules.yml
```

`moloch-capture` is run using a command like this (this example uses environment variables to override certain values specified in [`config.ini`](#molochConfigIni))

```bash
$ /opt/moloch/bin/moloch-capture
  -c /opt/moloch/etc/config.ini
  -o pcapDir="$PCAP_PATH"
  -o bpf="$CAPTURE_FILTER"
  -o packetThreads=$ARKIME_PACKET_THREADS
  -o dropUser=sensor
  -o dropGroup=netdev
  -o geoLite2Country=/opt/moloch/etc/GeoLite2-Country.mmdb
  -o geoLite2ASN=/opt/moloch/etc/GeoLite2-ASN.mmdb
  -o rirFile=/opt/moloch/etc/ipv4-address-space.csv
  -o ouiFile=/opt/moloch/etc/oui.txt
  -o rulesFiles=/opt/moloch/etc/rules.yml
  -o parsersDir=/opt/moloch/parsers
  -o pluginsDir=/opt/moloch/plugins
  --node "$ARKIME_NODE_NAME"
  --host "$ARKIME_NODE_HOST"
```

#### <a name="molochRules"></a>capture rules

Arkime allows [defining capture rules](https://molo.ch/rulesformat) to limit what is stored in PCAP and what is logged to the Elasticsearch database. Hedgehog Linux uses some rules similar to those examples in the [High Performance Settings](https://molo.ch/settings#high-performance-settings) page in the Arkime documentation in order to maximize performance and tune PCAP storage utilization.

```
---
version: 1
rules:
  - name: "Only save first n packets of TLS"
    when: "fieldSet"
    fields:
      protocols:
      - tls
    ops:
      _maxPacketsToSave: 15
  - name: "Only save first n packets of SSH"
    when: "fieldSet"
    fields:
      protocols:
      - ssh
    ops:
      _maxPacketsToSave: 20
  - name: "Dont save SPI sessions with only 1 source packet"
    when: "beforeFinalSave"
    fields:
      packets.src: 1
      packets.dst: 0
      tcpflags.syn: 1
    ops:
      _dontSaveSPI: 1
```

#### <a name="molochViewer"></a>Arkime viewer

In order for a remote Arkime viewer instance to retrieve PCAP payloads from the host running `moloch-capture`, the capture host must also be running an instance of Arkime viewer which accepts connections (by default) on port 8005. Arkime viewer uses the same [`config.ini`](#molochConfigIni) as `moloch-capture` and can be run like this:

```bash
$ /opt/moloch/bin/node /opt/moloch/viewer/viewer.js
  -c /opt/moloch/etc/config.ini
  -o pcapDir="$PCAP_PATH"
  -o viewPort=8005
```

This may require opening a firewall port to the host running Arkime viewer to allow remote connections to this port from the main Arkime viewer instance.

# <a name="Zeek"></a>Zeek

At the time of writing, the [current stable release](https://github.com/zeek/zeek/blob/release/NEWS) of Zeek is [v3.0.10](https://github.com/zeek/zeek/releases/tag/v3.0.10). The notes in this section apply to that version, although some may apply to others as well.

## <a name="ZeekCompile"></a>Compiling Zeek from source

The following bash script was used to download, [build and install](https://docs.zeek.org/en/stable/install/install.html#installing-from-source) Zeek on Hedgehog Linux:

```bash
#!/bin/bash

ZEEK_VER="3.0.10"
ZEEK_URL="https://old.zeek.org/downloads/zeek-$ZEEK_VER.tar.gz"
ZEEK_PATCH_URLS=(
  # nothing here for now
)

# Build and install zeek
mkdir -p /usr/local/src/zeek-patches
cd /usr/local/src/zeek-patches
for i in ${ZEEK_PATCH_URLS[@]}; do
  curl -L -J -O "$i"
done
cd /tmp
curl -L -o zeek-$ZEEK_VER.tar.gz "$ZEEK_URL"
tar -xvzf zeek-$ZEEK_VER.tar.gz
cd zeek-$ZEEK_VER
for i in /usr/local/src/zeek-patches/*; do
  patch -p 1 -r - --no-backup-if-mismatch < "$i" || true
done
./configure --prefix=/opt/zeek --generator=Ninja
cd build
ninja
checkinstall -y -D --strip=yes --stripso=yes --install=yes --fstrans=no --pkgname="zeek" --pkgversion="$ZEEK_VER" --pkgarch="amd64" --pkgsource="$ZEEK_URL" ninja install
```

* Notes:
    - Zeek is installed to `/opt/zeek` in this configuration
    - `ninja` was used instead of `make` to reduce build times
    - `checkinstall` is used instead of `make install` to generate a Debian `.deb` package that can be installed and uninstalled with standard system package management utilities

## <a name="ZeekThirdParty"></a>Third party plugins

Where possible, [`zkg`](https://docs.zeek.org/projects/package-manager/en/stable/zkg.html) can be used to install third party Zeek packages. However, at the time of writing not all Zeek plugins support the zkg package format.

Hedgehog Linux utilizest he following third party Zeek packages:

* some of Amazon.com, Inc.'s [ICS protocol](https://github.com/amzn?q=zeek) analyzers
* Andrew Klaus's [Sniffpass](https://github.com/cybera/zeek-sniffpass) plugin for detecting cleartext passwords in HTTP POST requests
* Andrew Klaus's [zeek-httpattacks](https://github.com/precurse/zeek-httpattacks) plugin for detecting noncompliant HTTP requests
* ICS protocol analyzers for Zeek published by [DHS CISA](https://github.com/cisagov/ICSNPP) and [Idaho National Lab](https://github.com/idaholab/ICSNPP)
* Corelight's [bro-xor-exe](https://github.com/corelight/bro-xor-exe-plugin) plugin
* Corelight's ["bad neighbor" (CVE-2020-16898)](https://github.com/corelight/CVE-2020-16898) plugin    
* Corelight's [callstranger-detector](https://github.com/corelight/callstranger-detector) plugin
* Corelight's [community ID](https://github.com/corelight/zeek-community-id) flow hashing plugin
* Corelight's [ripple20](https://github.com/corelight/ripple20) plugin
* Corelight's [SIGred](https://github.com/corelight/SIGred) plugin
* Corelight's [Zerologon](https://github.com/corelight/zerologon) plugin
* J-Gras' [Zeek::AF_Packet](https://github.com/J-Gras/zeek-af_packet-plugin) plugin
* Johanna Amann's [CVE-2020-0601](https://github.com/0xxon/cve-2020-0601) ECC certificate validation plugin and [CVE-2020-13777](https://github.com/0xxon/cve-2020-13777) GnuTLS unencrypted session ticket detection plugin
* Lexi Brent's [EternalSafety](https://github.com/0xl3x1/zeek-EternalSafety) plugin
* MITRE Cyber Analytics Repository's [Bro/Zeek ATT&CK-Based Analytics (BZAR)](https://github.com/mitre-attack/car/tree/master/implementations) script
* Salesforce's [gQUIC](https://github.com/salesforce/GQUIC_Protocol_Analyzer) analyzer
* Salesforce's [HASSH](https://github.com/salesforce/hassh) SSH fingerprinting plugin
* Salesforce's [JA3](https://github.com/salesforce/ja3) TLS fingerprinting plugin
* SoftwareConsultingEmporium's [Bro::LDAP](https://github.com/SoftwareConsultingEmporium/ldap-analyzer) analyzer
* Verizon Media's [spicy-noise](https://github.com/theparanoids/spicy-noise) WireGuard analyzer plugin
* Zeek's [Spicy](https://github.com/zeek/spicy) plugin framework

### <a name="ZeekThirdPartyBash"></a>bash script to install third party plugins for Zeek

While not all of the aforementioned plugins install correctly with zkg, this bash script can be used to install those which can be installed with zkg using that tool, and to manually install the others.

```bash
#!/bin/bash

# Copyright (c) 2021 Battelle Energy Alliance, LLC.  All rights reserved.

if [ -z "$BASH_VERSION" ]; then
  echo "Wrong interpreter, please run \"$0\" with bash"
  exit 1
fi

# some of the packages will install via zkg, so the zkg config file must be present
# read Zeek paths out of zkg config file for plugins that must be installed manually
ZKG_CONFIG_FILE="$HOME/.zkg/config"
if [[ -f "$ZKG_CONFIG_FILE" ]]; then
  ZEEK_SCRIPTS_DIR="$(grep -P "^script_dir\s*=\s*" "$ZKG_CONFIG_FILE" | sed 's/^script_dir[[:space:]]*=[[:space:]]*//')"
  ZEEK_DIST_DIR="$(grep -P "^zeek_dist\s*=\s*" "$ZKG_CONFIG_FILE" | sed 's/^zeek_dist[[:space:]]*=[[:space:]]*//')"
  ZEEK_PLUGIN_DIR="$(grep -P "^plugin_dir\s*=\s*" "$ZKG_CONFIG_FILE" | sed 's/^plugin_dir[[:space:]]*=[[:space:]]*//')"
else
  unset ZEEK_SCRIPTS_DIR
  unset ZEEK_DIST_DIR
  unset ZEEK_PLUGIN_DIR
fi
if [[ -z $ZEEK_SCRIPTS_DIR ]] || [[ -z $ZEEK_DIST_DIR ]]; then
  echo "Unable to determine Zeek scripts and/or source directory"
  exit 1
fi

# going to clone under /usr/local/src
SRC_BASE_DIR="/usr/local/src"
mkdir -p "$SRC_BASE_DIR"

#
# get_latest_github_tagged_release
#
# get the latest GitHub release tag name given a github repo URL
#
function get_latest_github_tagged_release() {
  REPO_URL="$1"
  REPO_NAME="$(echo "$REPO_URL" | sed 's|.*github\.com/||')"
  LATEST_URL="https://github.com/$REPO_NAME/releases/latest"
  REDIRECT_URL="$(curl -fsSLI -o /dev/null -w %{url_effective} "$LATEST_URL" 2>/dev/null)"
  if [[ "$LATEST_URL" = "$REDIRECT_URL"/latest ]]; then
    echo ""
  else
    echo "$REDIRECT_URL" | sed 's|.*tag/||'
  fi
}

#
# clone_github_repo
#
# clone the latest GitHub release tag if available (else, master/HEAD) under $SRC_BASE_DIR
#
function clone_github_repo() {
  REPO_URL="$1"
  if [[ -n $REPO_URL ]]; then
    REPO_LATEST_RELEASE="$(get_latest_github_tagged_release "$REPO_URL")"
    SRC_DIR="$SRC_BASE_DIR"/"$(echo "$REPO_URL" | sed 's|.*/||')"
    rm -rf "$SRC_DIR"
    if [[ -n $REPO_LATEST_RELEASE ]]; then
      git -c core.askpass=true clone --branch "$REPO_LATEST_RELEASE" --recursive "$REPO_URL" "$SRC_DIR" >/dev/null 2>&1
    else
      git -c core.askpass=true clone --recursive "$REPO_URL" "$SRC_DIR" >/dev/null 2>&1
    fi
    [ $? -eq 0 ] && echo "$SRC_DIR" || echo "cloning \"$REPO_URL\" failed" >&2
  fi
}

# install Zeek packages that insatll nicely using zkg
ZKG_GITHUB_URLS=(
  https://github.com/0xxon/cve-2020-0601
  https://github.com/0xxon/cve-2020-13777
  https://github.com/amzn/zeek-plugin-profinet
  https://github.com/amzn/zeek-plugin-s7comm
  https://github.com/amzn/zeek-plugin-tds
  https://github.com/corelight/callstranger-detector
  https://github.com/corelight/CVE-2020-16898
  https://github.com/corelight/ripple20
  https://github.com/corelight/SIGRed
  https://github.com/corelight/zeek-community-id
  https://github.com/corelight/zerologon
  https://github.com/cybera/zeek-sniffpass
  https://github.com/0xl3x1/zeek-EternalSafety
  https://github.com/mitre-attack/bzar
  https://github.com/precurse/zeek-httpattacks
  https://github.com/salesforce/hassh
  https://github.com/salesforce/ja3
)
for i in ${ZKG_GITHUB_URLS[@]}; do
  SRC_DIR="$(clone_github_repo "$i")"
  [[ -d "$SRC_DIR" ]] && zkg install --force --skiptests "$SRC_DIR"
done

# manual build processes that don't fit the other patterns

# DHS/INL ICS parsers
SRC_DIR="$(clone_github_repo "https://github.com/cisagov/ICSNPP")"
if [[ -d "$SRC_DIR" ]]; then
  CWD="$(pwd)"
  for FULL_PARSER in zeek_bacnet_parser zeek_enip_parser; do
    cd "$SRC_DIR"/"$FULL_PARSER" && \
      ./configure --bro-dist="$ZEEK_DIST_DIR" --install-root="$ZEEK_PLUGIN_DIR" && \
      make && \
      make install
  done
  cp "$SRC_DIR"/zeek_dnp3_parser/*.zeek /opt/zeek/share/zeek/base/protocols/dnp3/
  cp "$SRC_DIR"/zeek_modbus_parser/*.zeek /opt/zeek/share/zeek/base/protocols/modbus/
  cd "$CWD"
fi

SRC_DIR="$(clone_github_repo "https://github.com/salesforce/GQUIC_Protocol_Analyzer")"
if [[ -d "$SRC_DIR" ]]; then
  CWD="$(pwd)"
  cd "$ZEEK_DIST_DIR"/aux/zeek-aux/plugin-support && \
    ./init-plugin ./zeek-quic Salesforce GQUIC && \
    cd ./zeek-quic && \
    rm -rf CMakeLists.txt ./scripts ./src && \
    cp -vr "$SRC_DIR"/CMakeLists.txt "$SRC_DIR"/scripts "$SRC_DIR"/src ./ && \
    ./configure --bro-dist="$ZEEK_DIST_DIR" --install-root="$ZEEK_PLUGIN_DIR" && \
    make && \
    make install
  cd "$CWD"
fi

SRC_DIR="$(clone_github_repo "https://github.com/J-Gras/zeek-af_packet-plugin")"
if [[ -d "$SRC_DIR" ]]; then
  CWD="$(pwd)"
  cd "$SRC_DIR" && \
    ./configure --with-kernel=/usr --zeek-dist="$ZEEK_DIST_DIR" --install-root="$ZEEK_PLUGIN_DIR" && \
    make && \
    make install
  cd "$CWD"
fi

MANUAL_BRO_GITHUB_URLS=(
  https://github.com/SoftwareConsultingEmporium/ldap-analyzer
  https://github.com/corelight/bro-xor-exe-plugin
)
for i in ${MANUAL_BRO_GITHUB_URLS[@]}; do
  SRC_DIR="$(clone_github_repo "$i")"
  if [[ -d "$SRC_DIR" ]]; then
    CWD="$(pwd)"
    cd "$SRC_DIR" && \
      ./configure --bro-dist="$ZEEK_DIST_DIR" --install-root="$ZEEK_PLUGIN_DIR" && \
      make && \
      make install
    cd "$CWD"
  fi
done

# install Spicy
SRC_DIR="$(clone_github_repo "https://github.com/zeek/spicy")"
if [[ -d "$SRC_DIR" ]]; then
  CWD="$(pwd)"
  cd "$SRC_DIR" && \
    ./configure --generator=Ninja --prefix=/opt/spicy --with-zeek=/opt/zeek --enable-ccache && \
    ninja -C build install
  cd "$CWD"
fi

if /opt/zeek/bin/zeek -N | grep -q Zeek::Spicy; then
  SRC_DIR="$(clone_github_repo "https://github.com/theparanoids/spicy-noise")"
  if [[ -d "$SRC_DIR" ]]; then
    CWD="$(pwd)"
    cd "$SRC_DIR" && \
      /opt/spicy/bin/spicyz -o spicy-noise.hlto spicy-noise.spicy spicy-noise.evt && \
      cp -f ./spicy-noise.hlto ./zeek/spicy-noise.hlto && \
      chmod 644 ./zeek/spicy-noise.hlto && \
      echo '@load /opt/zeek/share/zeek/site/spicy-noise/spicy-noise.hlto' >> ./zeek/__load__.zeek && \
      cp -vr ./zeek /opt/zeek/share/zeek/site/spicy-noise && \
    cd "$CWD"
  fi
fi
```

### <a name="ZeekAfPacket"></a>Zeek::AF_Packet configuration

Of particular mention is J-Gras' [Zeek::AF_Packet](https://github.com/J-Gras/zeek-af_packet-plugin) plugin to allow Zeek to use the Linux kernel's AF_PACKET capabilities natively for packet capture. To determine if your Linux distribution's kernel supports AF_PACKET:

```bash
$ grep -x 'CONFIG_PACKET=[ym]' "/boot/config-$(uname -r)"
CONFIG_PACKET=y
```

This plugin must be used with [`zeekctl`](https://github.com/zeek/zeekctl). To enable the use of the AF_PACKET plugin, append the following to the `zeekctl.cfg` file:

```
# all interfaces using lb_method=custom should use AF_PACKET
lb_custom.InterfacePrefix=af_packet::
```

Then, workers can be created for specific interfaces with further customization in `node.cfg`, for example:

```
...

[worker-1]
type=worker
host=localhost
interface=enp8s0
lb_procs=1
lb_method=custom
pin_cpus=0,1,2,3,4,5
af_packet_fanout_id=1
af_packet_fanout_mode=AF_Packet::FANOUT_HASH
af_packet_buffer_size=67108864
```

## <a name="ZeekLocalPolicy"></a>`local.zeek`

The local site policy (`local.zeek`) configures which Zeek scripts are loaded when Zeek is run. Hedgehog Linux's `local.zeek` file, based on the [list of third party plugins above](#ZeekThirdParty), differs slightly from [the default](https://github.com/zeek/zeek/blob/master/scripts/site/local.zeek):

```
##! Zeek local site policy. Customize as appropriate.
##!
##! See https://github.com/zeek/zeekctl
##!     https://docs.zeek.org/en/stable/script-reference/scripts.html
##!     https://github.com/zeek/zeek/blob/master/scripts/site/local.zeek

redef Broker::default_listen_address = "127.0.0.1";
redef ignore_checksums = T;
redef HTTP::default_capture_password = T;
redef FTP::default_capture_password = T;
redef SOCKS::default_capture_password = T;

@load tuning/defaults
@load misc/scan
@load frameworks/software/vulnerable
@load frameworks/software/version-changes
@load frameworks/software/windows-version-detection
@load-sigs frameworks/signatures/detect-windows-shells
@load protocols/conn/known-hosts
@load protocols/conn/known-services
@load protocols/dhcp/software
@load protocols/dns/detect-external-names
@load protocols/ftp/detect
@load protocols/ftp/software
@load protocols/http/detect-sqli
@load protocols/http/detect-webapps
@load protocols/http/software
@load protocols/http/software-browser-plugins
@load protocols/mysql/software
@load protocols/smtp/software
@load protocols/ssh/detect-bruteforcing
@load protocols/ssh/geo-data
@load protocols/ssh/interesting-hostnames
@load protocols/ssh/software
@load protocols/ssl/known-certs
@load protocols/ssl/log-hostcerts-only
@load protocols/ssl/validate-certs
@load tuning/track-all-assets.zeek
@load frameworks/files/hash-all-files
@load policy/protocols/conn/vlan-logging
@load policy/protocols/conn/mac-logging
@load policy/protocols/modbus/track-memmap
@load policy/protocols/modbus/known-masters-slaves
@load policy/protocols/mqtt
# @load frameworks/files/detect-MHR

# custom packages installed manually
@load Salesforce/GQUIC
@load ./bzar
# custom packages managed by zkg via packages/packages.zeek
@load ./packages/packages.zeek
# and apparently some installed packages (BRO::LDAP) are loaded automatically
```

## <a name="ZeekFileCarving"></a>File carving

Zeek can be used to extract ("carve") files from network traffic using known protocols (see [Package: base/files/extract](https://docs.zeek.org/en/stable/scripts/base/files/extract/), [`extract-all-files.zeek`](https://docs.zeek.org/en/stable/scripts/policy/frameworks/files/extract-all-files.zeek.html), [Bro File Analysis Exercises](https://www.zeek.org/bro-exchange-2013/exercises/faf.html), [Bro File Carving](https://www.zeek.org/current/slides/file_analysis-Bill_Stackpole.pdf))

Below are a set of Zeek scripts which allow file carving based on a list of desired MIME types and saving those files with the file extension generally associated with those MIME types.

These scripts use environment variables to determine file carving behavior:

* `ZEEK_EXTRACTOR_MODE`, possible values:
    - `none` - carve no files
    - `known` - carve any files for which a MIME type can be determined
    - `mapped` - carve any files for which a MIME type can be mapped to a common file extension (defined in `extractor_mime_to_ext_map` in `extractor_params.zeek` for the complete list, or overridden in `extractor_override.interesting.zeek` for a list of MIME types of files used as common attack vectors)
    - `all` - carve all files
* `EXTRACTED_FILE_MAX_BYTES` - the maximum file size, in bytes, for a file to be carved
* `ZEEK_EXTRACTOR_PATH` - the path in which to store extracted files 

Zeek can then be executed normally with the addition of `/opt/zeek/share/zeek/site/extractor.zeek` to the list of scripts specified on the command line (and `/opt/zeek/share/zeek/site/extractor_override.interesting.zeek` if using `mapped` mode and limiting the list of carved files to the "interesting" subset described above), or by appending these script filenames to the `SitePolicyScripts` setting in `zeekctl.cfg` if using [`zeekctl`](https://github.com/zeek/zeekctl).

For example, from the command line:

```bash
$ export ZEEK_EXTRACTOR_MODE=mapped
$ export EXTRACTED_FILE_MAX_BYTES=536870912
$ export ZEEK_EXTRACTOR_PATH=/storage/zeek/extract-files
$ /opt/zeek/bin/zeek -C \
    -i enp8s0 \
    local \
    /opt/zeek/share/zeek/site/extractor.zeek \
    /opt/zeek/share/zeek/site/extractor_override.interesting.zeek
```

Or, in `zeekctl.cfg` if using [`zeekctl`](https://github.com/zeek/zeekctl) (assuming the environment variables have been set as shown above fo the context of `zeekctl` and its child processes):

```
...
SitePolicyScripts = local /opt/zeek/share/zeek/site/extractor.zeek /opt/zeek/share/zeek/site/extractor_override.interesting.zeek
...
```

The scripts themselves are as follows:

* `/opt/zeek/share/zeek/site/extractor.zeek`

```bash
#!/usr/bin/env zeek

@load ./extractor_params

global extractor_extract_mode = (getenv("ZEEK_EXTRACTOR_MODE") == "") ? extractor_extract_known : getenv("ZEEK_EXTRACTOR_MODE");
global extractor_max_size = (getenv("EXTRACTED_FILE_MAX_BYTES") == "") ? extractor_max_size_default : to_count(getenv("EXTRACTED_FILE_MAX_BYTES"));
redef FileExtract::prefix = (getenv("ZEEK_EXTRACTOR_PATH") == "") ? "./extract_files/" : getenv("ZEEK_EXTRACTOR_PATH");

event file_sniff(f: fa_file, meta: fa_metadata) {

      # extract all files OR
  if ((extractor_extract_mode == extractor_extract_all) ||
      # we don't know the mime type and we always want to extract unknowns OR
      ((! meta?$mime_type) && extractor_always_extract_unknown) ||
      # we only want to extract knowns and we know the mime type OR
      ((extractor_extract_mode == extractor_extract_known) && meta?$mime_type) ||
      # we only want to extract mime->extension mapped files, we know the mimetype, and the mime type is mapped
      ((extractor_extract_mode == extractor_extract_mapped) && meta?$mime_type && (meta$mime_type in extractor_mime_to_ext_map))) {

    local ext: string = "";
    if (! meta?$mime_type)
      ext = extractor_mime_to_ext_map["default"];
    else if (meta$mime_type in extractor_mime_to_ext_map)
      ext = extractor_mime_to_ext_map[meta$mime_type];
    else
      ext = split_string(meta$mime_type, /\//)[1];

    local ftime: time = 0.0;
    if (! f?$last_active)
      ftime = f$last_active;
    else
      ftime = network_time();

    local uid: string = "unknown";
    if (f?$conns)
      # todo this is a little hacky, figure out how to do this better
      for (cid in f$conns) {
        uid = f$conns[cid]$uid;
        break;
      }

    local fname = fmt("%s-%s-%s-%s.%s", f$source, f$id, uid, strftime("%Y%m%d%H%M%S", ftime), ext);
    Files::add_analyzer(f, Files::ANALYZER_EXTRACT, [$extract_filename=fname, $extract_limit=extractor_max_size]);
  }
}
```

* `/opt/zeek/share/zeek/site/extractor_params.zeek`

```bash
#!/usr/bin/env zeek

export {
  const extractor_extract_none      = "none" &redef;
  const extractor_extract_known     = "known" &redef;
  const extractor_extract_mapped    = "mapped" &redef;
  const extractor_extract_all       = "all" &redef;

  const extractor_always_extract_unknown = F &redef;

  const extractor_max_size_default = 134217728 &redef;

  # wget -qO- http://svn.apache.org/repos/asf/httpd/httpd/trunk/docs/conf/mime.types | egrep -v ^# | awk '{ for (i=2; i<=NF; i++) {print "[\x22"$1"\x22]"" = ""\x22"$i"\x22,"}}' | sort
  const extractor_mime_to_ext_map : table[string] of string = {
    ["application/acad"]= "dwg",
    ["application/andrew-inset"]= "ez",
    ["application/annodex"]= "anx",
    ["application/applixware"]= "aw",
    ["application/atom+xml"]= "atom",
    ["application/atomcat+xml"]= "atomcat",
    ["application/atomsvc+xml"]= "atomsvc",
    ["application/binary"]= "bin",
    ["application/ccxml+xml"]= "ccxml",
    ["application/cdmi-capability"]= "cdmia",
    ["application/cdmi-container"]= "cdmic",
    ["application/cdmi-domain"]= "cdmid",
    ["application/cdmi-object"]= "cdmio",
    ["application/cdmi-queue"]= "cdmiq",
    ["application/cu-seeme"]= "cu",
    ["application/davmount+xml"]= "davmount",
    ["application/directx"]= "x",
    ["application/docbook+xml"]= "dbk",
    ["application/dssc+der"]= "dssc",
    ["application/dssc+xml"]= "xdssc",
    ["application/ecmascript"]= "es",
    ["application/emma+xml"]= "emma",
    ["application/envoy"]= "evy",
    ["application/epub+zip"]= "epub",
    ["application/etl"]= "etl",
    ["application/exi"]= "exi",
    ["application/font-sfnt"]= "ttf",
    ["application/fractals"]= "fif",
    ["application/fsharp-script"]= "fsscript",
    ["application/futuresplash"]= "spl",
    ["application/gml+xml"]= "gml",
    ["application/gpx+xml"]= "gpx",
    ["application/gxf"]= "gxf",
    ["application/hta"]= "hta",
    ["application/hyperstudio"]= "stk",
    ["application/inkml+xml"]= "inkml",
    ["application/internet-property-stream"]= "acx",
    ["application/ipfix"]= "ipfix",
    ["application/java-archive"]= "jar",
    ["application/java-serialized-object"]= "ser",
    ["application/java-vm"]= "class",
    ["application/javascript"]= "js",
    ["application/json"]= "json",
    ["application/jsonml+json"]= "jsonml",
    ["application/liquidmotion"]= "jck",
    ["application/lost+xml"]= "lostxml",
    ["application/mac-binhex40"]= "hqx",
    ["application/mac-compactpro"]= "cpt",
    ["application/mads+xml"]= "mads",
    ["application/marc"]= "mrc",
    ["application/marcxml+xml"]= "mrcx",
    ["application/mathematica"]= "ma",
    ["application/mathml+xml"]= "mathml",
    ["application/mbox"]= "mbox",
    ["application/mediaservercontrol+xml"]= "mscml",
    ["application/metalink+xml"]= "metalink",
    ["application/metalink4+xml"]= "meta4",
    ["application/mets+xml"]= "mets",
    ["application/mods+xml"]= "mods",
    ["application/mp21"]= "mp21",
    ["application/mp4"]= "mp4s",
    ["application/mpeg"]= "amc",
    ["application/ms-vsi"]= "vsi",
    ["application/msaccess"]= "accdb",
    ["application/msaccess.addin"]= "accda",
    ["application/msaccess.cab"]= "accdc",
    ["application/msaccess.ftemplate"]= "accft",
    ["application/msaccess.runtime"]= "accdr",
    ["application/msaccess.webapplication"]= "accdw",
    ["application/msexcel"]= "xls",
    ["application/mspowerpoint"]= "ppt",
    ["application/msword"]= "doc",
    ["application/mxf"]= "mxf",
    ["application/octet-stream"]= "bin",
    ["application/oda"]= "oda",
    ["application/oebps-package+xml"]= "opf",
    ["application/ogg"]= "ogx",
    ["application/olescript"]= "axs",
    ["application/omdoc+xml"]= "omdoc",
    ["application/onenote"]= "one",
    ["application/opensearchdescription+xml"]= "osdx",
    ["application/oxps"]= "oxps",
    ["application/patch-ops-error+xml"]= "xer",
    ["application/pdf"]= "pdf",
    ["application/pgp-encrypted"]= "pgp",
    ["application/pgp-signature"]= "pgp",
    ["application/pics-rules"]= "prf",
    ["application/pkcs10"]= "p10",
    ["application/pkcs7-mime"]= "p7c",
    ["application/pkcs7-signature"]= "p7s",
    ["application/pkcs8"]= "p8",
    ["application/pkix-attr-cert"]= "ac",
    ["application/pkix-cert"]= "cer",
    ["application/pkix-crl"]= "crl",
    ["application/pkix-pkipath"]= "pkipath",
    ["application/pkixcmp"]= "pki",
    ["application/pls+xml"]= "pls",
    ["application/postscript"]= "ps",
    ["application/PowerShell"]= "psc1",
    ["application/prs.cww"]= "cww",
    ["application/pskc+xml"]= "pskcxml",
    ["application/rat-file"]= "rat",
    ["application/rdf+xml"]= "rdf",
    ["application/reginfo+xml"]= "rif",
    ["application/relax-ng-compact-syntax"]= "rnc",
    ["application/resource-lists+xml"]= "rl",
    ["application/resource-lists-diff+xml"]= "rld",
    ["application/rls-services+xml"]= "rs",
    ["application/rpki-ghostbusters"]= "gbr",
    ["application/rpki-manifest"]= "mft",
    ["application/rpki-roa"]= "roa",
    ["application/rsd+xml"]= "rsd",
    ["application/rss+xml"]= "rss",
    ["application/rtf"]= "rtf",
    ["application/sbml+xml"]= "sbml",
    ["application/scvp-cv-request"]= "scq",
    ["application/scvp-cv-response"]= "scs",
    ["application/scvp-vp-request"]= "spq",
    ["application/scvp-vp-response"]= "spp",
    ["application/sdp"]= "sdp",
    ["application/set-payment-initiation"]= "setpay",
    ["application/set-registration-initiation"]= "setreg",
    ["application/shf+xml"]= "shf",
    ["application/smil+xml"]= "smil",
    ["application/sparql-query"]= "rq",
    ["application/sparql-results+xml"]= "srx",
    ["application/srgs"]= "gram",
    ["application/srgs+xml"]= "grxml",
    ["application/sru+xml"]= "sru",
    ["application/ssdl+xml"]= "ssdl",
    ["application/ssml+xml"]= "ssml",
    ["application/step"]= "step",
    ["application/streamingmedia"]= "ssm",
    ["application/tei+xml"]= "tei",
    ["application/thraud+xml"]= "tfi",
    ["application/timestamped-data"]= "tsd",
    ["application/vnd.3gpp.pic-bw-large"]= "plb",
    ["application/vnd.3gpp.pic-bw-small"]= "psb",
    ["application/vnd.3gpp.pic-bw-var"]= "pvb",
    ["application/vnd.3gpp2.tcap"]= "tcap",
    ["application/vnd.3m.post-it-notes"]= "pwn",
    ["application/vnd.accpac.simply.aso"]= "aso",
    ["application/vnd.accpac.simply.imp"]= "imp",
    ["application/vnd.acucobol"]= "acu",
    ["application/vnd.acucorp"]= "acutc",
    ["application/vnd.adobe.air-application-installer-package+zip"]= "air",
    ["application/vnd.adobe.formscentral.fcdt"]= "fcdt",
    ["application/vnd.adobe.fxp"]= "fxp",
    ["application/vnd.adobe.xdp+xml"]= "xdp",
    ["application/vnd.adobe.xfdf"]= "xfdf",
    ["application/vnd.ahead.space"]= "ahead",
    ["application/vnd.airzip.filesecure.azf"]= "azf",
    ["application/vnd.airzip.filesecure.azs"]= "azs",
    ["application/vnd.amazon.ebook"]= "azw",
    ["application/vnd.americandynamics.acc"]= "acc",
    ["application/vnd.amiga.ami"]= "ami",
    ["application/vnd.android.package-archive"]= "apk",
    ["application/vnd.anser-web-certificate-issue-initiation"]= "cii",
    ["application/vnd.anser-web-funds-transfer-initiation"]= "fti",
    ["application/vnd.antix.game-component"]= "atx",
    ["application/vnd.apple.installer+xml"]= "mpkg",
    ["application/vnd.apple.mpegurl"]= "m3u8",
    ["application/vnd.aristanetworks.swi"]= "swi",
    ["application/vnd.astraea-software.iota"]= "iota",
    ["application/vnd.audiograph"]= "aep",
    ["application/vnd.blueice.multipass"]= "mpm",
    ["application/vnd.bmi"]= "bmi",
    ["application/vnd.businessobjects"]= "rep",
    ["application/vnd.chemdraw+xml"]= "cdxml",
    ["application/vnd.chipnuts.karaoke-mmd"]= "mmd",
    ["application/vnd.cinderella"]= "cdy",
    ["application/vnd.claymore"]= "cla",
    ["application/vnd.cloanto.rp9"]= "rp9",
    ["application/vnd.clonk.c4group"]= "c4g",
    ["application/vnd.cluetrust.cartomobile-config"]= "c11amc",
    ["application/vnd.cluetrust.cartomobile-config-pkg"]= "c11amz",
    ["application/vnd.commonspace"]= "csp",
    ["application/vnd.contact.cmsg"]= "cdbcmsg",
    ["application/vnd.cosmocaller"]= "cmc",
    ["application/vnd.crick.clicker"]= "clkx",
    ["application/vnd.crick.clicker.keyboard"]= "clkk",
    ["application/vnd.crick.clicker.palette"]= "clkp",
    ["application/vnd.crick.clicker.template"]= "clkt",
    ["application/vnd.crick.clicker.wordbank"]= "clkw",
    ["application/vnd.criticaltools.wbs+xml"]= "wbs",
    ["application/vnd.ctc-posml"]= "pml",
    ["application/vnd.cups-ppd"]= "ppd",
    ["application/vnd.curl.car"]= "car",
    ["application/vnd.curl.pcurl"]= "pcurl",
    ["application/vnd.dart"]= "dart",
    ["application/vnd.data-vision.rdz"]= "rdz",
    ["application/vnd.dece.data"]= "uvd",
    ["application/vnd.dece.ttml+xml"]= "uvt",
    ["application/vnd.dece.unspecified"]= "uvx",
    ["application/vnd.dece.zip"]= "uvz",
    ["application/vnd.denovo.fcselayout-link"]= "fe_launch",
    ["application/vnd.dna"]= "dna",
    ["application/vnd.dolby.mlp"]= "mlp",
    ["application/vnd.dpgraph"]= "dpg",
    ["application/vnd.dreamfactory"]= "dfac",
    ["application/vnd.ds-keypoint"]= "kpxx",
    ["application/vnd.dvb.ait"]= "ait",
    ["application/vnd.dvb.service"]= "svc",
    ["application/vnd.dynageo"]= "geo",
    ["application/vnd.ecowin.chart"]= "mag",
    ["application/vnd.enliven"]= "nml",
    ["application/vnd.epson.esf"]= "esf",
    ["application/vnd.epson.msf"]= "msf",
    ["application/vnd.epson.quickanime"]= "qam",
    ["application/vnd.epson.salt"]= "slt",
    ["application/vnd.epson.ssf"]= "ssf",
    ["application/vnd.eszigno3+xml"]= "es3",
    ["application/vnd.ezpix-album"]= "ez2",
    ["application/vnd.ezpix-package"]= "ez3",
    ["application/vnd.fdf"]= "fdf",
    ["application/vnd.fdsn.mseed"]= "mseed",
    ["application/vnd.fdsn.seed"]= "seed",
    ["application/vnd.flographit"]= "gph",
    ["application/vnd.fluxtime.clip"]= "ftc",
    ["application/vnd.framemaker"]= "fm",
    ["application/vnd.frogans.fnc"]= "fnc",
    ["application/vnd.frogans.ltf"]= "ltf",
    ["application/vnd.fsc.weblaunch"]= "fsc",
    ["application/vnd.fujitsu.oasys"]= "oas",
    ["application/vnd.fujitsu.oasys2"]= "oa2",
    ["application/vnd.fujitsu.oasys3"]= "oa3",
    ["application/vnd.fujitsu.oasysgp"]= "fg5",
    ["application/vnd.fujitsu.oasysprs"]= "bh2",
    ["application/vnd.fujixerox.ddd"]= "ddd",
    ["application/vnd.fujixerox.docuworks"]= "xdw",
    ["application/vnd.fujixerox.docuworks.binder"]= "xbd",
    ["application/vnd.fuzzysheet"]= "fzs",
    ["application/vnd.genomatix.tuxedo"]= "txd",
    ["application/vnd.geogebra.file"]= "ggb",
    ["application/vnd.geogebra.tool"]= "ggt",
    ["application/vnd.geometry-explorer"]= "gex",
    ["application/vnd.geonext"]= "gxt",
    ["application/vnd.geoplan"]= "g2w",
    ["application/vnd.geospace"]= "g3w",
    ["application/vnd.gmx"]= "gmx",
    ["application/vnd.google-earth.kml+xml"]= "kml",
    ["application/vnd.google-earth.kmz"]= "kmz",
    ["application/vnd.grafeq"]= "gqf",
    ["application/vnd.groove-account"]= "gac",
    ["application/vnd.groove-help"]= "ghf",
    ["application/vnd.groove-identity-message"]= "gim",
    ["application/vnd.groove-injector"]= "grv",
    ["application/vnd.groove-tool-message"]= "gtm",
    ["application/vnd.groove-tool-template"]= "tpl",
    ["application/vnd.groove-vcard"]= "vcg",
    ["application/vnd.hal+xml"]= "hal",
    ["application/vnd.handheld-entertainment+xml"]= "zmm",
    ["application/vnd.hbci"]= "hbci",
    ["application/vnd.hhe.lesson-player"]= "les",
    ["application/vnd.hp-hpgl"]= "hpgl",
    ["application/vnd.hp-hpid"]= "hpid",
    ["application/vnd.hp-hps"]= "hps",
    ["application/vnd.hp-jlyt"]= "jlt",
    ["application/vnd.hp-pcl"]= "pcl",
    ["application/vnd.hp-pclxl"]= "pclxl",
    ["application/vnd.hydrostatix.sof-data"]= "sfd-hdstx",
    ["application/vnd.ibm.minipay"]= "mpy",
    ["application/vnd.ibm.modcap"]= "afp",
    ["application/vnd.ibm.rights-management"]= "irm",
    ["application/vnd.ibm.secure-container"]= "sc",
    ["application/vnd.iccprofile"]= "icc",
    ["application/vnd.igloader"]= "igl",
    ["application/vnd.immervision-ivp"]= "ivp",
    ["application/vnd.immervision-ivu"]= "ivu",
    ["application/vnd.insors.igm"]= "igm",
    ["application/vnd.intercon.formnet"]= "xpw",
    ["application/vnd.intergeo"]= "i2g",
    ["application/vnd.intu.qbo"]= "qbo",
    ["application/vnd.intu.qfx"]= "qfx",
    ["application/vnd.ipunplugged.rcprofile"]= "rcprofile",
    ["application/vnd.irepository.package+xml"]= "irp",
    ["application/vnd.is-xpr"]= "xpr",
    ["application/vnd.isac.fcs"]= "fcs",
    ["application/vnd.jam"]= "jam",
    ["application/vnd.jcp.javame.midlet-rms"]= "rms",
    ["application/vnd.jisp"]= "jisp",
    ["application/vnd.joost.joda-archive"]= "joda",
    ["application/vnd.kahootz"]= "ktz",
    ["application/vnd.kde.karbon"]= "karbon",
    ["application/vnd.kde.kchart"]= "chrt",
    ["application/vnd.kde.kformula"]= "kfo",
    ["application/vnd.kde.kivio"]= "flw",
    ["application/vnd.kde.kontour"]= "kon",
    ["application/vnd.kde.kpresenter"]= "kpt",
    ["application/vnd.kde.kspread"]= "ksp",
    ["application/vnd.kde.kword"]= "kwd",
    ["application/vnd.kenameaapp"]= "htke",
    ["application/vnd.kidspiration"]= "kia",
    ["application/vnd.kinar"]= "kne",
    ["application/vnd.koan"]= "skd",
    ["application/vnd.kodak-descriptor"]= "sse",
    ["application/vnd.las.las+xml"]= "lasxml",
    ["application/vnd.llamagraphics.life-balance.desktop"]= "lbd",
    ["application/vnd.llamagraphics.life-balance.exchange+xml"]= "lbe",
    ["application/vnd.lotus-1-2-3"]= "123",
    ["application/vnd.lotus-approach"]= "apr",
    ["application/vnd.lotus-freelance"]= "pre",
    ["application/vnd.lotus-notes"]= "nsf",
    ["application/vnd.lotus-organizer"]= "org",
    ["application/vnd.lotus-screencam"]= "scm",
    ["application/vnd.lotus-wordpro"]= "lwp",
    ["application/vnd.macports.portpkg"]= "portpkg",
    ["application/vnd.mcd"]= "mcd",
    ["application/vnd.medcalcdata"]= "mc1",
    ["application/vnd.mediastation.cdkey"]= "cdkey",
    ["application/vnd.mfer"]= "mwf",
    ["application/vnd.mfmp"]= "mfm",
    ["application/vnd.micrografx.flo"]= "flo",
    ["application/vnd.micrografx.igx"]= "igx",
    ["application/vnd.microsoft.portable-executable"]= "exe",
    ["application/vnd.mif"]= "mif",
    ["application/vnd.mobius.daf"]= "daf",
    ["application/vnd.mobius.dis"]= "dis",
    ["application/vnd.mobius.mbk"]= "mbk",
    ["application/vnd.mobius.mqy"]= "mqy",
    ["application/vnd.mobius.msl"]= "msl",
    ["application/vnd.mobius.plc"]= "plc",
    ["application/vnd.mobius.txf"]= "txf",
    ["application/vnd.mophun.application"]= "mpn",
    ["application/vnd.mophun.certificate"]= "mpc",
    ["application/vnd.mozilla.xul+xml"]= "xul",
    ["application/vnd.ms-artgalry"]= "cil",
    ["application/vnd.ms-cab-compressed"]= "cab",
    ["application/vnd.ms-excel"]= "xls",
    ["application/vnd.ms-excel.addin.macroEnabled.12"]= "xlam",
    ["application/vnd.ms-excel.addin.macroenabled.12"]= "xlam",
    ["application/vnd.ms-excel.sheet.binary.macroEnabled.12"]= "xlsb",
    ["application/vnd.ms-excel.sheet.binary.macroenabled.12"]= "xlsb",
    ["application/vnd.ms-excel.sheet.macroEnabled.12"]= "xlsm",
    ["application/vnd.ms-excel.sheet.macroenabled.12"]= "xlsm",
    ["application/vnd.ms-excel.template.macroEnabled.12"]= "xltm",
    ["application/vnd.ms-excel.template.macroenabled.12"]= "xltm",
    ["application/vnd.ms-fontobject"]= "eot",
    ["application/vnd.ms-htmlhelp"]= "chm",
    ["application/vnd.ms-ims"]= "ims",
    ["application/vnd.ms-lrm"]= "lrm",
    ["application/vnd.ms-mediapackage"]= "mpf",
    ["application/vnd.ms-office.calx"]= "calx",
    ["application/vnd.ms-officetheme"]= "thmx",
    ["application/vnd.ms-outlook"]= "msg",
    ["application/vnd.ms-pki.certstore"]= "sst",
    ["application/vnd.ms-pki.pko"]= "pko",
    ["application/vnd.ms-pki.seccat"]= "cat",
    ["application/vnd.ms-pki.stl"]= "stl",
    ["application/vnd.ms-powerpoint"]= "ppt",
    ["application/vnd.ms-powerpoint.addin.macroEnabled.12"]= "ppam",
    ["application/vnd.ms-powerpoint.addin.macroenabled.12"]= "ppam",
    ["application/vnd.ms-powerpoint.presentation.macroEnabled.12"]= "pptm",
    ["application/vnd.ms-powerpoint.presentation.macroenabled.12"]= "pptm",
    ["application/vnd.ms-powerpoint.slide.macroEnabled.12"]= "sldm",
    ["application/vnd.ms-powerpoint.slide.macroenabled.12"]= "sldm",
    ["application/vnd.ms-powerpoint.slideshow.macroEnabled.12"]= "ppsm",
    ["application/vnd.ms-powerpoint.slideshow.macroenabled.12"]= "ppsm",
    ["application/vnd.ms-powerpoint.template.macroEnabled.12"]= "potm",
    ["application/vnd.ms-powerpoint.template.macroenabled.12"]= "potm",
    ["application/vnd.ms-project"]= "mpt",
    ["application/vnd.ms-visio.viewer"]= "vdx",
    ["application/vnd.ms-word.document.macroEnabled.12"]= "docm",
    ["application/vnd.ms-word.document.macroenabled.12"]= "docm",
    ["application/vnd.ms-word.template.macroEnabled.12"]= "dotm",
    ["application/vnd.ms-word.template.macroenabled.12"]= "dotm",
    ["application/vnd.ms-works"]= "wks",
    ["application/vnd.ms-wpl"]= "wpl",
    ["application/vnd.ms-xpsdocument"]= "xps",
    ["application/vnd.mseq"]= "mseq",
    ["application/vnd.musician"]= "mus",
    ["application/vnd.muvee.style"]= "msty",
    ["application/vnd.mynfc"]= "taglet",
    ["application/vnd.neurolanguage.nlu"]= "nlu",
    ["application/vnd.nitf"]= "nitf",
    ["application/vnd.noblenet-directory"]= "nnd",
    ["application/vnd.noblenet-sealer"]= "nns",
    ["application/vnd.noblenet-web"]= "nnw",
    ["application/vnd.nokia.n-gage.data"]= "ngdat",
    ["application/vnd.nokia.n-gage.symbian.install"]= "n-gage",
    ["application/vnd.nokia.radio-preset"]= "rpst",
    ["application/vnd.nokia.radio-presets"]= "rpss",
    ["application/vnd.novadigm.edm"]= "edm",
    ["application/vnd.novadigm.edx"]= "edx",
    ["application/vnd.novadigm.ext"]= "ext",
    ["application/vnd.oasis.opendocument.chart"]= "odc",
    ["application/vnd.oasis.opendocument.chart-template"]= "otc",
    ["application/vnd.oasis.opendocument.database"]= "odb",
    ["application/vnd.oasis.opendocument.formula"]= "odf",
    ["application/vnd.oasis.opendocument.formula-template"]= "odft",
    ["application/vnd.oasis.opendocument.graphics"]= "odg",
    ["application/vnd.oasis.opendocument.graphics-template"]= "otg",
    ["application/vnd.oasis.opendocument.image"]= "odi",
    ["application/vnd.oasis.opendocument.image-template"]= "oti",
    ["application/vnd.oasis.opendocument.presentation"]= "odp",
    ["application/vnd.oasis.opendocument.presentation-template"]= "otp",
    ["application/vnd.oasis.opendocument.spreadsheet"]= "ods",
    ["application/vnd.oasis.opendocument.spreadsheet-template"]= "ots",
    ["application/vnd.oasis.opendocument.text"]= "odt",
    ["application/vnd.oasis.opendocument.text-master"]= "odm",
    ["application/vnd.oasis.opendocument.text-template"]= "ott",
    ["application/vnd.oasis.opendocument.text-web"]= "oth",
    ["application/vnd.olpc-sugar"]= "xo",
    ["application/vnd.oma.dd2+xml"]= "dd2",
    ["application/vnd.openofficeorg.extension"]= "oxt",
    ["application/vnd.openxmlformats-officedocument.presentationml.presentation"]= "pptx",
    ["application/vnd.openxmlformats-officedocument.presentationml.slide"]= "sldx",
    ["application/vnd.openxmlformats-officedocument.presentationml.slideshow"]= "ppsx",
    ["application/vnd.openxmlformats-officedocument.presentationml.template"]= "potx",
    ["application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"]= "xlsx",
    ["application/vnd.openxmlformats-officedocument.spreadsheetml.template"]= "xltx",
    ["application/vnd.openxmlformats-officedocument.wordprocessingml.document"]= "docx",
    ["application/vnd.openxmlformats-officedocument.wordprocessingml.template"]= "dotx",
    ["application/vnd.osgeo.mapguide.package"]= "mgp",
    ["application/vnd.osgi.dp"]= "dp",
    ["application/vnd.osgi.subsystem"]= "esa",
    ["application/vnd.palm"]= "pdb",
    ["application/vnd.pawaafile"]= "paw",
    ["application/vnd.pg.format"]= "str",
    ["application/vnd.pg.osasli"]= "ei6",
    ["application/vnd.picsel"]= "efif",
    ["application/vnd.pmi.widget"]= "wg",
    ["application/vnd.pocketlearn"]= "plf",
    ["application/vnd.powerbuilder6"]= "pbd",
    ["application/vnd.previewsystems.box"]= "box",
    ["application/vnd.proteus.magazine"]= "mgz",
    ["application/vnd.publishare-delta-tree"]= "qps",
    ["application/vnd.pvi.ptid1"]= "ptid",
    ["application/vnd.quark.quarkxpress"]= "qxt",
    ["application/vnd.realvnc.bed"]= "bed",
    ["application/vnd.recordare.musicxml"]= "mxl",
    ["application/vnd.recordare.musicxml+xml"]= "musicxml",
    ["application/vnd.rig.cryptonote"]= "cryptonote",
    ["application/vnd.rim.cod"]= "cod",
    ["application/vnd.rn-realmedia"]= "rm",
    ["application/vnd.rn-realmedia-vbr"]= "rmvb",
    ["application/vnd.rn-rn_music_package"]= "rmp",
    ["application/vnd.route66.link66+xml"]= "link66",
    ["application/vnd.sailingtracker.track"]= "st",
    ["application/vnd.seemail"]= "see",
    ["application/vnd.sema"]= "sema",
    ["application/vnd.semd"]= "semd",
    ["application/vnd.semf"]= "semf",
    ["application/vnd.shana.informed.formdata"]= "ifm",
    ["application/vnd.shana.informed.formtemplate"]= "itp",
    ["application/vnd.shana.informed.interchange"]= "iif",
    ["application/vnd.shana.informed.package"]= "ipk",
    ["application/vnd.simtech-mindmapper"]= "twd",
    ["application/vnd.smaf"]= "mmf",
    ["application/vnd.smart.teacher"]= "teacher",
    ["application/vnd.solent.sdkm+xml"]= "sdkm",
    ["application/vnd.spotfire.dxp"]= "dxp",
    ["application/vnd.spotfire.sfs"]= "sfs",
    ["application/vnd.stardivision.calc"]= "sdc",
    ["application/vnd.stardivision.draw"]= "sda",
    ["application/vnd.stardivision.impress"]= "sdd",
    ["application/vnd.stardivision.math"]= "smf",
    ["application/vnd.stardivision.writer"]= "sdw",
    ["application/vnd.stardivision.writer-global"]= "sgl",
    ["application/vnd.stepmania.package"]= "smzip",
    ["application/vnd.stepmania.stepchart"]= "sm",
    ["application/vnd.sun.xml.calc"]= "sxc",
    ["application/vnd.sun.xml.calc.template"]= "stc",
    ["application/vnd.sun.xml.draw"]= "sxd",
    ["application/vnd.sun.xml.draw.template"]= "std",
    ["application/vnd.sun.xml.impress"]= "sxi",
    ["application/vnd.sun.xml.impress.template"]= "sti",
    ["application/vnd.sun.xml.math"]= "sxm",
    ["application/vnd.sun.xml.writer"]= "sxw",
    ["application/vnd.sun.xml.writer.global"]= "sxg",
    ["application/vnd.sun.xml.writer.template"]= "stw",
    ["application/vnd.sus-calendar"]= "sus",
    ["application/vnd.svd"]= "svd",
    ["application/vnd.symbian.install"]= "sis",
    ["application/vnd.syncml+xml"]= "xsm",
    ["application/vnd.syncml.dm+wbxml"]= "bdm",
    ["application/vnd.syncml.dm+xml"]= "xdm",
    ["application/vnd.tao.intent-module-archive"]= "tao",
    ["application/vnd.tcpdump.pcap"]= "pcap",
    ["application/vnd.tmobile-livetv"]= "tmo",
    ["application/vnd.trid.tpt"]= "tpt",
    ["application/vnd.triscape.mxs"]= "mxs",
    ["application/vnd.trueapp"]= "tra",
    ["application/vnd.ufdl"]= "ufdl",
    ["application/vnd.uiq.theme"]= "utz",
    ["application/vnd.umajin"]= "umj",
    ["application/vnd.unity"]= "unityweb",
    ["application/vnd.uoml+xml"]= "uoml",
    ["application/vnd.vcx"]= "vcx",
    ["application/vnd.visio"]= "vsd",
    ["application/vnd.visionary"]= "vis",
    ["application/vnd.vsf"]= "vsf",
    ["application/vnd.wap.wbxml"]= "wbxml",
    ["application/vnd.wap.wmlc"]= "wmlc",
    ["application/vnd.wap.wmlscriptc"]= "wmlsc",
    ["application/vnd.webturbo"]= "wtb",
    ["application/vnd.wolfram.player"]= "nbp",
    ["application/vnd.wordperfect"]= "wpd",
    ["application/vnd.wqd"]= "wqd",
    ["application/vnd.wt.stf"]= "stf",
    ["application/vnd.xara"]= "xar",
    ["application/vnd.xfdl"]= "xfdl",
    ["application/vnd.yamaha.hv-dic"]= "hvd",
    ["application/vnd.yamaha.hv-script"]= "hvs",
    ["application/vnd.yamaha.hv-voice"]= "hvp",
    ["application/vnd.yamaha.openscoreformat"]= "osf",
    ["application/vnd.yamaha.openscoreformat.osfpvg+xml"]= "osfpvg",
    ["application/vnd.yamaha.smaf-audio"]= "saf",
    ["application/vnd.yamaha.smaf-phrase"]= "spf",
    ["application/vnd.yellowriver-custom-menu"]= "cmp",
    ["application/vnd.zul"]= "zir",
    ["application/vnd.zzazz.deck+xml"]= "zaz",
    ["application/voicexml+xml"]= "vxml",
    ["application/vsix"]= "vsix",
    ["application/wasm"]= "wasm",
    ["application/widget"]= "wgt",
    ["application/windows-library+xml"]= "library-ms",
    ["application/windows-search-connector+xml"]= "searchConnector-ms",
    ["application/winhlp"]= "hlp",
    ["application/wlmoviemaker"]= "WLMP",
    ["application/wsdl+xml"]= "wsdl",
    ["application/wspolicy+xml"]= "wspolicy",
    ["application/x-7z-compressed"]= "7z",
    ["application/x-abiword"]= "abw",
    ["application/x-ace-compressed"]= "ace",
    ["application/x-apple-diskimage"]= "dmg",
    ["application/x-authorware-bin"]= "aab",
    ["application/x-authorware-map"]= "aam",
    ["application/x-authorware-seg"]= "aas",
    ["application/x-bcpio"]= "bcpio",
    ["application/x-bittorrent"]= "torrent",
    ["application/x-blorb"]= "blorb",
    ["application/x-bridge-url"]= "adobebridge",
    ["application/x-bzip"]= "bz",
    ["application/x-bzip2"]= "bz2",
    ["application/x-cbr"]= "cbr",
    ["application/x-cdlink"]= "vcd",
    ["application/x-cfs-compressed"]= "cfs",
    ["application/x-chat"]= "chat",
    ["application/x-chess-pgn"]= "pgn",
    ["application/x-compress"]= "z",
    ["application/x-compressed"]= "tgz",
    ["application/x-conference"]= "nsc",
    ["application/x-cpio"]= "cpio",
    ["application/x-csh"]= "csh",
    ["application/x-debian-package"]= "deb",
    ["application/x-dgc-compressed"]= "dgc",
    ["application/x-director"]= "dir",
    ["application/x-doom"]= "wad",
    ["application/x-dosexec"]= "exe",
    ["application/x-dtbncx+xml"]= "ncx",
    ["application/x-dtbook+xml"]= "dtb",
    ["application/x-dtbresource+xml"]= "res",
    ["application/x-dvi"]= "dvi",
    ["application/x-dxf"]= "dxf",
    ["application/x-elf"]= "elf",
    ["application/x-envoy"]= "evy",
    ["application/x-eva"]= "eva",
    ["application/x-executable"]= "exe",
    ["application/x-font-bdf"]= "bdf",
    ["application/x-font-ghostscript"]= "gsf",
    ["application/x-font-linux-psf"]= "psf",
    ["application/x-font-pcf"]= "pcf",
    ["application/x-font-snf"]= "snf",
    ["application/x-font-type1"]= "pfm",
    ["application/x-freearc"]= "arc",
    ["application/x-futuresplash"]= "spl",
    ["application/x-gca-compressed"]= "gca",
    ["application/x-glulx"]= "ulx",
    ["application/x-gnumeric"]= "gnumeric",
    ["application/x-gramps-xml"]= "gramps",
    ["application/x-gtar"]= "gtar",
    ["application/x-gzip"]= "gz",
    ["application/x-hdf"]= "hdf",
    ["application/x-install-instructions"]= "install",
    ["application/x-internet-signup"]= "isp",
    ["application/x-iphone"]= "iii",
    ["application/x-iso9660-image"]= "iso",
    ["application/x-itunes-ipa"]= "ipa",
    ["application/x-itunes-ipg"]= "ipg",
    ["application/x-itunes-ipsw"]= "ipsw",
    ["application/x-itunes-ite"]= "ite",
    ["application/x-itunes-itlp"]= "itlp",
    ["application/x-itunes-itms"]= "itms",
    ["application/x-itunes-itpc"]= "itpc",
    ["application/x-java-applet"]= "class",
    ["application/x-java-jnlp-file"]= "jnlp",
    ["application/x-koan"]= "skp",
    ["application/x-latex"]= "latex",
    ["application/x-lzh-compressed"]= "lzh",
    ["application/x-mie"]= "mie",
    ["application/x-miva-compiled"]= "mvc",
    ["application/x-mmxp"]= "mxp",
    ["application/x-mobipocket-ebook"]= "mobi",
    ["application/x-ms-application"]= "application",
    ["application/x-ms-installer"]= "msi",
    ["application/x-ms-license"]= "slupkg-ms",
    ["application/x-ms-manifest"]= "manifest",
    ["application/x-ms-reader"]= "lit",
    ["application/x-ms-shortcut"]= "lnk",
    ["application/x-ms-vsto"]= "vsto",
    ["application/x-ms-wmd"]= "wmd",
    ["application/x-ms-wmz"]= "wmz",
    ["application/x-ms-xbap"]= "xbap",
    ["application/x-msaccess"]= "mdb",
    ["application/x-msbinder"]= "obd",
    ["application/x-mscardfile"]= "crd",
    ["application/x-msclip"]= "clp",
    ["application/x-msdos-program"]= "exe",
    ["application/x-msdownload"]= "exe",
    ["application/x-msmediaview"]= "mvb",
    ["application/x-msmetafile"]= "wmf",
    ["application/x-msmoney"]= "mny",
    ["application/x-mspublisher"]= "pub",
    ["application/x-msschedule"]= "scd",
    ["application/x-msterminal"]= "trm",
    ["application/x-mswrite"]= "wri",
    ["application/x-netcdf"]= "cdf",
    ["application/x-nzb"]= "nzb",
    ["application/x-oleobject"]= "hhc",
    ["application/x-pcapng"]= "pcap",
    ["application/x-pe-app-32bit-i386"]= "exe",
    ["application/x-perfmon"]= "pmw",
    ["application/x-perl"]= "pl",
    ["application/x-pkcs12"]= "p12",
    ["application/x-pkcs7-certificates"]= "p7b",
    ["application/x-pkcs7-certreqresp"]= "p7r",
    ["application/x-podcast"]= "pcast",
    ["application/x-python"]= "py",
    ["application/x-quicktimeplayer"]= "qtl",
    ["application/x-rar-compressed"]= "rar",
    ["application/x-research-info-systems"]= "ris",
    ["application/x-safari-safariextz"]= "safariextz",
    ["application/x-safari-webarchive"]= "webarchive",
    ["application/x-sgimb"]= "sgimb",
    ["application/x-sh"]= "sh",
    ["application/x-shar"]= "shar",
    ["application/x-sharedlib"]= "lib",
    ["application/x-shockwave-flash"]= "swf",
    ["application/x-silverlight-app"]= "xap",
    ["application/x-smaf"]= "mmf",
    ["application/x-sql"]= "sql",
    ["application/x-stuffit"]= "sit",
    ["application/x-stuffitx"]= "sitx",
    ["application/x-subrip"]= "srt",
    ["application/x-sv4cpio"]= "sv4cpio",
    ["application/x-sv4crc"]= "sv4crc",
    ["application/x-t3vm-image"]= "t3",
    ["application/x-tads"]= "gam",
    ["application/x-tar"]= "tar",
    ["application/x-tcl"]= "tcl",
    ["application/x-tex"]= "tex",
    ["application/x-tex-tfm"]= "tfm",
    ["application/x-texinfo"]= "texinfo",
    ["application/x-tgif"]= "obj",
    ["application/x-troff"]= "tr",
    ["application/x-troff-man"]= "man",
    ["application/x-troff-me"]= "me",
    ["application/x-troff-ms"]= "ms",
    ["application/x-ustar"]= "ustar",
    ["application/x-wais-source"]= "src",
    ["application/x-wlpg-detect"]= "wlpginstall",
    ["application/x-wlpg3-detect"]= "wlpginstall3",
    ["application/x-x509-ca-cert"]= "crt",
    ["application/x-xfig"]= "fig",
    ["application/x-xliff+xml"]= "xlf",
    ["application/x-xpinstall"]= "xpi",
    ["application/x-xz"]= "xz",
    ["application/x-zip-compressed"]= "zip",
    ["application/x-zmachine"]= "z1",
    ["application/xaml+xml"]= "xaml",
    ["application/xcap-diff+xml"]= "xdf",
    ["application/xenc+xml"]= "xenc",
    ["application/xhtml+xml"]= "xhtml",
    ["application/xml"]= "xml",
    ["application/xml-dtd"]= "dtd",
    ["application/xop+xml"]= "xop",
    ["application/xproc+xml"]= "xpl",
    ["application/xslt+xml"]= "xslt",
    ["application/xspf+xml"]= "xspf",
    ["application/xv+xml"]= "xvml",
    ["application/yang"]= "yang",
    ["application/yin+xml"]= "yin",
    ["application/zip"]= "zip",
    ["audio/aac"]= "aac",
    ["audio/ac3"]= "ac3",
    ["audio/adpcm"]= "adp",
    ["audio/aiff"]= "aiff",
    ["audio/annodex"]= "axa",
    ["audio/audible"]= "aa",
    ["audio/basic"]= "au",
    ["audio/flac"]= "flac",
    ["audio/m4a"]= "m4a",
    ["audio/m4b"]= "m4b",
    ["audio/m4p"]= "m4p",
    ["audio/mid"]= "midi",
    ["audio/midi"]= "midi",
    ["audio/mp4"]= "m4a",
    ["audio/mpeg"]= "mp3",
    ["audio/ogg"]= "ogg",
    ["audio/s3m"]= "s3m",
    ["audio/scpls"]= "pls",
    ["audio/silk"]= "sil",
    ["audio/vnd.audible.aax"]= "aax",
    ["audio/vnd.dece.audio"]= "uva",
    ["audio/vnd.digital-winds"]= "eol",
    ["audio/vnd.dlna.adts"]= "ADT",
    ["audio/vnd.dra"]= "dra",
    ["audio/vnd.dts"]= "dts",
    ["audio/vnd.dts.hd"]= "dtshd",
    ["audio/vnd.lucent.voice"]= "lvp",
    ["audio/vnd.ms-playready.media.pya"]= "pya",
    ["audio/vnd.nuera.ecelp4800"]= "ecelp4800",
    ["audio/vnd.nuera.ecelp7470"]= "ecelp7470",
    ["audio/vnd.nuera.ecelp9600"]= "ecelp9600",
    ["audio/vnd.rip"]= "rip",
    ["audio/wav"]= "wav",
    ["audio/webm"]= "weba",
    ["audio/x-aac"]= "aac",
    ["audio/x-aiff"]= "aiff",
    ["audio/x-caf"]= "caf",
    ["audio/x-flac"]= "flac",
    ["audio/x-gsm"]= "gsm",
    ["audio/x-m4a"]= "m4a",
    ["audio/x-m4r"]= "m4r",
    ["audio/x-matroska"]= "mka",
    ["audio/x-mpegurl"]= "m3u",
    ["audio/x-ms-wax"]= "wax",
    ["audio/x-ms-wma"]= "wma",
    ["audio/x-pn-realaudio"]= "ra",
    ["audio/x-pn-realaudio-plugin"]= "rmp",
    ["audio/x-sd2"]= "sd2",
    ["audio/x-smd"]= "smd",
    ["audio/x-wav"]= "wav",
    ["audio/xm"]= "xm",
    ["chemical/x-cdx"]= "cdx",
    ["chemical/x-cif"]= "cif",
    ["chemical/x-cmdf"]= "cmdf",
    ["chemical/x-cml"]= "cml",
    ["chemical/x-csml"]= "csml",
    ["chemical/x-xyz"]= "xyz",
    ["drawing/x-dwf"]= "dwf",
    ["font/collection"]= "ttc",
    ["font/otf"]= "otf",
    ["font/ttf"]= "ttf",
    ["font/woff"]= "woff",
    ["font/woff2"]= "woff2",
    ["image/bmp"]= "bmp",
    ["image/cgm"]= "cgm",
    ["image/cis-cod"]= "cod",
    ["image/g3fax"]= "g3",
    ["image/gif"]= "gif",
    ["image/ief"]= "ief",
    ["image/jpeg"]= "jpg",
    ["image/ktx"]= "ktx",
    ["image/pict"]= "pict",
    ["image/pjpeg"]= "jfif",
    ["image/png"]= "png",
    ["image/prs.btif"]= "btif",
    ["image/sgi"]= "sgi",
    ["image/svg+xml"]= "svg",
    ["image/tiff"]= "tiff",
    ["image/vnd.adobe.photoshop"]= "psd",
    ["image/vnd.dece.graphic"]= "uvg",
    ["image/vnd.djvu"]= "djvu",
    ["image/vnd.dvb.subtitle"]= "sub",
    ["image/vnd.dwg"]= "dwg",
    ["image/vnd.dxf"]= "dxf",
    ["image/vnd.fastbidsheet"]= "fbs",
    ["image/vnd.fpx"]= "fpx",
    ["image/vnd.fst"]= "fst",
    ["image/vnd.fujixerox.edmics-mmr"]= "mmr",
    ["image/vnd.fujixerox.edmics-rlc"]= "rlc",
    ["image/vnd.ms-modi"]= "mdi",
    ["image/vnd.ms-photo"]= "wdp",
    ["image/vnd.net-fpx"]= "npx",
    ["image/vnd.rn-realflash"]= "rf",
    ["image/vnd.wap.wbmp"]= "wbmp",
    ["image/vnd.xiff"]= "xif",
    ["image/webp"]= "webp",
    ["image/x-3ds"]= "3ds",
    ["image/x-cmu-raster"]= "ras",
    ["image/x-cmx"]= "cmx",
    ["image/x-freehand"]= "fh",
    ["image/x-gif"]= "gif",
    ["image/x-icon"]= "ico",
    ["image/x-jg"]= "art",
    ["image/x-jpeg"]= "jpg",
    ["image/x-macpaint"]= "mac",
    ["image/x-mrsid-image"]= "sid",
    ["image/x-pcx"]= "pcx",
    ["image/x-pict"]= "pic",
    ["image/x-png"]= "png",
    ["image/x-portable-anymap"]= "pnm",
    ["image/x-portable-bitmap"]= "pbm",
    ["image/x-portable-graymap"]= "pgm",
    ["image/x-portable-pixmap"]= "ppm",
    ["image/x-quicktime"]= "qti",
    ["image/x-rgb"]= "rgb",
    ["image/x-tga"]= "tga",
    ["image/x-xbitmap"]= "xbm",
    ["image/x-xpixmap"]= "xpm",
    ["image/x-xwindowdump"]= "xwd",
    ["message/rfc822"]= "eml",
    ["model/iges"]= "iges",
    ["model/mesh"]= "mesh",
    ["model/vnd.collada+xml"]= "dae",
    ["model/vnd.dwf"]= "dwf",
    ["model/vnd.gdl"]= "gdl",
    ["model/vnd.gtw"]= "gtw",
    ["model/vnd.mts"]= "mts",
    ["model/vnd.vtu"]= "vtu",
    ["model/vrml"]= "vrml",
    ["model/x3d+binary"]= "x3db",
    ["model/x3d+vrml"]= "x3dv",
    ["model/x3d+xml"]= "x3d",
    ["text/cache-manifest"]= "appcache",
    ["text/calendar"]= "ics",
    ["text/css"]= "css",
    ["text/csv"]= "csv",
    ["text/dlm"]= "dlm",
    ["text/h323"]= "323",
    ["text/html"]= "html",
    ["text/iuls"]= "uls",
    ["text/jscript"]= "jsx",
    ["text/n3"]= "n3",
    ["text/plain"]= "txt",
    ["text/prs.lines.tag"]= "dsc",
    ["text/richtext"]= "rtx",
    ["text/rtf"]= "rtf",
    ["text/scriptlet"]= "sct",
    ["text/sgml"]= "sgml",
    ["text/tab-separated-values"]= "tsv",
    ["text/troff"]= "tr",
    ["text/uri-list"]= "uri",
    ["text/vbscript"]= "vbs",
    ["text/vcard"]= "vcard",
    ["text/vnd.curl"]= "curl",
    ["text/vnd.curl.dcurl"]= "dcurl",
    ["text/vnd.curl.mcurl"]= "mcurl",
    ["text/vnd.curl.scurl"]= "scurl",
    ["text/vnd.dvb.subtitle"]= "sub",
    ["text/vnd.fly"]= "fly",
    ["text/vnd.fmi.flexstor"]= "flx",
    ["text/vnd.graphviz"]= "gv",
    ["text/vnd.in3d.3dml"]= "3dml",
    ["text/vnd.in3d.spot"]= "spot",
    ["text/vnd.sun.j2me.app-descriptor"]= "jad",
    ["text/vnd.wap.wml"]= "wml",
    ["text/vnd.wap.wmlscript"]= "wmls",
    ["text/vtt"]= "vtt",
    ["text/webviewhtml"]= "htt",
    ["text/x-asm"]= "asm",
    ["text/x-c"]= "c",
    ["text/x-component"]= "htc",
    ["text/x-fortran"]= "f",
    ["text/x-hdml"]= "hdml",
    ["text/x-html-insertion"]= "qhtm",
    ["text/x-java-source"]= "java",
    ["text/x-ms-contact"]= "contact",
    ["text/x-ms-group"]= "group",
    ["text/x-ms-iqy"]= "iqy",
    ["text/x-ms-rqy"]= "rqy",
    ["text/x-nfo"]= "nfo",
    ["text/x-opml"]= "opml",
    ["text/x-pascal"]= "pas",
    ["text/x-setext"]= "etx",
    ["text/x-sfv"]= "sfv",
    ["text/x-uuencode"]= "uu",
    ["text/x-vcalendar"]= "vcs",
    ["text/x-vcard"]= "vcf",
    ["text/xml"]= "xml",
    ["video/3gpp"]= "3gp",
    ["video/3gpp2"]= "3g2",
    ["video/annodex"]= "axv",
    ["video/divx"]= "divx",
    ["video/h261"]= "h261",
    ["video/h263"]= "h263",
    ["video/h264"]= "h264",
    ["video/jpeg"]= "jpgv",
    ["video/jpm"]= "jpm",
    ["video/mj2"]= "mj2",
    ["video/mp4"]= "mp4",
    ["video/mpeg"]= "mpg",
    ["video/ogg"]= "ogv",
    ["video/quicktime"]= "mov",
    ["video/vnd.dece.hd"]= "uvh",
    ["video/vnd.dece.mobile"]= "uvm",
    ["video/vnd.dece.pd"]= "uvp",
    ["video/vnd.dece.sd"]= "uvs",
    ["video/vnd.dece.video"]= "uvv",
    ["video/vnd.dlna.mpeg-tts"]= "m2t",
    ["video/vnd.dvb.file"]= "dvb",
    ["video/vnd.fvt"]= "fvt",
    ["video/vnd.mpegurl"]= "m4u",
    ["video/vnd.ms-playready.media.pyv"]= "pyv",
    ["video/vnd.uvvu.mp4"]= "uvu",
    ["video/vnd.vivo"]= "viv",
    ["video/webm"]= "webm",
    ["video/x-dv"]= "dv",
    ["video/x-f4v"]= "f4v",
    ["video/x-fli"]= "fli",
    ["video/x-flv"]= "flv",
    ["video/x-ivf"]= "IVF",
    ["video/x-la-asf"]= "lsf",
    ["video/x-m4v"]= "m4v",
    ["video/x-matroska"]= "mkv",
    ["video/x-matroska-3d"]= "mk3d",
    ["video/x-mng"]= "mng",
    ["video/x-ms-asf"]= "asf",
    ["video/x-ms-vob"]= "vob",
    ["video/x-ms-wm"]= "wm",
    ["video/x-ms-wmp"]= "wmp",
    ["video/x-ms-wmv"]= "wmv",
    ["video/x-ms-wmx"]= "wmx",
    ["video/x-ms-wvx"]= "wvx",
    ["video/x-msvideo"]= "avi",
    ["video/x-sgi-movie"]= "movie",
    ["video/x-smv"]= "smv",
    ["x-conference/x-cooltalk"]= "ice",
    ["x-world/x-vrml"]= "wrl"
  } &default="bin" &redef;
}
```

* `/opt/zeek/share/zeek/site/extractor_override.interesting.zeek`

```bash
#!/usr/bin/env zeek

export {
  redef extractor_always_extract_unknown = F;

  redef extractor_mime_to_ext_map : table[string] of string = {
    ["application/binary"]= "bin",
    ["application/ecmascript"]= "es",
    ["application/hta"]= "hta",
    ["application/java-archive"]= "jar",
    ["application/java-serialized-object"]= "ser",
    ["application/java-vm"]= "class",
    ["application/javascript"]= "js",
    ["application/ms-vsi"]= "vsi",
    ["application/msaccess"]= "accdb",
    ["application/msaccess.addin"]= "accda",
    ["application/msaccess.cab"]= "accdc",
    ["application/msaccess.ftemplate"]= "accft",
    ["application/msaccess.runtime"]= "accdr",
    ["application/msaccess.webapplication"]= "accdw",
    ["application/msexcel"]= "xls",
    ["application/mspowerpoint"]= "ppt",
    ["application/msword"]= "doc",
    ["application/octet-stream"]= "bin",
    ["application/pdf"]= "pdf",
    ["application/PowerShell"]= "psc1",
    ["application/rtf"]= "rtf",
    ["application/vnd.apple.installer+xml"]= "mpkg",
    ["application/vnd.microsoft.portable-executable"]= "exe",
    ["application/vnd.ms-cab-compressed"]= "cab",
    ["application/vnd.ms-excel"]= "xls",
    ["application/vnd.ms-excel.addin.macroEnabled.12"]= "xlam",
    ["application/vnd.ms-excel.addin.macroenabled.12"]= "xlam",
    ["application/vnd.ms-excel.sheet.binary.macroEnabled.12"]= "xlsb",
    ["application/vnd.ms-excel.sheet.binary.macroenabled.12"]= "xlsb",
    ["application/vnd.ms-excel.sheet.macroEnabled.12"]= "xlsm",
    ["application/vnd.ms-excel.sheet.macroenabled.12"]= "xlsm",
    ["application/vnd.ms-excel.template.macroEnabled.12"]= "xltm",
    ["application/vnd.ms-excel.template.macroenabled.12"]= "xltm",
    ["application/vnd.ms-office.calx"]= "calx",
    ["application/vnd.ms-officetheme"]= "thmx",
    ["application/vnd.ms-powerpoint"]= "ppt",
    ["application/vnd.ms-powerpoint.addin.macroEnabled.12"]= "ppam",
    ["application/vnd.ms-powerpoint.addin.macroenabled.12"]= "ppam",
    ["application/vnd.ms-powerpoint.presentation.macroEnabled.12"]= "pptm",
    ["application/vnd.ms-powerpoint.presentation.macroenabled.12"]= "pptm",
    ["application/vnd.ms-powerpoint.slide.macroEnabled.12"]= "sldm",
    ["application/vnd.ms-powerpoint.slide.macroenabled.12"]= "sldm",
    ["application/vnd.ms-powerpoint.slideshow.macroEnabled.12"]= "ppsm",
    ["application/vnd.ms-powerpoint.slideshow.macroenabled.12"]= "ppsm",
    ["application/vnd.ms-powerpoint.template.macroEnabled.12"]= "potm",
    ["application/vnd.ms-powerpoint.template.macroenabled.12"]= "potm",
    ["application/vnd.ms-word.document.macroEnabled.12"]= "docm",
    ["application/vnd.ms-word.document.macroenabled.12"]= "docm",
    ["application/vnd.ms-word.template.macroEnabled.12"]= "dotm",
    ["application/vnd.ms-word.template.macroenabled.12"]= "dotm",
    ["application/vnd.openofficeorg.extension"]= "oxt",
    ["application/vnd.openxmlformats-officedocument.presentationml.presentation"]= "pptx",
    ["application/vnd.openxmlformats-officedocument.presentationml.slide"]= "sldx",
    ["application/vnd.openxmlformats-officedocument.presentationml.slideshow"]= "ppsx",
    ["application/vnd.openxmlformats-officedocument.presentationml.template"]= "potx",
    ["application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"]= "xlsx",
    ["application/vnd.openxmlformats-officedocument.spreadsheetml.template"]= "xltx",
    ["application/vnd.openxmlformats-officedocument.wordprocessingml.document"]= "docx",
    ["application/vnd.openxmlformats-officedocument.wordprocessingml.template"]= "dotx",
    ["application/windows-library+xml"]= "library-ms",
    ["application/x-7z-compressed"]= "7z",
    ["application/x-ace-compressed"]= "ace",
    ["application/x-apple-diskimage"]= "dmg",
    ["application/x-bzip"]= "bz",
    ["application/x-bzip2"]= "bz2",
    ["application/x-cfs-compressed"]= "cfs",
    ["application/x-compress"]= "z",
    ["application/x-compressed"]= "tgz",
    ["application/x-cpio"]= "cpio",
    ["application/x-csh"]= "csh",
    ["application/x-dgc-compressed"]= "dgc",
    ["application/x-dosexec"]= "exe",
    ["application/x-elf"]= "elf",
    ["application/x-executable"]= "exe",
    ["application/x-gca-compressed"]= "gca",
    ["application/x-gtar"]= "gtar",
    ["application/x-gzip"]= "gz",
    ["application/x-install-instructions"]= "install",
    ["application/x-lzh-compressed"]= "lzh",
    ["application/x-ms-application"]= "application",
    ["application/x-ms-installer"]= "msi",
    ["application/x-ms-shortcut"]= "lnk",
    ["application/x-msdos-program"]= "exe",
    ["application/x-msdownload"]= "exe",
    ["application/x-pe-app-32bit-i386"]= "exe",
    ["application/x-perl"]= "pl",
    ["application/x-python"]= "py",
    ["application/x-rar-compressed"]= "rar",
    ["application/x-sh"]= "sh",
    ["application/x-shockwave-flash"]= "swf",
    ["application/x-zip-compressed"]= "zip",
    ["application/zip"]= "zip",
    ["text/jscript"]= "jsx",
    ["text/rtf"]= "rtf",
    ["text/vbscript"]= "vbs"
  } &default="dat";

}
```

Once carved, the files in the directory indicated by the `$ZEEK_EXTRACTOR_PATH` environment variable can be examined using a virus scanner or other file analysis utilities.

# <a name="Forwarding"></a>Forwarding

The Elastic Stack's [Beats](https://www.elastic.co/products/beats) platform is an excellent suite of data shippers for logs, packet metadata, performance metrics and more. These forwarders can be downloaded from the [Elastic downloads page](https://www.elastic.co/downloads/beats) or installed via a script as in this example:

```bash
#!/bin/bash

set -e

BEATS_VER="7.10.0"
BEATS_OSS="-oss"
BEATS_DEB_URL_TEMPLATE_REPLACER="XXXXX"
BEATS_DEB_URL_TEMPLATE="https://artifacts.elastic.co/downloads/beats/$BEATS_DEB_URL_TEMPLATE_REPLACER/$BEATS_DEB_URL_TEMPLATE_REPLACER$BEATS_OSS-$BEATS_VER-amd64.deb"

# install filebeat/metricbeat/auditbeat/packetbeat
for BEAT in filebeat metricbeat auditbeat packetbeat; do
  BEATS_URL="$(echo "$BEATS_DEB_URL_TEMPLATE" | sed "s/$BEATS_DEB_URL_TEMPLATE_REPLACER/$BEAT/g")"
  BEATS_DEB="$BEAT-$BEATS_VER-amd64.deb"
  pushd /tmp && \
    curl -f -L -o "$BEATS_DEB" "$BEATS_URL" && \
    dpkg -i "$BEATS_DEB" && \
    rm -f "$BEATS_DEB" && \
    popd
done
```

While the examples in this document use the Elastic Stack (particularly [Logstash](https://www.elastic.co/products/logstash) and [Elasticsearch](https://www.elastic.co/products/elasticsearch)) as destinations, Beats support [many](https://www.elastic.co/guide/en/beats/filebeat/current/configuring-output.html) [other](https://www.elastic.co/guide/en/beats/auditbeat/current/configuring-output.html) [output](https://www.elastic.co/guide/en/beats/metricbeat/current/configuring-output.html) [transports](https://www.elastic.co/guide/en/beats/packetbeat/current/configuring-output.html) as well.

## <a name="ForwardingZeekLogs"></a>Forwarding Zeek logs

[Filebeat](https://www.elastic.co/products/beats/filebeat) can be used to forward Zeek logs (or any other kind of log) to a variety of destinations, including a [Logstash](https://www.elastic.co/products/logstash) instance for additional [parsing](https://github.com/idaholab/Malcolm/blob/master/logstash/pipelines/zeek/11_zeek_logs.conf) and [enrichment](https://github.com/idaholab/Malcolm/blob/master/logstash/pipelines/enrichment/01_input_log_enrichment.conf) or directly into an [Elasticsearch](https://www.elastic.co/products/elasticsearch) instance.

Here is an example `filebeat.yml` [configuration file](https://www.elastic.co/guide/en/beats/filebeat/current/configuring-howto-filebeat.html) used to collect Zeek logs from a directory and forward them to a Logstash instance. Some values here are specified in the via environment variables with sane defaults if those environment variables are not specified:

```
logging.metrics.enabled: false

filebeat.inputs:
- type: log
  paths:
    - ${BEAT_LOG_PATTERN:/home/sensor/bro_logs/*.log}
  symlinks: true
  fields_under_root: true
  # tags: ["remote"]
  fields:
    type: "session"
  compression_level: 0
  exclude_lines: ['^\s*#']
  scan_frequency: ${BEAT_SCAN_FREQUENCY:10s}
  clean_inactive: ${BEAT_CLEAN_INACTIVE:180m}
  ignore_older: ${BEAT_IGNORE_OLDER:120m}
  close_inactive: ${BEAT_CLOSE_INACTIVE:90m}
  close_renamed: ${BEAT_CLOSE_RENAMED:true}
  close_removed: ${BEAT_CLOSE_REMOVED:true}
  close_eof: ${BEAT_CLOSE_EOF:false}
  clean_renamed: ${BEAT_CLEAN_RENAMED:true}
  clean_removed: ${BEAT_CLEAN_REMOVED:true}

output.logstash:
  hosts: ["${BEAT_LS_HOST}:${BEAT_LS_PORT}"]
  ssl.enabled: ${BEAT_LS_SSL:false}
  ssl.certificate_authorities: ["${BEAT_LS_SSL_CA_CRT}"]
  ssl.certificate: "${BEAT_LS_SSL_CLIENT_CRT}"
  ssl.key: "${BEAT_LS_SSL_CLIENT_KEY}"
  ssl.supported_protocols: "TLSv1.2"
  ssl.verification_mode: "${BEAT_LS_SSL_VERIFY}"
```

Note that if the remote Logstash server is using SSL, Filebeat must also be configured to use SSL with the appropriate settings for `ssl.enabled`, `ssl.certificate_authorities`, `ssl.certificate`, `ssl.key`, `ssl.supported_protocols` and `ssl.verification_mode` corresponding to the values used by Logstash on the other side of the connection. See [Secure communication with Logstash](https://www.elastic.co/guide/en/beats/filebeat/current/configuring-ssl-logstash.html) for more information.

## <a name="ForwardingMetrics"></a>Forwarding sensor system metrics

[Metricbeat](https://www.elastic.co/products/beats/metricbeat) can be used to ship system metrics (CPU, memory, file system, disk IO, network IO, etc.) to a remote Elasticsearch [Elasticsearch](https://www.elastic.co/products/elasticsearch) instance. This may be useful to monitor the performance of a network sensor device.

Here is a sample `metricbeat.yml` [configuration file](https://www.elastic.co/guide/en/beats/metricbeat/current/metricbeat-reference-yml.html) similar to the one used in Hedgehog Linux. This configuration includes setting up prebuilt [Kibana dashboards](https://www.elastic.co/guide/en/beats/metricbeat/current/view-kibana-dashboards.html) for visualizing the system metrics data. Credentials for the Elasticsearch database can be stored securely using a [secrets keystore](https://www.elastic.co/guide/en/beats/filebeat/current/keystore.html).

```
metricbeat.config.modules:
  path: ${path.config}/conf.d/*.yml
  reload.period: 10s
  reload.enabled: false

metricbeat.max_start_delay: 10s

#==========================  Modules configuration ============================
metricbeat.modules:

#------------------------------- System Module -------------------------------
- module: system
  period: ${BEAT_INTERVAL}
  metricsets:
    - cpu             # CPU usage
    - load            # CPU load averages
    - memory          # Memory usage
    - network         # Network IO
    - process         # Per process metrics
    - process_summary # Process summary
    - uptime          # System Uptime
    - diskio          # Disk IO
  enabled: true
  processes: ['.*']
  process.include_top_n:
    enabled: true
    by_cpu: 10
    by_memory: 10

  cpu.metrics:  ["percentages"]
  core.metrics: ["percentages"]

- module: system
  period: 1m
  metricsets:
    - filesystem     # File system usage for each mountpoint
    - fsstat         # File system summary metrics
  processors:
  - drop_event.when.regexp:
      system.filesystem.mount_point: '^/(sys|cgroup|proc|dev|etc|host|lib|boot)($|/)'

#================================ General ======================================
fields_under_root: true

#================================ Outputs ======================================

#-------------------------- Elasticsearch output -------------------------------
output.elasticsearch:
  enabled: true
  hosts: ["${BEAT_ES_HOST}:${BEAT_ES_PORT}"]
  protocol: "${BEAT_ES_PROTOCOL}"
  username: "${BEAT_HTTP_USERNAME}"
  password: "${BEAT_HTTP_PASSWORD}"
  ssl.verification_mode: "${BEAT_ES_SSL_VERIFY}"

setup.template.enabled: true
setup.template.overwrite: false
setup.template.settings:
  index.number_of_shards: 1
  index.number_of_replicas: 0

#============================== Dashboards =====================================
setup.dashboards.enabled: "${BEAT_KIBANA_DASHBOARDS_ENABLED}"
setup.dashboards.directory: "${BEAT_KIBANA_DASHBOARDS_PATH}"

#============================== Kibana =====================================
setup.kibana:
  host: "${BEAT_KIBANA_HOST}:${BEAT_KIBANA_PORT}"
  protocol: "${BEAT_KIBANA_PROTOCOL}"
  username: "${BEAT_HTTP_USERNAME}"
  password: "${BEAT_HTTP_PASSWORD}"
  ssl.verification_mode: "${BEAT_KIBANA_SSL_VERIFY}"

#================================ Logging ======================================
logging.metrics.enabled: false
```

## <a name="ForwardingAuditLogs"></a>Forwarding audit logs

[Auditbeat](https://www.elastic.co/products/beats/auditbeat) communicates directly with the Linux audit framework, collects the same data as `auditd`, and sends the events to the [Elastic Stack]([Elasticsearch](https://www.elastic.co/products/elasticsearch) using existing audit rules.

Here is a sample `auditbeat.yml` [configuration file](https://www.elastic.co/guide/en/beats/auditbeat/current/auditbeat-reference-yml.html) similar to the one used in Hedgehog Linux. This configuration includes setting up prebuilt [Kibana dashboards](https://www.elastic.co/guide/en/beats/auditbeat/current/view-kibana-dashboards.html) for visualizing the audit log data. Configuring Auditbeat may require some tuning by adding [`drop_event`](https://www.elastic.co/guide/en/beats/auditbeat/current/drop-event.html) processors to reduce verbosity for known/common functions, so some examples are listed here. Credentials for the Elasticsearch database can be stored securely using a [secrets keystore](https://www.elastic.co/guide/en/beats/filebeat/current/keystore.html).

```
#==========================  Modules configuration =============================
auditbeat.modules:

- module: auditd
  socket_type: multicast
  resolve_ids: true
  failure_mode: log
  backlog_limit: 16384
  rate_limit: 0
  include_raw_message: false
  include_warnings: false
  backpressure_strategy: auto
  # audit_rule_files: [ '${path.config}/audit.rules.d/*.conf' ]
  # no rules specified, auditd will run and manage rules
  # see https://www.elastic.co/guide/en/beats/auditbeat/master/auditbeat-module-auditd.html

  # don't forward some things that are always going to be happening
  # (/proc/ accesses by beats and/or PCAP capture) to cut down on noise
  # and some other approved common stuff that would clutter the logs
  processors:
  - drop_event:
      when:
        or:
          - and:
              - equals:
                  auditd.data.syscall: 'setsockopt'
              - equals:
                  auditd.summary.object.type: 'network-device'
              - or:
                  - equals:
                      auditd.summary.how: '/usr/sbin/tcpdump'
                  - equals:
                      auditd.summary.how: '/opt/zeek/bin/zeek'
                  - equals:
                      auditd.summary.how: '/usr/sbin/netsniff-ng'
          - and:
              - equals:
                  auditd.message_type: 'syscall'
              - equals:
                  auditd.summary.object.type: 'file'
              - or:
                - and:
                    - or:
                        - equals:
                            auditd.data.syscall: 'open'
                        - equals:
                            auditd.data.syscall: 'openat'
                    - regexp:
                        auditd.summary.object.primary: '^/(proc/|etc/localtime|usr/lib/x86_64-linux-gnu/gconv/gconv-modules\.cache)'
                    - or:
                        - equals:
                            auditd.summary.how: '/usr/share/auditbeat/bin/auditbeat'
                        - equals:
                            auditd.summary.how: '/usr/share/metricbeat/bin/metricbeat'
                        - equals:
                            auditd.summary.how: '/usr/sbin/tcpdump'
                        - equals:
                            auditd.summary.how: '/opt/zeek/bin/zeek'
                        - equals:
                            auditd.summary.how: '/usr/sbin/netsniff-ng'
                - and:
                    - or:
                        - equals:
                            auditd.data.syscall: 'open'
                        - equals:
                            auditd.data.syscall: 'openat'
                    - not:
                        has_fields: ['auditd.summary.object.primary']
                    - equals:
                        auditd.summary.how: '/usr/share/metricbeat/bin/metricbeat'

- module: file_integrity
  paths:
  - /bin
  - /opt/zeek
  - /sbin
  - /usr/bin
  - /usr/local/bin
  - /usr/sbin

#================================ General ======================================
fields_under_root: true

#================================ Outputs ======================================

#-------------------------- Elasticsearch output -------------------------------
output.elasticsearch:
  enabled: true
  hosts: ["${BEAT_ES_HOST}:${BEAT_ES_PORT}"]
  protocol: "${BEAT_ES_PROTOCOL}"
  username: "${BEAT_HTTP_USERNAME}"
  password: "${BEAT_HTTP_PASSWORD}"
  ssl.verification_mode: "${BEAT_ES_SSL_VERIFY}"

setup.template.enabled: true
setup.template.overwrite: false
setup.template.settings:
  index.number_of_shards: 1
  index.number_of_replicas: 0

#============================== Dashboards =====================================
setup.dashboards.enabled: "${BEAT_KIBANA_DASHBOARDS_ENABLED}"
setup.dashboards.directory: "${BEAT_KIBANA_DASHBOARDS_PATH}"

#============================== Kibana =====================================
setup.kibana:
  host: "${BEAT_KIBANA_HOST}:${BEAT_KIBANA_PORT}"
  protocol: "${BEAT_KIBANA_PROTOCOL}"
  username: "${BEAT_HTTP_USERNAME}"
  password: "${BEAT_HTTP_PASSWORD}"
  ssl.verification_mode: "${BEAT_KIBANA_SSL_VERIFY}"

#================================ Logging ======================================
logging.metrics.enabled: false
```

## <a name="ForwardingSyslogs"></a>Forwarding syslogs

[Filebeat](https://www.elastic.co/products/beats/filebeat)'s [syslog input module](https://www.elastic.co/guide/en/beats/filebeat/master/filebeat-input-syslog.html) can be used to forward Linux system logs to a remote Elasticsearch [Elasticsearch](https://www.elastic.co/products/elasticsearch) instance.

Here is an example `filebeat.yml` [configuration file](https://www.elastic.co/guide/en/beats/filebeat/current/configuring-howto-filebeat.html) for this purpose. In this example, the local `rsyslog` instance has been configured to forward syslogs over UDP to the loopback interface on port 9514, which is being monitored by `filebeat` for forwarding. This is accomplished by appending `*.* @127.0.0.1:9514` to `/etc/rsyslog.conf` and restarting `rsyslog`.

Credentials for the Elasticsearch database can be stored securely using a [secrets keystore](https://www.elastic.co/guide/en/beats/filebeat/current/keystore.html).

```
filebeat.inputs:
- type: syslog
  protocol.udp:
    host: "127.0.0.1:9514"

#================================ General ======================================
fields_under_root: true

#================================ Outputs ======================================

#-------------------------- Elasticsearch output -------------------------------
output.elasticsearch:
  enabled: true
  hosts: ["${BEAT_ES_HOST}:${BEAT_ES_PORT}"]
  protocol: "${BEAT_ES_PROTOCOL}"
  username: "${BEAT_HTTP_USERNAME}"
  password: "${BEAT_HTTP_PASSWORD}"
  ssl.verification_mode: "${BEAT_ES_SSL_VERIFY}"

setup.template.enabled: true
setup.template.overwrite: false
setup.template.settings:
  index.number_of_shards: 1
  index.number_of_replicas: 0

#============================== Dashboards =====================================
setup.dashboards.enabled: "${BEAT_KIBANA_DASHBOARDS_ENABLED}"
setup.dashboards.directory: "${BEAT_KIBANA_DASHBOARDS_PATH}"

#============================== Kibana =====================================
setup.kibana:
  host: "${BEAT_KIBANA_HOST}:${BEAT_KIBANA_PORT}"
  protocol: "${BEAT_KIBANA_PROTOCOL}"
  username: "${BEAT_HTTP_USERNAME}"
  password: "${BEAT_HTTP_PASSWORD}"
  ssl.verification_mode: "${BEAT_KIBANA_SSL_VERIFY}"

#================================ Logging ======================================
logging.metrics.enabled: false
```

# <a name="System"></a>System considerations

## <a name="nicOffloading"></a>NIC offloading and ring buffer sizes.

Modern operating systems offload various functions from the OS to the hardware of the network interface cards. In order for packet capture tools to capture what is actually crossing the wire (vs. what the OS networking stack sees), the offloading of these functions should be disabled prior to capture. Additionally, the NIC ring buffer sizes should be increased for capture.

This short script can be called with a network interface name (e.g., `nic-capture-setup.sh enp8s0`) to disable NIC offloading for these features.

```bash
#!/bin/bash

IFACE_NAME="$1"

if [[ -n "$IFACE_NAME" ]]; then
  # disable NIC feature offloading
  /sbin/ethtool -K "$IFACE_NAME" rx off tx off sg off tso off ufo off gso off gro off lro off

  # increase ring buffer sizes to maximum (may increase latency, but maximize throughput)
  MAX_BUFFER_SIZES=($(/sbin/ethtool -g "$IFACE_NAME" | grep -E "^(RX|TX):" | head -n 2 | awk '{print $2}'))
  if ((${#MAX_BUFFER_SIZES[@]} == 2)); then
    /sbin/ethtool -G "$IFACE_NAME" rx ${MAX_BUFFER_SIZES[0]} tx ${MAX_BUFFER_SIZES[1]}
  fi

fi
```

For more reading on this subject, see [Large send offload](https://en.wikipedia.org/wiki/Large_send_offload), [Generic Segmentation Offload](https://lwn.net/Articles/188489/), [Generic receive offload](https://lwn.net/Articles/358910/), [Super packets](https://www.unleashnetworks.com/blog/?p=307), [Offloading](https://wiki.wireshark.org/CaptureSetup/Offloading), [Packet Acquisition](http://manual-snort-org.s3-website-us-east-1.amazonaws.com/node7.html) and [Security Onion](https://blog.securityonion.net/2011/10/when-is-full-packet-capture-not-full.html).

## <a name="Performance"></a>Performance

Varoius system settings need to be modified for a Linux distribution to perform optimally as a network sensor appliance. A few of those used by Hedgehog Linux are listed here:

* appended to [`/etc/sysctl.conf`](http://man7.org/linux/man-pages/man5/sysctl.conf.5.html)
```
# the maximum number of open file handles
fs.file-max=2097152

# increase maximums for inotify watches
fs.inotify.max_user_watches=131072
fs.inotify.max_queued_events=131072
fs.inotify.max_user_instances=512

# the maximum number of memory map areas a process may have
vm.max_map_count=262144

# decrease "swappiness" (swapping out runtime memory vs. dropping pages)
vm.swappiness=1

# the % of system memory fillable with "dirty" pages before flushing
vm.dirty_background_ratio=40

# maximum % of dirty system memory before committing everything
vm.dirty_ratio=80

net.core.netdev_max_backlog=250000
net.core.optmem_max=33554432
net.core.rmem_default=425984
net.core.rmem_max=33554432
net.core.somaxconn=65535
net.core.wmem_default=425984
net.core.wmem_max=33554432
net.ipv4.tcp_rmem=10240 425984 33554432
net.ipv4.tcp_wmem=10240 425984 33554432
net.ipv4.udp_mem=10240 425984 33554432
```

* [`/etc/security/limits.d/limits.conf`](https://linux.die.net/man/5/limits.conf)

```
* soft nofile 65535
* hard nofile 65535
* soft memlock unlimited
* hard memlock unlimited
* soft core 0
* hard core 0
```

* kernel parameters for GRUB specified in `/etc/default/grub` (followed by running `update-grub` as `root`)

```
GRUB_CMDLINE_LINUX_DEFAULT="elevator=deadline cgroup_enable=memory swapaccount=1 cgroup.memory=nokmem apparmor=1 security=apparmor ipv6.disable=1 audit=1"
```

This is by no means an exhaustive list of tunable settings for network packet capture (it does not go into considerations for choosing a file system, RAM disks, CPU pinning and `nice`, high-performance NICs and their drivers, etc.), but it is a starting point.

## <a name="Hardening"></a>Hardening

Hedgehog Linux targets the following guidelines for establishing a secure configuration posture:

* DISA STIG ([Security Technical Implementation Guides](https://public.cyber.mil/stigs/)) [ported](https://github.com/hardenedlinux/STIG-4-Debian) from DISA RHEL 7 STIG v1r1 to a Debian 9 base platform
* [CIS](https://learn.cisecurity.org/benchmarks) Debian Linux 9 Benchmark with additional recommendations by the [hardenedlinux/harbian-audit](https://github.com/hardenedlinux/harbian-audit) project

# <a name="Footer"></a>Copyright

Hedgehog Linux - part of [Malcolm](https://github.com/idaholab/Malcolm) - is Copyright 2021 Battelle Energy Alliance, LLC, and is developed and released through the cooperation of the Cybersecurity and Infrastructure Security Agency of the U.S. Department of Homeland Security.

See [`License.txt`](https://raw.githubusercontent.com/idaholab/Malcolm/master/License.txt) for the terms of its release.

### Contact information of author(s):

[Seth Grover](mailto:malcolm.netsec@gmail.com?subject=Network%20sensor%20development)
