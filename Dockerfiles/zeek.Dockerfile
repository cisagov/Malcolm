FROM debian:buster-slim

# Copyright (c) 2021 Battelle Energy Alliance, LLC.  All rights reserved.

LABEL maintainer="malcolm.netsec@gmail.com"
LABEL org.opencontainers.image.authors='malcolm.netsec@gmail.com'
LABEL org.opencontainers.image.url='https://github.com/idaholab/Malcolm'
LABEL org.opencontainers.image.documentation='https://github.com/idaholab/Malcolm/blob/master/README.md'
LABEL org.opencontainers.image.source='https://github.com/idaholab/Malcolm'
LABEL org.opencontainers.image.vendor='Idaho National Laboratory'
LABEL org.opencontainers.image.title='malcolmnetsec/zeek'
LABEL org.opencontainers.image.description='Malcolm container providing Zeek'

ENV DEBIAN_FRONTEND noninteractive
ENV TERM xterm

# configure unprivileged user and runtime parameters
ARG DEFAULT_UID=1000
ARG DEFAULT_GID=1000
ENV DEFAULT_UID $DEFAULT_UID
ENV DEFAULT_GID $DEFAULT_GID
ENV PUSER "zeeker"
ENV PGROUP "zeeker"
ENV PUSER_PRIV_DROP true

# for download and install
ARG ZEEK_LTS=1
ARG ZEEK_VERSION=4.0.0-0
ARG SPICY_VERSION=1.0.0

ENV ZEEK_LTS $ZEEK_LTS
ENV ZEEK_VERSION $ZEEK_VERSION
ENV SPICY_VERSION $SPICY_VERSION

# for build
ENV LLVM_VERSION "11"
ENV CC "clang-${LLVM_VERSION}"
ENV CXX "clang++-${LLVM_VERSION}"
ENV ASM "clang-${LLVM_VERSION}"
ENV CCACHE_DIR "/var/spool/ccache"
ENV CCACHE_COMPRESS 1

# put Zeek and Spicy in PATH
ENV ZEEK_DIR "/opt/zeek"
ENV SPICY_DIR "/opt/spicy"
ENV PATH "${ZEEK_DIR}/bin:${SPICY_DIR}/bin:${PATH}"

# add script for building 3rd-party plugins
ADD shared/bin/zeek_install_plugins.sh /usr/local/bin/

# build and install system packages, zeek, spicy and plugins
RUN echo "deb http://deb.debian.org/debian buster-backports main" >> /etc/apt/sources.list && \
    apt-get -q update && \
    apt-get install -q -y --no-install-recommends \
      ca-certificates \
      curl \
      file \
      git \
      gnupg2 \
      jq \
      less \
      libcap2-bin \
      moreutils \
      procps \
      psmisc \
      vim-tiny && \
    ( curl -sSL https://apt.llvm.org/llvm-snapshot.gpg.key | apt-key add - ) && \
    echo "deb http://apt.llvm.org/buster/ llvm-toolchain-buster-${LLVM_VERSION} main" >> /etc/apt/sources.list && \
    echo "deb-src http://apt.llvm.org/buster/ llvm-toolchain-buster-${LLVM_VERSION} main" >> /etc/apt/sources.list && \
    apt-get -q update && \
    apt-get install -q -y -t buster-backports --no-install-recommends \
      bison \
      ccache \
      clang-${LLVM_VERSION} \
      cmake \
      flex \
      libatomic1 \
      libclang-${LLVM_VERSION}-dev \
      libfl-dev \
      libgoogle-perftools4 \
      libkrb5-3 \
      libmaxminddb-dev \
      libmaxminddb0 \
      libpcap-dev \
      libpcap0.8 \
      libssl-dev \
      libtcmalloc-minimal4 \
      libunwind8 \
      libzmq5 \
      llvm-${LLVM_VERSION}-dev \
      locales-all \
      make \
      ninja-build \
      python3 \
      python3-git \
      python3-pip \
      python3-semantic-version \
      python3-setuptools \
      python3-wheel \
      supervisor \
      zlib1g-dev && \
    python3 -m pip install --no-cache-dir pyzmq && \
    mkdir -p /tmp/zeek-packages && \
      cd /tmp/zeek-packages && \
      if [ -n "${ZEEK_LTS}" ]; then ZEEK_LTS="-lts"; fi && export ZEEK_LTS && \
      curl -sSL --remote-name-all \
        "https://download.zeek.org/binary-packages/Debian_10/amd64/libbroker${ZEEK_LTS}-dev_${ZEEK_VERSION}_amd64.deb" \
        "https://download.zeek.org/binary-packages/Debian_10/amd64/zeek${ZEEK_LTS}-core-dev_${ZEEK_VERSION}_amd64.deb" \
        "https://download.zeek.org/binary-packages/Debian_10/amd64/zeek${ZEEK_LTS}-core_${ZEEK_VERSION}_amd64.deb" \
        "https://download.zeek.org/binary-packages/Debian_10/amd64/zeek${ZEEK_LTS}-libcaf-dev_${ZEEK_VERSION}_amd64.deb" \
        "https://download.zeek.org/binary-packages/Debian_10/amd64/zeek${ZEEK_LTS}_${ZEEK_VERSION}_amd64.deb" \
        "https://download.zeek.org/binary-packages/Debian_10/amd64/zeek${ZEEK_LTS}-btest_${ZEEK_VERSION}_amd64.deb" \
        "https://download.zeek.org/binary-packages/Debian_10/amd64/zeek${ZEEK_LTS}-zkg_${ZEEK_VERSION}_amd64.deb" \
        "https://download.zeek.org/binary-packages/Debian_10/amd64/zeekctl${ZEEK_LTS}_${ZEEK_VERSION}_amd64.deb" && \
      dpkg -i ./*.deb && \
    mkdir -p /tmp/spicy-packages && \
      cd /tmp/spicy-packages && \
    curl -sSL --remote-name-all \
      "https://github.com/zeek/spicy/releases/download/v${SPICY_VERSION}/spicy_linux_debian10.deb" && \
      dpkg -i ./*.deb && \
    cd /tmp && \
    mkdir -p "${CCACHE_DIR}" && \
    zkg autoconfig --force && \
    zkg install --force --skiptests zeek/spicy-plugin && \
    bash /usr/local/bin/zeek_install_plugins.sh && \
    ( find "${ZEEK_DIR}"/lib -type d -name CMakeFiles -exec rm -rf "{}" \; 2>/dev/null || true ) && \
    ( find "${ZEEK_DIR}"/var/lib/zkg -type d -name build -exec rm -rf "{}" \; 2>/dev/null || true ) && \
    ( find "${ZEEK_DIR}"/var/lib/zkg/clones -type d -name .git -execdir bash -c "pwd; du -sh; git pull --depth=1 --ff-only; git reflog expire --expire=all --all; git tag -l | xargs -r git tag -d; git gc --prune=all; du -sh" \; ) && \
    rm -rf "${ZEEK_DIR}"/var/lib/zkg/scratch && \
    ( find "${ZEEK_DIR}/" "${SPICY_DIR}/" -type f -exec file "{}" \; | grep -Pi "ELF 64-bit.*not stripped" | sed 's/:.*//' | xargs -l -r strip --strip-unneeded ) && \
    mkdir -p "${ZEEK_DIR}"/var/lib/zkg/clones/package/spicy-plugin/build/plugin/bin/ && \
      ln -s -r "${ZEEK_DIR}"/lib/zeek/plugins/packages/spicy-plugin/bin/spicyz \
               "${ZEEK_DIR}"/var/lib/zkg/clones/package/spicy-plugin/build/plugin/bin/spicyz && \
    mkdir -p "${ZEEK_DIR}"/var/lib/zkg/clones/package/spicy-plugin/plugin/lib/ && \
      ln -s -r "${ZEEK_DIR}"/lib/zeek/plugins/packages/spicy-plugin/lib/bif \
               "${ZEEK_DIR}"/var/lib/zkg/clones/package/spicy-plugin/plugin/lib/bif && \
    cd /usr/lib/locale && \
      ( ls | grep -Piv "^(en|en_US|en_US\.utf-?8|C\.utf-?8)$" | xargs -l -r rm -rf ) && \
    cd /tmp && \
    apt-get clean && \
      rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* /var/cache/*/*

# add configuration and scripts
ADD shared/bin/docker-uid-gid-setup.sh /usr/local/bin/
ADD shared/bin/pcap_moloch_and_zeek_processor.py /usr/local/bin/
ADD shared/bin/pcap_utils.py /usr/local/bin/
ADD shared/pcaps /tmp/pcaps
ADD zeek/supervisord.conf /etc/supervisord.conf
ADD zeek/config/*.zeek ${ZEEK_DIR}/share/zeek/site/

# sanity checks to make sure the plugins installed and copied over correctly
# these ENVs should match the number of third party scripts/plugins installed by zeek_install_plugins.sh
# todo: Bro::LDAP is broken right now, disabled
ENV ZEEK_THIRD_PARTY_PLUGINS_COUNT 18
ENV ZEEK_THIRD_PARTY_PLUGINS_GREP  "(_Zeek::Spicy|ANALYZER_SPICY_DHCP|ANALYZER_SPICY_DNS|ANALYZER_SPICY_HTTP|ANALYZER_SPICY_OPENVPN|ANALYZER_SPICY_IPSEC|ANALYZER_SPICY_TFTP|ANALYZER_SPICY_WIREGUARD|Corelight::CommunityID|Corelight::PE_XOR|ICSNPP::BACnet|ICSNPP::BSAP_IP|ICSNPP::BSAP_SERIAL|ICSNPP::ENIP|Salesforce::GQUIC|Zeek::PROFINET|Zeek::S7comm|Zeek::TDS)"
ENV ZEEK_THIRD_PARTY_SCRIPTS_COUNT 13
ENV ZEEK_THIRD_PARTY_SCRIPTS_GREP  "(bzar/main|callstranger-detector/callstranger|cve-2020-0601/cve-2020-0601|cve-2020-13777/cve-2020-13777|CVE-2020-16898/CVE-2020-16898|hassh/hassh|ja3/ja3|ripple20/ripple20|SIGRed/CVE-2020-1350|zeek-EternalSafety/main|zeek-httpattacks/main|zeek-sniffpass/__load__|zerologon/main)\.(zeek|bro)"

RUN mkdir -p /tmp/logs && \
    cd /tmp/logs && \
    "$ZEEK_DIR"/bin/zeek -NN local >zeeknn.log 2>/dev/null && \
      bash -c "(( $(grep -cP "$ZEEK_THIRD_PARTY_PLUGINS_GREP" zeeknn.log) >= $ZEEK_THIRD_PARTY_PLUGINS_COUNT)) && echo 'Zeek plugins loaded correctly' || (echo 'One or more Zeek plugins did not load correctly' && cat zeeknn.log && exit 1)" && \
    "$ZEEK_DIR"/bin/zeek -C -r /tmp/pcaps/udp.pcap local policy/misc/loaded-scripts 2>/dev/null && \
      bash -c "(( $(grep -cP "$ZEEK_THIRD_PARTY_SCRIPTS_GREP" loaded_scripts.log) == $ZEEK_THIRD_PARTY_SCRIPTS_COUNT)) && echo 'Zeek scripts loaded correctly' || (echo 'One or more Zeek scripts did not load correctly' && cat loaded_scripts.log && exit 1)" && \
    cd /tmp && \
    rm -rf /tmp/logs /tmp/pcaps

RUN groupadd --gid ${DEFAULT_GID} ${PUSER} && \
    useradd -M --uid ${DEFAULT_UID} --gid ${DEFAULT_GID} --home /nonexistant ${PUSER} && \
    usermod -a -G tty ${PUSER} && \
    ln -sfr /usr/local/bin/pcap_moloch_and_zeek_processor.py /usr/local/bin/pcap_zeek_processor.py

#Whether or not to auto-tag logs based on filename
ARG AUTO_TAG=true
#Whether or not to run "zeek -r XXXXX.pcap local" on each pcap file
ARG ZEEK_AUTO_ANALYZE_PCAP_FILES=false
ARG ZEEK_AUTO_ANALYZE_PCAP_THREADS=1
ARG ZEEK_EXTRACTOR_MODE=none
ARG ZEEK_EXTRACTOR_PATH=/zeek/extract_files
ARG PCAP_PIPELINE_DEBUG=false
ARG PCAP_PIPELINE_DEBUG_EXTRA=false
ARG PCAP_MONITOR_HOST=pcap-monitor

ENV AUTO_TAG $AUTO_TAG
ENV ZEEK_AUTO_ANALYZE_PCAP_FILES $ZEEK_AUTO_ANALYZE_PCAP_FILES
ENV ZEEK_AUTO_ANALYZE_PCAP_THREADS $ZEEK_AUTO_ANALYZE_PCAP_THREADS
ENV ZEEK_EXTRACTOR_MODE $ZEEK_EXTRACTOR_MODE
ENV ZEEK_EXTRACTOR_PATH $ZEEK_EXTRACTOR_PATH
ENV PCAP_PIPELINE_DEBUG $PCAP_PIPELINE_DEBUG
ENV PCAP_PIPELINE_DEBUG_EXTRA $PCAP_PIPELINE_DEBUG_EXTRA
ENV PCAP_MONITOR_HOST $PCAP_MONITOR_HOST

# environment variables for zeek runtime tweaks (used in local.zeek)
ARG ZEEK_DISABLE_HASH_ALL_FILES=
ARG ZEEK_DISABLE_LOG_PASSWORDS=
ARG ZEEK_DISABLE_SSL_VALIDATE_CERTS=
ARG ZEEK_DISABLE_TRACK_ALL_ASSETS=
# TODO: assess spicy-analyzer that replace built-in Zeek parsers
# for now, disable them by default when a Zeek parser exists
ARG ZEEK_DISABLE_SPICY_DHCP=true
ARG ZEEK_DISABLE_SPICY_DNS=true
ARG ZEEK_DISABLE_SPICY_HTTP=true
ARG ZEEK_DISABLE_SPICY_IPSEC=
ARG ZEEK_DISABLE_SPICY_OPENVPN=
ARG ZEEK_DISABLE_SPICY_TFTP=
ARG ZEEK_DISABLE_SPICY_WIREGUARD=

ENV ZEEK_DISABLE_HASH_ALL_FILES $ZEEK_DISABLE_HASH_ALL_FILES
ENV ZEEK_DISABLE_LOG_PASSWORDS $ZEEK_DISABLE_LOG_PASSWORDS
ENV ZEEK_DISABLE_SSL_VALIDATE_CERTS $ZEEK_DISABLE_SSL_VALIDATE_CERTS
ENV ZEEK_DISABLE_TRACK_ALL_ASSETS $ZEEK_DISABLE_TRACK_ALL_ASSETS
ENV ZEEK_DISABLE_SPICY_DHCP $ZEEK_DISABLE_SPICY_DHCP
ENV ZEEK_DISABLE_SPICY_DNS $ZEEK_DISABLE_SPICY_DNS
ENV ZEEK_DISABLE_SPICY_HTTP $ZEEK_DISABLE_SPICY_HTTP
ENV ZEEK_DISABLE_SPICY_OPENVPN $ZEEK_DISABLE_SPICY_OPENVPN
ENV ZEEK_DISABLE_SPICY_TFTP $ZEEK_DISABLE_SPICY_TFTP
ENV ZEEK_DISABLE_SPICY_WIREGUARD $ZEEK_DISABLE_SPICY_WIREGUARD

ENTRYPOINT ["/usr/local/bin/docker-uid-gid-setup.sh"]

CMD ["/usr/bin/supervisord", "-c", "/etc/supervisord.conf", "-n"]


# to be populated at build-time:
ARG BUILD_DATE
ARG MALCOLM_VERSION
ARG VCS_REVISION

LABEL org.opencontainers.image.created=$BUILD_DATE
LABEL org.opencontainers.image.version=$MALCOLM_VERSION
LABEL org.opencontainers.image.revision=$VCS_REVISION
