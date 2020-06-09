FROM debian:buster-slim AS build

# Copyright (c) 2020 Battelle Energy Alliance, LLC.  All rights reserved.

ENV DEBIAN_FRONTEND noninteractive

# build zeek and plugins (spicy, additional protocol parsers, etc.)

ENV BISON_VERSION "3.6.2"
ENV CCACHE_DIR "/var/spool/ccache"
ENV CCACHE_COMPRESS 1
ENV CMAKE_DIR "/opt/cmake"
ENV CMAKE_VERSION "3.17.2"
ENV SPICY_DIR "/opt/spicy"
ENV SRC_BASE_DIR "/usr/local/src"
ENV ZEEK_DIR "/opt/zeek"
ENV ZEEK_PATCH_DIR "${SRC_BASE_DIR}/zeek-patches"
ENV ZEEK_SRC_DIR "${SRC_BASE_DIR}/zeek-${ZEEK_VERSION}"
ENV ZEEK_VERSION "3.0.6"

# using clang now instead of gcc because Spicy depends on it
ENV LLVM_VERSION "10"
ENV CC "clang-${LLVM_VERSION}"
ENV CXX "clang++-${LLVM_VERSION}"
ENV ASM "clang-${LLVM_VERSION}"

ENV PATH "${ZEEK_DIR}/bin:${CMAKE_DIR}/bin:${PATH}"

ADD shared/bin/zeek_install_plugins.sh /usr/local/bin/
# empty for now...
# ADD zeek/patches ${ZEEK_PATCH_DIR}

RUN sed -i "s/buster main/buster main contrib non-free/g" /etc/apt/sources.list && \
      echo "deb http://deb.debian.org/debian buster-backports main" >> /etc/apt/sources.list && \
      apt-get -q update && \
      apt-get install -q -y --no-install-recommends gnupg2 curl ca-certificates && \
      bash -c "curl -sSL https://apt.llvm.org/llvm-snapshot.gpg.key | apt-key add -" && \
      echo "deb http://apt.llvm.org/buster/ llvm-toolchain-buster-${LLVM_VERSION} main" >> /etc/apt/sources.list && \
    apt-get -q update && \
    apt-get install -q -y -t buster-backports --no-install-recommends \
        binutils \
        ccache \
        clang-${LLVM_VERSION} \
        file \
        flex \
        git \
        google-perftools \
        jq \
        libclang-${LLVM_VERSION}-dev \
        libfl-dev \
        libgoogle-perftools-dev \
        libkrb5-dev \
        libmaxminddb-dev \
        libpcap0.8-dev \
        libssl-dev \
        llvm-${LLVM_VERSION}-dev \
        locales-all \
        make \
        ninja-build \
        patch \
        python3 \
        python3-dev \
        python3-pip \
        python3-setuptools \
        python3-wheel \
        swig \
        zlib1g-dev && \
  pip3 install --no-cache-dir zkg btest pre-commit && \
  mkdir -p "${CMAKE_DIR}" && \
    curl -sSL "https://github.com/Kitware/CMake/releases/download/v${CMAKE_VERSION}/cmake-${CMAKE_VERSION}-Linux-x86_64.tar.gz" | tar xzf - -C "${CMAKE_DIR}" --strip-components 1 && \
  cd "${SRC_BASE_DIR}" && \
    curl -sSL "https://ftp.gnu.org/gnu/bison/bison-${BISON_VERSION}.tar.gz" | tar xzf - -C "${SRC_BASE_DIR}" && \
    cd "./bison-${BISON_VERSION}" && \
    ./configure --prefix=/usr && \
    make && \
    make install && \
  cd "${SRC_BASE_DIR}" && \
    curl -sSL "https://old.zeek.org/downloads/zeek-${ZEEK_VERSION}.tar.gz" | tar xzf - -C "${SRC_BASE_DIR}" && \
    cd "./zeek-${ZEEK_VERSION}" && \
    bash -c "for i in ${ZEEK_PATCH_DIR}/* ; do patch -p 1 -r - --no-backup-if-mismatch < \$i || true; done" && \
    ./configure --prefix="${ZEEK_DIR}" --generator=Ninja --ccache --enable-perftools && \
    cd build && \
    ninja && \
    ninja install && \
    zkg autoconfig && \
    bash /usr/local/bin/zeek_install_plugins.sh && \
    bash -c "find ${ZEEK_DIR}/lib -type d -name CMakeFiles -exec rm -rf '{}' \; 2>/dev/null || true" && \
    bash -c "file ${ZEEK_DIR}/{lib,bin}/* ${ZEEK_DIR}/lib/zeek/plugins/packages/*/lib/* ${ZEEK_DIR}/lib/zeek/plugins/*/lib/* ${SPICY_DIR}/{lib,bin}/* ${SPICY_DIR}/lib/spicy/Zeek_Spicy/lib/* | grep 'ELF 64-bit' | sed 's/:.*//' | xargs -l -r strip -v --strip-unneeded"

FROM debian:buster-slim

LABEL maintainer="malcolm.netsec@gmail.com"
LABEL org.opencontainers.image.authors='malcolm.netsec@gmail.com'
LABEL org.opencontainers.image.url='https://github.com/idaholab/Malcolm'
LABEL org.opencontainers.image.documentation='https://github.com/idaholab/Malcolm/blob/master/README.md'
LABEL org.opencontainers.image.source='https://github.com/idaholab/Malcolm'
LABEL org.opencontainers.image.vendor='Idaho National Laboratory'
LABEL org.opencontainers.image.title='malcolmnetsec/zeek'
LABEL org.opencontainers.image.description='Malcolm container providing Zeek'

ENV DEBIAN_FRONTEND noninteractive

ENV LLVM_VERSION "10"
ENV ZEEK_DIR "/opt/zeek"
ENV SPICY_DIR "/opt/spicy"

COPY --from=build ${ZEEK_DIR} ${ZEEK_DIR}
COPY --from=build ${SPICY_DIR} ${SPICY_DIR}

RUN sed -i "s/buster main/buster main contrib non-free/g" /etc/apt/sources.list && \
      echo "deb http://deb.debian.org/debian buster-backports main" >> /etc/apt/sources.list && \
      apt-get -q update && \
      apt-get install -q -y --no-install-recommends gnupg2 curl ca-certificates && \
      bash -c "curl -sSL https://apt.llvm.org/llvm-snapshot.gpg.key | apt-key add -" && \
      echo "deb http://apt.llvm.org/buster/ llvm-toolchain-buster-${LLVM_VERSION} main" >> /etc/apt/sources.list && \
    apt-get -q update && \
    apt-get install -q -y -t buster-backports --no-install-recommends \
      file \
      libatomic1 \
      libclang-cpp${LLVM_VERSION} \
      libclang1-${LLVM_VERSION} \
      libgoogle-perftools4 \
      libkrb5-3 \
      libmaxminddb0 \
      libpcap0.8 \
      libssl1.0 \
      libtcmalloc-minimal4 \
      libunwind8 \
      libzmq5 \
      llvm-${LLVM_VERSION} \
      procps \
      psmisc \
      python \
      python3 \
      python3-pip \
      python3-setuptools \
      python3-wheel \
      supervisor \
      vim-tiny && \
    pip3 install --no-cache-dir pyzmq && \
    apt-get -q -y --purge remove libssl-dev && \
      apt-get -q -y autoremove && \
      apt-get clean && \
      rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# add configuration and scripts
ADD shared/bin/pcap_moloch_and_zeek_processor.py /usr/local/bin/
ADD shared/bin/pcap_utils.py /usr/local/bin/
ADD shared/pcaps /tmp/pcaps
ADD zeek/supervisord.conf /etc/supervisord.conf
ADD zeek/config/*.zeek ${ZEEK_DIR}/share/zeek/site/

# sanity check to make sure the plugins installed and copied over correctly
# these ENVs should match the number of third party plugins installed by zeek_install_plugins.sh
ENV ZEEK_THIRD_PARTY_PLUGINS_COUNT 19
ENV ZEEK_THIRD_PARTY_GREP_STRING "(Bro_LDAP/scripts/main|Corelight/PE_XOR/main|Salesforce/GQUIC/main|Zeek_AF_Packet/scripts/init|bzar/main|cve-2020-0601/cve-2020-0601|cve-2020-13777/cve-2020-13777|hassh/hassh|ja3/ja3|zeek-community-id/main|zeek-EternalSafety/main|zeek-httpattacks/main|zeek-plugin-bacnet/main|zeek-plugin-enip/main|zeek-plugin-profinet/main|zeek-plugin-s7comm/main|zeek-plugin-tds/main|zeek-sniffpass/main|spicy/main)\.(zeek|bro)"

RUN mkdir -p /tmp/logs && \
    cd /tmp/logs && \
      $ZEEK_DIR/bin/zeek -C -r /tmp/pcaps/udp.pcap local policy/misc/loaded-scripts 2>/dev/null && \
      bash -c "(( $(grep -cP "$ZEEK_THIRD_PARTY_GREP_STRING" loaded_scripts.log) == $ZEEK_THIRD_PARTY_PLUGINS_COUNT)) && echo 'Zeek plugins loaded correctly' || (echo 'One or more Zeek plugins did not load correctly' && cat loaded_scripts.log && exit 1)" && \
      cd /tmp && \
      rm -rf /tmp/logs /tmp/pcaps

#Whether or not to auto-tag logs based on filename
ARG AUTO_TAG=true
#Whether or not to run "zeek -r XXXXX.pcap local" on each pcap file
ARG ZEEKUSER=zeek
ARG ZEEK_AUTO_ANALYZE_PCAP_FILES=false
ARG ZEEK_AUTO_ANALYZE_PCAP_THREADS=1
ARG ZEEK_EXTRACTOR_MODE=none
ARG ZEEK_EXTRACTOR_PATH=/zeek/extract_files
ARG PCAP_PIPELINE_DEBUG=false
ARG PCAP_PIPELINE_DEBUG_EXTRA=false
ARG PCAP_MONITOR_HOST=pcap-monitor

ENV AUTO_TAG $AUTO_TAG
ENV ZEEKUSER $ZEEKUSER
ENV ZEEK_AUTO_ANALYZE_PCAP_FILES $ZEEK_AUTO_ANALYZE_PCAP_FILES
ENV ZEEK_AUTO_ANALYZE_PCAP_THREADS $ZEEK_AUTO_ANALYZE_PCAP_THREADS
ENV ZEEK_EXTRACTOR_MODE $ZEEK_EXTRACTOR_MODE
ENV ZEEK_EXTRACTOR_PATH $ZEEK_EXTRACTOR_PATH
ENV PCAP_PIPELINE_DEBUG $PCAP_PIPELINE_DEBUG
ENV PCAP_PIPELINE_DEBUG_EXTRA $PCAP_PIPELINE_DEBUG_EXTRA
ENV PCAP_MONITOR_HOST $PCAP_MONITOR_HOST

RUN groupadd --gid 1000 ${ZEEKUSER} && \
    useradd -M --uid 1000 --gid 1000 --home /nonexistant ${ZEEKUSER} && \
    ln -sfr /usr/local/bin/pcap_moloch_and_zeek_processor.py /usr/local/bin/pcap_zeek_processor.py

#Update Path
ENV PATH "${ZEEK_DIR}/bin:${SPICY_DIR}/bin:${PATH}"

CMD ["/usr/bin/supervisord", "-c", "/etc/supervisord.conf", "-u", "root", "-n"]


# to be populated at build-time:
ARG BUILD_DATE
ARG MALCOLM_VERSION
ARG VCS_REVISION

LABEL org.opencontainers.image.created=$BUILD_DATE
LABEL org.opencontainers.image.version=$MALCOLM_VERSION
LABEL org.opencontainers.image.revision=$VCS_REVISION
