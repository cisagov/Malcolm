FROM debian:buster-slim AS build

# Copyright (c) 2020 Battelle Energy Alliance, LLC.  All rights reserved.

ENV DEBIAN_FRONTEND noninteractive

ENV SRC_BASE_DIR "/usr/local/src"
ENV ZEEK_VERSION "3.0.2"
ENV ZEEK_DIR "/opt/zeek"
ENV ZEEK_SRC_DIR "${SRC_BASE_DIR}/zeek-${ZEEK_VERSION}"
ENV ZEEK_PATCH_DIR "${SRC_BASE_DIR}/zeek-patches"
ENV PATH="${ZEEK_DIR}/bin:${PATH}"

ADD https://www.zeek.org/downloads/zeek-$ZEEK_VERSION.tar.gz $SRC_BASE_DIR/zeek.tar.gz
ADD shared/bin/zeek_install_plugins.sh /usr/local/bin/

RUN sed -i "s/buster main/buster main contrib non-free/g" /etc/apt/sources.list && \
    apt-get -q update && \
    apt-get install -q -y --no-install-recommends \
        binutils \
        bison \
        cmake \
        curl \
        file \
        flex \
        g++ \
        gcc \
        git \
        libkrb5-dev \
        libpcap0.8-dev \
        libssl-dev \
        make \
        ninja-build \
        patch \
        python3-dev \
        python3-pip \
        python3-setuptools \
        python3-wheel \
        swig \
        zlib1g-dev && \
  pip3 install --no-cache-dir zkg && \
  cd "${SRC_BASE_DIR}" && \
    tar -xvf "zeek.tar.gz" && \
    cd "./zeek-${ZEEK_VERSION}" && \
    bash -c "for i in ${ZEEK_PATCH_DIR}/* ; do patch -p 1 -r - --no-backup-if-mismatch < \$i || true; done" && \
    ./configure --prefix="${ZEEK_DIR}" --generator=Ninja && \
    cd build && \
    ninja && \
    ninja install && \
    bash -c "file ${ZEEK_DIR}/{lib,bin}/* ${ZEEK_DIR}/lib/zeek/plugins/packages/*/lib/* ${ZEEK_DIR}/lib/zeek/plugins/*/lib/* | grep 'ELF 64-bit' | sed 's/:.*//' | xargs -l -r strip -v --strip-unneeded" && \
    zkg autoconfig && \
    bash /usr/local/bin/zeek_install_plugins.sh && \
    bash -c "find ${ZEEK_DIR}/lib -type d -name CMakeFiles -exec rm -rf '{}' \; 2>/dev/null || true"

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

ENV ZEEK_DIR "/opt/zeek"

COPY --from=build $ZEEK_DIR $ZEEK_DIR

RUN sed -i "s/buster main/buster main contrib non-free/" /etc/apt/sources.list && \
    apt-get -q update && \
    apt-get install -q -y --no-install-recommends \
      curl \
      file \
      libkrb5-3 \
      libpcap0.8 \
      libssl1.0 \
      libzmq5 \
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
    apt-get -q -y --purge remove gcc gcc-8 cpp cpp-8 libssl-dev && \
      apt-get -q -y autoremove && \
      apt-get clean && \
      rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# add configuration and scripts
ADD shared/bin/pcap_moloch_and_zeek_processor.py /usr/local/bin/
ADD shared/bin/pcap_utils.py /usr/local/bin/
ADD zeek/supervisord.conf /etc/supervisord.conf
ADD zeek/config/*.zeek $ZEEK_DIR/share/zeek/site/

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

RUN groupadd --gid 1000 $ZEEKUSER && \
    useradd -M --uid 1000 --gid 1000 --home /nonexistant $ZEEKUSER && \
    ln -sfr /usr/local/bin/pcap_moloch_and_zeek_processor.py /usr/local/bin/pcap_zeek_processor.py

#Update Path
ENV PATH="$ZEEK_DIR/bin:${PATH}"

CMD ["/usr/bin/supervisord", "-c", "/etc/supervisord.conf", "-u", "root", "-n"]


# to be populated at build-time:
ARG BUILD_DATE
ARG MALCOLM_VERSION
ARG VCS_REVISION

LABEL org.opencontainers.image.created=$BUILD_DATE
LABEL org.opencontainers.image.version=$MALCOLM_VERSION
LABEL org.opencontainers.image.revision=$VCS_REVISION
