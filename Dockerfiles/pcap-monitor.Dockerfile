FROM debian:buster-slim

# Copyright (c) 2019 Battelle Energy Alliance, LLC.  All rights reserved.
LABEL maintainer="Seth.Grover@inl.gov"
LABEL org.opencontainers.image.authors='Seth.Grover@inl.gov'
LABEL org.opencontainers.image.url='https://github.com/idaholab/Malcolm'
LABEL org.opencontainers.image.documentation='https://github.com/idaholab/Malcolm/blob/master/README.md'
LABEL org.opencontainers.image.source='https://github.com/idaholab/Malcolm'
LABEL org.opencontainers.image.vendor='Idaho National Laboratory'
LABEL org.opencontainers.image.title='malcolmnetsec/pcap-monitor'
LABEL org.opencontainers.image.description='Malcolm container watching for captured or uploaded artifacts to be processed'


ENV DEBIAN_FRONTEND noninteractive

ARG ELASTICSEARCH_URL="http://elasticsearch:9200"
ARG MONITOR_USER=watcher
ARG PCAP_PATH=/pcap
ARG PCAP_PIPELINE_DEBUG=false
ARG PCAP_PIPELINE_DEBUG_EXTRA=false
ARG PCAP_PIPELINE_IGNORE_PREEXISTING=false
ARG ZEEK_PATH=/zeek

ENV ELASTICSEARCH_URL $ELASTICSEARCH_URL
ENV MONITOR_USER $MONITOR_USER
ENV PCAP_PATH $PCAP_PATH
ENV PCAP_PIPELINE_DEBUG $PCAP_PIPELINE_DEBUG
ENV PCAP_PIPELINE_DEBUG_EXTRA $PCAP_PIPELINE_DEBUG_EXTRA
ENV PCAP_PIPELINE_IGNORE_PREEXISTING $PCAP_PIPELINE_IGNORE_PREEXISTING
ENV ZEEK_PATH $ZEEK_PATH

RUN apt-get update && \
    apt-get install --no-install-recommends -y -q \
      file \
      inotify-tools \
      libzmq5 \
      procps \
      psmisc \
      python \
      python3-pip \
      python3-setuptools \
      python3-wheel \
      supervisor \
      vim-tiny && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* && \
    pip3 install --no-cache-dir elasticsearch elasticsearch_dsl pyzmq pyinotify python-magic && \
    mkdir -p /var/log/supervisor && \
    groupadd --gid 1000 $MONITOR_USER && \
      useradd -M --uid 1000 --gid 1000 $MONITOR_USER

ADD pcap-monitor/supervisord.conf /etc/supervisord.conf
ADD pcap-monitor/scripts/ /usr/local/bin/
ADD shared/bin/pcap_watcher.py /usr/local/bin/
ADD shared/bin/pcap_utils.py /usr/local/bin/

EXPOSE 30441

CMD ["/usr/bin/supervisord", "-c", "/etc/supervisord.conf", "-u", "root", "-n"]

# to be populated at build-time:
ARG BUILD_DATE
ARG MALCOLM_VERSION
ARG VCS_REVISION

LABEL org.opencontainers.image.created=$BUILD_DATE
LABEL org.opencontainers.image.version=$MALCOLM_VERSION
LABEL org.opencontainers.image.revision=$VCS_REVISION
