FROM python:3.13.5-bookworm

# TODO:
# - extracted files server
# - size-based file pruning
# - filescan logs going where other logs go (other drives, etc.)
# - preservation policy

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.
LABEL maintainer="malcolm@inl.gov"
LABEL org.opencontainers.image.authors='malcolm@inl.gov'
LABEL org.opencontainers.image.url='https://github.com/idaholab/Malcolm'
LABEL org.opencontainers.image.documentation='https://github.com/idaholab/Malcolm/blob/main/README.md'
LABEL org.opencontainers.image.source='https://github.com/idaholab/Malcolm'
LABEL org.opencontainers.image.vendor='Idaho National Laboratory'
LABEL org.opencontainers.image.title='ghcr.io/idaholab/malcolm/filescan'
LABEL org.opencontainers.image.description='Malcolm container for scanning files extracted by Zeek'

################################################################################

ARG DEFAULT_UID=1000
ARG DEFAULT_GID=1000
ENV DEFAULT_UID $DEFAULT_UID
ENV DEFAULT_GID $DEFAULT_GID
ENV PUSER "scan"
ENV PGROUP "scan"
ENV PUSER_PRIV_DROP true
USER root

################################################################################

ENV DEBIAN_FRONTEND noninteractive
ENV TERM xterm
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

################################################################################

ARG STRELKA_HOST=strelka-frontend
ARG STRELKA_PORT=57314
ARG FILESCAN_HEALTH_PORT=8001

ARG ZEEK_EXTRACTOR_PATH=/zeek/extract_files

################################################################################

ENV SUPERCRONIC_VERSION "0.2.39"
ENV SUPERCRONIC_URL "https://github.com/aptible/supercronic/releases/download/v$SUPERCRONIC_VERSION/supercronic-linux-"
ENV SUPERCRONIC_CRONTAB "/etc/crontab"

ENV YQ_VERSION "4.49.2"
ENV YQ_URL "https://github.com/mikefarah/yq/releases/download/v${YQ_VERSION}/yq_linux_"

ENV STRELKA_HOST $STRELKA_HOST
ENV STRELKA_PORT $STRELKA_PORT
ENV FILESCAN_HEALTH_PORT $FILESCAN_HEALTH_PORT

ENV ZEEK_EXTRACTOR_PATH $ZEEK_EXTRACTOR_PATH

################################################################################

# add our user/group very first, since it isn't likely to change (and if it
# does, we ought to redo a lot of steps)
RUN set -e ; \
    groupadd --gid ${DEFAULT_GID} ${PGROUP} ; \
    useradd -M --uid ${DEFAULT_UID} --gid ${DEFAULT_GID} --home /nonexistant ${PUSER} ; \
    usermod -a -G tty ${PUSER}

################################################################################

# fix our package lists, upgrade, and install a few minimal dependencies
RUN set -e ; \
    sed -i /etc/apt/sources.list.d/debian.sources \
      -e 's/main$/main contrib non-free/' ; \
    apt-get update -q ; \
    apt-get upgrade -y -q \
      --no-install-recommends ; \
    apt-get install -y -q \
      --no-install-recommends \
      bc \
      ca-certificates \
      curl \
      rsync \
      tini \
      unzip

################################################################################

# add supercronic early on because it's also unlikely to change
RUN set -e ; \
    curl -fsSL -o /usr/local/bin/supercronic "${SUPERCRONIC_URL}$(uname -m | sed 's/x86_64/amd64/' | sed 's/aarch64/arm64/')" ; \
    chmod +x /usr/local/bin/supercronic

# Download and install YQ
RUN set -e ; \
    curl -fsSL -o /usr/local/bin/yq "${YQ_URL}$(uname -m | sed 's/x86_64/amd64/' | sed 's/aarch64/arm64/')" && \
    chmod 755 /usr/local/bin/yq

################################################################################

# install the rest of our build/run dependencies
RUN set -e ; \
    apt-get update -q ; \
    apt-get install -y -q \
      --no-install-recommends \
      automake \
      bash \
      gcc \
      git \
      inotify-tools \
      jq \
      libjansson4 \
      libjansson-dev \
      libmagic1 \
      libmagic-dev \
      libssl3 \
      libssl-dev \
      libtool \
      make \
      pkg-config \
      psmisc \
      python3 \
      python3-dev \
      python3-pip \
      python3-venv \
      rsync \
      webfs

################################################################################

COPY --from=ghcr.io/mmguero-dev/gostatic --chmod=755 /goStatic /usr/bin/goStatic
ADD --chmod=755 filescan/docker-entrypoint.sh /docker-entrypoint.sh
ADD --chmod=755 shared/bin/docker-uid-gid-setup.sh /usr/local/bin/
ADD --chmod=755 shared/bin/service_check_passthrough.sh /usr/local/bin/
ADD --chmod=755 container-health-scripts/filescan.sh /usr/local/bin/container_health.sh
# originally also copied: shared/bin/prune_files.sh

RUN mkdir -p /install-filescan
COPY --chmod=644 filescan/python-filescan /install-filescan/
RUN cd /install-filescan && \
    python3 -m pip install --break-system-packages --no-cache-dir -r requirements.txt && \
    make && \
    python3 -m pip install --break-system-packages --no-cache-dir .
RUN rm -rf /install-filescan

################################################################################

# clean up our build dependencies
RUN set -e ; \
    apt-get remove -y -q \
      --allow-downgrades \
      --allow-remove-essential \
      --allow-change-held-packages \
      --purge \
      automake \
      build-essential \
      gcc \
      gcc-12 \
      libc6-dev \
      libgcc-12-dev \
      libjansson-dev \
      libmagic-dev \
      libssl-dev \
      libtool \
      make \
      python3-dev \
      python3-venv ; \
    apt-get autoremove -y -q \
      --allow-downgrades \
      --allow-remove-essential \
      --allow-change-held-packages ; \
    apt-get clean ; \
    rm -rf /var/lib/apt/lists/* /tmp/*

################################################################################

# copy the most-likely-to-change files last
RUN mkdir -p /filescan /filescan/data/files /filescan/data/logs
COPY --chmod=644 \
    filescan/supervisord.conf /etc/supervisord.conf
COPY --chmod=644 \
    filescan/filescan-config.yml /filescan/filescan-config.yml
ADD --chmod=755 container-health-scripts/filescan.sh /usr/local/bin/container_health.sh

################################################################################

WORKDIR /filescan

ENTRYPOINT ["/usr/bin/tini", \
            "--", \
            "/usr/local/bin/docker-uid-gid-setup.sh", \
            "/usr/local/bin/service_check_passthrough.sh", \
            "-s", "filescan", \
            "/docker-entrypoint.sh"]

CMD ["/usr/local/bin/supervisord", "-c", "/etc/supervisord.conf", "-n"]

# to be populated at build-time:
ARG BUILD_DATE
ARG MALCOLM_VERSION
ARG VCS_REVISION
ENV BUILD_DATE $BUILD_DATE
ENV MALCOLM_VERSION $MALCOLM_VERSION
ENV VCS_REVISION $VCS_REVISION

LABEL org.opencontainers.image.created=$BUILD_DATE
LABEL org.opencontainers.image.version=$MALCOLM_VERSION
LABEL org.opencontainers.image.revision=$VCS_REVISION
