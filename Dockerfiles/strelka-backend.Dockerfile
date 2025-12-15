FROM ghcr.io/idaholab/strelka/backend:malcolm

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.
LABEL maintainer="malcolm@inl.gov"
LABEL org.opencontainers.image.authors='malcolm@inl.gov'
LABEL org.opencontainers.image.url='https://github.com/idaholab/Malcolm'
LABEL org.opencontainers.image.documentation='https://github.com/idaholab/Malcolm/blob/main/README.md'
LABEL org.opencontainers.image.source='https://github.com/idaholab/Malcolm'
LABEL org.opencontainers.image.vendor='Idaho National Laboratory'
LABEL org.opencontainers.image.title='ghcr.io/idaholab/malcolm/strelka-backend'
LABEL org.opencontainers.image.description='Malcolm container for the Strelka backend'

ARG DEFAULT_UID=1001
ARG DEFAULT_GID=1001
ENV DEFAULT_UID=$DEFAULT_UID
ENV DEFAULT_GID=$DEFAULT_GID
ENV PUSER="strelka"
ENV PGROUP="strelka"
ENV PUSER_PRIV_DROP=true
# see PUSER_CHOWN at the bottom of the file (after the other environment variables it references)
USER root

ARG RULES_UPDATE_ENABLED=false
ENV RULES_UPDATE_ENABLED=$RULES_UPDATE_ENABLED

ENV DEBIAN_FRONTEND=noninteractive
ENV TERM=xterm

ENV YQ_VERSION="4.50.1"
ENV YQ_URL="https://github.com/mikefarah/yq/releases/download/v${YQ_VERSION}/yq_linux_"

ENV SUPERCRONIC_VERSION="0.2.39"
ENV SUPERCRONIC_URL="https://github.com/aptible/supercronic/releases/download/v$SUPERCRONIC_VERSION/supercronic-linux-"
ENV SUPERCRONIC_CRONTAB="/etc/crontab"

ENV YARA_RULES_SRC_DIR="/yara-rules-src"
ENV YARA_RULES_DIR="/yara-rules"
ENV YARA_COMPILED_RULES_FILE="rules.compiled"

ADD --chmod=755 strelka/*.sh /usr/local/bin/
ADD --chmod=755 strelka/backend/*.sh /usr/local/bin/

RUN export BINARCH=$(uname -m | sed 's/x86_64/amd64/' | sed 's/aarch64/arm64/') && \
    apt-get -q update && \
    apt-get -y -q --no-install-recommends upgrade && \
    apt-get -y --no-install-recommends install \
      curl \
      git \
      jq \
      procps \
      psmisc \
      rsync \
      tini && \
    usermod -a -G tty ${PUSER} && \
    curl -fsSL -o /usr/local/bin/yq "${YQ_URL}${BINARCH}" && \
      chmod 755 /usr/local/bin/yq && \
    curl -fsSL -o /usr/local/bin/supercronic "${SUPERCRONIC_URL}${BINARCH}" && \
      chmod +x /usr/local/bin/supercronic && \
    mkdir -p "${YARA_RULES_DIR}" "${YARA_RULES_SRC_DIR}" && \
    cd "${YARA_RULES_SRC_DIR}" && \
      /usr/local/bin/yara_rules_setup.sh -u && \
      rm -rf "${YARA_RULES_SRC_DIR}"/* && \
      find "${YARA_RULES_DIR}" -type l \( ! -exec test -r "{}" \; \) -delete && \
    chown -R ${PUSER}:${PGROUP} "${YARA_RULES_DIR}" "${YARA_RULES_SRC_DIR}" && \
      find "${YARA_RULES_DIR}" "${YARA_RULES_SRC_DIR}" -type d -exec chmod 750 "{}" \; && \
    echo "0 0 * * * /usr/local/bin/yara_rules_setup.sh -s" > ${SUPERCRONIC_CRONTAB} && \
    apt-get -y -q --allow-downgrades --allow-remove-essential --allow-change-held-packages autoremove && \
      apt-get clean && \
      rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

COPY --from=ghcr.io/mmguero-dev/gostatic --chmod=755 /goStatic /usr/bin/goStatic
ADD --chmod=644 strelka/backend/supervisord.conf /etc/supervisord.conf
ADD --chmod=755 shared/bin/docker-uid-gid-setup.sh /usr/local/bin/
ADD --chmod=755 shared/bin/service_check_passthrough.sh /usr/local/bin/
ADD --chmod=755 container-health-scripts/strelka-backend.sh /usr/local/bin/container_health.sh

# This is to handle an issue when running with rootless podman and
#   "userns_mode: keep-id". It seems that anything defined as a VOLUME
#   in the Dockerfile is getting set with an ownership of 999:999.
#   This is to override that, although I'm not yet sure if there are
#   other implications. See containers/podman#23347.
ENV PUSER_CHOWN="$YARA_RULES_DIR;$YARA_RULES_SRC_DIR"

# see PUSER_CHOWN comment above
VOLUME ["$YARA_RULES_DIR"]
VOLUME ["$YARA_RULES_SRC_DIR"]

ENTRYPOINT ["/usr/bin/tini", \
            "--", \
            "/usr/local/bin/docker-uid-gid-setup.sh", \
            "/usr/local/bin/service_check_passthrough.sh", \
            "-s", "strelka_backend", \
            "/usr/local/bin/docker-entrypoint.sh" ]

CMD ["/usr/bin/supervisord", "-c", "/etc/supervisord.conf", "-n"]

# to be populated at build-time:
ARG BUILD_DATE=ARG MALCOLM_VERSION=ARG VCS_REVISION=ENV BUILD_DATE=$BUILD_DATE
ENV MALCOLM_VERSION=$MALCOLM_VERSION
ENV VCS_REVISION=$VCS_REVISION

LABEL org.opencontainers.image.created=$BUILD_DATE
LABEL org.opencontainers.image.version=$MALCOLM_VERSION
LABEL org.opencontainers.image.revision=$VCS_REVISION
