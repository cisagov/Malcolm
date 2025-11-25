FROM ghcr.io/mmguero-dev/strelka/backend:malcolm

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
ENV DEFAULT_UID $DEFAULT_UID
ENV DEFAULT_GID $DEFAULT_GID
ENV PUSER "strelka"
ENV PGROUP "strelka"
ENV PUSER_PRIV_DROP true
USER root

ENV DEBIAN_FRONTEND noninteractive
ENV TERM xterm

ENV YQ_VERSION "4.49.2"
ENV YQ_URL "https://github.com/mikefarah/yq/releases/download/v${YQ_VERSION}/yq_linux_"

RUN apt-get -q update && \
    apt-get -y -q --no-install-recommends upgrade && \
    apt-get -y --no-install-recommends install \
      curl \
      jq \
      procps \
      psmisc \
      rsync \
      tini && \
    usermod -a -G tty ${PUSER} && \
    curl -fsSL -o /usr/local/bin/yq "${YQ_URL}$(uname -m | sed 's/x86_64/amd64/' | sed 's/aarch64/arm64/')" && \
      chmod 755 /usr/local/bin/yq && \
    apt-get -y -q --allow-downgrades --allow-remove-essential --allow-change-held-packages autoremove && \
      apt-get clean && \
      rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

COPY --from=ghcr.io/mmguero-dev/gostatic --chmod=755 /goStatic /usr/bin/goStatic
ADD --chmod=755 strelka/*.sh /usr/local/bin/
ADD --chmod=755 shared/bin/docker-uid-gid-setup.sh /usr/local/bin/
ADD --chmod=755 shared/bin/service_check_passthrough.sh /usr/local/bin/

ENTRYPOINT ["/usr/bin/tini", \
            "--", \
            "/usr/local/bin/docker-uid-gid-setup.sh", \
            "/usr/local/bin/service_check_passthrough.sh", \
            "-s", "strelka_backend", \
            "/usr/local/bin/strelka-expand-redis-config.sh" ]

CMD ["/home/strelka/.pyenv/bin/pyenv", "exec", "strelka-backend"]

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
