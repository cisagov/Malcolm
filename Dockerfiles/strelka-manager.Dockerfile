FROM ghcr.io/mmguero-dev/strelka/manager:malcolm

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.
LABEL maintainer="malcolm@inl.gov"
LABEL org.opencontainers.image.authors='malcolm@inl.gov'
LABEL org.opencontainers.image.url='https://github.com/idaholab/Malcolm'
LABEL org.opencontainers.image.documentation='https://github.com/idaholab/Malcolm/blob/main/README.md'
LABEL org.opencontainers.image.source='https://github.com/idaholab/Malcolm'
LABEL org.opencontainers.image.vendor='Idaho National Laboratory'
LABEL org.opencontainers.image.title='ghcr.io/idaholab/malcolm/strelka-manager'
LABEL org.opencontainers.image.description='Malcolm container for the Strelka manager'

ARG DEFAULT_UID=1000
ARG DEFAULT_GID=1000
ENV DEFAULT_UID $DEFAULT_UID
ENV DEFAULT_GID $DEFAULT_GID
ENV PUSER "manager"
ENV PGROUP "manager"
ENV PUSER_PRIV_DROP true
USER root

ENV TERM xterm

RUN apk update --no-cache && \
    apk upgrade --no-cache && \
    apk --no-cache add bash jq psmisc rsync shadow tini && \
    addgroup -g ${DEFAULT_GID} ${PGROUP} ; \
      adduser -D -H -u ${DEFAULT_UID} -h /nonexistant -s /sbin/nologin -G ${PGROUP} -g ${PUSER} ${PUSER} ; \
      addgroup ${PUSER} tty

COPY --from=ghcr.io/mmguero-dev/gostatic --chmod=755 /goStatic /usr/bin/goStatic
ADD --chmod=755 shared/bin/docker-uid-gid-setup.sh /usr/local/bin/
ADD --chmod=755 shared/bin/service_check_passthrough.sh /usr/local/bin/

ENTRYPOINT ["/usr/bin/tini", \
            "--", \
            "/usr/local/bin/docker-uid-gid-setup.sh", \
            "/usr/local/bin/service_check_passthrough.sh", \
            "-s", "strelka_manager"]

CMD ["strelka-manager"]

# to be populated at build-time:
ARG BUILD_DATE
ARG MALCOLM_VERSION
ARG VCS_REVISION

ENV BUILD_DATE $BUILD_DATE
ENV MALCOLM_VERSION $MALCOLM_VERSION
ENV VCS_REVISION $VCS_REVISION
ENV BUILD_DATE $BUILD_DATE
ENV MALCOLM_VERSION $MALCOLM_VERSION
ENV VCS_REVISION $VCS_REVISION

LABEL org.opencontainers.image.created=$BUILD_DATE
LABEL org.opencontainers.image.version=$MALCOLM_VERSION
LABEL org.opencontainers.image.revision=$VCS_REVISION
