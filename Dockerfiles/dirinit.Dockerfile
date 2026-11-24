FROM alpine:3.24

# Copyright (c) 2026 Battelle Energy Alliance, LLC.  All rights reserved.
LABEL maintainer="malcolm@inl.gov"
LABEL org.opencontainers.image.authors='malcolm@inl.gov'
LABEL org.opencontainers.image.url='https://github.com/idaholab/Malcolm'
LABEL org.opencontainers.image.documentation='https://github.com/idaholab/Malcolm/blob/main/README.md'
LABEL org.opencontainers.image.source='https://github.com/idaholab/Malcolm'
LABEL org.opencontainers.image.vendor='Idaho National Laboratory'
LABEL org.opencontainers.image.title='ghcr.io/idaholab/malcolm/dirinit'
LABEL org.opencontainers.image.description='Sidecar container that ensures the creation of some volume subdirectories and does nothing else'

ARG DEFAULT_UID=1000
ARG DEFAULT_GID=1000
ENV DEFAULT_UID=$DEFAULT_UID
ENV DEFAULT_GID=$DEFAULT_GID
ENV PUSER="dirinit"
ENV PGROUP="dirinit"
ENV PUSER_PRIV_DROP=true
USER root

ENV TERM=xterm

ADD --chmod=755 shared/bin/docker-uid-gid-setup.sh /usr/local/bin/

ENV JQ_VERSION="1.8.2"
ENV JQ_URL="https://github.com/jqlang/jq/releases/download/jq-${JQ_VERSION}/jq-linux-"

RUN --mount=type=bind,source=shared/bin/install-verified-binary.sh,target=/usr/local/share/install-verified-binary.sh,ro \
    --mount=type=bind,source=shared/pins/binaries.sha256,target=/usr/local/share/binaries.sha256,ro \
    apk update --no-cache && \
    apk --no-cache add bash kubectl psmisc rsync shadow tini && \
    apk --no-cache add --virtual .jq-fetch-deps curl && \
      sh /usr/local/share/install-verified-binary.sh /usr/local/bin/jq "${JQ_URL}{arch}" "jq_${JQ_VERSION}_linux_{arch}" && \
      apk del .jq-fetch-deps && \
    addgroup -g ${DEFAULT_GID} ${PGROUP} ; \
      adduser -D -H -u ${DEFAULT_UID} -h /nonexistent -s /sbin/nologin -G ${PGROUP} -g ${PUSER} ${PUSER} ; \
      addgroup ${PUSER} tty ; \
    addgroup ${PUSER} tty

WORKDIR /home/${PUSER}

ENTRYPOINT ["/sbin/tini", \
            "--", \
            "/usr/local/bin/docker-uid-gid-setup.sh", \
            "true"]

# to be populated at build-time:
ARG BUILD_DATE
ARG MALCOLM_VERSION
ARG VCS_REVISION
ENV BUILD_DATE=$BUILD_DATE
ENV MALCOLM_VERSION=$MALCOLM_VERSION
ENV VCS_REVISION=$VCS_REVISION

LABEL org.opencontainers.image.created=$BUILD_DATE
LABEL org.opencontainers.image.version=$MALCOLM_VERSION
LABEL org.opencontainers.image.revision=$VCS_REVISION
