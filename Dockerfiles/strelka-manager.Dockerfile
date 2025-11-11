# Strelka Manager
# Manages portions of Strelka's Redis database.
# For more information, please see: https://target.github.io/strelka/#/?id=strelka-manager
FROM golang:1.21.5 AS build
LABEL maintainer="Target Brands, Inc. TTS-CFC-OpenSource@target.com"

# Copy source files and set the working directory
COPY ./strelka/src/go/ /go/src/github.com/target/strelka/src/go/
WORKDIR /go/src/github.com/target/strelka/src/go/
COPY ./strelka/go.* /go/src/github.com/target/strelka/

# Statically compile and output to /tmp
RUN go mod download && \
    CGO_ENABLED=0 go build -o /tmp/strelka-manager cmd/strelka-manager/main.go

# Initialize runtime container with non-root user
FROM alpine:3.22

LABEL maintainer="malcolm@inl.gov"
# LABEL maintainer="Target Brands, Inc. TTS-CFC-OpenSource@target.com"
LABEL org.opencontainers.image.authors='malcolm@inl.gov'
LABEL org.opencontainers.image.url='https://github.com/idaholab/Malcolm'
LABEL org.opencontainers.image.documentation='https://github.com/idaholab/Malcolm/blob/master/README.md'
LABEL org.opencontainers.image.source='https://github.com/idaholab/Malcolm'
LABEL org.opencontainers.image.vendor='Idaho National Laboratory'
LABEL org.opencontainers.image.title='ghcr.io/idaholab/malcolm/strelka-manager'
LABEL org.opencontainers.image.description='Malcolm container providing Strelka manager'

ARG DEFAULT_UID=1000
ARG DEFAULT_GID=1000
ENV DEFAULT_UID $DEFAULT_UID
ENV DEFAULT_GID $DEFAULT_GID
ENV PUSER "strelka"
ENV PGROUP "strelka"
ENV PUSER_PRIV_DROP true
USER root
# This is to handle an issue when running with rootless podman and
#   "userns_mode: keep-id". It seems that anything defined as a VOLUME
#   in the Dockerfile is getting set with an ownership of 999:999.
#   This is to override that, although I'm not yet sure if there are
#   other implications. See containers/podman#23347.
ENV PUSER_CHOWN "/etc/strelka"

ARG YQ_VERSION=4.48.1
ENV YQ_VERSION $YQ_VERSION
ENV YQ_URL "https://github.com/mikefarah/yq/releases/download/v${YQ_VERSION}/yq_linux_"

COPY --from=build /tmp/strelka-manager /usr/local/bin/strelka-manager

RUN apk update --no-cache; \
    apk upgrade --no-cache; \
    apk add --no-cache tini shadow bash curl jq psmisc rsync

# Download and install YQ
RUN curl -fsSL -o /usr/local/bin/yq "${YQ_URL}$(uname -m | sed 's/x86_64/amd64/' | sed 's/aarch64/arm64/')" && \
    chmod 755 /usr/local/bin/yq

RUN addgroup -g ${DEFAULT_GID} ${PGROUP} ; \
      adduser -D -H -u ${DEFAULT_UID} -h /nonexistant -s /sbin/nologin -G ${PGROUP} -g ${PUSER} ${PUSER} ; \
      addgroup ${PUSER} tty

COPY --chmod=755 \
    shared/bin/docker-uid-gid-setup.sh \
    shared/bin/service_check_passthrough.sh \
    shared/bin/strelka-expand-redis-config.sh \
    /usr/local/bin/

# see PUSER_CHOWN comment above
VOLUME ["/etc/strelka"]

ENTRYPOINT ["/sbin/tini", \
            "--", \
            "/usr/local/bin/docker-uid-gid-setup.sh", \
            "/usr/local/bin/service_check_passthrough.sh", \
            "-s", "strelka-manager", \
            "/usr/local/bin/strelka-expand-redis-config.sh"]

CMD ["strelka-manager"]

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
