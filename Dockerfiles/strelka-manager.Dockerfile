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

COPY --from=build /tmp/strelka-manager /usr/local/bin/strelka-manager

RUN apk update --no-cache; \
    apk upgrade --no-cache; \
    apk add --no-cache tini shadow bash jq psmisc rsync

RUN addgroup -g ${DEFAULT_GID} ${PGROUP} ; \
      adduser -D -H -u ${DEFAULT_UID} -h /nonexistant -s /sbin/nologin -G ${PGROUP} -g ${PUSER} ${PUSER} ; \
      addgroup ${PUSER} tty

COPY --chmod=755 \
    shared/bin/docker-uid-gid-setup.sh \
    shared/bin/service_check_passthrough.sh \
    /usr/local/bin/

ENTRYPOINT ["/sbin/tini", \
            "--", \
            "/usr/local/bin/docker-uid-gid-setup.sh", \
            "/usr/local/bin/service_check_passthrough.sh", \
            "-s", "strelka"]

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
