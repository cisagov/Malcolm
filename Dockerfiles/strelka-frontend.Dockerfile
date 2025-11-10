# Strelka Frontend
# The frontend for a cluster in which clients can connect directly via Envoy.
# For more information, please see: https://target.github.io/strelka/#/?id=strelka-frontend
FROM golang:1.21.5-alpine AS build
LABEL maintainer="Target Brands, Inc. TTS-CFC-OpenSource@target.com"

RUN apk add openssl-dev bash build-base pkgconfig librdkafka librdkafka-dev

# Pull dependencies
WORKDIR /go/src/github.com/target/strelka/src/go/
COPY strelka/go.* /go/src/github.com/target/strelka/
RUN go mod download

# Copy source files and set the working directory
COPY strelka/src/go /go/src/github.com/target/strelka/src/go
RUN CGO_ENABLED=1 go build -tags musl -o /tmp/strelka-frontend cmd/strelka-frontend/main.go

# Initialize runtime container
FROM alpine:3.22

LABEL maintainer="malcolm@inl.gov"
# LABEL maintainer="Target Brands, Inc. TTS-CFC-OpenSource@target.com"
LABEL org.opencontainers.image.authors='malcolm@inl.gov'
LABEL org.opencontainers.image.url='https://github.com/idaholab/Malcolm'
LABEL org.opencontainers.image.documentation='https://github.com/idaholab/Malcolm/blob/master/README.md'
LABEL org.opencontainers.image.source='https://github.com/idaholab/Malcolm'
LABEL org.opencontainers.image.vendor='Idaho National Laboratory'
LABEL org.opencontainers.image.title='ghcr.io/idaholab/malcolm/strelka-frontend'
LABEL org.opencontainers.image.description='Malcolm container providing Strelka frontend'

ARG DEFAULT_UID=1000
ARG DEFAULT_GID=1000
ENV DEFAULT_UID $DEFAULT_UID
ENV DEFAULT_GID $DEFAULT_GID
ENV PUSER "strelka"
ENV PGROUP "strelka"
ENV PUSER_PRIV_DROP true
USER root

# Copy binary
COPY --from=build /tmp/strelka-frontend /usr/local/bin/strelka-frontend
COPY --from=build  /usr/local/lib/ /usr/local/lib/

RUN apk update --no-cache; \
    apk upgrade --no-cache; \
    apk add --no-cache librdkafka tini shadow bash jq psmisc rsync

RUN addgroup -g ${DEFAULT_GID} ${PGROUP} ; \
      adduser -D -H -u ${DEFAULT_UID} -h /nonexistant -s /sbin/nologin -G ${PGROUP} -g ${PUSER} ${PUSER} ; \
      addgroup ${PUSER} tty

COPY --chmod=755 \
    shared/bin/docker-uid-gid-setup.sh \
    shared/bin/service_check_passthrough.sh \
    /usr/local/bin/

# Create logging directory
RUN mkdir /var/log/strelka/ && \
    chgrp -R 0 /var/log/strelka/ && \
    chmod -R g=u /var/log/strelka/

#Create blank strelka.log file to make sure watcher has something to start with
RUN touch /var/log/strelka/strelka.log
RUN chmod -R 777 /var/log/strelka/strelka.log

ENTRYPOINT ["/sbin/tini", \
            "--", \
            "/usr/local/bin/docker-uid-gid-setup.sh", \
            "/usr/local/bin/service_check_passthrough.sh", \
            "-s", "strelka"]

CMD ["strelka-frontend", "-locallog=true", "-kafkalog=false"]

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
