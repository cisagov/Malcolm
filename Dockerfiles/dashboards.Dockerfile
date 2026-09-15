FROM opensearchproject/opensearch-dashboards:3.8.0 AS permissions

ENV PUSER="opensearch-dashboards"
ENV PGROUP="opensearch-dashboards"
ENV OPENSEARCH_DASHBOARDS_HOME=/usr/share/opensearch-dashboards

USER root
RUN yum install -y findutils && \
    rm -rf $OPENSEARCH_DASHBOARDS_HOME/config/opensearch.example.org.key \
           $OPENSEARCH_DASHBOARDS_HOME/config/opensearch.example.org.cert \
           $OPENSEARCH_DASHBOARDS_HOME/node/fallback && \
    mkdir -p $OPENSEARCH_DASHBOARDS_HOME/config $OPENSEARCH_DASHBOARDS_HOME/data && \
    chown -R root:root $OPENSEARCH_DASHBOARDS_HOME && \
    find $OPENSEARCH_DASHBOARDS_HOME -type d -exec chmod a+rx,go-w {} + && \
    find $OPENSEARCH_DASHBOARDS_HOME -type f -exec chmod a+r,go-w {} + && \
    mkdir -p $OPENSEARCH_DASHBOARDS_HOME/config $OPENSEARCH_DASHBOARDS_HOME/data && \
    chown --silent -R ${PUSER}:${PGROUP} \
      $OPENSEARCH_DASHBOARDS_HOME/config \
      $OPENSEARCH_DASHBOARDS_HOME/data && \
    chmod -R u+rwX,go-rwx \
      $OPENSEARCH_DASHBOARDS_HOME/config \
      $OPENSEARCH_DASHBOARDS_HOME/data

FROM redhat/ubi9-minimal:latest AS ubi-micro-build

LABEL maintainer="malcolm@inl.gov"
LABEL org.opencontainers.image.authors='malcolm@inl.gov'
LABEL org.opencontainers.image.url='https://github.com/idaholab/Malcolm'
LABEL org.opencontainers.image.documentation='https://github.com/idaholab/Malcolm/blob/master/README.md'
LABEL org.opencontainers.image.source='https://github.com/idaholab/Malcolm'
LABEL org.opencontainers.image.vendor='Idaho National Laboratory'
LABEL org.opencontainers.image.title='ghcr.io/idaholab/malcolm/opensearch-dashboards'
LABEL org.opencontainers.image.description='Malcolm container providing OpenSearch Dashboards'

ARG DEFAULT_UID=1000
ARG DEFAULT_GID=1000
ENV DEFAULT_UID=$DEFAULT_UID
ENV DEFAULT_GID=$DEFAULT_GID
ENV PUSER="opensearch-dashboards"
ENV PGROUP="opensearch-dashboards"
ENV PUSER_PRIV_DROP=true
USER root

ENV TERM=xterm

ENV TINI_VERSION=v0.19.0
ENV TINI_URL=https://github.com/krallin/tini/releases/download/${TINI_VERSION}/tini

ARG NODE_OPTIONS="--max_old_space_size=4096"
ENV NODE_OPTIONS=$NODE_OPTIONS
ENV OPENSEARCH_DASHBOARDS_HOME=/usr/share/opensearch-dashboards
ENV PATH="$PATH:$OPENSEARCH_DASHBOARDS_HOME/bin"

USER root

RUN export BINARCH=$(uname -m | sed 's/x86_64/amd64/' | sed 's/aarch64/arm64/') && \
    microdnf install -y \
        bash \
        curl-minimal \
        findutils \
        gzip \
        jq \
        nss \
        openssl \
        procps-ng \
        psmisc \
        python3 \
        rsync \
        shadow-utils \
        tar \
        unzip \
        util-linux \
        which \
        xorg-x11-fonts-Type1 \
        zip && \
    groupadd -g $DEFAULT_GID $PGROUP && \
        adduser -u $DEFAULT_UID -g $DEFAULT_GID -d $OPENSEARCH_DASHBOARDS_HOME $PUSER && \
    usermod -a -G tty ${PUSER} && \
    curl -sSLf -o /usr/bin/tini "${TINI_URL}-${BINARCH}" && \
      chmod +x /usr/bin/tini && \
    microdnf clean all && \
    rm -rf /var/cache/dnf /var/cache/yum

COPY --from=ghcr.io/mmguero-dev/gostatic --chmod=755 /goStatic /usr/bin/goStatic
ADD --chmod=755 shared/bin/docker-uid-gid-setup.sh /usr/local/bin/
ADD --chmod=755 shared/bin/service_check_passthrough.sh /usr/local/bin/
ADD --chmod=755 container-health-scripts/dashboards.sh /usr/local/bin/container_health.sh
ADD --chmod=755 dashboards/scripts/docker_entrypoint.sh /usr/local/bin/
COPY --from=permissions $OPENSEARCH_DASHBOARDS_HOME $OPENSEARCH_DASHBOARDS_HOME
ADD --chmod=644 dashboards/opensearch_dashboards.yml $OPENSEARCH_DASHBOARDS_HOME/config/opensearch_dashboards.orig.yml
ADD --chmod=755 dashboards/scripts/docker_entrypoint.sh /usr/local/bin/
ADD --chmod=644 scripts/malcolm_utils.py /usr/local/bin/
ADD --chmod=644 scripts/malcolm_constants.py /usr/local/bin/

# This is in part to handle an issue when running with rootless podman and
#   "userns_mode: keep-id". It seems that anything defined as a VOLUME
#   in the Dockerfile is getting set with an ownership of 999:999.
#   This is to override that, although I'm not yet sure if there are
#   other implications. See containers/podman#23347.
ENV PUSER_CHOWN="$OPENSEARCH_DASHBOARDS_HOME/config;$OPENSEARCH_DASHBOARDS_HOME/data"

# see PUSER_CHOWN comment above
VOLUME ["/usr/share/opensearch-dashboards/config"]
VOLUME ["/usr/share/opensearch-dashboards/data"]

ENTRYPOINT ["/usr/bin/tini", \
            "--", \
            "/usr/local/bin/docker-uid-gid-setup.sh", \
            "/usr/local/bin/service_check_passthrough.sh", \
            "-s", "dashboards", \
            "/usr/local/bin/docker_entrypoint.sh"]

CMD ["/usr/share/opensearch-dashboards/opensearch-dashboards-docker-entrypoint.sh"]

EXPOSE 5601

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