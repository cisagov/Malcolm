FROM opensearchproject/opensearch-dashboards:3.3.0

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
ENV DEFAULT_UID $DEFAULT_UID
ENV DEFAULT_GID $DEFAULT_GID
ENV PUSER "opensearch-dashboards"
ENV PGROUP "opensearch-dashboards"
ENV PUSER_PRIV_DROP true
USER root

ENV TERM xterm

ENV TINI_VERSION v0.19.0
ENV TINI_URL https://github.com/krallin/tini/releases/download/${TINI_VERSION}/tini

ENV OSD_TRANSFORM_VIS_VERSION 3.3.0

ARG NODE_OPTIONS="--max_old_space_size=4096"
ENV NODE_OPTIONS $NODE_OPTIONS

ENV PATH="/data:${PATH}"

USER root

ADD https://github.com/lguillaud/osd_transform_vis/releases/download/$OSD_TRANSFORM_VIS_VERSION/transformVis-$OSD_TRANSFORM_VIS_VERSION.zip /tmp/transformVis.zip

RUN export BINARCH=$(uname -m | sed 's/x86_64/amd64/' | sed 's/aarch64/arm64/') && \
    yum upgrade -y && \
    yum install -y curl-minimal psmisc findutils util-linux jq openssl rsync procps-ng python3 zip unzip && \
    yum remove -y vim-* && \
    usermod -a -G tty ${PUSER} && \
    cd /tmp && \
        # unzip transformVis.zip opensearch-dashboards/transformVis/opensearch_dashboards.json opensearch-dashboards/transformVis/package.json && \
        # sed -i "s/3\.0\.0/3\.3\.0/g" opensearch-dashboards/transformVis/opensearch_dashboards.json && \
        # sed -i "s/3\.0\.0/3\.3\.0/g" opensearch-dashboards/transformVis/package.json && \
        # zip transformVis.zip opensearch-dashboards/transformVis/opensearch_dashboards.json opensearch-dashboards/transformVis/package.json && \
        cd /usr/share/opensearch-dashboards/plugins && \
        /usr/share/opensearch-dashboards/bin/opensearch-dashboards-plugin install file:///tmp/transformVis.zip --allow-root && \
        rm -rf /tmp/transformVis /tmp/opensearch-dashboards && \
    chown --silent -R ${PUSER}:${PGROUP} /usr/share/opensearch-dashboards && \
    curl -sSLf -o /usr/bin/tini "${TINI_URL}-${BINARCH}" && \
      chmod +x /usr/bin/tini && \
    yum clean all && \
    rm -rf /var/cache/yum

COPY --from=ghcr.io/mmguero-dev/gostatic --chmod=755 /goStatic /usr/bin/goStatic
ADD --chmod=755 shared/bin/docker-uid-gid-setup.sh /usr/local/bin/
ADD --chmod=755 shared/bin/service_check_passthrough.sh /usr/local/bin/
ADD --chmod=755 container-health-scripts/dashboards.sh /usr/local/bin/container_health.sh
ADD --chmod=755 dashboards/scripts/docker_entrypoint.sh /usr/local/bin/
ADD --chmod=644 dashboards/opensearch_dashboards.yml /usr/share/opensearch-dashboards/config/opensearch_dashboards.orig.yml
ADD --chmod=755 dashboards/scripts/docker_entrypoint.sh /usr/local/bin/
ADD --chmod=644 scripts/malcolm_utils.py /usr/local/bin/
ADD --chmod=644 scripts/malcolm_constants.py /usr/local/bin/

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
ENV BUILD_DATE $BUILD_DATE
ENV MALCOLM_VERSION $MALCOLM_VERSION
ENV VCS_REVISION $VCS_REVISION

LABEL org.opencontainers.image.created=$BUILD_DATE
LABEL org.opencontainers.image.version=$MALCOLM_VERSION
LABEL org.opencontainers.image.revision=$VCS_REVISION
