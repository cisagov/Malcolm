FROM opensearchproject/opensearch-dashboards:2.8.0

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

ENV TERM xterm

ENV TINI_VERSION v0.19.0
ENV OSD_TRANSFORM_VIS_VERSION 2.8.0

ARG OPENSEARCH_URL="http://opensearch:9200"
ARG OPENSEARCH_PRIMARY="opensearch-local"
ARG CREATE_OS_ARKIME_SESSION_INDEX="true"
ARG ARKIME_INDEX_PATTERN="arkime_sessions3-*"
ARG ARKIME_INDEX_PATTERN_ID="arkime_sessions3-*"
ARG ARKIME_INDEX_TIME_FIELD="firstPacket"
ARG NODE_OPTIONS="--max_old_space_size=4096"

ENV CREATE_OS_ARKIME_SESSION_INDEX $CREATE_OS_ARKIME_SESSION_INDEX
ENV ARKIME_INDEX_PATTERN $ARKIME_INDEX_PATTERN
ENV ARKIME_INDEX_PATTERN_ID $ARKIME_INDEX_PATTERN_ID
ENV ARKIME_INDEX_TIME_FIELD $ARKIME_INDEX_TIME_FIELD
ENV OPENSEARCH_DEFAULT_DASHBOARD $OPENSEARCH_DEFAULT_DASHBOARD
ENV PATH="/data:${PATH}"
ENV OPENSEARCH_URL $OPENSEARCH_URL
ENV OPENSEARCH_PRIMARY $OPENSEARCH_PRIMARY
ENV NODE_OPTIONS $NODE_OPTIONS

USER root

ADD https://github.com/krallin/tini/releases/download/${TINI_VERSION}/tini /usr/bin/tini
ADD https://github.com/lguillaud/osd_transform_vis/releases/download/$OSD_TRANSFORM_VIS_VERSION/transformVis-$OSD_TRANSFORM_VIS_VERSION.zip /tmp/transformVis.zip

RUN yum upgrade -y && \
    yum install -y curl psmisc util-linux openssl rsync python3 zip unzip && \
    yum remove -y vim-* && \
    usermod -a -G tty ${PUSER} && \
    # Malcolm manages authentication and encryption via NGINX reverse proxy
    /usr/share/opensearch-dashboards/bin/opensearch-dashboards-plugin remove securityDashboards --allow-root && \
    cd /tmp && \
        # unzip transformVis.zip opensearch-dashboards/transformVis/opensearch_dashboards.json opensearch-dashboards/transformVis/package.json && \
        # sed -i "s/2\.9\.0/2\.9\.0/g" opensearch-dashboards/transformVis/opensearch_dashboards.json && \
        # sed -i "s/2\.9\.0/2\.9\.0/g" opensearch-dashboards/transformVis/package.json && \
        # zip transformVis.zip opensearch-dashboards/transformVis/opensearch_dashboards.json opensearch-dashboards/transformVis/package.json && \
        cd /usr/share/opensearch-dashboards/plugins && \
        /usr/share/opensearch-dashboards/bin/opensearch-dashboards-plugin install file:///tmp/transformVis.zip --allow-root && \
        rm -rf /tmp/transformVis /tmp/opensearch-dashboards && \
    chown --silent -R ${PUSER}:${PGROUP} /usr/share/opensearch-dashboards && \
    chmod +x /usr/bin/tini && \
    yum clean all && \
    rm -rf /var/cache/yum

COPY --chmod=755 shared/bin/docker-uid-gid-setup.sh /usr/local/bin/
COPY --chmod=755 shared/bin/service_check_passthrough.sh /usr/local/bin/
COPY --from=ghcr.io/mmguero-dev/gostatic --chmod=755 /goStatic /usr/bin/goStatic
COPY --chmod=755 dashboards/scripts/docker_entrypoint.sh /usr/local/bin/
ADD dashboards/opensearch_dashboards.yml /usr/share/opensearch-dashboards/config/opensearch_dashboards.orig.yml
ADD dashboards/scripts/docker_entrypoint.sh /usr/local/bin/
ADD scripts/malcolm_utils.py /usr/local/bin/

# Yeah, I know about https://opensearch.org/docs/latest/dashboards/branding ... but I can't figure out a way
# to specify the entries in the opensearch_dashboards.yml such that they are valid BOTH from the
# internal opensearch code validating them AND the web browser retrieving them. So we're going scorched earth instead.
ADD docs/images/logo/malcolm_logo.svg /usr/share/opensearch-dashboards/src/core/server/core_app/assets/default_branding/opensearch_logo.svg
ADD docs/images/logo/malcolm_logo.svg /usr/share/opensearch-dashboards/src/core/server/core_app/assets/default_branding/opensearch_logo_dark_mode.svg
ADD docs/images/logo/malcolm_logo.svg /usr/share/opensearch-dashboards/src/core/server/core_app/assets/default_branding/opensearch_logo_default_mode.svg
ADD docs/images/icon/malcolm_mark_dashboards.svg /usr/share/opensearch-dashboards/src/core/server/core_app/assets/default_branding/opensearch_mark_dark_mode.svg
ADD docs/images/icon/malcolm_mark_dashboards.svg /usr/share/opensearch-dashboards/src/core/server/core_app/assets/default_branding/opensearch_mark_default_mode.svg
ADD docs/images/favicon/favicon.ico /usr/share/opensearch-dashboards/src/core/server/core_app/assets/favicons/favicon.ico
ADD docs/images/favicon/favicon16.png /usr/share/opensearch-dashboards/src/core/server/core_app/assets/favicons/favicon-16x16.png
ADD docs/images/favicon/favicon32.png /usr/share/opensearch-dashboards/src/core/server/core_app/assets/favicons/favicon-32x32.png
ADD docs/images/favicon/apple-touch-icon-precomposed.png /usr/share/opensearch-dashboards/src/core/server/core_app/assets/favicons/apple-touch-icon.png


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

LABEL org.opencontainers.image.created=$BUILD_DATE
LABEL org.opencontainers.image.version=$MALCOLM_VERSION
LABEL org.opencontainers.image.revision=$VCS_REVISION
