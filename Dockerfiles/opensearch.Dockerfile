FROM opensearchproject/opensearch:1.0.1

# Copyright (c) 2021 Battelle Energy Alliance, LLC.  All rights reserved.
LABEL maintainer="malcolm@inl.gov"
LABEL org.opencontainers.image.authors='malcolm@inl.gov'
LABEL org.opencontainers.image.url='https://github.com/idaholab/Malcolm'
LABEL org.opencontainers.image.documentation='https://github.com/idaholab/Malcolm/blob/master/README.md'
LABEL org.opencontainers.image.source='https://github.com/idaholab/Malcolm'
LABEL org.opencontainers.image.vendor='Idaho National Laboratory'
LABEL org.opencontainers.image.title='malcolmnetsec/opensearch'
LABEL org.opencontainers.image.description='Malcolm container providing OpenSearch'

ARG DEFAULT_UID=1000
ARG DEFAULT_GID=1000
ENV DEFAULT_UID $DEFAULT_UID
ENV DEFAULT_GID $DEFAULT_GID
ENV PUID $DEFAULT_UID
ENV PUSER "opensearch"
ENV PGROUP "opensearch"
ENV PUSER_PRIV_DROP true

ENV TERM xterm

ARG GITHUB_OAUTH_TOKEN=""
ARG DISABLE_INSTALL_DEMO_CONFIG=true
ENV DISABLE_INSTALL_DEMO_CONFIG $DISABLE_INSTALL_DEMO_CONFIG
ENV JAVA_HOME=/usr/share/opensearch/jdk

USER root

# Malcolm manages authentication and encryption via NGINX reverse proxy
RUN yum install -y openssl util-linux  && \
  /usr/share/opensearch/bin/opensearch-plugin remove opensearch-security && \
  echo -e 'cluster.name: "docker-cluster"\nnetwork.host: 0.0.0.0' > /usr/share/opensearch/config/opensearch.yml && \
  chown -R $PUSER:$PGROUP /usr/share/opensearch/config/opensearch.yml && \
  sed -i "s/user=1000\b/user=%(ENV_PUID)s/g" /usr/share/opensearch/plugins/opensearch-performance-analyzer/pa_config/supervisord.conf && \
  sed -i "s/user=1000\b/user=%(ENV_PUID)s/g" /usr/share/opensearch/performance-analyzer-rca/pa_config/supervisord.conf && \
  sed -i '/[^#].*\$OPENSEARCH_HOME\/bin\/opensearch.*/i /usr/local/bin/jdk-cacerts-auto-import.sh || true' /usr/share/opensearch/opensearch-docker-entrypoint.sh


# just used for initial keystore creation
ADD shared/bin/docker-uid-gid-setup.sh /usr/local/bin/
ADD shared/bin/jdk-cacerts-auto-import.sh /usr/local/bin/

ENTRYPOINT ["/usr/local/bin/docker-uid-gid-setup.sh"]

CMD ["/usr/share/opensearch/opensearch-docker-entrypoint.sh"]

# to be populated at build-time:
ARG BUILD_DATE
ARG MALCOLM_VERSION
ARG VCS_REVISION

LABEL org.opencontainers.image.created=$BUILD_DATE
LABEL org.opencontainers.image.version=$MALCOLM_VERSION
LABEL org.opencontainers.image.revision=$VCS_REVISION
