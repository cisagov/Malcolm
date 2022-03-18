FROM opensearchproject/opensearch:1.3.0

# Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.
LABEL maintainer="malcolm@inl.gov"
LABEL org.opencontainers.image.authors='malcolm@inl.gov'
LABEL org.opencontainers.image.url='https://github.com/idaholab/Malcolm'
LABEL org.opencontainers.image.documentation='https://github.com/idaholab/Malcolm/blob/main/README.md'
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

ARG MALCOLM_API_URL="http://api:5000/event"
ENV MALCOLM_API_URL $MALCOLM_API_URL

ARG DISABLE_INSTALL_DEMO_CONFIG=true
ENV DISABLE_INSTALL_DEMO_CONFIG $DISABLE_INSTALL_DEMO_CONFIG
ENV JAVA_HOME=/usr/share/opensearch/jdk

USER root

# Remove the opensearch-security plugin - Malcolm manages authentication and encryption via NGINX reverse proxy
# Remove the performance-analyzer plugin - Reduce resources in docker image
# override_main_response_version - https://opensearch.org/docs/latest/clients/agents-and-ingestion-tools/index/#compatibility-matrices
RUN yum install -y openssl util-linux procps && \
  yum upgrade -y && \
  /usr/share/opensearch/bin/opensearch-plugin remove opensearch-security --purge && \
  /usr/share/opensearch/bin/opensearch-plugin remove opensearch-performance-analyzer --purge && \
  echo -e 'cluster.name: "docker-cluster"\nnetwork.host: 0.0.0.0\ncompatibility.override_main_response_version: true\nbootstrap.memory_lock: true' > /usr/share/opensearch/config/opensearch.yml && \
  chown -R $PUSER:$PGROUP /usr/share/opensearch/config/opensearch.yml && \
  sed -i "s/^\([[:space:]]*\)\(performance-analyzer-agent-cli\)/\1# \2/" /usr/share/opensearch/opensearch-docker-entrypoint.sh && \
  sed -i '/[^#].*OPENSEARCH_HOME\/bin\/opensearch.*/i /usr/local/bin/jdk-cacerts-auto-import.sh || true' /usr/share/opensearch/opensearch-docker-entrypoint.sh


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
