FROM opensearchproject/opensearch:2.7.0

# Copyright (c) 2023 Battelle Energy Alliance, LLC.  All rights reserved.
LABEL maintainer="malcolm@inl.gov"
LABEL org.opencontainers.image.authors='malcolm@inl.gov'
LABEL org.opencontainers.image.url='https://github.com/idaholab/Malcolm'
LABEL org.opencontainers.image.documentation='https://github.com/idaholab/Malcolm/blob/main/README.md'
LABEL org.opencontainers.image.source='https://github.com/idaholab/Malcolm'
LABEL org.opencontainers.image.vendor='Idaho National Laboratory'
LABEL org.opencontainers.image.title='ghcr.io/idaholab/malcolm/opensearch'
LABEL org.opencontainers.image.description='Malcolm container providing OpenSearch'

ARG DEFAULT_UID=1000
ARG DEFAULT_GID=1000
ENV DEFAULT_UID $DEFAULT_UID
ENV DEFAULT_GID $DEFAULT_GID
ENV PUID $DEFAULT_UID
ENV PUSER "opensearch"
ENV PGROUP "opensearch"
ENV PUSER_PRIV_DROP true
ENV PUSER_RLIMIT_UNLOCK true

ENV TERM xterm

ENV TINI_VERSION v0.19.0

ARG OPENSEARCH_LOCAL=true
ENV OPENSEARCH_LOCAL $OPENSEARCH_LOCAL

ARG MALCOLM_API_URL="http://api:5000/mapi/event"
ENV MALCOLM_API_URL $MALCOLM_API_URL

ARG DISABLE_INSTALL_DEMO_CONFIG=true
ARG DISABLE_PERFORMANCE_ANALYZER_AGENT_CLI=true
ENV DISABLE_INSTALL_DEMO_CONFIG $DISABLE_INSTALL_DEMO_CONFIG
ENV DISABLE_PERFORMANCE_ANALYZER_AGENT_CLI $DISABLE_PERFORMANCE_ANALYZER_AGENT_CLI
ENV OPENSEARCH_JAVA_HOME=/usr/share/opensearch/jdk

USER root

ADD https://github.com/krallin/tini/releases/download/${TINI_VERSION}/tini /usr/bin/tini

# Remove the opensearch-security plugin - Malcolm manages authentication and encryption via NGINX reverse proxy
# Remove the performance-analyzer plugin - Reduce resources in docker image
RUN yum install -y openssl util-linux procps rsync && \
  yum upgrade -y && \
  /usr/share/opensearch/bin/opensearch-plugin remove opensearch-security --purge && \
  /usr/share/opensearch/bin/opensearch-plugin remove opensearch-performance-analyzer --purge && \
  echo -e 'cluster.name: "docker-cluster"\nnetwork.host: 0.0.0.0\nbootstrap.memory_lock: true\nhttp.cors.enabled: true\nhttp.cors.allow-origin: "*"\nhttp.cors.allow-methods: OPTIONS, HEAD, GET, POST, PUT, DELETE\nhttp.cors.allow-headers: "kbn-version, Origin, X-Requested-With, Content-Type, Accept, Engaged-Auth-Token Authorization"' > /usr/share/opensearch/config/opensearch.yml && \
  sed -i "s/#[[:space:]]*\([0-9]*-[0-9]*:-XX:-\(UseConcMarkSweepGC\|UseCMSInitiatingOccupancyOnly\)\)/\1/" /usr/share/opensearch/config/jvm.options && \
  sed -i "s/^[0-9][0-9]*\(-:-XX:\(+UseG1GC\|G1ReservePercent\|InitiatingHeapOccupancyPercent\)\)/$($OPENSEARCH_JAVA_HOME/bin/java -version 2>&1 | grep version | awk '{print $3}' | tr -d '\"' | cut -d. -f1)\1/" /usr/share/opensearch/config/jvm.options && \
  mkdir -p /var/local/ca-trust \
           /opt/opensearch/backup \
           /usr/share/opensearch/config/bootstrap \
           /usr/share/opensearch/config/persist && \
  chown -R $PUSER:$PGROUP /usr/share/opensearch/config/opensearch.yml \
                          /var/local/ca-trust \
                          /opt/opensearch/backup \
                          /usr/share/opensearch/config/bootstrap \
                          /usr/share/opensearch/config/persist && \
  chmod +x /usr/bin/tini && \
  sed -i '/^[[:space:]]*runOpensearch.*/i /usr/local/bin/jdk-cacerts-auto-import.sh || true' /usr/share/opensearch/opensearch-docker-entrypoint.sh && \
  sed -i '/^[[:space:]]*runOpensearch.*/i /usr/local/bin/keystore-bootstrap.sh || true' /usr/share/opensearch/opensearch-docker-entrypoint.sh

COPY --chmod=755 shared/bin/docker-uid-gid-setup.sh /usr/local/bin/
COPY --chmod=755 shared/bin/jdk-cacerts-auto-import.sh /usr/local/bin/
COPY --chmod=755 shared/bin/keystore-bootstrap.sh /usr/local/bin/
COPY --chmod=755 shared/bin/service_check_passthrough.sh /usr/local/bin/
COPY --from=ghcr.io/mmguero-dev/gostatic --chmod=755 /goStatic /usr/bin/goStatic

ENV bootstrap.memory_lock "true"
ENV cluster.routing.allocation.disk.threshold_enabled "false"
ENV cluster.routing.allocation.node_initial_primaries_recoveries 8
ENV discovery.type "single-node"
ENV indices.query.bool.max_clause_count 4096
ENV logger.level "WARN"
ENV MAX_LOCKED_MEMORY "unlimited"
ENV path.repo "/opt/opensearch/backup"

VOLUME ["/var/local/ca-trust"]

ENTRYPOINT ["/usr/bin/tini", \
            "--", \
            "/usr/local/bin/docker-uid-gid-setup.sh", \
            "/usr/local/bin/service_check_passthrough.sh", \
            "-s", "opensearch"]

CMD ["/usr/share/opensearch/opensearch-docker-entrypoint.sh"]

# to be populated at build-time:
ARG BUILD_DATE
ARG MALCOLM_VERSION
ARG VCS_REVISION

LABEL org.opencontainers.image.created=$BUILD_DATE
LABEL org.opencontainers.image.version=$MALCOLM_VERSION
LABEL org.opencontainers.image.revision=$VCS_REVISION
