FROM opensearchproject/opensearch:3.3.2

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.
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
# This is to handle an issue when running with rootless podman and
#   "userns_mode: keep-id". It seems that anything defined as a VOLUME
#   in the Dockerfile is getting set with an ownership of 999:999.
#   This is to override that, although I'm not yet sure if there are
#   other implications. See containers/podman#23347.
ENV PUSER_CHOWN "/var/local/ca-trust"
USER root

ENV TERM xterm

ENV TINI_VERSION v0.19.0
ENV TINI_URL https://github.com/krallin/tini/releases/download/${TINI_VERSION}/tini

ENV YQ_VERSION "4.48.2"
ENV YQ_URL "https://github.com/mikefarah/yq/releases/download/v${YQ_VERSION}/yq_linux_"

ARG DISABLE_INSTALL_DEMO_CONFIG=true
ARG DISABLE_PERFORMANCE_ANALYZER_AGENT_CLI=true
ENV DISABLE_INSTALL_DEMO_CONFIG $DISABLE_INSTALL_DEMO_CONFIG
ENV DISABLE_PERFORMANCE_ANALYZER_AGENT_CLI $DISABLE_PERFORMANCE_ANALYZER_AGENT_CLI
ENV OPENSEARCH_JAVA_HOME=/usr/share/opensearch/jdk

USER root

# Remove the performance-analyzer plugin - Reduce resources in docker image
RUN export BINARCH=$(uname -m | sed 's/x86_64/amd64/' | sed 's/aarch64/arm64/') && \
  yum upgrade -y && \
    yum install -y gettext openssl util-linux procps jq rsync findutils && \
    yum remove -y vim-* && \
  curl -fsSL -o /usr/local/bin/yq "${YQ_URL}${BINARCH}" && \
      chmod 755 /usr/local/bin/yq && \
  /usr/share/opensearch/bin/opensearch-plugin remove opensearch-performance-analyzer --purge && \
  /usr/share/opensearch/bin/opensearch-plugin install --batch repository-s3 && \
  sed -i "s/#[[:space:]]*\([0-9]*-[0-9]*:-XX:-\(UseConcMarkSweepGC\|UseCMSInitiatingOccupancyOnly\)\)/\1/" /usr/share/opensearch/config/jvm.options && \
  sed -i "s/^[0-9][0-9]*\(-:-XX:\(+UseG1GC\|G1ReservePercent\|InitiatingHeapOccupancyPercent\)\)/$($OPENSEARCH_JAVA_HOME/bin/java -version 2>&1 | grep version | awk '{print $3}' | tr -d '\"' | cut -d. -f1)\1/" /usr/share/opensearch/config/jvm.options && \
  mkdir -p /var/local/ca-trust \
           /opt/opensearch/backup \
           /usr/share/opensearch/config/bootstrap \
           /usr/share/opensearch/config/certs \
           /usr/share/opensearch/config/opensearch-security \
           /usr/share/opensearch/config/persist && \
  chown -R $PUSER:$PGROUP /usr/share/opensearch/config \
                          /var/local/ca-trust \
                          /opt/opensearch/backup && \
  curl -sSLf -o /usr/bin/tini "${TINI_URL}-${BINARCH}" && \
    chmod +x /usr/bin/tini && \
  sed -i 's/^\([[:space:]]*\)echo "Disabling execution of install_demo_configuration.*/\1\/usr\/local\/bin\/setup-internal-users.sh || true/' /usr/share/opensearch/opensearch-docker-entrypoint.sh && \
  sed -i '/^[[:space:]]*runOpensearch.*/i /usr/local/bin/jdk-cacerts-auto-import.sh || true' /usr/share/opensearch/opensearch-docker-entrypoint.sh && \
  sed -i '/^[[:space:]]*runOpensearch.*/i /usr/local/bin/keystore-bootstrap.sh || true' /usr/share/opensearch/opensearch-docker-entrypoint.sh

COPY --from=ghcr.io/mmguero-dev/gostatic --chmod=755 /goStatic /usr/bin/goStatic
ADD --chmod=755 shared/bin/docker-uid-gid-setup.sh /usr/local/bin/
ADD --chmod=755 shared/bin/jdk-cacerts-auto-import.sh /usr/local/bin/
ADD --chmod=755 shared/bin/keystore-bootstrap.sh /usr/local/bin/
ADD --chmod=755 shared/bin/opensearch_status.sh /usr/local/bin/
ADD --chmod=755 shared/bin/self_signed_key_gen.sh /usr/local/bin/
ADD --chmod=755 shared/bin/service_check_passthrough.sh /usr/local/bin/
ADD --chmod=755 container-health-scripts/opensearch.sh /usr/local/bin/container_health.sh
ADD --chmod=755 opensearch-config/scripts/*.* /usr/local/bin/
ADD --chmod=644 opensearch-config/config/opensearch/*.* /usr/share/opensearch/config/
ADD --chmod=644 opensearch-config/config/opensearch-security/*.* /usr/share/opensearch/config/opensearch-security/
ADD --chmod=644 scripts/malcolm_utils.py /usr/local/bin/
ADD --chmod=644 scripts/malcolm_constants.py /usr/local/bin/

ENV bootstrap.memory_lock "true"
ENV cluster.routing.allocation.disk.threshold_enabled "false"
ENV cluster.routing.allocation.node_initial_primaries_recoveries 8
ENV discovery.type "single-node"
ENV indices.query.bool.max_clause_count 8192
ENV logger.level "WARN"
ENV MAX_LOCKED_MEMORY "unlimited"
ENV path.repo "/opt/opensearch/backup"

# see PUSER_CHOWN comment above
VOLUME ["/var/local/ca-trust", "/usr/share/opensearch/config/certs"]

ENTRYPOINT ["/usr/bin/tini", \
            "--", \
            "/usr/local/bin/docker-uid-gid-setup.sh", \
            "/usr/local/bin/service_check_passthrough.sh", \
            "-s", "opensearch"]

CMD [ "/usr/share/opensearch/opensearch-docker-entrypoint.sh" ]

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
