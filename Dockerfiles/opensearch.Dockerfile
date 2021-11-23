FROM opensearchproject/opensearch:1.1.0

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

ARG DISABLE_INSTALL_DEMO_CONFIG=true
ENV DISABLE_INSTALL_DEMO_CONFIG $DISABLE_INSTALL_DEMO_CONFIG

ARG DISABLE_SECURITY_PLUGIN=true
ENV DISABLE_SECURITY_PLUGIN $DISABLE_SECURITY_PLUGIN

ENV JAVA_HOME=/usr/share/opensearch/jdk

USER root

RUN echo -e 'cluster.name: "docker-cluster"\n\
network.host: 0.0.0.0\n\
\n\
# Malcolm handles security and authentication via reverse proxy.
# This, plus the DISABLE_SECURITY_PLUGIN environment variable
# should hopefully do the trick to disable the OpenSearch security plugin.
plugins.security.disabled: true\n\
plugins.security.ssl.transport.pemcert_filepath: /usr/share/opensearch/config/dummycerts/server.crt\n\
plugins.security.ssl.transport.pemkey_filepath: /usr/share/opensearch/config/dummycerts/server.key\n\
plugins.security.ssl.transport.pemtrustedcas_filepath: /usr/share/opensearch/config/dummycerts/ca.crt\n\
plugins.security.ssl.transport.enforce_hostname_verification: false\n\
plugins.security.ssl.http.enabled: false\n\
plugins.security.ssl.http.pemcert_filepath: /usr/share/opensearch/config/dummycerts/server.crt\n\
plugins.security.ssl.http.pemkey_filepath: /usr/share/opensearch/config/dummycerts/server.key\n\
plugins.security.ssl.http.pemtrustedcas_filepath: /usr/share/opensearch/config/dummycerts/ca.crt\n\
plugins.security.allow_unsafe_democertificates: true\n\
plugins.security.allow_default_init_securityindex: true\n\
plugins.security.authcz.admin_dn:\n\
  - CN=malcolm,OU=client,O=client,L=dummy,C=us\n\
plugins.security.audit.type: internal_opensearch\n\
plugins.security.enable_snapshot_restore_privilege: true\n\
plugins.security.check_snapshot_restore_write_privileges: true\n\
plugins.security.restapi.roles_enabled: ["all_access", "security_rest_api_access"]\n\
plugins.security.system_indices.enabled: true\n\
plugins.security.system_indices.indices: [".opendistro-alerting-config", ".opendistro-alerting-alert*", ".opendistro-anomaly-results*", ".opendistro-anomaly-detector*", ".opendistro-anomaly-checkpoints", ".opendistro-anomaly-detection-state", ".opendistro-reports-*", ".opendistro-notifications-*", ".opendistro-notebooks", ".opendistro-asynchronous-search-response*"]'\
> /usr/share/opensearch/config/opensearch.yml

# just used for initial keystore creation
ADD shared/bin/docker-uid-gid-setup.sh /usr/local/bin/
ADD shared/bin/jdk-cacerts-auto-import.sh /usr/local/bin/
ADD shared/bin/self_signed_key_gen.sh /usr/local/bin/

RUN yum install -y openssl util-linux  && \
  /usr/local/bin/self_signed_key_gen.sh /usr/share/opensearch/config/dummycerts >/dev/null 2>&1 && \
  find /usr/share/opensearch/config/dummycerts/ -type f ! \( -name server.crt -o -name server.key -o -name ca.crt \) -delete && \
  chown -R $PUSER:$PGROUP /usr/share/opensearch/config/opensearch.yml /usr/share/opensearch/config/dummycerts && \
  sed -i "s/user=1000\b/user=%(ENV_PUID)s/g" /usr/share/opensearch/plugins/opensearch-performance-analyzer/pa_config/supervisord.conf && \
  sed -i "s/user=1000\b/user=%(ENV_PUID)s/g" /usr/share/opensearch/performance-analyzer-rca/pa_config/supervisord.conf && \
  sed -i '/[^#].*OPENSEARCH_HOME\/bin\/opensearch.*/i /usr/local/bin/jdk-cacerts-auto-import.sh || true' /usr/share/opensearch/opensearch-docker-entrypoint.sh

ENTRYPOINT ["/usr/local/bin/docker-uid-gid-setup.sh"]

CMD ["/usr/share/opensearch/opensearch-docker-entrypoint.sh"]

# to be populated at build-time:
ARG BUILD_DATE
ARG MALCOLM_VERSION
ARG VCS_REVISION

LABEL org.opencontainers.image.created=$BUILD_DATE
LABEL org.opencontainers.image.version=$MALCOLM_VERSION
LABEL org.opencontainers.image.revision=$VCS_REVISION
