FROM bitsensor/elastalert:2.0.0

# Copyright (c) 2019 Battelle Energy Alliance, LLC.  All rights reserved.
LABEL maintainer="malcolm.netsec@gmail.com"
LABEL org.opencontainers.image.authors='malcolm.netsec@gmail.com'
LABEL org.opencontainers.image.url='https://github.com/idaholab/Malcolm'
LABEL org.opencontainers.image.documentation='https://github.com/idaholab/Malcolm/blob/master/README.md'
LABEL org.opencontainers.image.source='https://github.com/idaholab/Malcolm'
LABEL org.opencontainers.image.vendor='Idaho National Laboratory'
LABEL org.opencontainers.image.title='malcolmnetsec/elastalert'
LABEL org.opencontainers.image.description='Malcolm container providing an alerting framework for Elasticsearch'


USER root

RUN apk update && \
    apk add bash curl && \
    rm -rf /var/cache/apk/*

ADD elastalert/elastalert-start.sh /usr/local/bin/
ADD shared/bin/elastic_search_status.sh /usr/local/bin/

RUN chmod +x /usr/local/bin/elastalert-start.sh && \
    mkdir -p /opt/elastalert/server_data/tests && \
    chown -R node:node /opt

VOLUME ["/opt/elastalert/server_data"]

USER node

ENTRYPOINT ["/usr/local/bin/elastalert-start.sh"]


# to be populated at build-time:
ARG BUILD_DATE
ARG MALCOLM_VERSION
ARG VCS_REVISION

LABEL org.opencontainers.image.created=$BUILD_DATE
LABEL org.opencontainers.image.version=$MALCOLM_VERSION
LABEL org.opencontainers.image.revision=$VCS_REVISION
