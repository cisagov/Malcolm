FROM ubuntu:22.04
ARG DEBIAN_FRONTEND=noninteractive

ENV TINI_VERSION v0.19.0
ADD https://github.com/krallin/tini/releases/download/${TINI_VERSION}/tini-static /tini
RUN chmod a+rx /tini

RUN apt-get -q update && \
    apt-get install -q -y --no-install-recommends \
    ca-certificates \
    clamav \
    clamav-daemon \
    clamav-freshclam && \
    apt-get clean -qq && \
    rm -rf /var/lib/apt/lists/* && \
    update-rc.d clamav-daemon remove && \
    update-rc.d clamav-freshclam remove

COPY ./strelka/build/other/clamav/freshclam.conf \
     ./strelka/build/other/clamav/freshclam-clamd.conf \
     ./strelka/build/other/clamav/clamd.conf \
     /etc/clamav/
COPY ./strelka/build/other/clamav/clamd-entrypoint.sh /clamd-entrypoint.sh
RUN chmod a+rx /clamd-entrypoint.sh

ENTRYPOINT ["/tini", "--"]
CMD ["/clamd-entrypoint.sh"]

