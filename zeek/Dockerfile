# based on https://github.com/zeek/zeek-docker/blob/master/master.Dockerfile

FROM zeek/zeek
ENV PATH /usr/local/zeek/bin:$PATH

RUN apt-get update \
    && apt-get -y install --no-install-recommends inotify-tools zstd \
    && apt-get clean

# Configure new user
RUN useradd -U -m zeek
RUN chown -R zeek:zeek /usr/local/zeek

# Setup directories for PCAP processing
WORKDIR /home/zeek
ARG ZEEK_INDIR
ARG ZEEK_OUTDIR
ARG ZEEK_LOGDIR
ENV ZEEK_INDIR=${ZEEK_INDIR}
ENV ZEEK_OUTDIR=${ZEEK_OUTDIR}
ENV ZEEK_LOGDIR=${ZEEK_LOGDIR}
RUN mkdir ${ZEEK_INDIR}
RUN mkdir ${ZEEK_OUTDIR}
RUN mkdir ${ZEEK_LOGDIR}
RUN chown zeek:zeek ${ZEEK_INDIR}
RUN chown zeek:zeek ${ZEEK_OUTDIR}
RUN chown zeek:zeek ${ZEEK_LOGDIR}
COPY run.sh .
RUN chmod +x run.sh

# Switch to non-root user
USER zeek

# Install zeek packages
RUN zkg autoconfig  --force
RUN zkg refresh
RUN zkg install --force ja3 hassh

# HTTP Expansions
# the following is a fork of corelight/log-add-http-post-bodies but allows to change the size of the body that is logged (default is 1KB)
RUN zkg install --force https://github.com/nturley3/zeek-http-post-bodies
RUN zkg install --force sethhall/zeek-log-all-http-headers

# Modbox Expansions
RUN zkg install --force icsnpp-modbus

# Add Zeek config
COPY local.zeek /tmp/local.zeek
RUN cat /tmp/local.zeek >> /usr/local/zeek/share/zeek/site/local.zeek

# Run script
CMD ./run.sh