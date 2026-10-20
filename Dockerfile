# BUILD LAYER
# Compiles mdindex and all pinned dependencies via the Makefile.
# Debian (glibc) rather than Alpine (musl), matching hashpipe: the shared
# encoding code decodes through utf8_to_utf32() and is exercised by the
# UTF-16 and NTLM type families.
#
# `make deps` clones eight dependencies at pinned commits and downloads the
# SQLite amalgamation, so this layer needs git, curl and unzip and takes
# several minutes. It is cached: only a source change re-runs the second
# stage.
FROM debian:bookworm-slim AS build
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    make \
    git \
    curl \
    unzip \
    autoconf \
    automake \
    libtool \
    perl \
    zlib1g-dev \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src/mdindex
COPY . .
RUN make deps && make && ./mdindex selftest

# RUNTIME LAYER
# Only the binary. The database is a volume: an index is far larger than
# any image should be -- the default one is 226 GB -- so it is mounted,
# never baked in.
FROM debian:bookworm-slim

COPY --from=build /src/mdindex/mdindex /usr/local/bin/mdindex

# -d names the database directory and has no useful default inside a
# container, so point it at the mount and let -d override it.
ENV MDINDEX_DB=/db
WORKDIR /data
VOLUME ["/db", "/data"]

ENTRYPOINT ["mdindex"]
