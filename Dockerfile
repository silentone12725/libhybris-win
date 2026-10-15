# Reproducible Linux build/test environment.  Package installation is done at
# image-build time; `make test` never contacts a package repository.
FROM debian:bookworm-slim@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install --no-install-recommends -y \
       bash \
       ca-certificates \
       file \
       g++ \
       gcc \
       git \
       libc6-dev \
       libgtest-dev \
       libtool \
       make \
       pkg-config \
       python3 \
       autoconf \
       automake \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src/libhybris-win
COPY . .

CMD ["make", "test"]
