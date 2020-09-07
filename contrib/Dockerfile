FROM debian:buster-slim

RUN apt update && apt install -y --no-install-recommends \
    ca-certificates \
    file \
    git \
    subversion \
    python \
    python3 \
    python3-pytest \
    build-essential \
    gawk \
    unzip \
    libncurses5-dev \
    zlib1g-dev \
    libssl-dev \
    libelf-dev \
    wget \
    time \
    ecdsautils \
    lua-check \
    shellcheck \
    qemu-system-x86 \
  && rm -rf /var/lib/apt/lists/*
RUN python3 -m pip install gluon-qemu-testlab

RUN useradd -d /gluon gluon
USER gluon

VOLUME /gluon
WORKDIR /gluon
