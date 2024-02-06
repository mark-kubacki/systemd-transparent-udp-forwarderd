FROM docker.io/library/gcc:13-bookworm

RUN \
  echo "debconf debconf/frontend select Noninteractive" | debconf-set-selections && \
  apt-get -q update && \
  apt-get -y install --no-install-recommends \
    cmake \
    git \
    libsystemd-dev \
    ninja-build \
    sudo
