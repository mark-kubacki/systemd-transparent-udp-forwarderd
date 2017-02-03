#!/bin/bash

set -euxo pipefail

if [[ ! -s vendor/libmill/.libs/libmill.a ]]; then
  pushd .
  cd vendor/libmill/
  ./autogen.sh
  ./configure --prefix=/usr CFLAGS="-Os -ffunction-sections -fdata-sections"
  make -j$(nproc)
  popd
fi

gcc -Os -fwhole-program -fpic -fpie \
  -Wall -Werror=implicit-function-declaration \
  -Wl,--gc-sections \
  -o systemd-udp-forwarderd udp-proxy.c \
  -Ivendor/libmill vendor/libmill/.libs/libmill.a \
  -lsystemd

exit 0
