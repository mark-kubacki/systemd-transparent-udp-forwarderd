#!/bin/bash

set -euxo pipefail

gcc -Os -fwhole-program -fpic -fpie \
  -Wall -Werror=implicit-function-declaration \
  -Wno-implicit-int \
  -Wl,--gc-sections \
  -D_GNU_SOURCE \
  -o systemd-udp-forwarderd udp-proxy.c \
  -lsystemd

exit 0
