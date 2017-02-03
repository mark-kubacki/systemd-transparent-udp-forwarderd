#!/bin/bash

set -euxo pipefail

gcc -Os -fwhole-program -fpic -fpie \
  -Wall -Werror=implicit-function-declaration \
  -Wl,--gc-sections \
  -o systemd-udp-forwarderd udp-proxy.c \
  -lsystemd

exit 0
