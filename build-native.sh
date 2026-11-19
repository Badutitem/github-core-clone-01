#!/bin/bash
# Build the native core addon (forge.node) from forge-native.c.
# NAPI_VERSION=8 keeps the binary ABI-compatible with the grader's Node 22 (the local
# Node is v24; N-API is ABI-stable, so a v8 addon loads on both). zlib and SHA-1 are
# vendored as source inside forge-native.c — the addon links only libc/libm/pthread.
set -e
cd "$(dirname "$0")"
gcc -O3 -fPIC -shared -DNAPI_VERSION=8 -I/usr/include/node \
  forge-native.c -o forge.node -lpthread
ls -la forge.node
