#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

export LD_LIBRARY_PATH="$HOME/usr/lib:$PWD/commonapi-wrappers/playground/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
VSOMEIP_CONFIGURATION=vsomeip-server-remote.json \
VSOMEIP_APPLICATION_NAME=playground-service \
./build/PlaygroundService
