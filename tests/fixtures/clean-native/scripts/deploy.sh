#!/bin/bash
set -eu
chmod 750 /opt/app/run.sh
rm -rf "${BUILD_DIR:?}"/
curl -fsS https://example.invalid/data.json -o data.json
ssh deploy@example.invalid uptime
curl --user "$USER:$TOKEN" https://example.invalid/
