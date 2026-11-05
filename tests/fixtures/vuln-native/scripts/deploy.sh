#!/bin/bash
eval "$1"
chmod -R 777 /opt/app
rm -rf "$BUILD_DIR"/
curl -k https://example.invalid/data.json -o data.json
ssh -o StrictHostKeyChecking=no deploy@example.invalid uptime
sshpass -p hunter2hunter ssh deploy@example.invalid uptime
curl -o update.sh http://downloads.example.invalid/update.sh
