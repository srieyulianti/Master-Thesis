#!/bin/bash
set -e

BLUE='\033[1;34m'
NC='\033[0m'
INSTANCE_DIR="ra_tls_instance"

make -j
rm -rf ${INSTANCE_DIR} && occlum new ${INSTANCE_DIR}
cd ${INSTANCE_DIR}
cp ../build/bin/App image/bin
occlum build

echo -e "${BLUE}occlum run /bin/App${NC}"
occlum run /bin/App