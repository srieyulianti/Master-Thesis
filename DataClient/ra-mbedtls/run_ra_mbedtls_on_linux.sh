#!/bin/bash
set -e

BLUE='\033[1;34m'
NC='\033[0m'

echo -e "${BLUE} ./ra-tls-client non-enclave${NC}"
cd bin
./ra-tls-client non-enclave

#cd ..
#make clean

