#!/bin/bash
set -e

BLUE='\033[1;34m'
NC='\033[0m'
INSTANCE_DIR="ra_tls_instance"
occlum_glibc=/opt/occlum/glibc/lib

rm -rf ${INSTANCE_DIR} && occlum new ${INSTANCE_DIR}
cd ${INSTANCE_DIR}

# Copy mbedTLS library to $occlum_glibc
cp ../lib/libmbedcrypto.so.6 image/$occlum_glibc
cp ../lib/libmbedcrypto.so image/$occlum_glibc
cp ../lib/libmbedtls.so image/$occlum_glibc
cp ../lib/libmbedtls.so.13 image/$occlum_glibc
cp ../lib/libmbedx509.so image/$occlum_glibc
cp ../lib/libmbedx509.so.1 image/$occlum_glibc
cp ../lib/libra_tls_verify_dcap.so image/lib
cp ../lib/libsgx_urts.so image/lib
cp /usr/lib/x86_64-linux-gnu/libsgx_enclave_common.so.1 image/$occlum_glibc

# Copy ra-tls-server image to image/bin
cp ../bin/ra-tls-client image/bin

# Copy network libraries to image/$occlum_glibc
cp $occlum_glibc/libnss_files.so.2 image/$occlum_glibc
cp $occlum_glibc/libnss_dns.so.2 image/$occlum_glibc
cp $occlum_glibc/libdl.so.2 image/$occlum_glibc
cp $occlum_glibc/libresolv.so.2 image/$occlum_glibc
cp /usr/lib/x86_64-linux-gnu/libsgx_dcap_quoteverify.so.1 image/$occlum_glibc
cp /etc/nsswitch.conf image/etc
cp /etc/resolv.conf image/etc
cp /etc/host.conf image/etc
cp /etc/group image/etc
cp /etc/hosts image/etc
cp /etc/gai.conf image/etc
#cp /etc/ethers image/etc
cp /etc/passwd image/etc
cp /etc/ssl/certs/ca-certificates.crt image/etc
cp /etc/sgx_default_qcnl.conf image/etc


mkdir -p image/opt/occlum/glibc/etc
cp /etc/ld.so.cache image/opt/occlum/glibc/etc

occlum build

echo -e "${BLUE}occlum run /bin/ra-tls-client${NC}"
occlum run /bin/ra-tls-client enclave

cd ..
make clean
