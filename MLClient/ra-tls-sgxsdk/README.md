# Configure SGX RA settings

## For DCAP RA

```shell
mkdir -p $PATH_TO_DCAP_SOURCE
cd $PATH_TO_DCAP_SOURCE
git clone https://github.com/intel/SGXDataCenterAttestationPrimitives/
export SGX_DCAP=$PATH_TO_DCAP_SOURCE/SGXDataCenterAttestationPrimitives
```

# Build

## For DCAP RA

Please refer to [this guide](https://github.com/intel/SGXDataCenterAttestationPrimitives/blob/master/README.md) to install DCAP.
Note: If your platform is pre-product SGX platform (SBX), please follow this guide to resolve the quote verification problem on SBX platforms: https://github.com/alibaba/inclavare-containers/blob/master/hack/use-sbx-platform/README.md.

```shell
cd $src/ra-tls
make ECDSA=1
```

# Run Client

``` shell
cd build/bin
./App -c
```


