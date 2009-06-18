#!/bin/sh

echo "http://t2.unl.edu/store/cache" > trusted.caches
echo "http://vdt.cs.wisc.edu/vdt_1101_cache" >> trusted.caches
export VDTSETUP_AGREE_TO_LICENSES=y
export VDTSETUP_INSTALL_CERTS=l
export VDTSETUP_CA_CERT_UPDATER=n

