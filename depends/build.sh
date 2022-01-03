#!/bin/bash

pushd depends/secp256k1-zkp
./autogen.sh
./configure --enable-module-ecdh --enable-module-generator --enable-module-recovery --enable-experimental  --enable-module-commitment  --enable-module-rangeproof --enable-module-bulletproof --enable-module-schnorrsig --enable-module-aggsig --disable-benchmark
make -j"$(($(nproc)+1))"
popd
