#!/bin/bash

#
# This project is licensed as below.
#
# ***************************************************************************
#
# Copyright 2020-2026 Altera Corporation. All Rights Reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice,
# this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright
# notice, this list of conditions and the following disclaimer in the
# documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
# PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER
# OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
# EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
# PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
# OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
# WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
# OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
# ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
# ***************************************************************************
#

IMAGE_NAME="bkpprogrammer-builder"
BKPPROG_DOCKER_BUILD_DIR="/bkpprogrammer"
FCS_DOCKER_BUILD_DIR="/FCS"
CLEAN=true

for arg in "$@"; do
    if [[ $arg == OPENSSL_AARCH64_VERSION=* ]]; then
        OPENSSL_AARCH64_VERSION="${arg#*=}"
    fi

    if [[ $arg == BOOST_AARCH64_VERSION=* ]]; then
        BOOST_AARCH64_VERSION="${arg#*=}"
    fi

    if [[ $arg == LIBCURL_AARCH64_VERSION=* ]]; then
        LIBCURL_AARCH64_VERSION="${arg#*=}"
    fi

    if [[ $arg == CLEAN=* ]]; then
        CLEAN="${arg#*=}"
    fi
done

if [[ "$CLEAN" == true ]]; then
  echo "Recreating ${IMAGE_NAME} ..."
  docker rmi ${IMAGE_NAME} -f
  docker build -t ${IMAGE_NAME} -f Dockerfile . || exit 1
fi

CONTAINER_ID=$(docker run --interactive --detach ${IMAGE_NAME}) || exit 1

echo "Copying sources ..."
docker cp ../src/. ${CONTAINER_ID}:${BKPPROG_DOCKER_BUILD_DIR}/src
docker cp ../CMakeLists.txt ${CONTAINER_ID}:${BKPPROG_DOCKER_BUILD_DIR}
docker cp ../../build-dependencies.sh ${CONTAINER_ID}:/
docker cp ../../FCS/. ${CONTAINER_ID}:${FCS_DOCKER_BUILD_DIR}

echo "Building dependencies"
docker exec --interactive ${CONTAINER_ID} ../build-dependencies.sh OPENSSL_AARCH64_VERSION="${OPENSSL_AARCH64_VERSION}" BOOST_AARCH64_VERSION="${BOOST_AARCH64_VERSION}" LIBCURL_AARCH64_VERSION="${LIBCURL_AARCH64_VERSION}" || exit 1

echo "Building bkpprogrammer and bkp_app in aarch64"
docker exec --interactive ${CONTAINER_ID} bash -c "mkdir -p build/MinSizeRel && cd build/MinSizeRel && cmake -DHPS_BUILD:BOOL=ON ../.. && cmake --build ." || exit 1

echo "Copying results out of docker"
rm -rf ./out_docker
mkdir ./out_docker
docker cp ${CONTAINER_ID}:${BKPPROG_DOCKER_BUILD_DIR}/build/. ./out_docker/
docker cp ${CONTAINER_ID}:/usr/aarch64-linux-gnu/lib/libstdc++.so.6.0.25 ./out_docker/
docker cp ${CONTAINER_ID}:/usr/aarch64-linux-gnu/lib/libgcc_s.so.1 ./out_docker/

docker stop ${CONTAINER_ID}
docker rm ${CONTAINER_ID} || exit

echo "Done"
