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

CLEAN=true
BUILD_OPENSSL=false
BUILD_BOOST=false
BUILD_LIBCURL=false
BUILD_OPENSSL_AARCH64=false
BUILD_BOOST_AARCH64=false
BUILD_LIBCURL_AARCH64=false
BUILD_GTEST=false
BUILD_MBEDTLS=false
BUILD_LIBSPDM=false
CMAKE_POLICY_FLAG=""

set -E -o pipefail

export no_proxy="altera.com,.altera.com,${no_proxy}"

for arg in "$@"; do
    if [[ $arg == OUTPUT_FOLDER=* ]]; then
        OUTPUT_FOLDER="${arg#*=}"
    fi

    if [[ $arg == OPENSSL_VERSION=* ]]; then
        OPENSSL_VERSION="${arg#*=}"
        BUILD_OPENSSL=true
    fi

    if [[ $arg == BOOST_VERSION=* ]]; then
        BOOST_VERSION="${arg#*=}"
        BUILD_BOOST=true
    fi

    if [[ $arg == LIBCURL_VERSION=* ]]; then
        LIBCURL_VERSION="${arg#*=}"
        BUILD_LIBCURL=true
    fi

    if [[ $arg == OPENSSL_AARCH64_VERSION=* ]]; then
        OPENSSL_AARCH64_VERSION="${arg#*=}"
        BUILD_OPENSSL_AARCH64=true
    fi

    if [[ $arg == BOOST_AARCH64_VERSION=* ]]; then
        BOOST_AARCH64_VERSION="${arg#*=}"
        BUILD_BOOST_AARCH64=true
    fi

    if [[ $arg == LIBCURL_AARCH64_VERSION=* ]]; then
        LIBCURL_AARCH64_VERSION="${arg#*=}"
        BUILD_LIBCURL_AARCH64=true
    fi

    if [[ $arg == GTEST_VERSION=* ]]; then
        GTEST_VERSION="${arg#*=}"
        BUILD_GTEST=true
    fi

    if [[ $arg == MBEDTLS_VERSION=* ]]; then
        MBEDTLS_VERSION="${arg#*=}"
        BUILD_MBEDTLS=true
    fi

    if [[ $arg == LIBSPDM_VERSION=* ]]; then
        LIBSPDM_VERSION="${arg#*=}"
        BUILD_LIBSPDM=true
    fi

    if [[ $arg == CLEAN=* ]]; then
        CLEAN="${arg#*=}"
    fi

done

OUTPUT_FOLDER="${OUTPUT_FOLDER:-dependencies}"
HOME_DIR=""
OUTPUT_DIR=""
WORK_DIR=""

function print_error() {
    local message=$1
    echo -e "\e[1;31mERROR: $message\e[0m"
}

function print_info() {
    local message=$1
    echo -e "\e[1;33m$message\e[0m"
}

function verify_version_provided() {
    local variable_name=$1
    local variable_value=$2

    if [ -z "${variable_value}" ]; then
        print_error "${variable_name} not provided"
        exit 1
    fi
}

function create_output_folders() {
    local library_folder_name=$1
    mkdir -p "${OUTPUT_DIR}/${library_folder_name}/lib" "${OUTPUT_DIR}/${library_folder_name}/include"
}

function copy_headers_to_output() {
    local path_to_include_folder=$1
    local path_to_output_folder=$2

    print_info "Copying headers from ${path_to_include_folder} to ${OUTPUT_DIR}/${path_to_output_folder}"

    cp -rL "${path_to_include_folder}" "${OUTPUT_DIR}/${path_to_output_folder}"
}

function copy_artifacts_to_output() {
    local path_to_artifacts_folder=$1
    local artifacts_extension=$2
    local path_to_output_folder=$3

    print_info "Copying ${artifacts_extension} from ${path_to_artifacts_folder} to ${OUTPUT_DIR}/${path_to_output_folder}"

    cp -P "${path_to_artifacts_folder}"/${artifacts_extension} "${OUTPUT_DIR}/${path_to_output_folder}"
}

function copy_artifacts_to_output_recursive() {
    local path_to_artifacts_folder=$1
    local artifacts_extension=$2
    local path_to_output_folder=$3

    copy_files_recursive "${path_to_artifacts_folder}" "${artifacts_extension}" "${OUTPUT_DIR}/${path_to_output_folder}"
}

function check_error_code() {
    ERROR_CODE="$?"

    if [[ "$ERROR_CODE" != "0" ]]; then
        print_error "Build failed with error code $ERROR_CODE! Aborting!"
        exit 1
    fi
}

function clean_environment_var() {
    unset CROSS_COMPILE
    unset AR
    unset AS
    unset LD
    unset RANLIB
    unset CC
    unset NM
    unset LDFLAGS
}

function downloadFromLibrarySource() {
    local library_name=$1
    local workdir=$2
    local packed_filename=$3
    local path_to_repository=$4
    local library_full_filename="${library_name}-${library_version}.tar.gz"

    mkdir -p "${workdir}" && cd "${workdir}" || (print_error "Failed to create and enter working directory: ${workdir}" && exit 1)

    if [ -f "${library_full_filename}" ]; then
        print_info "Package for ${library_name} already exists - skipped downloading: ${library_full_filename}"
    else
        print_info "---- Downloading ${library_name} from remote repository ----"
        wget --no-if-modified-since -N "${path_to_repository}/${packed_filename}" -O "${library_full_filename}"|| \
        curl -o "${library_full_filename}" -L "${path_to_repository}/${packed_filename}" || (print_error "Failed to download" && exit 1)

        tar xzf "${library_full_filename}" || (print_error "Failed to unpack library" && exit 1)
    fi
    cd "${HOME_DIR}" || exit 1
}

function handle_openssl() {
    local arch=$1
    local library_version=$2
    local library_name=openssl

    print_info "---- Building ${library_name}, version: ${library_version}, arch: ${arch} ----"

    local workdir="${WORK_DIR}/${library_name}_${arch}"

    local library_path=${workdir}/openssl-${library_version}
    local packed_filename=openssl-${library_version}.tar.gz
    local path_to_repository=https://www.openssl.org/source/

    downloadFromLibrarySource "${library_name}" "${workdir}" "${packed_filename}" "${path_to_repository}" && \
    build_openssl "${library_name}" "${library_path}" "${arch}"

    print_info "---- Finished building: ${library_name}, version: ${library_version} ----"
}

function handle_boost() {
    local arch=$1
    local library_version=$2
    local library_name=boost

    print_info "---- Building ${library_name}, version: ${library_version}, arch: ${arch} ----"

    local workdir="${WORK_DIR}/${library_name}_${arch}"
    local version_sed=$(echo "${library_version//./$'_'}")

    local library_path=${workdir}/boost_${version_sed}
    local packed_filename=boost_${version_sed}.tar.gz
    local path_to_repository=https://sourceforge.net/projects/boost/files/boost/${library_version}

    downloadFromLibrarySource "${library_name}" "${workdir}" "${packed_filename}" "${path_to_repository}" && \
    build_boost "${library_name}" "${library_path}" "${arch}"

    print_info "---- Finished building: ${library_name}, version: ${library_version} ----"
}

function handle_libcurl() {
    local arch=$1
    local library_version=$2
    local library_name=libcurl

    print_info "---- Building ${library_name}, version: ${library_version}, arch: ${arch} ----"

    local workdir="${WORK_DIR}/${library_name}_${arch}"

    local library_path=${workdir}/curl-${library_version}
    local packed_filename=curl-${library_version}.tar.gz
    local path_to_repository=https://curl.se/download

    downloadFromLibrarySource "${library_name}" "${workdir}" "${packed_filename}" "${path_to_repository}" && \
    build_libcurl "${library_name}" "${library_path}" "${arch}"

    print_info "---- Finished building: ${library_name}, version: ${library_version} ----"
}

function handle_gtest() {
    local arch=$1
    local library_version=$2
    local library_name=gtest

    print_info "---- Building ${library_name}, version: ${library_version}, arch: ${arch} ----"

    local workdir="${WORK_DIR}/${library_name}"

    local library_path=${workdir}/googletest-${library_version}
    local packed_filename=v${library_version}.tar.gz
    local path_to_repository=https://github.com/google/googletest/archive/refs/tags

    downloadFromLibrarySource "${library_name}" "${workdir}" "${packed_filename}" "${path_to_repository}" && \
    build_gtest "${library_name}" "${library_path}"

    print_info "---- Finished building: ${library_name}, version: ${library_version} ----"
}

function handle_mbedtls() {
    local arch=$1
    local library_version=$2
    local library_name=mbedtls

    print_info "---- Building ${library_name}, version: ${library_version}, arch: ${arch} ----"

    local workdir="${WORK_DIR}/${library_name}"

    local library_path=${workdir}/mbedtls-mbedtls-${library_version}
    local packed_filename=mbedtls-${library_version}.tar.gz
    local path_to_repository=https://github.com/ARMmbed/mbedtls/archive

    downloadFromLibrarySource "${library_name}" "${workdir}" "${packed_filename}" "${path_to_repository}" && \
    build_mbedtls "${library_name}" "${library_path}"

    print_info "---- Finished building: ${library_name}, version: ${library_version} ----"
}

function handle_libspdm() {
    local arch=$1
    local library_version=$2
    local library_name=libspdm

    print_info "---- Building ${library_name}, version: ${library_version}, arch: ${arch} ----"

    local workdir="${WORK_DIR}/${library_name}"

    local packed_filename=${library_version}.tar.gz
    local path_to_repository=https://github.com/DMTF/libspdm/archive/refs/tags
    local library_path=${workdir}/libspdm-${library_version}

    downloadFromLibrarySource "${library_name}" "${workdir}" "${packed_filename}" "${path_to_repository}" && \
    build_libspdm "${library_name}" "${library_path}"

    print_info "---- Finished building: ${library_name}, version: ${library_version} ----"
}

function build_openssl() {
    local library_name=$1
    local library_path=$2
    local arch=$3

    cd "${library_path}" || exit 1
    clean_environment_var

    if [ "${arch}" = "aarch64" ]; then
        ./Configure linux-aarch64 --cross-compile-prefix=aarch64-linux-gnu- shared -L-fPIC -L-O0 -fPIC -O0
    else
        ./config shared -L-fPIC -L-g -L-O0 -fPIC -g -O0
    fi
    check_error_code
    make -j $(nproc) --silent

    check_error_code

    cd "${HOME_DIR}" || exit 1

    local output_folder_name="${library_name}"
    create_output_folders "${output_folder_name}" && \
    copy_headers_to_output "${library_path}/include/" "${output_folder_name}" && \
    copy_artifacts_to_output "${library_path}" "*.so*" "${output_folder_name}/lib" && \
    copy_artifacts_to_output "${library_path}" "*.a" "${output_folder_name}/lib"
    check_error_code
}

function build_boost() {
    local library_name=$1
    local library_path=$2
    local arch=$3
    local build_output_dir=build_result

    cd "${library_path}" || exit 1
    clean_environment_var

    ./bootstrap.sh --with-libraries=program_options --prefix=./${build_output_dir}
    check_error_code
    if [ "${arch}" = "aarch64" ]; then
        sed -i 's/using gcc/using gcc : arm : aarch64-linux-gnu-g++/g' project-config.jam
        check_error_code
    fi
    ./b2
    check_error_code
    ./b2 install
    check_error_code
    local output_folder_name="${library_name}"
    create_output_folders "${output_folder_name}" && \
    cp -rLv "${library_path}/${build_output_dir}"/* "${OUTPUT_DIR}/${output_folder_name}/"
    check_error_code

    cd "${HOME_DIR}" || exit 1
}

function build_libcurl() {
    local library_name=$1
    local library_path=$2
    local arch=$3

    cd "${library_path}" || exit 1
    clean_environment_var

    local output_folder_name="${library_name}"
    export OPENSSL_ROOT_DIR="${OUTPUT_DIR}/openssl"
    if [ "${arch}" = "aarch64" ]; then
        export CROSS_COMPILE="aarch64-linux-gnu"
        export AR=${CROSS_COMPILE}-ar
        export AS=${CROSS_COMPILE}-as
        export LD=${CROSS_COMPILE}-ld
        export RANLIB=${CROSS_COMPILE}-ranlib
        export CC=${CROSS_COMPILE}-gcc
        export NM=${CROSS_COMPILE}-nm
        export LDFLAGS="-L${OPENSSL_ROOT_DIR}/lib -Wl,-rpath,${OPENSSL_ROOT_DIR}/lib"
        ./configure --target=${CROSS_COMPILE} --host=${CROSS_COMPILE} --build=i586-pc-linux-gnu --with-openssl=${OPENSSL_ROOT_DIR} --without-libpsl --without-zlib --without-zstd --without-brotli --prefix=$(pwd)/output
        check_error_code
        make
        local make_status=$?
        if [[ ${make_status} -ne 0 ]]; then
            print_info "libcurl make returned ${make_status}; continuing because the curl executable may fail while libraries are usable."
        fi
        make install
        check_error_code
        if ! find "$(pwd)/output/lib" -maxdepth 1 \( -name 'libcurl.so*' -o -name 'libcurl.a' \) | grep -q .; then
            print_error "libcurl library was not produced"
            exit 1
        fi
    else
        ./configure --with-openssl=${OPENSSL_ROOT_DIR} --without-libpsl --without-zlib --without-zstd --without-brotli --prefix=$(pwd)/output
        check_error_code
        # Add openssl to LD_LIBRARY_PATH, so that curl don't try to link to system provided one. It caused issues on the systems with installed openssl 3.0
        export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:${OPENSSL_ROOT_DIR}/lib
        make
        check_error_code
        make install
        check_error_code
    fi

    local output_folder_name="${library_name}"
    create_output_folders "${output_folder_name}" &&
    mkdir -p "${OUTPUT_DIR}/${output_folder_name}/include/curl" &&
    cp -rL "${library_path}"/output/* "${OUTPUT_DIR}/${output_folder_name}" &&
    cp -rL "${library_path}"/include/curl/*.h "${OUTPUT_DIR}/${output_folder_name}/include/curl/"
    check_error_code

    cd "${HOME_DIR}" || exit 1
}

function build_libspdm() {
    local library_name=$1
    local library_path=$2

    cd "${library_path}" || exit 1
    clean_environment_var

    build_libspdm_internal "Release" "${library_name}"
    check_error_code

    cd "${HOME_DIR}" || exit 1
}

function build_libspdm_internal() {
    local cmake_build_type=$1
    local output_folder_name=$2

    local openssl_folder_name="openssl"
    local openssl_root_dir=${OUTPUT_DIR}/${openssl_folder_name}

    local custom_defines="-DLIBSPDM_MAX_MESSAGE_BUFFER_SIZE=20000 -DLIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN=15000 -DLIBSPDM_MAX_CERT_CHAIN_SIZE=18000 -DLIBSPDM_MAX_MEASUREMENT_RECORD_SIZE=15000"
    local algorithms_enabled="-DLIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT=1"
    local algorithms_disabled="-DLIBSPDM_ENABLE_CAPABILITY_CHUNK_CAP=0 -DLIBSPDM_ENABLE_CAPABILITY_CSR_CAP=0 -DLIBSPDM_ENABLE_CAPABILITY_HBEAT_CAP=0 -DLIBSPDM_ENABLE_CAPABILITY_PSK_CAP=0 -DLIBSPDM_ENABLE_CAPABILITY_CHAL_CAP=0 -DLIBSPDM_ENABLE_CAPABILITY_ENDPOINT_INFO_CAP=0"

    local sources_dir=$(pwd)
    local build_dir="build/${cmake_build_type}"
    mkdir -p "${build_dir}" && cd "${build_dir}" || exit 1
    clean_environment_var

    cmake ${CMAKE_POLICY_FLAG} -DCMAKE_VERBOSE_MAKEFILE:BOOL=ON -DARCH=x64 -DTOOLCHAIN=GCC -DTARGET="${cmake_build_type}" -DDISABLE_TESTS=1 -DCRYPTO=openssl -DENABLE_BINARY_BUILD=1 -DCMAKE_C_FLAGS="${custom_defines} ${algorithms_enabled} ${algorithms_disabled} -I${openssl_root_dir}/include" -DCOMPILED_LIBCRYPTO_PATH="${openssl_root_dir}/lib/libcrypto.a" -DCOMPILED_LIBSSL_PATH="${openssl_root_dir}/lib/libssl.a" "${sources_dir}"
    check_error_code

    make
    check_error_code

    create_output_folders "${output_folder_name}" &&
    cp -rL "${library_path}/include" "${OUTPUT_DIR}/${output_folder_name}" || exit 1

    local lib_path="${library_path}/${build_dir}/lib"
    local output_lib_filenames=(libdebuglib_null.a libdebuglib.a libmalloclib.a libmemlib.a libplatform_lib_null.a libplatform_lib.a librnglib.a libspdm_common_lib.a libspdm_crypt_lib.a libspdm_requester_lib.a libspdm_secured_message_lib.a libspdm_transport_mctp_lib.a libcryptlib_openssl.a libspdm_device_secret_lib_null.a)
    for i in "${output_lib_filenames[@]}"
    do
        cp "${lib_path}/${i}" "${OUTPUT_DIR}/${output_folder_name}/lib/" || exit 1
    done

    cd "${sources_dir}" || exit 1
}

function build_gtest() {
    local library_name=$1
    local library_path=$2

    cd "${library_path}" || exit 1
    clean_environment_var

    mkdir -p build && cd build || exit 1
    cmake ${CMAKE_POLICY_FLAG} -DBUILD_GMOCK=ON ../
    check_error_code
    make -j $(nproc) --silent

    check_error_code

    cd "${HOME_DIR}" || exit 1

    local output_folder_name="${library_name}"
    create_output_folders "${output_folder_name}" &&
    copy_headers_to_output "${library_path}/googletest/include" "${output_folder_name}" &&
    copy_headers_to_output "${library_path}/googlemock/include" "${output_folder_name}" &&
    copy_artifacts_to_output_recursive "${library_name}" "*.a" "${output_folder_name}/lib"
    check_error_code
}

function build_mbedtls() {
    local library_name=$1
    local library_path=$2

    cd "${library_path}" || exit 1
    clean_environment_var

    mkdir -p build && cd build || exit 1
    cmake ${CMAKE_POLICY_FLAG} -DENABLE_TESTING=OFF ../
    check_error_code
    make -j $(nproc) --silent

    check_error_code

    cd "${HOME_DIR}" || exit 1

    local output_folder_name="${library_name}"
    create_output_folders "${output_folder_name}" && \
    copy_headers_to_output "${library_path}/include" "${output_folder_name}" && \
    copy_artifacts_to_output_recursive "${library_name}" "*.a" "${output_folder_name}/lib"
    check_error_code
}

function copy_files_recursive {
    local path_to_artifacts_folder=$1
    local artifacts_extension=$2
    local path_to_output_folder=$3
    local found=false

    while IFS= read -r -d '' line; do
        found=true
        echo "Processing file '$line'"
        cp -- "$line" "${path_to_output_folder}" || return 1
    done < <(find "${WORK_DIR}/${path_to_artifacts_folder}" -name "${artifacts_extension}" -print0)

    if [[ "${found}" == false ]]; then
        print_error "No ${artifacts_extension} files found under ${WORK_DIR}/${path_to_artifacts_folder}"
        return 1
    fi
}

function doit() {
    if [[ "$BUILD_OPENSSL" = true ]]; then
        verify_version_provided "OPENSSL_VERSION" "${OPENSSL_VERSION}"
        handle_openssl "x64" "${OPENSSL_VERSION}"
    fi

    if [[ "$BUILD_OPENSSL_AARCH64" = true ]]; then
        verify_version_provided "OPENSSL_AARCH64_VERSION" "${OPENSSL_AARCH64_VERSION}"
        handle_openssl "aarch64" "${OPENSSL_AARCH64_VERSION}"
    fi

    if [[ "$BUILD_BOOST" = true ]]; then
        verify_version_provided "BOOST_VERSION" "${BOOST_VERSION}"
        handle_boost "x64" "${BOOST_VERSION}"
    fi

    if [[ "$BUILD_BOOST_AARCH64" = true ]]; then
        verify_version_provided "BOOST_AARCH64_VERSION" "${BOOST_AARCH64_VERSION}"
        handle_boost "aarch64" "${BOOST_AARCH64_VERSION}"
    fi

    if [[ "$BUILD_LIBCURL" = true ]]; then
        verify_version_provided "LIBCURL_VERSION" "${LIBCURL_VERSION}"
        handle_libcurl "x64" "${LIBCURL_VERSION}"
    fi

    if [[ "$BUILD_LIBCURL_AARCH64" = true ]]; then
        verify_version_provided "LIBCURL_AARCH64_VERSION" "${LIBCURL_AARCH64_VERSION}"
        handle_libcurl "aarch64" "${LIBCURL_AARCH64_VERSION}"
    fi

    if [[ "$BUILD_GTEST" = true ]]; then
        verify_version_provided "GTEST_VERSION" "${GTEST_VERSION}"
        handle_gtest "x64" "${GTEST_VERSION}"
    fi

    if [[ "$BUILD_MBEDTLS" = true ]]; then
        verify_version_provided "MBEDTLS_VERSION" "${MBEDTLS_VERSION}"
        handle_mbedtls "x64" "${MBEDTLS_VERSION}"
    fi

    if [[ "$BUILD_LIBSPDM" = true ]]; then
        verify_version_provided "LIBSPDM_VERSION" "${LIBSPDM_VERSION}"
        handle_libspdm "x64" "${LIBSPDM_VERSION}"
    fi
}

function prepare_building_environment() {
    source ~/.bashrc

    HOME_DIR=$(pwd)
    OUTPUT_DIR=${HOME_DIR}/${OUTPUT_FOLDER}
    WORK_DIR=${OUTPUT_DIR}/tmp

    print_info "HOME_DIR: ${HOME_DIR}"
    print_info "OUTPUT_DIR: ${OUTPUT_DIR}"
    print_info "WORK_DIR: ${WORK_DIR}"
}

function clean_directory() {
    if [[ "$CLEAN" == true ]]; then
        echo 'Cleaning...'
        rm -rf "${OUTPUT_DIR}"
        rm -rf build_dependencies
    fi
}

function check_cmake() {
    if ! command -v cmake &> /dev/null; then
        print_info "cmake not found. Installing..."
        sudo apt --yes install cmake
        check_error_code
        if ! command -v cmake &> /dev/null; then
            print_error "Failed to install cmake. Aborting!"
            exit 1
        fi
    fi

    local cmake_version
    cmake_version=$(cmake --version | head -1 | awk '{print $3}')
    print_info "Detected cmake version: ${cmake_version}"

    # CMake >= 3.27 dropped support for cmake_minimum_required < 3.5
    if [[ "$(printf '%s\n' "3.27" "${cmake_version}" | sort -V | head -1)" == "3.27" ]]; then
        print_info "cmake >= 3.27 detected — enabling CMAKE_POLICY_VERSION_MINIMUM=3.5"
        CMAKE_POLICY_FLAG="-DCMAKE_POLICY_VERSION_MINIMUM=3.5"
    fi
}

function check_required_tools() {
    sudo apt update
    check_error_code

    local basic_packages=("make" "wget" "curl" "tar" "perl" "python3")
    for pkg in "${basic_packages[@]}"; do
        if ! command -v "$pkg" &> /dev/null; then
            print_info "${pkg} not found. Installing..."
            sudo apt --yes install "$pkg"
            check_error_code
            if ! command -v "$pkg" &> /dev/null; then
                print_error "Failed to install ${pkg}. Aborting!"
                exit 1
            fi
        fi
    done

    if ! command -v gcc &> /dev/null; then
        print_info "build-essential not found. Installing..."
        sudo apt --yes install build-essential
        check_error_code
        if ! command -v gcc &> /dev/null; then
            print_error "Failed to install build-essential. Aborting!"
            exit 1
        fi
    fi

    if [[ "$BUILD_OPENSSL_AARCH64" == true || "$BUILD_BOOST_AARCH64" == true || "$BUILD_LIBCURL_AARCH64" == true ]]; then
        local cross_packages=("gcc-aarch64-linux-gnu" "g++-aarch64-linux-gnu" "binutils-aarch64-linux-gnu")
        for pkg in "${cross_packages[@]}"; do
            if ! dpkg -s "$pkg" &> /dev/null 2>&1; then
                print_info "${pkg} not found. Installing..."
                sudo apt --yes install "$pkg"
                check_error_code
                if ! dpkg -s "$pkg" &> /dev/null 2>&1; then
                    print_error "Failed to install ${pkg}. Aborting!"
                    exit 1
                fi
            fi
        done
    fi
}

main() {
    print_info "OPENSSL_VERSION is set to: ${OPENSSL_VERSION}"
    print_info "BOOST_VERSION is set to: ${BOOST_VERSION}"
    print_info "LIBCURL_VERSION is set to: ${LIBCURL_VERSION}"
    print_info "GTEST_VERSION is set to: ${GTEST_VERSION}"
    print_info "MBEDTLS_VERSION is set to: ${MBEDTLS_VERSION}"
    print_info "LIBSPDM_VERSION is set to: ${LIBSPDM_VERSION}"
    print_info "OUTPUT_FOLDER is set to: ${OUTPUT_FOLDER}"

    print_info "OPENSSL_AARCH64_VERSION is set to: ${OPENSSL_AARCH64_VERSION}"
    print_info "BOOST_AARCH64_VERSION is set to: ${BOOST_AARCH64_VERSION}"
    print_info "LIBCURL_AARCH64_VERSION is set to: ${LIBCURL_AARCH64_VERSION}"

    prepare_building_environment
    clean_directory
    check_required_tools
    check_cmake
    doit

    print_info "Done"
}

main "$@"
