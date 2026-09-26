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

CONFIG_FILENAME="config.txt"
CLEAN=true
BUILD_OPENSSL=false
BUILD_BOOST=false
BUILD_LIBCURL=false
BUILD_AARCH64=false
BUILD_GTEST=false
BUILD_LIBSPDM=false
CMAKE_POLICY_FLAG=""
SPDM_WRAPPER_ONLY=false
set -E -o pipefail

export no_proxy="altera.com,.altera.com,${no_proxy}"

function print_error() {
    local message=$1
    echo -e "\e[1;31mERROR: $message\e[0m"
}

function print_info() {
    local message=$1
    echo -e "\e[1;33m$message\e[0m"
}

function parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --config)
                shift
                CONFIG_FILENAME="$1"
                ;;
            --spdm-wrapper-only)
                shift
                SPDM_WRAPPER_ONLY=true
                ;;
            --output)
                shift
                OUTPUT_FOLDER="$1"
                ;;
            --clean)
                CLEAN=true
                ;;
            --no-clean)
                CLEAN=false
                ;;
            OUTPUT_FOLDER=*)
                OUTPUT_FOLDER="${1#*=}"
                ;;
            CLEAN=*)
                CLEAN="${1#*=}"
                ;;
            -h|--help)
                echo "Usage: $0 [--config FILE] [--output DIR] [--clean|--no-clean]"
                echo "Libraries to build are selected by *.version in config.txt"
                echo "(same as the Windows script). URLs are derived from version."
                exit 0
                ;;
            *)
                print_error "Unknown argument: $1"
                exit 1
                ;;
        esac
        shift
    done
}

function read_config() {
    local script_dir
    script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    if [[ ! -f "${CONFIG_FILENAME}" && -f "${script_dir}/${CONFIG_FILENAME}" ]]; then
        CONFIG_FILENAME="${script_dir}/${CONFIG_FILENAME}"
    fi
    if [[ ! -f "${CONFIG_FILENAME}" ]]; then
        print_error "Configuration file ( ${CONFIG_FILENAME} ) not found."
        exit 1
    fi

    print_info "Reading configuration file: ${CONFIG_FILENAME}"
    local key value
    while IFS= read -r line || [[ -n "${line}" ]]; do
        line="${line%%#*}"
        line="${line#"${line%%[![:space:]]*}"}"
        line="${line%"${line##*[![:space:]]}"}"
        [[ -z "${line}" || "${line}" != *=* ]] && continue
        key="${line%%=*}"
        value="${line#*=}"
        key="${key//[[:space:]]/}"
        value="${value#"${value%%[![:space:]]*}"}"
        value="${value%"${value##*[![:space:]]}"}"
        key="${key//./_}"
        printf -v "${key}" '%s' "${value}"
    done < "${CONFIG_FILENAME}"

    OPENSSL_VERSION="${openssl_version}"
    OPENSSL_SHA256="${openssl_sha256}"
    OPENSSL_TARBALL="${OPENSSL_TARBALL:-${openssl_tarball}}"
    BOOST_VERSION="${boost_version}"
    BOOST_SHA256="${boost_sha256}"
    BOOST_TARBALL="${BOOST_TARBALL:-${boost_tarball}}"
    LIBCURL_VERSION="${libcurl_version}"
    LIBCURL_SHA256="${libcurl_sha256}"
    LIBCURL_TARBALL="${LIBCURL_TARBALL:-${libcurl_tarball}}"
    GTEST_VERSION="${gtest_version}"
    GTEST_SHA256="${gtest_sha256}"
    GTEST_TARBALL="${GTEST_TARBALL:-${gtest_tarball}}"
    LIBSPDM_VERSION="${libspdm_version}"
    LIBSPDM_SHA256="${libspdm_sha256}"
    LIBSPDM_TARBALL="${LIBSPDM_TARBALL:-${libspdm_tarball}}"

}

function enable_builds_from_config() {
    [[ -n "${OPENSSL_VERSION}" ]] && BUILD_OPENSSL=true
    [[ -n "${LIBSPDM_VERSION}" ]] && BUILD_LIBSPDM=true
    [[ -n "${BOOST_VERSION}" && "${SPDM_WRAPPER_ONLY}" == false ]] && BUILD_BOOST=true
    [[ -n "${LIBCURL_VERSION}" && "${SPDM_WRAPPER_ONLY}" == false ]] && BUILD_LIBCURL=true
    [[ -n "${GTEST_VERSION}" && "${SPDM_WRAPPER_ONLY}" == false ]] && BUILD_GTEST=true
    if [[ -n "${aarch64}" && "${aarch64,,}" == "true" ]]; then
        BUILD_AARCH64=true
    fi
}

function resolve_download_url() {
    local library_name=$1
    local library_version=$2
    case "${library_name}" in
        openssl)
            echo "https://www.openssl.org/source/openssl-${library_version}.tar.gz"
            ;;
        boost)
            echo "https://archives.boost.io/release/${library_version}/source/boost_${library_version//./_}.tar.gz"
            ;;
        libcurl)
            echo "https://curl.se/download/curl-${library_version}.tar.gz"
            ;;
        gtest)
            echo "https://github.com/google/googletest/archive/refs/tags/v${library_version}.tar.gz"
            ;;
        libspdm)
            echo "https://github.com/DMTF/libspdm/archive/refs/tags/${library_version}.tar.gz"
            ;;
        *)
            print_error "No download URL template for ${library_name}"
            exit 1
            ;;
    esac
}

OUTPUT_FOLDER="${OUTPUT_FOLDER:-dependencies}"
HOME_DIR=""
OUTPUT_DIR=""
WORK_DIR=""

function verify_version_provided() {
    local variable_name=$1
    local variable_value=$2

    if [ -z "${variable_value}" ]; then
        print_error "${variable_name} not provided"
        exit 1
    fi
}

function openssl_root_dir() {
    echo "${OUTPUT_DIR}/openssl"
}

function detect_elf_arch() {
    local file=$1
    local desc machine
    if [[ ! -e "${file}" ]]; then
        echo "missing"
        return
    fi
    desc="$(file -b "${file}" 2>/dev/null || true)"
    if [[ "${desc}" == *"ARM aarch64"* || "${desc}" == *"aarch64"* ]]; then
        echo "aarch64"
        return
    fi
    if [[ "${desc}" == *"x86-64"* || "${desc}" == *"x86_64"* ]]; then
        echo "x86_64"
        return
    fi
    # lib*.a is an ar archive; file(1) only says "current ar archive".
    machine="$(readelf -h "${file}" 2>/dev/null | awk -F: '/Machine:/ {gsub(/^[ \t]+/, "", $2); print $2; exit}')"
    case "${machine}" in
        *AArch64*|*aarch64*) echo "aarch64" ;;
        *X86-64*|*x86-64*|*x86_64*) echo "x86_64" ;;
        *) echo "${desc:-unknown}" ;;
    esac
}

function expected_compiler_arch() {
    if [[ "$1" == "aarch64" ]]; then
        echo "aarch64"
    else
        echo "x86_64"
    fi
}

function require_matching_openssl_arch() {
    local arch=$1
    local openssl_root=$2
    local expected actual lib
    expected="$(expected_compiler_arch "${arch}")"

    if [[ ! -d "${openssl_root}" ]]; then
        print_error "OpenSSL for ${expected} not found at ${openssl_root}"
        print_error "Build openssl for this arch before generating libcurl/libspdm."
        exit 1
    fi

    lib="$(find "${openssl_root}" \( -name 'libssl.so*' -o -name 'libcrypto.so*' \) -type f 2>/dev/null | head -1)"
    if [[ -z "${lib}" ]]; then
        lib="$(find "${openssl_root}" \( -name 'libssl.a' -o -name 'libcrypto.a' \) -type f 2>/dev/null | head -1)"
    fi
    if [[ -z "${lib}" ]]; then
        print_error "No OpenSSL library found under ${openssl_root}/lib"
        exit 1
    fi

    actual="$(detect_elf_arch "${lib}")"
    if [[ "${actual}" != "${expected}" ]]; then
        print_error "Architecture mismatch — refuse to link:"
        print_error "  Compiler/linker: ${expected}"
        print_error "  OpenSSL:         ${actual}   <-- incompatible"
        print_error "  library:         ${lib}"
        exit 1
    fi
    print_info "OpenSSL arch OK: ${actual} (${lib})"
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

function verify_sha256() {
    local file=$1
    local expected=$2
    expected="$(printf '%s' "${expected}" | tr -d '[:space:]' | tr 'A-F' 'a-f')"
    if [[ -z "${expected}" ]]; then
        print_error "No SHA256 provided for ${file} — refuse to unpack"
        exit 1
    fi
    if [[ ! -f "${file}" ]]; then
        print_error "Tarball not found for SHA256 check: ${file}"
        exit 1
    fi
    print_info "Verifying SHA256 of ${file}"
    local actual
    actual="$(sha256sum "${file}" | awk '{print $1}' | tr 'A-F' 'a-f')"
    if [[ "${actual}" != "${expected}" ]]; then
        print_error "SHA256 mismatch for ${file}"
        print_error "  expected: ${expected}"
        print_error "  actual:   ${actual}"
        print_error "  size:     $(wc -c < "${file}") bytes"
        exit 1
    fi
    echo "${expected}  ${file}" | sha256sum -c - || {
        print_error "SHA256 mismatch for ${file}"
        exit 1
    }
}

# Args: name workdir dest_filename download_url expected_sha256 [local_tarball]
function downloadFromLibrarySource() {
    local library_name=$1
    local workdir=$2
    local library_full_filename=$3
    local download_url=$4
    local expected_sha256=$5
    local local_tarball=$6

    if [[ -n "${local_tarball}" ]]; then
        if [[ ! -f "${local_tarball}" ]]; then
            print_error "Local tarball not found: ${local_tarball}"
            exit 1
        fi
        local_tarball="$(cd "$(dirname "${local_tarball}")" && pwd)/$(basename "${local_tarball}")"
    fi

    mkdir -p "${workdir}" && cd "${workdir}" || {
        print_error "Failed to create and enter working directory: ${workdir}"
        exit 1
    }

    if [[ -n "${local_tarball}" ]]; then
        print_info "Using local tarball for ${library_name}: ${local_tarball}"
        cp -f "${local_tarball}" "${library_full_filename}" || {
            print_error "Failed to copy local tarball: ${local_tarball}"
            exit 1
        }
    elif [[ -f "${library_full_filename}" ]]; then
        print_info "Package for ${library_name} already present: ${library_full_filename}"
    else
        if [[ -z "${download_url}" ]]; then
            print_error "Download URL not provided for ${library_name}"
            exit 1
        fi
        print_info "---- Downloading ${library_name} from ${download_url} ----"
        aria2c --max-connection-per-server=16 --split=16 \
            --connect-timeout=300 --timeout=300 --max-tries=5 --retry-wait=2 \
            --allow-overwrite=true --auto-file-renaming=false --file-allocation=none \
            --dir=. --out="${library_full_filename}" \
            "${download_url}" || \
        wget --timeout=300 --read-timeout=300 --no-if-modified-since -N "${download_url}" -O "${library_full_filename}" || \
        curl --connect-timeout 300 --max-time 3600 -fL -o "${library_full_filename}" "${download_url}" || {
            print_error "Failed to download"
            exit 1
        }
    fi

    verify_sha256 "${library_full_filename}" "${expected_sha256}"
    if ! gzip -t "${library_full_filename}" 2>/dev/null; then
        print_error "Tarball is truncated or corrupt (gzip -t failed): ${library_full_filename}"
        print_error "  size: $(wc -c < "${library_full_filename}") bytes — re-download a complete archive"
        exit 1
    fi
    tar xzf "${library_full_filename}" || {
        print_error "Failed to unpack library"
        exit 1
    }
    cd "${HOME_DIR}" || exit 1
}

function handle_openssl() {
    local arch=$1
    local library_version=$2
    local library_name=openssl

    print_info "---- Building ${library_name}, version: ${library_version}, arch: ${arch} ----"

    local workdir="${WORK_DIR}/${library_name}_${arch}"

    local library_path=${workdir}/openssl-${library_version}
    local dest_filename="openssl-${library_version}.tar.gz"
    local url sha tarball
    url="$(resolve_download_url openssl "${library_version}")"
    sha="${OPENSSL_SHA256}"
    tarball="${OPENSSL_TARBALL}"

    downloadFromLibrarySource "${library_name}" "${workdir}" "${dest_filename}" "${url}" "${sha}" "${tarball}" && \
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
    local dest_filename="boost_${version_sed}.tar.gz"
    local url sha tarball
    url="$(resolve_download_url boost "${library_version}")"
    sha="${BOOST_SHA256}"
    tarball="${BOOST_TARBALL}"

    downloadFromLibrarySource "${library_name}" "${workdir}" "${dest_filename}" "${url}" "${sha}" "${tarball}" && \
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
    local dest_filename="curl-${library_version}.tar.gz"
    local url sha tarball
    url="$(resolve_download_url libcurl "${library_version}")"
    sha="${LIBCURL_SHA256}"
    tarball="${LIBCURL_TARBALL}"

    downloadFromLibrarySource "${library_name}" "${workdir}" "${dest_filename}" "${url}" "${sha}" "${tarball}" && \
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
    local dest_filename="gtest-${library_version}.tar.gz"

    downloadFromLibrarySource "${library_name}" "${workdir}" "${dest_filename}" \
        "$(resolve_download_url gtest "${library_version}")" "${GTEST_SHA256}" "${GTEST_TARBALL}" && \
    build_gtest "${library_name}" "${library_path}"

    print_info "---- Finished building: ${library_name}, version: ${library_version} ----"
}

function handle_libspdm() {
    local arch=$1
    local library_version=$2
    local library_name=libspdm

    print_info "---- Building ${library_name}, version: ${library_version}, arch: ${arch} ----"

    local workdir="${WORK_DIR}/${library_name}"

    local dest_filename="libspdm-${library_version}.tar.gz"
    local library_path=${workdir}/libspdm-${library_version}

    downloadFromLibrarySource "${library_name}" "${workdir}" "${dest_filename}" \
        "$(resolve_download_url libspdm "${library_version}")" "${LIBSPDM_SHA256}" "${LIBSPDM_TARBALL}" && \
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

    export OPENSSL_ROOT_DIR
    OPENSSL_ROOT_DIR="$(openssl_root_dir)"
    require_matching_openssl_arch "${arch}" "${OPENSSL_ROOT_DIR}"
    export CPPFLAGS="-I${OPENSSL_ROOT_DIR}/include ${CPPFLAGS}"
    export LDFLAGS="-L${OPENSSL_ROOT_DIR}/lib -Wl,-rpath,${OPENSSL_ROOT_DIR}/lib ${LDFLAGS}"
    export LD_LIBRARY_PATH="${OPENSSL_ROOT_DIR}/lib${LD_LIBRARY_PATH:+:${LD_LIBRARY_PATH}}"
    if [ "${arch}" = "aarch64" ]; then
        export CROSS_COMPILE="aarch64-linux-gnu"
        export AR=${CROSS_COMPILE}-ar
        export AS=${CROSS_COMPILE}-as
        export LD=${CROSS_COMPILE}-ld
        export RANLIB=${CROSS_COMPILE}-ranlib
        export CC=${CROSS_COMPILE}-gcc
        export NM=${CROSS_COMPILE}-nm
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

    local openssl_root_dir
    openssl_root_dir="$(openssl_root_dir)"
    require_matching_openssl_arch "x64" "${openssl_root_dir}"

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
    local dep_arch="x64"
    if [[ "$BUILD_AARCH64" = true ]]; then
        dep_arch="aarch64"
        print_info "aarch64=true — building openssl/boost/libcurl for aarch64 only"
    fi

    if [[ "$BUILD_OPENSSL" = true ]]; then
        verify_version_provided "OPENSSL_VERSION" "${OPENSSL_VERSION}"
        handle_openssl "${dep_arch}" "${OPENSSL_VERSION}"
    fi

    if [[ "$BUILD_BOOST" = true ]]; then
        verify_version_provided "BOOST_VERSION" "${BOOST_VERSION}"
        handle_boost "${dep_arch}" "${BOOST_VERSION}"
    fi

    if [[ "$BUILD_LIBCURL" = true ]]; then
        verify_version_provided "LIBCURL_VERSION" "${LIBCURL_VERSION}"
        handle_libcurl "${dep_arch}" "${LIBCURL_VERSION}"
    fi

    if [[ "$BUILD_GTEST" = true ]]; then
        if [[ "$BUILD_AARCH64" = true ]]; then
            print_info "Skipping gtest: it is x64-only (built on host); aarch64 docker only needs openssl/boost/libcurl"
        else
            verify_version_provided "GTEST_VERSION" "${GTEST_VERSION}"
            handle_gtest "x64" "${GTEST_VERSION}"
        fi
    fi

    if [[ "$BUILD_LIBSPDM" = true ]]; then
        if [[ "$BUILD_AARCH64" = true ]]; then
            print_info "Skipping libspdm: it is x64-only and cannot link the aarch64 OpenSSL in openssl/"
        else
            verify_version_provided "LIBSPDM_VERSION" "${LIBSPDM_VERSION}"
            handle_libspdm "x64" "${LIBSPDM_VERSION}"
        fi
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

    if ! command -v aria2c &> /dev/null; then
        print_info "aria2c not found. Installing..."
        sudo apt --yes install aria2
        check_error_code
        if ! command -v aria2c &> /dev/null; then
            print_error "Failed to install aria2. Aborting!"
            exit 1
        fi
    fi

    if ! command -v gcc &> /dev/null; then
        print_info "build-essential not found. Installing..."
        sudo apt --yes install build-essential
        check_error_code
        if ! command -v gcc &> /dev/null; then
            print_error "Failed to install build-essential. Aborting!"
            exit 1
        fi
    fi

    if [[ "$BUILD_AARCH64" == true ]]; then
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
    parse_args "$@"
    read_config
    enable_builds_from_config

    print_info "OPENSSL_VERSION is set to: ${OPENSSL_VERSION}"
    print_info "OPENSSL_SHA256 is set to: ${OPENSSL_SHA256}"
    print_info "BOOST_VERSION is set to: ${BOOST_VERSION}"
    print_info "BOOST_SHA256 is set to: ${BOOST_SHA256}"
    print_info "LIBCURL_VERSION is set to: ${LIBCURL_VERSION}"
    print_info "LIBCURL_SHA256 is set to: ${LIBCURL_SHA256}"
    print_info "GTEST_VERSION is set to: ${GTEST_VERSION}"
    print_info "GTEST_SHA256 is set to: ${GTEST_SHA256}"
    print_info "LIBSPDM_VERSION is set to: ${LIBSPDM_VERSION}"
    print_info "LIBSPDM_SHA256 is set to: ${LIBSPDM_SHA256}"
    print_info "OUTPUT_FOLDER is set to: ${OUTPUT_FOLDER}"

    prepare_building_environment
    clean_directory
    check_required_tools
    check_cmake
    doit

    print_info "Done"
}

main "$@"
