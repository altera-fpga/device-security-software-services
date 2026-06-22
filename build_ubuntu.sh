#!/bin/bash

#
# This project is licensed as below.
#
# ***************************************************************************
#
# Copyright 2020-2025 Altera Corporation. All Rights Reserved.
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

OPENSSL_VERSION="3.1.4"
BOOST_VERSION="1.84.0"
LIBCURL_VERSION="8.5.0"
GTEST_VERSION="1.14.0"
LIBSPDM_VERSION="3.2.0"
MINIMUM_JAVA_VERSION="17.0.0"
BKPS_BUILD_VERSION="${BKPS_BUILD_VERSION:-0.0.1}"
BKPS_OUTPUT_BASE_NAME="${BKPS_OUTPUT_BASE_NAME:-bkpq}"

set -E -o pipefail

FCSSERVER_IMAGE_NAME="fcsserver-builder"
FCS_DOCKER_BUILD_DIR="/fcs-server"
BKPPROG_IMAGE_NAME="bkpprogrammer-builder"
BKPPROG_DOCKER_BUILD_DIR="/bkpprogrammer"
CONTAINER_ID=

# path from bkps/src/integrationTest/resources/config/application.yml ssl.bundle.jks.web-server.truststore.location
TRUSTSTORE_PATH="/tmp/bkps-nonprod.p12"

REQUIRED_PACKAGE_NOT_INSTALLED="\n\n++++++++++ Package %s not installed. Try to install... +++++++++++++++\n\n"
REQUIRED_PACKAGE_INSTALLED="\n\n++++++++++++++++ Package %s already installed ++++++++++++++++++++++++\n\n"
BUILD_WRAPPER="\n\n+++++++++++++++++++++ BUILD SPDM WRAPPER +++++++++++++++++++++++++++++\n\n"
BUILD_BKPPROGRAMMER="\n\n+++++++++++++++++++++ BUILD BKPPROGRAMMER ++++++++++++++++++++++++++++\n\n"
BUILD_FCSSERVER="\n\n+++++++++++++++++++++ BUILD FCS SERVER +++++++++++++++++++++++++++++++\n\n"
BUILD_SQL_SCHEMA="\n\n+++++++++++++++++++++ BUILD SQL SCHEMA +++++++++++++++++++++++++++++++\n\n"
LOG_PRIVILEGED_REQUIRED="\n\n++++++++++++++++++++++ Cannot connect to the Docker daemon ++++++++++++++++++++++
+++++++ If running docker from docker, make sure to give extended privileges ++++
++++++++ to host container (docker run --privileged) ++++++++++++++++++++++++++++\n\n"

LOG_SUCCESS="\n\n++++++++++++++++++++++++++++++++ SUCCESS ++++++++++++++++++++++++++++++++++++++++\n\n"
LOG_FAILURE="\n\n++++++++++++++++++++++++++++++++ FAILURE ++++++++++++++++++++++++++++++++++++++++\n\n"
LOG_OUTPUT="\n\n+++++++++++++++++++++++++++++ Output folder: %s ++++++++++++++++++++++++++++++++++++\n"

CURRENT_SCRIPT_PATH=$(dirname "$0")
cd "$CURRENT_SCRIPT_PATH" || exit 1
CURRENT_SCRIPT_PATH=$(pwd)
printf "\n\n+++++++++++++++++++++++++++++++++ Current script path: %s ++++++++++++++++++++++++++++\n\n" "${CURRENT_SCRIPT_PATH}"

OUT_PATH=${CURRENT_SCRIPT_PATH}/out
SPDM_WRAPPER_PATH=${CURRENT_SCRIPT_PATH}/spdm_wrapper
BKPPROGRAMMER_PATH=${CURRENT_SCRIPT_PATH}/bkpprogrammer
FCS_PATH=${CURRENT_SCRIPT_PATH}/FCS
openssl_root_dir=${CURRENT_SCRIPT_PATH}/dependencies/openssl
libspdm_root_dir=${CURRENT_SCRIPT_PATH}/dependencies/libspdm
boost_root_dir=${CURRENT_SCRIPT_PATH}/dependencies/boost
gtest_root_dir=${CURRENT_SCRIPT_PATH}/dependencies/gtest
libcurl_root_dir=${CURRENT_SCRIPT_PATH}/dependencies/libcurl

function build_spdm_wrapper() {
    printf "${BUILD_WRAPPER}"
    cd "${SPDM_WRAPPER_PATH}" || return 1
    local cmake_build_type=Release
    local sources_dir=$(pwd)
    local build_dir="build/${cmake_build_type}"
    mkdir -p "${build_dir}" && cd "${build_dir}" || return 1

    CMAKE_OPTS="-DCMAKE_BUILD_TYPE=${cmake_build_type}"
    echo "cmake ${CMAKE_OPTS} ${sources_dir}"
    cmake ${CMAKE_OPTS} "${sources_dir}"
    check_error_code

    echo "cmake --build . -- -j $(nproc)"
    cmake --build . -- -j $(nproc)
    check_error_code

    cd "${CURRENT_SCRIPT_PATH}" || return 1
    mkdir -p "${OUT_PATH}/spdm_wrapper/" || return 1
    cp -r "${SPDM_WRAPPER_PATH}"/build/Release/* "${OUT_PATH}/spdm_wrapper/" || return 1
}

function build_bkpprogrammer() {
    if ! check_if_docker_daemon_can_run; then
        print_error "Docker is required for BKPProgrammer, but Docker is not available."
        return 1
    fi

    printf "${BUILD_BKPPROGRAMMER}"
    if ! build_bkpprogrammer_internal; then
        printf "${LOG_FAILURE}"
        cd "${CURRENT_SCRIPT_PATH}" || return 1
        return 1
    fi
    printf "${LOG_SUCCESS}"
    mkdir -p "${OUT_PATH}/bkpprogrammer/" || return 1
    cp "${BKPPROGRAMMER_PATH}/docker/out_docker/libbkpprog.so" "${OUT_PATH}/bkpprogrammer/" || return 1
    cp "${BKPPROGRAMMER_PATH}/docker/out_docker/MinSizeRel/src/bkp_app/bkp_app" "${OUT_PATH}/bkpprogrammer/" || return 1
    cp "${BKPPROGRAMMER_PATH}"/docker/out_docker/libgcc_* "${OUT_PATH}/bkpprogrammer/" || return 1
    cp "${BKPPROGRAMMER_PATH}/docker/out_docker/libstdc++.so.6.0.25" "${OUT_PATH}/bkpprogrammer/" || return 1
    cd "${CURRENT_SCRIPT_PATH}" || return 1
}

function build_fcsserver() {
    if ! check_if_docker_daemon_can_run; then
        print_error "Docker is required for FCSServer, but Docker is not available."
        return 1
    fi

    printf "${BUILD_FCSSERVER}"
    if ! build_fcs_server_internal; then
        printf "${LOG_FAILURE}"
        cd "${CURRENT_SCRIPT_PATH}" || return 1
        return 1
    fi
    printf "${LOG_SUCCESS}"
    mkdir -p "${OUT_PATH}/FCS/" || return 1
    cp -r "${FCS_PATH}"/docker/out_docker/* "${OUT_PATH}/FCS/" || return 1
    cd "${CURRENT_SCRIPT_PATH}" || return 1
}

function install_package_if_does_not_exist() {
    local REQUIRED_PKG=$1
    check_if_package_exist "${REQUIRED_PKG}"
    if [[ $? -eq 1 ]]; then
        install_package "${REQUIRED_PKG}" || exit 1
    fi
}

function check_if_package_exist() {
    local REQUIRED_PKG=$1
    local PKG_OK
    PKG_OK=$(dpkg-query -W --showformat='${Status}\n' "${REQUIRED_PKG}" 2>/dev/null | grep "install ok installed")
    echo "Checking for ${REQUIRED_PKG}: ${REQUIRED_PKG}"
    if [ "install ok installed" = "$PKG_OK" ]; then
        printf "${REQUIRED_PACKAGE_INSTALLED}" "$REQUIRED_PKG"
        return 0
    else
        printf "${REQUIRED_PACKAGE_NOT_INSTALLED}" "$REQUIRED_PKG"
        return 1
    fi
}

function install_package() {
    local REQUIRED_PKG=$1
    echo "No ${REQUIRED_PKG}. Setting up ${REQUIRED_PKG}."
    sudo apt update || return 1
    sudo apt --yes install "${REQUIRED_PKG}"
}

function check_java() {
    if type -p java; then
        echo "Found java executable in PATH"
        _java=java
    elif [[ -n "$JAVA_HOME" ]] && [[ -x "$JAVA_HOME/bin/java" ]]; then
        echo "Found java executable in JAVA_HOME"
        _java="$JAVA_HOME/bin/java"
    else
        echo "No Java found. Install OPENJDK"
        install_package_if_does_not_exist openjdk-17-jdk
        _java=java
    fi

    if [[ "$_java" ]]; then
        version=$("$_java" -version 2>&1 | awk -F '"' '/version/ {print $2}')
        echo "Java version: $version"
        ver_comp "$version" $MINIMUM_JAVA_VERSION
        comp=$?
        if [[ $comp -lt 2 ]]; then
            echo "Your Java version is sufficient"
        else
            echo "Please update Java to version >=$MINIMUM_JAVA_VERSION"
            exit 1
        fi
    fi
}

function ver_comp() {
    # shellcheck disable=SC2053
    if [[ $1 == $2 ]]; then
        return 0
    fi
    local IFS=.
    # shellcheck disable=SC2206
    local i ver1=($1) ver2=($2)
    # fill empty fields in ver1 with zeros
    for ((i = ${#ver1[@]}; i < ${#ver2[@]}; i++)); do
        ver1[i]=0
    done
    for ((i = 0; i < ${#ver1[@]}; i++)); do
        if [[ -z ${ver2[i]} ]]; then
            # fill empty fields in ver2 with zeros
            ver2[i]=0
        fi
        if ((10#${ver1[i]} > 10#${ver2[i]})); then
            return 1
        fi
        if ((10#${ver1[i]} < 10#${ver2[i]})); then
            return 2 # normally would be -1
        fi
    done
    return 0
}

function check_if_require_privileged() {
    if { docker ps 2>&1 >&3 3>&- | grep '^' >&2; } 3>&1; then
        case $(docker ps 2>&1) in
        *"Cannot connect to the Docker daemon at unix:///var/run/docker.sock."*)
            printf "${LOG_PRIVILEGED_REQUIRED}"
            return 0
            ;;
        *) return 1 ;;
        esac
    fi
    return 1
}

function check_if_docker_daemon_can_run() {
    if command -v docker > /dev/null 2>&1; then
        check_if_require_privileged
        if [[ $? -eq 0 ]]; then
            return 1
        fi

        if docker ps; then
            echo "Docker daemon is available."
            return 0
        fi
    else
        print_info "Docker is not installed."
    fi

    install_docker || return 1

    # 2. INJECT THE FIX HERE: Set up and start the daemon ONLY if inside a nested container
    if [[ -f /.dockerenv ]] || grep -sqE 'docker|containerd' /proc/1/cgroup; then
        if ! docker ps > /dev/null 2>&1; then
            echo "Starting background Docker daemon for nested container environment..."
            apt-get install -y iptables kmod > /dev/null 2>&1
            mkdir -p /var/run /var/log /var/lib/docker
            dockerd --storage-driver=vfs --data-root=/var/lib/docker > /var/log/dockerd.log 2>&1 &

            # Stalls for up to 10 seconds to let the socket file generate
            for i in {1..10}; do
                docker ps > /dev/null 2>&1 && break
                sleep 1
            done
        fi
    else
        echo "Host environment detected. Skipping nested Docker daemon setup."
    fi

    if ! command -v docker > /dev/null 2>&1; then
        print_error "Docker installation completed, but docker was not found in PATH."
        return 1
    fi

    if docker ps; then
        echo "Docker daemon is available."
        return 0
    fi

    check_if_require_privileged
    return 1
}

function install_docker() {
    if [[ "$DOCKER_REQUIRED" == false ]]; then
        return 0
    fi
    printf "${REQUIRED_PACKAGE_NOT_INSTALLED}" "docker"
    curl -fsSL https://get.docker.com -o install-docker.sh || return 1
    chmod +x install-docker.sh || return 1
    sudo sh install-docker.sh || return 1
}

function copy_dependencies() {
    local destination_folder=$1
    local dependency_folder=$2

    local DEPENDENCIES_FOLDER=${destination_folder}/dependencies/
    mkdir -p "${DEPENDENCIES_FOLDER}" || return 1
    cp -r "${dependency_folder}" "${DEPENDENCIES_FOLDER}" || return 1
}

function create_dummy_key_if_does_not_exist() {
    if [ -f "${TRUSTSTORE_PATH}" ]; then
        if keytool -list -keystore "${TRUSTSTORE_PATH}" -storepass donotchange -alias dummy; then
            return
        fi
    fi
    keytool -genkey -keyalg RSA -keystore "${TRUSTSTORE_PATH}" -keysize 2048 -keypass donotchange -storepass donotchange -dname "CN=Developer, OU=Department, O=Company, L=City, ST=State, C=CA" -alias dummy
}

function build_fcs_server_internal() {
    cd "${FCS_PATH}/docker/" || return 1
    build_docker "${FCSSERVER_IMAGE_NAME}"
    local build_result=$?
    if [[ ${build_result} -eq 2 ]]; then
        printf "${LOG_PRIVILEGED_REQUIRED}"
        cd "${CURRENT_SCRIPT_PATH}" || return 1
        return 1
    elif [[ ${build_result} -ne 0 ]]; then
        cd "${CURRENT_SCRIPT_PATH}" || return 1
        return 1
    fi
    run_container "${FCSSERVER_IMAGE_NAME}" || return 1

    copy_files_to_docker_fcs || { clean_container; return 1; }
    run_build_fcs || { clean_container; return 1; }
    copy_files_from_docker_fcs || { clean_container; return 1; }

    clean_container
    echo "Done"
}

function build_bkpprogrammer_internal() {
    cd "${BKPPROGRAMMER_PATH}/docker/" || return 1
    build_docker "${BKPPROG_IMAGE_NAME}"
    local build_result=$?
    if [[ ${build_result} -eq 2 ]]; then
        printf "${LOG_PRIVILEGED_REQUIRED}"
        cd "${CURRENT_SCRIPT_PATH}" || return 1
        return 1
    elif [[ ${build_result} -ne 0 ]]; then
        cd "${CURRENT_SCRIPT_PATH}" || return 1
        return 1
    fi
    run_container "${BKPPROG_IMAGE_NAME}" || return 1

    copy_files_to_docker_bkpprogrammer || { clean_container; return 1; }
    run_build_bkpprogrammer || { clean_container; return 1; }
    copy_files_from_docker_bkpprogrammer || { clean_container; return 1; }

    clean_container
    echo "Done"
}

function build_docker() { #FCSSERVER_IMAGE_NAME ${FCS_PATH}/docker/
    local image_name=$1

    if docker image inspect "${image_name}" > /dev/null 2>&1; then
        return 0
    fi

    echo "--- Build docker image ${image_name} ---"
    local build_output
    build_output=$(docker build -t "${image_name}" -f Dockerfile . 2>&1)
    local build_status=$?
    echo "${build_output}"

    if echo "${build_output}" | grep -q "failed to solve: failed to read dockerfile: failed to mount"; then
        return 2
    fi

    if [[ ${build_status} -ne 0 ]]; then
        echo "Building docker failed!"
        return 1
    fi

    return 0
}

function run_container() {
    local image_name=$1
    echo "--- Run docker container ---"
    CONTAINER_ID=$(docker run --interactive --detach "${image_name}") || return 1
}

function clean_container() {
    echo "--- Clean docker container ---"
    if [[ -n "${CONTAINER_ID}" ]]; then
        docker stop "${CONTAINER_ID}" || return 1
        docker rm "${CONTAINER_ID}" || return 1
        CONTAINER_ID=
    fi
}

function copy_files_to_docker_fcs() {
    echo "--- Copy files to docker ---"
    docker exec --interactive "${CONTAINER_ID}" mkdir -p FCSFilter || return 1
    docker exec --interactive "${CONTAINER_ID}" mkdir -p FCSServer || return 1
    docker cp "${FCS_PATH}/FCSFilter/include/." "${CONTAINER_ID}:${FCS_DOCKER_BUILD_DIR}/FCSFilter/include" || return 1
    docker cp "${FCS_PATH}/FCSFilter/src/." "${CONTAINER_ID}:${FCS_DOCKER_BUILD_DIR}/FCSFilter/src" || return 1
    docker cp "${FCS_PATH}/FCSServer/src/." "${CONTAINER_ID}:${FCS_DOCKER_BUILD_DIR}/FCSServer/src" || return 1
    docker cp "${FCS_PATH}/FCSFilter/test/." "${CONTAINER_ID}:${FCS_DOCKER_BUILD_DIR}/FCSFilter/test" || return 1
    docker cp "${FCS_PATH}/Makefile" "${CONTAINER_ID}:${FCS_DOCKER_BUILD_DIR}" || return 1
    docker cp "${FCS_PATH}/build_gtest.sh" "${CONTAINER_ID}:${FCS_DOCKER_BUILD_DIR}" || return 1
    docker cp "${FCS_PATH}/FCSServer/install.sh" "${CONTAINER_ID}:${FCS_DOCKER_BUILD_DIR}/FCSServer" || return 1
    docker cp "${FCS_PATH}/FCSServer/fcsServer.service" "${CONTAINER_ID}:${FCS_DOCKER_BUILD_DIR}/FCSServer" || return 1
}

function copy_files_to_docker_bkpprogrammer() {
    echo "--- Copy files to docker ---"
    docker cp "${BKPPROGRAMMER_PATH}/src/." "${CONTAINER_ID}:${BKPPROG_DOCKER_BUILD_DIR}/src" || return 1
    docker cp "${BKPPROGRAMMER_PATH}/CMakeLists.txt" "${CONTAINER_ID}:${BKPPROG_DOCKER_BUILD_DIR}" || return 1
    docker cp "${CURRENT_SCRIPT_PATH}/build-dependencies.sh" "${CONTAINER_ID}:/" || return 1
    docker cp "${FCS_PATH}/." "${CONTAINER_ID}:/FCS" || return 1
}

function run_build_fcs() {
    echo "--- Make FCSServer ---"
    docker exec --interactive "${CONTAINER_ID}" make build || return 1
    docker exec --interactive "${CONTAINER_ID}" make test || return 1

}

function run_build_bkpprogrammer() {
    docker exec --interactive "${CONTAINER_ID}" ../build-dependencies.sh OPENSSL_AARCH64_VERSION="${OPENSSL_VERSION}" BOOST_AARCH64_VERSION="${BOOST_VERSION}" LIBCURL_AARCH64_VERSION="${LIBCURL_VERSION}" || return 1
    docker exec --interactive "${CONTAINER_ID}" bash -c "mkdir -p build/MinSizeRel && cd build/MinSizeRel && cmake -DHPS_BUILD:BOOL=ON ../.. && cmake --build ." || return 1
}

function copy_files_from_docker_fcs() {
    echo "--- Copy FCSServer artifacts from docker ---"
    rm -rf ./out_docker
    mkdir ./out_docker || return 1
    docker cp "${CONTAINER_ID}:${FCS_DOCKER_BUILD_DIR}/out/." ./out_docker/ || return 1
}

function copy_files_from_docker_bkpprogrammer() {
    echo "--- Copy BKPProgrammer artifacts from docker ---"
    rm -rf ./out_docker
    mkdir ./out_docker || return 1
    docker cp "${CONTAINER_ID}:${BKPPROG_DOCKER_BUILD_DIR}/build/." ./out_docker/ || return 1
    docker cp "${CONTAINER_ID}:/usr/aarch64-linux-gnu/lib/libstdc++.so.6.0.25" ./out_docker/ || return 1
    docker cp "${CONTAINER_ID}:/usr/aarch64-linux-gnu/lib/libgcc_s.so.1" ./out_docker/ || return 1
}

function print_info() {
    local message=$1
    echo -e "\e[1;33m$message\e[0m"
}

function print_error() {
    local message=$1
    echo -e "\e[1;31mERROR: $message\e[0m"
}

function check_error_code() {
    ERROR_CODE="$?"
    if [[ "$ERROR_CODE" != "0" ]]; then
        echo -e "\e[1;31mERROR: Build failed with error code $ERROR_CODE! Aborting!\e[0m"
        exit 1
    fi
}

DOCKER_REQUIRED=false

function prompt_docker_required() {
    echo
    echo "Docker is optional."
    echo
    echo "If you choose yes:"
    echo "  - The script will build FCSServer."
    echo "  - The script will build BKPProgrammer."
    echo "  - Docker is required. If Docker is missing, the script will try to install it."
    echo
    echo "If you choose no:"
    echo "  - FCSServer build will be skipped."
    echo "  - BKPProgrammer build will be skipped."
    echo "  - The main BKPS Java components and SPDM wrapper build will still run."
    echo

    read -r -p "Do you want to enable Docker-dependent builds and allow Docker installation if needed? [y/N]: " response
    case "$response" in
        [yY][eE][sS]|[yY])
            DOCKER_REQUIRED=true
            print_info "Docker-dependent builds enabled."
            ;;
        *)
            DOCKER_REQUIRED=false
            print_info "Skipping FCSServer and BKPProgrammer because Docker was not enabled."
            ;;
    esac
}

function build_sql_schema() {
    printf "${BUILD_SQL_SCHEMA}"

    local sql_schema_file="${CURRENT_SCRIPT_PATH}/bkps/bkps-${BKPS_BUILD_VERSION}.sql"
    local changelog_file="${CURRENT_SCRIPT_PATH}/bkps/changelog-bkps-${BKPS_BUILD_VERSION}.csv"

    rm -f "${sql_schema_file}" "${changelog_file}" || return 1

    KEYSTORE_DUMMY_ALIAS=dummy ./gradlew -Pprod -Paws -Pversion="${BKPS_BUILD_VERSION}" -Dversion="${BKPS_BUILD_VERSION}" :bkps:liquibaseGenerateSql || return 1

    if [[ ! -s "${sql_schema_file}" ]]; then
        print_error "SQL schema file was not generated: ${sql_schema_file}"
        return 1
    fi

    cp "${sql_schema_file}" "${OUT_PATH}/" || return 1
    print_info "SQL schema copied to ${OUT_PATH}/$(basename "${sql_schema_file}")"
}

function copy_bkps_jar() {
    local source_jar=""
    local output_jar="${OUT_PATH}/${BKPS_OUTPUT_BASE_NAME}.${BKPS_BUILD_VERSION}.jar"

    source_jar=$(find "${CURRENT_SCRIPT_PATH}/bkps/build/libs" -maxdepth 1 -type f -name "*.jar" ! -name "*-plain.jar" 2>/dev/null | sort | head -n 1)

    if [[ -z "${source_jar}" || ! -s "${source_jar}" ]]; then
        print_error "BKPS JAR was not found under ${CURRENT_SCRIPT_PATH}/bkps/build/libs"
        return 1
    fi

    rm -f "${OUT_PATH}/bkps.jar" "${OUT_PATH}/bkps-"*.jar "${OUT_PATH}/${BKPS_OUTPUT_BASE_NAME}."*.jar || return 1
    cp "${source_jar}" "${output_jar}" || return 1
    print_info "BKPS JAR copied to ${output_jar}"
}

function print_generated_files_summary() {
    echo
    echo "==================== Generated Files Summary ===================="
    echo "Output folder:"
    echo "  ${OUT_PATH}"
    echo

    echo "BKPS Java artifacts:"
    find "${OUT_PATH}" -maxdepth 1 -type f -name "*.jar" -printf "  %p\n" 2>/dev/null || true
    echo

    echo "SQL schema:"
    find "${OUT_PATH}" -maxdepth 1 -type f -name "*.sql" -printf "  %p\n" 2>/dev/null || true
    echo

    echo "SPDM wrapper artifacts:"
    find "${OUT_PATH}/spdm_wrapper" -type f \( -name "*.so" -o -name "*.so.*" -o -name "*.a" \) -printf "  %p\n" 2>/dev/null || true
    echo

    if [[ "$DOCKER_REQUIRED" == true ]]; then
        echo "FCSServer artifacts:"
        find "${OUT_PATH}/FCS" -maxdepth 2 -type f -printf "  %p\n" 2>/dev/null || true
        echo

        echo "BKPProgrammer artifacts:"
        find "${OUT_PATH}/bkpprogrammer" -maxdepth 1 -type f -printf "  %p\n" 2>/dev/null || true
        echo
    else
        echo "Docker-dependent artifacts:"
        echo "  FCSServer and BKPProgrammer were skipped because Docker was not enabled."
        echo
    fi

    echo "Configuration:"
    find "${OUT_PATH}" -maxdepth 1 -type f -name "config.properties" -printf "  %p\n" 2>/dev/null || true
    echo "================================================================="
}

main() {
    mkdir -p "${OUT_PATH}"
    check_error_code

    prompt_docker_required          # <-- ask user first

    install_package_if_does_not_exist tar
    install_package_if_does_not_exist wget
    install_package_if_does_not_exist cmake
    install_package_if_does_not_exist make
    install_package_if_does_not_exist build-essential
    install_package_if_does_not_exist curl
    install_package_if_does_not_exist perl
    install_package_if_does_not_exist python3

    ./build-dependencies.sh OPENSSL_VERSION="${OPENSSL_VERSION}" LIBSPDM_VERSION="${LIBSPDM_VERSION}" \
        BOOST_VERSION="${BOOST_VERSION}" LIBCURL_VERSION="${LIBCURL_VERSION}" \
        GTEST_VERSION="${GTEST_VERSION}"
    check_error_code

    copy_dependencies "${SPDM_WRAPPER_PATH}" "${openssl_root_dir}"
    check_error_code
    copy_dependencies "${SPDM_WRAPPER_PATH}" "${libspdm_root_dir}"
    check_error_code
    copy_dependencies "${BKPPROGRAMMER_PATH}" "${libcurl_root_dir}"
    check_error_code
    copy_dependencies "${BKPPROGRAMMER_PATH}" "${gtest_root_dir}"
    check_error_code
    copy_dependencies "${BKPPROGRAMMER_PATH}" "${boost_root_dir}"
    check_error_code
    copy_dependencies "${BKPPROGRAMMER_PATH}" "${openssl_root_dir}"
    check_error_code

    build_spdm_wrapper
    check_error_code

    if [[ "$DOCKER_REQUIRED" == true ]]; then   # <-- gate Docker-dependent builds
        build_fcsserver
        check_error_code
        build_bkpprogrammer
        check_error_code
    fi

    check_java
    create_dummy_key_if_does_not_exist
    check_error_code
    KEYSTORE_DUMMY_ALIAS=dummy ./gradlew -Pversion="${BKPS_BUILD_VERSION}" -Dversion="${BKPS_BUILD_VERSION}" clean build deploy
    check_error_code
    build_sql_schema
    check_error_code
    copy_bkps_jar
    check_error_code
    cp ./workload/build/libs/* "${OUT_PATH}/"
    check_error_code
    cp ./Verifier/build/libs/* "${OUT_PATH}/"
    check_error_code
    cp ./Verifier/src/main/resources/config.properties "${OUT_PATH}/"
    check_error_code
    printf "${LOG_OUTPUT}" "${OUT_PATH}"
    print_generated_files_summary
}

main "$@"
