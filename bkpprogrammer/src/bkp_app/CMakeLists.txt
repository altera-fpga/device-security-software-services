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

set(TARGET_NAME bkp_app)
set(FCS_FILTER_DIR ${BASE_PATH}/../FCS/FCSFilter)


set(TARGET_FILE_PATH ${BASE_PATH}/build/${CMAKE_BUILD_TYPE})

include_directories(../core/headers)
include_directories(${FCS_FILTER_DIR}/src)
include_directories(${FCS_FILTER_DIR}/include)

file(GLOB SOURCE_FILES *.cpp)
file(GLOB FCS_SOURCE_FILES ${FCS_FILTER_DIR}/src/*.cpp)
add_executable(bkp_app ${SOURCE_FILES} ${FCS_SOURCE_FILES} ${MOCK_FILES})


if(NOT DEFINED DEPENDENCIES_PATH)
    set(DEPENDENCIES_PATH ${CMAKE_SOURCE_DIR}/dependencies)
endif()
set(OPENSSL_LIB_DIR ${DEPENDENCIES_PATH}/openssl/lib)
set(OPENSSL_INCLUDE_DIR ${DEPENDENCIES_PATH}/openssl/include)
set(LIBCURL_LIB_DIR ${DEPENDENCIES_PATH}/libcurl/lib)
set(LIBCURL_INCLUDE_DIR ${DEPENDENCIES_PATH}/libcurl/include)
set(BOOST_LIB_DIR ${DEPENDENCIES_PATH}/boost/lib)
set(BOOST_INCLUDE_DIR ${DEPENDENCIES_PATH}/boost/include)

target_include_directories(${TARGET_NAME} SYSTEM PRIVATE ${OPENSSL_INCLUDE_DIR} ${LIBCURL_INCLUDE_DIR} ${BOOST_INCLUDE_DIR})
target_link_libraries(${TARGET_NAME} PRIVATE
    ${LIBCURL_LIB_DIR}/libcurl.so
    ${OPENSSL_LIB_DIR}/libcrypto.so
    ${OPENSSL_LIB_DIR}/libssl.so
    ${BOOST_LIB_DIR}/libboost_program_options.a
    dl
    pthread
    bkpprog
)

add_custom_command(
        TARGET ${TARGET_NAME} POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy
        ${CMAKE_SOURCE_DIR}/src/bkp_app/bkp_options.txt
        ${CMAKE_CURRENT_BINARY_DIR}/bkp_options.txt)

