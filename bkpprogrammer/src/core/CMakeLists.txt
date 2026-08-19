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

set(TARGET_NAME bkpprog)
set(TARGET_FILE_PATH ${BASE_PATH}/build/${CMAKE_BUILD_TYPE})

if(DEFINED BUILD_VERSION)
    set(BKP_PROGRAMMER_VERSION ${BUILD_VERSION})
else()
    set(BKP_PROGRAMMER_VERSION "1.0.0.0")
endif()

#Insert version to header file
set(VERSION_FILENAME version.h)
set(BASE_HEADER_VERSION_PATH ${BASE_PATH}/src/core/headers/${VERSION_FILENAME})
configure_file(${BASE_HEADER_VERSION_PATH}.in ${BASE_HEADER_VERSION_PATH})

include_directories(headers)
file(GLOB_RECURSE SOURCES "cpp/*.cpp")

add_library(${TARGET_NAME} SHARED ${SOURCES})


if(NOT DEFINED DEPENDENCIES_PATH)
    set(DEPENDENCIES_PATH ${CMAKE_SOURCE_DIR}/dependencies)
endif()
set(OPENSSL_LIB_DIR ${DEPENDENCIES_PATH}/openssl/lib)
set(OPENSSL_INCLUDE_DIR ${DEPENDENCIES_PATH}/openssl/include)
set(LIBCURL_LIB_DIR ${DEPENDENCIES_PATH}/libcurl/lib)
set(LIBCURL_INCLUDE_DIR ${DEPENDENCIES_PATH}/libcurl/include)
set(BOOST_LIB_DIR ${DEPENDENCIES_PATH}/boost/lib)
set(BOOST_INCLUDE_DIR ${DEPENDENCIES_PATH}/boost/include)

target_include_directories(${TARGET_NAME} SYSTEM PRIVATE ${OPENSSL_INCLUDE_DIR})
target_include_directories(${TARGET_NAME} SYSTEM PRIVATE ${LIBCURL_INCLUDE_DIR})
target_include_directories(${TARGET_NAME} SYSTEM PRIVATE ${BOOST_INCLUDE_DIR})
if (NOT WIN32)
    target_link_libraries(${TARGET_NAME} PRIVATE
        ${LIBCURL_LIB_DIR}/libcurl.so
        ${OPENSSL_LIB_DIR}/libcrypto.so
        ${OPENSSL_LIB_DIR}/libssl.so)
else()
    file(GLOB libboost_container_file "${BOOST_LIB_DIR}/libboost_container*.lib")
    file(GLOB libboost_json_file "${BOOST_LIB_DIR}/libboost_json*.lib")
    target_link_libraries(${TARGET_NAME} PRIVATE
        ${libboost_container_file}
        ${libboost_json_file})
    target_link_libraries(${TARGET_NAME} PRIVATE
        ${LIBCURL_LIB_DIR}/libcurl.lib
        ${OPENSSL_LIB_DIR}/libcrypto.lib
        ${OPENSSL_LIB_DIR}/libssl.lib
        ${libboost_container_file}
        ${libboost_json_file})
endif ()

function(copy_result_to_release target extension)
    if (WIN32)
        set(prefix "")
        set(SOURCE_NAME ${CMAKE_BINARY_DIR}/src/core/${CMAKE_BUILD_TYPE}/${prefix}${target}.${extension})
    else ()
        set(prefix lib)
        set(SOURCE_NAME ${CMAKE_BINARY_DIR}/src/core/${prefix}${target}.${extension})
    endif()
    set(TARGET_NAME ${TARGET_FILE_PATH}/${prefix}${target}.${extension})


    add_custom_command(TARGET ${target} POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
            ${SOURCE_NAME} ${TARGET_NAME}
            COMMENT "Copying '${SOURCE_NAME}' to '${TARGET_NAME}'"
            )
endfunction(copy_result_to_release)

if (WIN32)
    copy_result_to_release(${TARGET_NAME} dll)
    copy_result_to_release(${TARGET_NAME} lib)
    copy_result_to_release(${TARGET_NAME} exp)
    copy_result_to_release(${TARGET_NAME} pdb)
    copy_result_to_release(${TARGET_NAME} ilk)
else ()
    copy_result_to_release(${TARGET_NAME} so)
    file(GLOB SO_FILES
            "${OPENSSL_LIB_DIR}/*.so*"
            "${LIBCURL_LIB_DIR}/*.so*"
            )
    file(COPY ${SO_FILES} DESTINATION ${DEPENDENCIES_PATH}/lib)

endif ()

set_property(DIRECTORY PROPERTY ADDITIONAL_MAKE_CLEAN_FILES
        "${BASE_HEADER_VERSION_PATH}"
        "${TARGET_FILE_PATH}"
        )
