file(GLOB_RECURSE SOURCES "*.cpp" "*.h")
add_library(libspdm_wrapper SHARED ${SOURCES})

#    Order of the libraries is important
if(CMAKE_COMPILER_IS_GNUCC OR CMAKE_COMPILER_IS_GNUCXX)
    target_link_libraries(libspdm_wrapper PRIVATE
            ${LIBSPDM_LIB_DIR}/libspdm_requester_lib.a
            ${LIBSPDM_LIB_DIR}/libspdm_transport_mctp_lib.a
            ${LIBSPDM_LIB_DIR}/libspdm_secured_message_lib.a
            ${LIBSPDM_LIB_DIR}/libspdm_crypt_lib.a
            ${LIBSPDM_LIB_DIR}/libspdm_common_lib.a
            ${OPENSSL_LIB_DIR}/libcrypto.a
            ${OPENSSL_LIB_DIR}/libssl.a
            ${LIBSPDM_LIB_DIR}/librnglib.a
            ${LIBSPDM_LIB_DIR}/libcryptlib_openssl.a
            ${LIBSPDM_LIB_DIR}/libplatform_lib.a
            ${LIBSPDM_LIB_DIR}/libdebuglib_null.a
            ${LIBSPDM_LIB_DIR}/libmemlib.a
            ${LIBSPDM_LIB_DIR}/libmalloclib.a)
else()
    target_link_libraries(libspdm_wrapper PRIVATE
            ${LIBSPDM_LIB_DIR}/spdm_requester_lib.lib
            ${LIBSPDM_LIB_DIR}/spdm_secured_message_lib.lib
            ${LIBSPDM_LIB_DIR}/spdm_transport_mctp_lib.lib
            ${LIBSPDM_LIB_DIR}/spdm_crypt_lib.lib
            ${LIBSPDM_LIB_DIR}/spdm_common_lib.lib
            ${OPENSSL_LIB_DIR}/libcrypto_static.lib
            ${OPENSSL_LIB_DIR}/libssl_static.lib
            ${LIBSPDM_LIB_DIR}/rnglib.lib
            ${LIBSPDM_LIB_DIR}/cryptlib_openssl.lib
            ${LIBSPDM_LIB_DIR}/platform_lib.lib
            ${LIBSPDM_LIB_DIR}/debuglib_null.lib
            ${LIBSPDM_LIB_DIR}/memlib.lib
            ${LIBSPDM_LIB_DIR}/malloclib.lib
            Crypt32.lib
            Ws2_32.lib)
endif()

SET_TARGET_PROPERTIES(libspdm_wrapper PROPERTIES PREFIX "")
