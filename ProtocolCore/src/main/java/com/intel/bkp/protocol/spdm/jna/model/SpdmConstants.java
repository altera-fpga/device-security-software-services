/*
 * This project is licensed as below.
 *
 * **************************************************************************
 *
 * Copyright 2020-2026 Altera Corporation. All Rights Reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER
 * OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * **************************************************************************
 */

package com.intel.bkp.protocol.spdm.jna.model;

public class SpdmConstants {

    // Values taken from libspdm library
    public static final int LIBSPDM_SENDER_RECEIVE_BUFFER_SIZE = 20064;
    public static final int MAX_SPDM_BUFFER_SIZE = 20000;
    public static final int MAX_LOCAL_CERTIFICATE_CHAIN_SIZE = 8192;
    public static final int SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE = 0x01;
    public static final int SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_RAW_BIT_STREAM_REQUESTED = 0x02;
    public static final int SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_ALL_MEASUREMENTS = 0xFF;
    public static final int SPDM_KEY_EXCHANGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH = 0x00;
    public static final int SPDM_KEY_EXCHANGE_REQUEST_ALL_MEASUREMENTS_HASH = 0xFF;
    public static final int SPDM_MEASUREMENT_SPECIFICATION_DMTF = 0x01;
    public static final int SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384 = 0x80;
    public static final int SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384 = 0x02;
    public static final int SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_384_R1 = 0x10;
    public static final int SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_256_GCM = 0x02;
    public static final int SPDM_ALGORITHMS_KEY_SCHEDULE_HMAC_HASH = 0x01;
    public static final int SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_1 = 0x02;
    public static final int MAX_SLOT_COUNT = 8;
    public static final int DEFAULT_SLOT_ID = 0x00;
    public static final int DEFAULT_CT_EXPONENT = 0x0E;
    public static final String SPDM_SIGNATURE_FINISH_SIGNING_CONTEXT = "finish signing";
}
