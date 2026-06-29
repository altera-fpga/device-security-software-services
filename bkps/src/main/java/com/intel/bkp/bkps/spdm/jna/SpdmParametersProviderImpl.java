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

package com.intel.bkp.bkps.spdm.jna;

import com.intel.bkp.protocol.spdm.jna.model.SpdmParametersProvider;
import com.intel.bkp.protocol.spdm.jna.model.Uint16;
import com.intel.bkp.protocol.spdm.jna.model.Uint32;
import com.intel.bkp.protocol.spdm.jna.model.Uint8;

import static com.intel.bkp.protocol.spdm.jna.model.LibSpdmCapabilities.SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP;
import static com.intel.bkp.protocol.spdm.jna.model.LibSpdmCapabilities.SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP;
import static com.intel.bkp.protocol.spdm.jna.model.LibSpdmCapabilities.SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
import static com.intel.bkp.protocol.spdm.jna.model.LibSpdmCapabilities.SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
import static com.intel.bkp.protocol.spdm.jna.model.LibSpdmCapabilities.SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
import static com.intel.bkp.protocol.spdm.jna.model.LibSpdmCapabilities.SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP;
import static com.intel.bkp.protocol.spdm.jna.model.SpdmConstants.SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_256_GCM;
import static com.intel.bkp.protocol.spdm.jna.model.SpdmConstants.SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384;
import static com.intel.bkp.protocol.spdm.jna.model.SpdmConstants.SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384;
import static com.intel.bkp.protocol.spdm.jna.model.SpdmConstants.SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_384_R1;
import static com.intel.bkp.protocol.spdm.jna.model.SpdmConstants.SPDM_ALGORITHMS_KEY_SCHEDULE_HMAC_HASH;
import static com.intel.bkp.protocol.spdm.jna.model.SpdmConstants.SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_1;
import static com.intel.bkp.protocol.spdm.jna.model.SpdmConstants.SPDM_MEASUREMENT_SPECIFICATION_DMTF;

public class SpdmParametersProviderImpl implements SpdmParametersProvider {

    @Override
    public Uint8 ctExponent() {
        return new Uint8(0x0E);
    }

    @Override
    public Uint32 capabilities() {
        return new Uint32(SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP
            | SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP
            | SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP
            | SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP
            | SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP
            | SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP);
    }

    @Override
    public Uint8 measurementSpec() {
        return new Uint8(SPDM_MEASUREMENT_SPECIFICATION_DMTF);
    }

    @Override
    public Uint32 baseAsymAlgo() {
        return new Uint32(SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384);
    }

    @Override
    public Uint32 baseHashAlgo() {
        return new Uint32(SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384);
    }

    @Override
    public Uint16 dheNameGroup() {
        return new Uint16(SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_384_R1);
    }

    @Override
    public Uint16 aeadCipherSuite() {
        return new Uint16(SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_256_GCM);
    }

    @Override
    public Uint16 reqBaseAsymAlg() {
        return new Uint16(SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384);
    }

    @Override
    public Uint16 keySchedule() {
        return new Uint16(SPDM_ALGORITHMS_KEY_SCHEDULE_HMAC_HASH);
    }

    @Override
    public Uint8 otherParamsSupport() {
        return new Uint8(SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_1);
    }
}
