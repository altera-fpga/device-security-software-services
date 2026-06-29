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

package com.intel.bkp.protocol.spdm.jna;

import com.intel.bkp.protocol.spdm.exceptions.SpdmRuntimeException;
import com.intel.bkp.protocol.spdm.jna.model.CustomMemory;
import com.intel.bkp.protocol.spdm.jna.model.LibSpdmDataLocation;
import com.intel.bkp.protocol.spdm.jna.model.LibSpdmDataParameter;
import com.intel.bkp.protocol.spdm.jna.model.LibSpdmDataType;
import com.intel.bkp.protocol.spdm.jna.model.LibSpdmLibraryWrapper;
import com.intel.bkp.protocol.spdm.jna.model.LibSpdmReturn;
import com.intel.bkp.protocol.spdm.jna.model.NativeSize;
import com.intel.bkp.protocol.spdm.jna.model.SpdmParametersProvider;
import com.intel.bkp.protocol.spdm.jna.model.Uint16;
import com.intel.bkp.protocol.spdm.jna.model.Uint32;
import com.intel.bkp.protocol.spdm.jna.model.Uint8;
import com.intel.bkp.utils.ByteSwap;
import com.intel.bkp.utils.ByteSwapOrder;
import com.sun.jna.Memory;
import com.sun.jna.Pointer;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.digest.DigestUtils;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;

import java.io.IOException;
import java.nio.ByteBuffer;

import static com.intel.bkp.protocol.spdm.jna.SpdmUtils.copyBuffer;
import static com.intel.bkp.protocol.spdm.jna.model.LibSpdmDataType.LIBSPDM_DATA_AEAD_CIPHER_SUITE;
import static com.intel.bkp.protocol.spdm.jna.model.LibSpdmDataType.LIBSPDM_DATA_BASE_ASYM_ALGO;
import static com.intel.bkp.protocol.spdm.jna.model.LibSpdmDataType.LIBSPDM_DATA_BASE_HASH_ALGO;
import static com.intel.bkp.protocol.spdm.jna.model.LibSpdmDataType.LIBSPDM_DATA_CAPABILITY_CT_EXPONENT;
import static com.intel.bkp.protocol.spdm.jna.model.LibSpdmDataType.LIBSPDM_DATA_CAPABILITY_FLAGS;
import static com.intel.bkp.protocol.spdm.jna.model.LibSpdmDataType.LIBSPDM_DATA_DHE_NAME_GROUP;
import static com.intel.bkp.protocol.spdm.jna.model.LibSpdmDataType.LIBSPDM_DATA_KEY_SCHEDULE;
import static com.intel.bkp.protocol.spdm.jna.model.LibSpdmDataType.LIBSPDM_DATA_LOCAL_PUBLIC_CERT_CHAIN;
import static com.intel.bkp.protocol.spdm.jna.model.LibSpdmDataType.LIBSPDM_DATA_MEASUREMENT_SPEC;
import static com.intel.bkp.protocol.spdm.jna.model.LibSpdmDataType.LIBSPDM_DATA_OTHER_PARAMS_SUPPORT;
import static com.intel.bkp.protocol.spdm.jna.model.LibSpdmDataType.LIBSPDM_DATA_REQ_BASE_ASYM_ALG;
import static com.intel.bkp.protocol.spdm.jna.model.LibSpdmReturn.LIBSPDM_STATUS_SUCCESS;
import static com.intel.bkp.utils.HexConverter.toHex;

@Slf4j
@RequiredArgsConstructor
public class SpdmParametersSetter {

    private LibSpdmLibraryWrapper jnaInterface;
    private Pointer spdmContext;

    public SpdmParametersSetter with(LibSpdmLibraryWrapper jnaInterface, Pointer spdmContext) {
        this.jnaInterface = jnaInterface;
        this.spdmContext = spdmContext;
        return this;
    }

    public SpdmParametersSetter setLibspdmParameters(SpdmParametersProvider provider) {
        final LibSpdmDataParameter parameter = new LibSpdmDataParameter();
        parameter.setLocation(LibSpdmDataLocation.LIBSPDM_DATA_LOCATION_LOCAL);

        setData(parameter, LIBSPDM_DATA_CAPABILITY_CT_EXPONENT.getValue(), provider.ctExponent());
        setData(parameter, LIBSPDM_DATA_CAPABILITY_FLAGS.getValue(), provider.capabilities());
        setData(parameter, LIBSPDM_DATA_MEASUREMENT_SPEC.getValue(), provider.measurementSpec());
        setData(parameter, LIBSPDM_DATA_BASE_ASYM_ALGO.getValue(), provider.baseAsymAlgo());
        setData(parameter, LIBSPDM_DATA_BASE_HASH_ALGO.getValue(), provider.baseHashAlgo());
        setData(parameter, LIBSPDM_DATA_DHE_NAME_GROUP.getValue(), provider.dheNameGroup());
        setData(parameter, LIBSPDM_DATA_AEAD_CIPHER_SUITE.getValue(), provider.aeadCipherSuite());
        setData(parameter, LIBSPDM_DATA_REQ_BASE_ASYM_ALG.getValue(), provider.reqBaseAsymAlg());
        setData(parameter, LIBSPDM_DATA_KEY_SCHEDULE.getValue(), provider.keySchedule());
        setData(parameter, LIBSPDM_DATA_OTHER_PARAMS_SUPPORT.getValue(), provider.otherParamsSupport());

        return this;
    }

    public SpdmParametersSetter setCertChain(int slotId, byte[] certChain, Memory certChainP) {
        if (certChain == null || certChain.length == 0) {
            log.debug("No local public cert chain provided - skipped.");
            return this;
        }

        final byte[] preparedCertChain = prepareCertChainForProvisioning(certChain);

        final LibSpdmDataParameter parameter = new LibSpdmDataParameter();
        parameter.setLocation(LibSpdmDataLocation.LIBSPDM_DATA_LOCATION_LOCAL);
        parameter.setAdditionalData(new Uint8(slotId));

        final int certChainLen = preparedCertChain.length;
        copyBuffer(preparedCertChain, certChainP, certChainP.size());
        setData(parameter, LIBSPDM_DATA_LOCAL_PUBLIC_CERT_CHAIN.getValue(), certChainP, new NativeSize(certChainLen));

        return this;
    }

    private byte[] prepareCertChainForProvisioning(byte[] certChain) {
        final byte[] encodedSequence;
        try {
            encodedSequence = new DERSequence(new DEROctetString(certChain)).getEncoded();
        } catch (IOException e) {
            throw new SpdmRuntimeException("Failed to encode local public cert chain as ASN.1.", e);
        }

        log.trace("LOCAL PUBLIC CERT - ENCODED SEQUENCE: {}", toHex(encodedSequence));

        final byte[] hash = DigestUtils.sha384(encodedSequence);
        log.trace("LOCAL PUBLIC CERT - CALCULATED CHAIN 384 HASH: {}", toHex(hash));

        final int length = Integer.BYTES + hash.length + encodedSequence.length;
        final int lengthLittleEndian = ByteSwap.getSwappedInt(length, ByteSwapOrder.B2L);

        return ByteBuffer.allocate(length)
            .putInt(lengthLittleEndian)
            .put(hash)
            .put(encodedSequence)
            .array();
    }

    private void setData(LibSpdmDataParameter parameter, int param, Uint8 value) {
        try (final Memory valueP = new CustomMemory(Uint8.SIZE)) {
            valueP.setByte(0, value.byteValue());
            setData(parameter, param, valueP, Uint8.NATIVE_SIZE);
        }
    }

    private void setData(LibSpdmDataParameter parameter, int param, Uint16 value) {
        try (final Memory valueP = new CustomMemory(Uint16.SIZE)) {
            valueP.setShort(0, value.shortValue());
            setData(parameter, param, valueP, Uint16.NATIVE_SIZE);
        }
    }

    private void setData(LibSpdmDataParameter parameter, int param, Uint32 value) {
        try (final Memory valueP = new CustomMemory(Uint32.SIZE)) {
            valueP.setInt(0, value.intValue());
            setData(parameter, param, valueP, Uint32.NATIVE_SIZE);
        }
    }

    private void setData(LibSpdmDataParameter parameter, int param, Pointer value, NativeSize valueSize) {
        final LibSpdmReturn status = jnaInterface.libspdm_set_data_w(spdmContext, param, parameter, value, valueSize);

        if (!LIBSPDM_STATUS_SUCCESS.equals(status)) {
            log.error("Failed to set parameter {} for SPDM session.", LibSpdmDataType.paramNameFromValue(param));
            throw new SpdmRuntimeException("Failed to set parameter %s for SPDM session.".formatted(LibSpdmDataType
                .paramNameFromValue(param)), status);
        }
    }
}
