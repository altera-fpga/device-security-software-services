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

import com.intel.bkp.protocol.spdm.jna.model.LibSpdmDataType;
import com.intel.bkp.protocol.spdm.jna.model.LibSpdmLibraryWrapper;
import com.intel.bkp.protocol.spdm.jna.model.SpdmParametersProvider;
import com.intel.bkp.protocol.spdm.jna.model.Uint16;
import com.intel.bkp.protocol.spdm.jna.model.Uint32;
import com.intel.bkp.protocol.spdm.jna.model.Uint8;
import com.sun.jna.Pointer;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Arrays;

import static com.intel.bkp.protocol.spdm.jna.model.LibSpdmDataType.LIBSPDM_DATA_AEAD_CIPHER_SUITE;
import static com.intel.bkp.protocol.spdm.jna.model.LibSpdmDataType.LIBSPDM_DATA_BASE_ASYM_ALGO;
import static com.intel.bkp.protocol.spdm.jna.model.LibSpdmDataType.LIBSPDM_DATA_BASE_HASH_ALGO;
import static com.intel.bkp.protocol.spdm.jna.model.LibSpdmDataType.LIBSPDM_DATA_CAPABILITY_CT_EXPONENT;
import static com.intel.bkp.protocol.spdm.jna.model.LibSpdmDataType.LIBSPDM_DATA_CAPABILITY_FLAGS;
import static com.intel.bkp.protocol.spdm.jna.model.LibSpdmDataType.LIBSPDM_DATA_DHE_NAME_GROUP;
import static com.intel.bkp.protocol.spdm.jna.model.LibSpdmDataType.LIBSPDM_DATA_KEY_SCHEDULE;
import static com.intel.bkp.protocol.spdm.jna.model.LibSpdmDataType.LIBSPDM_DATA_MEASUREMENT_SPEC;
import static com.intel.bkp.protocol.spdm.jna.model.LibSpdmDataType.LIBSPDM_DATA_OTHER_PARAMS_SUPPORT;
import static com.intel.bkp.protocol.spdm.jna.model.LibSpdmDataType.LIBSPDM_DATA_REQ_BASE_ASYM_ALG;
import static com.intel.bkp.protocol.spdm.jna.model.LibSpdmReturn.LIBSPDM_STATUS_SUCCESS;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class SpdmParametersSetterTest {

    private static final int DUMMY_VALUE = 0x04;

    @Mock
    private LibSpdmLibraryWrapper wrapperMock;
    @Mock
    private Pointer context;
    @Mock
    private SpdmParametersProvider spdmParametersProvider;

    private final SpdmParametersSetter sut = new SpdmParametersSetter();

    @BeforeEach
    void setUp() {
        when(spdmParametersProvider.ctExponent()).thenReturn(new Uint8(DUMMY_VALUE));
        when(spdmParametersProvider.capabilities()).thenReturn(new Uint32(DUMMY_VALUE));
        when(spdmParametersProvider.measurementSpec()).thenReturn(new Uint8(DUMMY_VALUE));
        when(spdmParametersProvider.baseAsymAlgo()).thenReturn(new Uint32(DUMMY_VALUE));
        when(spdmParametersProvider.baseHashAlgo()).thenReturn(new Uint32(DUMMY_VALUE));
        when(spdmParametersProvider.dheNameGroup()).thenReturn(new Uint16(DUMMY_VALUE));
        when(spdmParametersProvider.aeadCipherSuite()).thenReturn(new Uint16(DUMMY_VALUE));
        when(spdmParametersProvider.reqBaseAsymAlg()).thenReturn(new Uint16(DUMMY_VALUE));
        when(spdmParametersProvider.keySchedule()).thenReturn(new Uint16(DUMMY_VALUE));
        when(spdmParametersProvider.otherParamsSupport()).thenReturn(new Uint8(DUMMY_VALUE));
    }

    @Test
    void setLibspdmParameters_Success() {
        // given
        Arrays.stream(LibSpdmDataType.values())
            .map(LibSpdmDataType::getValue)
            .limit(LibSpdmDataType.values().length - 1)
            .forEach(x ->
                when(wrapperMock.libspdm_set_data_w(eq(context), eq(x), any(), any(), any()))
                    .thenReturn(LIBSPDM_STATUS_SUCCESS));

        // when
        sut
            .with(wrapperMock, context)
            .setLibspdmParameters(spdmParametersProvider);

        // then
        assertAll(
            () -> verifyWrapperCallSetDataW8(LIBSPDM_DATA_CAPABILITY_CT_EXPONENT.getValue()),
            () -> verifyWrapperCallSetDataW32(LIBSPDM_DATA_CAPABILITY_FLAGS.getValue()),
            () -> verifyWrapperCallSetDataW8(LIBSPDM_DATA_MEASUREMENT_SPEC.getValue()),
            () -> verifyWrapperCallSetDataW32(LIBSPDM_DATA_BASE_ASYM_ALGO.getValue()),
            () -> verifyWrapperCallSetDataW32(LIBSPDM_DATA_BASE_HASH_ALGO.getValue()),
            () -> verifyWrapperCallSetDataW16(LIBSPDM_DATA_DHE_NAME_GROUP.getValue()),
            () -> verifyWrapperCallSetDataW16(LIBSPDM_DATA_AEAD_CIPHER_SUITE.getValue()),
            () -> verifyWrapperCallSetDataW16(LIBSPDM_DATA_REQ_BASE_ASYM_ALG.getValue()),
            () -> verifyWrapperCallSetDataW16(LIBSPDM_DATA_KEY_SCHEDULE.getValue()),
            () -> verifyWrapperCallSetDataW8(LIBSPDM_DATA_OTHER_PARAMS_SUPPORT.getValue())
        );
    }

    private void verifyWrapperCallSetDataW8(int parameter) {
        verify(wrapperMock).libspdm_set_data_w(eq(context), eq(parameter), any(),
            any(), eq(Uint8.NATIVE_SIZE));
    }

    private void verifyWrapperCallSetDataW16(int parameter) {
        verify(wrapperMock).libspdm_set_data_w(eq(context), eq(parameter), any(),
            any(), eq(Uint16.NATIVE_SIZE));
    }

    private void verifyWrapperCallSetDataW32(int parameter) {
        verify(wrapperMock).libspdm_set_data_w(eq(context), eq(parameter), any(),
            any(), eq(Uint32.NATIVE_SIZE));
    }
}
