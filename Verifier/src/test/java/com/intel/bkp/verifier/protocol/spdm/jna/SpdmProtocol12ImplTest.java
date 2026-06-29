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

package com.intel.bkp.verifier.protocol.spdm.jna;

import com.intel.bkp.crypto.constants.CryptoConstants;
import com.intel.bkp.protocol.spdm.exceptions.SpdmConnectionNotInitialized;
import com.intel.bkp.protocol.spdm.jna.model.LibSpdmDataType;
import com.intel.bkp.protocol.spdm.jna.model.LibSpdmLibraryWrapper;
import com.intel.bkp.protocol.spdm.jna.model.LibSpdmReturn;
import com.intel.bkp.protocol.spdm.jna.model.NativeSize;
import com.intel.bkp.protocol.spdm.jna.model.SessionCallbacks;
import com.intel.bkp.protocol.spdm.jna.model.SpdmGetDigestResult;
import com.intel.bkp.protocol.spdm.jna.model.Uint8;
import com.intel.bkp.verifier.exceptions.VerifierRuntimeException;
import com.intel.bkp.verifier.model.LibConfig;
import com.intel.bkp.verifier.model.LibSpdmParams;
import com.intel.bkp.verifier.service.certificate.AppContext;
import com.sun.jna.Pointer;
import com.sun.jna.ptr.ByteByReference;
import lombok.SneakyThrows;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.stubbing.Answer;

import java.nio.ByteBuffer;
import java.util.Arrays;

import static com.intel.bkp.protocol.spdm.jna.model.LibSpdmReturn.LIBSPDM_STATUS_SUCCESS;
import static com.intel.bkp.protocol.spdm.jna.model.SpdmConstants.SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE;
import static com.intel.bkp.utils.HexConverter.toHex;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class SpdmProtocol12ImplTest {

    private static final int SPDM_CT_EXP = 0x02;
    private static final int SLOT_ID = 0x02;
    private static final byte SLOT_MASK_GOOD = 4; // SLOT_ID of 0x02 means 3rd bit set in mask - 00000100 = 4
    private static final byte[] DIGEST = new byte[CryptoConstants.SHA384_LEN];

    static {
        // dummy data
        DIGEST[0] = (byte) 0x02;
        DIGEST[1] = (byte) 0x04;
    }

    private static MockedStatic<AppContext> appContextMockedStatic;

    @Mock
    private LibSpdmLibraryWrapper wrapperMock;
    @Mock
    private AppContext appContextMock;
    @Mock
    private LibConfig libConfigMock;
    @Mock
    private LibSpdmParams libSpdmParamsMock;

    private SpdmProtocol12Impl sut;

    @BeforeAll
    static void prepareStaticMock() {
        appContextMockedStatic = mockStatic(AppContext.class);
    }

    @AfterAll
    static void closeStaticMock() {
        appContextMockedStatic.close();
    }

    @BeforeEach
    void setUp() {
        when(AppContext.instance()).thenReturn(appContextMock);

        sut = new SpdmProtocol12Impl();
    }

    @Test
    void initializeLibrary_WrapperLibraryNotLoaded_Throws() {
        // given
        try (var wrapperMockedStatic = mockStatic(LibSpdmLibraryWrapperImpl.class)) {
            when(LibSpdmLibraryWrapperImpl.getInstance()).thenThrow(new UnsatisfiedLinkError());

            // when-then
            final VerifierRuntimeException ex =
                assertThrows(VerifierRuntimeException.class, sut::initializeLibrary);
            assertEquals("Failed to link SPDM Wrapper library.", ex.getMessage());
        }
    }

    @Test
    void getVersion_Success() throws Exception {
        // given
        mockSpdmSetData();
        try (var wrapperMockedStatic = mockStatic(LibSpdmLibraryWrapperImpl.class)) {
            mockWrapper();
            prepareLibConfig();
            prepareSpdmContextAndScratchBufferSize();

            final int expectedSpdmVersion = 0x01;

            when(wrapperMock.libspdm_init_connection_w(any(), eq(true)))
                .thenReturn(LIBSPDM_STATUS_SUCCESS);
            doAnswer(invocation -> {
                final Object[] arguments = invocation.getArguments();
                final ByteBuffer buffer = (ByteBuffer) arguments[1];
                buffer.put((byte) expectedSpdmVersion);
                buffer.rewind();
                return null;
            }).when(wrapperMock).libspdm_get_version_w(any(), any());

            // when
            final String result = sut.getVersion();

            // then
            assertEquals(toHex(expectedSpdmVersion), result);
            verifyCallbacksAreRegistered();
        }
    }

    @Test
    void getDigest_ConnectionNotInitialized_Throws() {
        // when-then
        assertThrows(SpdmConnectionNotInitialized.class, sut::getDigest);
    }

    @Test
    void getDigest_Success() throws Exception {
        // given
        try (var wrapperMockedStatic = mockStatic(LibSpdmLibraryWrapperImpl.class)) {
            mockWrapper();
            prepareLibConfig();
            prepareSpdmContextAndScratchBufferSize();

            final SpdmGetDigestResult result;
            mockSpdmSetData();
            try (SpdmProtocol12Impl sutSpy = mockConnectionAlreadyInitialized()) {

                when(wrapperMock.libspdm_get_digest_w(any(), any(), any(), any()))
                    .thenAnswer((Answer<LibSpdmReturn>) invocation -> {
                        final Object[] arguments = invocation.getArguments();
                        final ByteByReference slotMask = (ByteByReference) arguments[2];
                        final Pointer digests = (Pointer) arguments[3];
                        slotMask.setValue(SLOT_MASK_GOOD);
                        for (int i = 0; i < DIGEST.length; i++) {
                            digests.setByte(i, DIGEST[i]);
                        }

                        return LIBSPDM_STATUS_SUCCESS;
                    });


                // when
                result = sutSpy.getDigest();
            }

            // then
            assertEquals(SLOT_MASK_GOOD, result.slotMask());
            assertArrayEquals(DIGEST, result.digests());
            verifyCallbacksAreRegistered();
        }
    }

    @Test
    void getCerts_ConnectionNotInitialized_Throws() {
        // when-then
        assertThrows(SpdmConnectionNotInitialized.class, () -> sut.getCerts(SLOT_ID));
    }

    @Test
    void getCerts_Success() throws Exception {
        // given
        try (var wrapperMockedStatic = mockStatic(LibSpdmLibraryWrapperImpl.class)) {
            mockWrapper();
            prepareLibConfig();
            prepareSpdmContextAndScratchBufferSize();

            final byte[] expectedCertChain;
            final String result;

            mockSpdmSetData();
            try (SpdmProtocol12Impl sutSpy = mockConnectionAlreadyInitialized()) {

                expectedCertChain = new byte[]{1, 2, 3, 4};
                when(wrapperMock.libspdm_get_certificate_w(any(), any(), any(), any(), any()))
                    .thenAnswer((Answer<LibSpdmReturn>) invocation -> {
                        final Object[] arguments = invocation.getArguments();
                        final Pointer certChainSize = (Pointer) arguments[3];
                        final Pointer certChain = (Pointer) arguments[4];
                        setBufferData(expectedCertChain, certChain, certChainSize);

                        return LIBSPDM_STATUS_SUCCESS;
                    });

                // when
                result = sutSpy.getCerts(SLOT_ID);
            }

            // then
            assertEquals(toHex(expectedCertChain), result);
            verifyCallbacksAreRegistered();
        }
    }

    @Test
    void getCerts_EmptyCert_ReturnEmpty() throws Exception {
        // given
        try (var wrapperMockedStatic = mockStatic(LibSpdmLibraryWrapperImpl.class)) {
            mockWrapper();
            prepareLibConfig();
            prepareSpdmContextAndScratchBufferSize();

            final byte[] oneElementArray;
            final int emptyArraySize = 0;
            final String result;

            mockSpdmSetData();
            try (SpdmProtocol12Impl sutSpy = mockConnectionAlreadyInitialized()) {

                oneElementArray = new byte[]{0};
                when(wrapperMock.libspdm_get_certificate_w(any(), any(), any(), any(), any()))
                    .thenAnswer((Answer<LibSpdmReturn>) invocation -> {
                        final Object[] arguments = invocation.getArguments();
                        final Pointer certChainSize = (Pointer) arguments[3];
                        final Pointer certChain = (Pointer) arguments[4];
                        certChain.setByte(0, oneElementArray[0]);
                        certChainSize.setInt(0, emptyArraySize);

                        return LIBSPDM_STATUS_SUCCESS;
                    });

                // when
                result = sutSpy.getCerts(SLOT_ID);
            }

            // then
            assertEquals("", result);
            verifyCallbacksAreRegistered();
        }
    }

    @Test
    void getCerts_CertSetTo0_Return00() throws Exception {
        // given
        try (var wrapperMockedStatic = mockStatic(LibSpdmLibraryWrapperImpl.class)) {
            mockWrapper();
            prepareLibConfig();
            prepareSpdmContextAndScratchBufferSize();

            final byte[] expectedCertChain;
            final String result;

            mockSpdmSetData();
            try (SpdmProtocol12Impl sutSpy = mockConnectionAlreadyInitialized()) {

                expectedCertChain = new byte[]{0};
                when(wrapperMock.libspdm_get_certificate_w(any(), any(), any(), any(), any()))
                    .thenAnswer((Answer<LibSpdmReturn>) invocation -> {
                        final Object[] arguments = invocation.getArguments();
                        final Pointer certChainSize = (Pointer) arguments[3];
                        final Pointer certChain = (Pointer) arguments[4];
                        certChain.setByte(0, expectedCertChain[0]);
                        certChainSize.setInt(0, expectedCertChain.length);

                        return LIBSPDM_STATUS_SUCCESS;
                    });

                // when
                result = sutSpy.getCerts(SLOT_ID);
            }

            // then
            assertEquals(toHex(expectedCertChain), result);
            verifyCallbacksAreRegistered();
        }
    }

    @Test
    void getMeasurements_ConnectionNotInitialized_Throws() {
        // when-then
        assertThrows(SpdmConnectionNotInitialized.class, () -> sut.getMeasurements(SLOT_ID));
    }

    @Test
    void getMeasurements_Success() throws Exception {
        // given
        try (var wrapperMockedStatic = mockStatic(LibSpdmLibraryWrapperImpl.class)) {
            mockWrapper();
            prepareLibConfig();
            prepareSpdmContextAndScratchBufferSize();

            final byte[] expectedMeasurements;
            final String result;

            mockSpdmSetData();
            try (SpdmProtocol12Impl sutSpy = mockConnectionAlreadyInitialized()) {

                expectedMeasurements = new byte[]{1, 2, 3, 4};
                when(wrapperMock.libspdm_get_measurement_w(any(), any(), any(), any(), any(), any(), any(), any(),
                    any()))
                    .thenAnswer((Answer<LibSpdmReturn>) invocation -> {
                        final Object[] arguments = invocation.getArguments();
                        final Pointer measurementRecordLength = (Pointer) arguments[7];
                        final Pointer measurementRecord = (Pointer) arguments[8];
                        setBufferData(expectedMeasurements, measurementRecord, measurementRecordLength);

                        return LIBSPDM_STATUS_SUCCESS;
                    });

                // when
                result = sutSpy.getMeasurements(SLOT_ID);
            }

            // then
            assertEquals(toHex(expectedMeasurements), result);
            verifyCallbacksAreRegistered();
        }
    }

    @Test
    void getMeasurements_WithoutSignature_CallsMethodWithOnlyRawBitStreamRequest() throws Exception {
        // given
        try (var wrapperMockedStatic = mockStatic(LibSpdmLibraryWrapperImpl.class)) {
            mockWrapper();
            prepareLibConfig();
            prepareSpdmContextAndScratchBufferSize();

            when(wrapperMock.libspdm_get_measurement_w(any(), any(), any(), any(), any(),
                any(), any(), any(), any())).thenReturn(LIBSPDM_STATUS_SUCCESS);

            mockSpdmSetData();
            try (SpdmProtocol12Impl sutSpy = mockConnectionAlreadyInitialized()) {
                when(libSpdmParamsMock.isMeasurementsRequestSignature()).thenReturn(false);

                // when
                sutSpy.getMeasurements(SLOT_ID);
            }

            // then
            verify(wrapperMock).libspdm_get_measurement_w(any(), any(),
                eq(new Uint8(0)),
                any(), any(), any(), any(), any(), any());
            verifyCallbacksAreRegistered();
        }
    }

    @Test
    void getMeasurements_WithSignature_CallsMethodWithSignatureRequest() throws Exception {
        // given
        try (var wrapperMockedStatic = mockStatic(LibSpdmLibraryWrapperImpl.class)) {
            mockWrapper();
            prepareLibConfig();
            prepareSpdmContextAndScratchBufferSize();

            when(wrapperMock.libspdm_get_measurement_w(any(), any(), any(), any(), any(),
                any(), any(), any(), any())).thenReturn(LIBSPDM_STATUS_SUCCESS);

            mockSpdmSetData();
            try (SpdmProtocol12Impl sutSpy = mockConnectionAlreadyInitialized()) {

                when(libSpdmParamsMock.isMeasurementsRequestSignature()).thenReturn(true);

                // when
                sutSpy.getMeasurements(SLOT_ID);
            }

            // then
            verify(wrapperMock).libspdm_get_measurement_w(any(), any(),
                eq(new Uint8(SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE)),
                any(), any(), any(), any(), any(), any());
            verifyCallbacksAreRegistered();
        }
    }

    private void verifyCallbacksAreRegistered() {
        verify(wrapperMock).set_callbacks(any(SessionCallbacks.class));
    }

    private void mockWrapper() {
        when(LibSpdmLibraryWrapperImpl.getInstance()).thenReturn(wrapperMock);
    }

    private void prepareLibConfig() {
        doReturn(libConfigMock).when(appContextMock).getLibConfig();
        doReturn(libSpdmParamsMock).when(libConfigMock).getLibSpdmParams();
        doReturn(SPDM_CT_EXP).when(libSpdmParamsMock).getCtExponent();
    }

    private void prepareSpdmContextSize() {
        final NativeSize spdmContextSize = new NativeSize(100);
        when(wrapperMock.libspdm_get_context_size_w()).thenReturn(spdmContextSize);
    }

    private void prepareSpdmContextAndScratchBufferSize() {
        prepareSpdmContextSize();

        final NativeSize scratchBufferSize = new NativeSize(500);
        when(wrapperMock.libspdm_get_sizeof_required_scratch_buffer_w(any())).thenReturn(scratchBufferSize);
        when(wrapperMock.libspdm_prepare_context_w(any(), any())).thenReturn(LIBSPDM_STATUS_SUCCESS);
    }

    private void mockSpdmSetData() {
        Arrays.stream(LibSpdmDataType.values())
            .map(LibSpdmDataType::getValue)
            .limit(LibSpdmDataType.values().length - 1)
            .forEach(x ->
                when(wrapperMock.libspdm_set_data_w(any(), eq(x), any(), any(), any()))
                    .thenReturn(new LibSpdmReturn()));
    }

    @SneakyThrows
    private static SpdmProtocol12Impl mockConnectionAlreadyInitialized() {
        final SpdmProtocol12Impl sut = new SpdmProtocol12Impl();
        final SpdmProtocol12Impl spdmProtocol12Spy = Mockito.spy(sut);
        when(spdmProtocol12Spy.isConnectionInitialized()).thenReturn(true);
        spdmProtocol12Spy.initSpdmConnection();
        return spdmProtocol12Spy;
    }

    private static void setBufferData(byte[] dataToSet, Pointer buffer, Pointer bufferSize) {
        buffer.setByte(0, dataToSet[0]);
        buffer.setByte(1, dataToSet[1]);
        buffer.setByte(2, dataToSet[2]);
        buffer.setByte(3, dataToSet[3]);

        bufferSize.setInt(0, dataToSet.length);
    }
}
