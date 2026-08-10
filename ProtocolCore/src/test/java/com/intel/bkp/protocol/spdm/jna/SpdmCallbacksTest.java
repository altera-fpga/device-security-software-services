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

import com.intel.bkp.protocol.spdm.jna.model.LibSpdmReturn;
import com.intel.bkp.protocol.spdm.jna.model.MessageSender;
import com.intel.bkp.protocol.spdm.jna.model.NativeSize;
import com.intel.bkp.protocol.spdm.jna.model.Uint64;
import com.sun.jna.Pointer;
import com.sun.jna.ptr.PointerByReference;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;

import java.nio.ByteBuffer;
import java.util.Optional;

import static com.intel.bkp.protocol.spdm.jna.model.LibSpdmReturn.LIBSPDM_STATUS_SPDM_INTERNAL_EXCEPTION;
import static com.intel.bkp.protocol.spdm.jna.model.LibSpdmReturn.LIBSPDM_STATUS_SPDM_NOT_SUPPORTED;
import static com.intel.bkp.protocol.spdm.jna.model.LibSpdmReturn.LIBSPDM_STATUS_SUCCESS;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class SpdmCallbacksTest {

    private static final LibSpdmReturn RETURN_SUCCESS = LIBSPDM_STATUS_SUCCESS;
    private static final LibSpdmReturn RETURN_EXCEPTION = LIBSPDM_STATUS_SPDM_INTERNAL_EXCEPTION;
    private static final LibSpdmReturn RETURN_NOT_SUPPORTED = LIBSPDM_STATUS_SPDM_NOT_SUPPORTED;
    private static final long EXPECTED_MESSAGE_SIZE_LONG = 100L;
    private static final RuntimeException RUNTIME_EXCEPTION = new RuntimeException("TEST");

    private static MockedStatic<SpdmUtils> spdmUtilsMockedStatic;

    @BeforeAll
    static void prepareStaticMock() {
        spdmUtilsMockedStatic = mockStatic(SpdmUtils.class);
    }

    @AfterAll
    static void closeStaticMock() {
        spdmUtilsMockedStatic.close();
    }

    private final NativeSize requestSize = new NativeSize(EXPECTED_MESSAGE_SIZE_LONG);
    private final ByteBuffer requestBuffer = ByteBuffer.allocate((int) EXPECTED_MESSAGE_SIZE_LONG);
    private final Uint64 timeout = new Uint64(100);

    @Mock
    private Pointer spdmContext;

    @Mock
    private Pointer request;
    @Mock
    private PointerByReference response;
    @Mock
    private Pointer responseSize;

    @Mock
    private MessageSender messageSender;

    @Mock
    private SignatureProvider signatureProvider;

    @InjectMocks
    private SpdmCallbacks sut;

    @Test
    void spdmDeviceSendMessage_Success() {
        // given
        when(request.getByteBuffer(0, EXPECTED_MESSAGE_SIZE_LONG)).thenReturn(requestBuffer);

        // when
        final LibSpdmReturn result = sut.spdmDeviceSendMessage(spdmContext, requestSize, request, timeout);

        // then
        assertEquals(RETURN_SUCCESS, result);
    }

    @Test
    void spdmDeviceSendMessage_SendingFailed_ReturnsException() throws Exception {
        // given
        when(request.getByteBuffer(0, EXPECTED_MESSAGE_SIZE_LONG)).thenReturn(requestBuffer);

        doThrow(RUNTIME_EXCEPTION).when(messageSender).sendMessage(any(), eq(requestBuffer));

        // when
        final LibSpdmReturn result = sut.spdmDeviceSendMessage(spdmContext, requestSize, request, timeout);

        // then
        assertEquals(RETURN_EXCEPTION, result);
    }

    @Test
    void spdmDeviceReceiveMessage_Success() throws Exception {
        // given
        when(messageSender.receiveResponse()).thenReturn(Optional.of(new byte[]{1, 2, 3, 4}));

        // when
        final LibSpdmReturn result =
            sut.spdmDeviceReceiveMessage(spdmContext, responseSize, response, timeout);

        // then
        assertEquals(RETURN_SUCCESS, result);
        spdmUtilsMockedStatic.verify(
            () -> SpdmUtils.copyBuffer(any(), eq(response), eq(responseSize)));
    }

    @Test
    void spdmDeviceReceiveMessage_EmptyResponse_ReturnsNotSupported() throws Exception {
        // given
        when(messageSender.receiveResponse()).thenReturn(Optional.empty());

        // when
        final LibSpdmReturn result =
            sut.spdmDeviceReceiveMessage(spdmContext, responseSize, response, timeout);

        // then
        assertEquals(RETURN_NOT_SUPPORTED, result);
    }

    @Test
    void spdmDeviceReceiveMessage_ExceptionOccurred_ReturnsException() throws Exception {
        // given
        doThrow(RUNTIME_EXCEPTION).when(messageSender).receiveResponse();

        // when
        final LibSpdmReturn result =
            sut.spdmDeviceReceiveMessage(spdmContext, responseSize, response, timeout);

        // then
        assertEquals(RETURN_EXCEPTION, result);
        spdmUtilsMockedStatic.verify(
            () -> SpdmUtils.copyBuffer(any(), eq(response), eq(responseSize)), never());
    }
}
