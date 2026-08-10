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

package com.intel.bkp.protocol.spdm.service;

import com.intel.bkp.protocol.spdm.jna.model.SpdmProtocol;
import com.intel.bkp.protocol.spdm.model.SpdmCertificateResponseBuilder;
import com.intel.bkp.utils.exceptions.ByteBufferSafeException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static com.intel.bkp.utils.HexConverter.toHex;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class SpdmGetCertificateMessageSenderTest {

    private static final byte[] CERTIFICATE_CHAIN = {1, 2, 3, 4};
    private static final int SLOT_ID = 2;

    @Mock
    private SpdmProtocol spdmProtocol;

    private SpdmGetCertificateMessageSender sut;

    @BeforeEach
    void setUp() {
        sut = new SpdmGetCertificateMessageSender(spdmProtocol);
    }

    @Test
    void send_Success() throws Exception {
        // given
        final SpdmCertificateResponseBuilder builder = new SpdmCertificateResponseBuilder()
            .withCertificateChain(CERTIFICATE_CHAIN);
        final String certResponse = toHex(builder.build().array());
        when(spdmProtocol.getCerts(SLOT_ID)).thenReturn(certResponse);

        // when
        final byte[] result = sut.send(SLOT_ID);

        // then
        assertArrayEquals(builder.getCertificateChain(), result);
    }

    @Test
    void send_EmptyCert_Throws() throws Exception {
        // given
        when(spdmProtocol.getCerts(SLOT_ID)).thenReturn("");

        // when-then
        final ByteBufferSafeException exception = assertThrows(ByteBufferSafeException.class,
            () -> sut.send(SLOT_ID)
        );

        // then
        assertEquals("Buffer remaining length is 0, but requested 2.", exception.getMessage());
    }

    @Test
    void send_00Cert_Throws() throws Exception {
        // given
        when(spdmProtocol.getCerts(SLOT_ID)).thenReturn("00");

        // when-then
        final ByteBufferSafeException exception = assertThrows(ByteBufferSafeException.class,
            () -> sut.send(SLOT_ID)
        );

        // then
        assertEquals("Buffer remaining length is 1, but requested 2.", exception.getMessage());
    }
}
