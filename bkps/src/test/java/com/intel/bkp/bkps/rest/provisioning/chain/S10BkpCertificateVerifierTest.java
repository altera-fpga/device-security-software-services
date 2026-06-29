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

package com.intel.bkp.bkps.rest.provisioning.chain;

import com.intel.bkp.bkps.exception.DeviceChainVerificationFailedException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;

import java.math.BigInteger;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.LinkedList;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class S10BkpCertificateVerifierTest {

    private static final byte[] DEVICE_ID = new byte[]{0x01, 0x02};

    @Mock
    private Map<String, X509CRL> cachedCrls;

    private S10BkpChainVerifier sutSpy;

    @BeforeEach
    void init() {
        sutSpy = spy(new S10BkpChainVerifier(cachedCrls, new String[]{"s10RootHash"}));
    }

    @Test
    void withDeviceId_SetsDeviceIdInBaseClass() {
        // when
        sutSpy.withDeviceId(DEVICE_ID);

        // then
        verify(sutSpy).setDeviceId(DEVICE_ID);
    }

    @Test
    void verifyChain_ThrowsExpectedExceptionType() {
        // given
        final var cert = mock(X509Certificate.class);
        when(cert.getSerialNumber()).thenReturn(BigInteger.ONE);
        final var certificates = new LinkedList<X509Certificate>();
        certificates.add(cert);
        sutSpy.withDeviceId(DEVICE_ID);

        // when-then
        assertThrows(DeviceChainVerificationFailedException.class,
            () -> sutSpy.verifyChain(certificates));
    }

}
