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

package com.intel.bkp.bkps.rest.prefetching.service;

import com.intel.bkp.bkps.attestation.DiceDpFetchService;
import com.intel.bkp.bkps.attestation.S10DpFetchService;
import com.intel.bkp.test.RandomUtils;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.cert.X509Certificate;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class ChainDataProviderTest {

    @Mock
    private X509Certificate x509Certificate;

    @Mock
    private DiceDpFetchService diceDpFetchService;

    @Mock
    private S10DpFetchService s10DpFetchService;

    @InjectMocks
    private ChainDataProvider sut;

    @Test
    void fetchDice_WithX509CertificateArgument_Success() {
        // when
        sut.fetchDice(x509Certificate);

        // then
        verify(diceDpFetchService).fetch(x509Certificate);
    }

    @Test
    void fetchDice_WithX509CertificateArgument_WithExceptionInFetching_Throws() {
        // given
        when(diceDpFetchService.fetch(x509Certificate)).thenThrow(RuntimeException.class);

        // when-then
        assertThrows(RuntimeException.class, () -> sut.fetchDice(x509Certificate));
    }

    @Test
    void fetchS10_Success() {
        // given
        String deviceIdHex = RandomUtils.generateDeviceIdHex();

        // when
        sut.fetchS10(deviceIdHex);

        // then
        verify(s10DpFetchService).fetch(deviceIdHex);
    }

    @Test
    void fetchS10_WithExceptionInFetching_Throws() {
        // given
        String deviceIdHex = RandomUtils.generateDeviceIdHex();
        when(s10DpFetchService.fetch(deviceIdHex)).thenThrow(RuntimeException.class);

        // when-then
        assertThrows(RuntimeException.class, () -> sut.fetchS10(deviceIdHex));
    }
}
