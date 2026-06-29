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

import com.intel.bkp.bkps.exception.ProvisioningGenericException;
import com.intel.bkp.bkps.rest.errors.enums.ErrorCodeMap;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.cert.X509CRL;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

@ExtendWith(MockitoExtension.class)
class PrePopulatedCrlProviderTest {

    private static final String CRL_1_URL = "dpUrl/filename1.crl";
    private static final String CRL_2_URL = "dpUrl/filename2.crl";
    private static final String CRL_2_URL_FROM_DIFFERENT_DP = "differentDpUrl/filename2.crl";
    private static final String NOT_CACHED_CRL_URL = "dpUrl/notCached.crl";

    @Mock
    private X509CRL crl1;

    @Mock
    private X509CRL crl2;

    private PrePopulatedCrlProvider sut;

    @BeforeEach
    void init() {
        final var cachedCrls = Map.of(CRL_1_URL, crl1, CRL_2_URL, crl2);
        sut = new PrePopulatedCrlProvider(cachedCrls);
    }

    @Test
    void getCrl_ExactUrlExistsInCache_Success() {
        // when
        final X509CRL result = sut.getCrl(CRL_1_URL);

        // then
        assertEquals(crl1, result);
    }

    @Test
    void getCrl_FilenameExistsInCache_Success() {
        // when
        final X509CRL result = sut.getCrl(CRL_2_URL_FROM_DIFFERENT_DP);

        // then
        assertEquals(crl2, result);
    }

    @Test
    void getCrl_FilenameDoesNotExistsInCache_Throws() {
        // when-then
        ProvisioningGenericException e = assertThrows(ProvisioningGenericException.class,
            () -> sut.getCrl(NOT_CACHED_CRL_URL));

        // then
        assertEquals(ErrorCodeMap.CRL_NOT_FOUND, e.getErrorCode());
    }

}
