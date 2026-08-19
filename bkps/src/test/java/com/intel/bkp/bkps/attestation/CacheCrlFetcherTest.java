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

package com.intel.bkp.bkps.attestation;

import com.intel.bkp.bkps.attestation.mapping.CacheCrlMapper;
import com.intel.bkp.bkps.config.ApplicationProperties;
import com.intel.bkp.bkps.connector.DpConnector;
import com.intel.bkp.bkps.rest.prefetching.service.CrlPrefetchRepositoryService;
import com.intel.bkp.core.properties.DistributionPoint;
import com.intel.bkp.crypto.exceptions.CrlGenerationFailed;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.cert.X509CRL;

import static com.intel.bkp.test.X509GeneratorUtil.generateCrl;
import static com.intel.bkp.test.X509GeneratorUtil.generateCrlWithoutNextUpdate;
import static com.intel.bkp.test.X509GeneratorUtil.generateExpiredCrl;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class CacheCrlFetcherTest {

    @Mock
    private CrlPrefetchRepositoryService crlPrefetchRepositoryService;

    @Mock
    private DpConnector dpConnector;

    private ApplicationProperties applicationProperties;

    private CacheCrlFetcher sut;


    @BeforeEach
    void prepareSut() {
        when(crlPrefetchRepositoryService.getMapper()).thenReturn(new CacheCrlMapper());
        applicationProperties = spy(new ApplicationProperties());
        applicationProperties.setDistributionPoint(new DistributionPoint(
            "https://tsci.intel.com/",
            "content/IPCS/certs/",
            "content/IPCS/rims/",
            "content/IPCS/rims_v2/",
            "content/IPCS/",
            null,
            null
        ));
        sut = new CacheCrlFetcher(crlPrefetchRepositoryService, dpConnector, applicationProperties);
    }

    @Test
    void isValid_WithValidCrl_ReturnsTrue() throws CrlGenerationFailed {
        // given
        final var validCrl = generateCrl();

        // when-then
        assertTrue(sut.isValid(validCrl));
    }

    @Test
    void isValid_WithCrlAfterItsNextUpdate_ReturnsFalse() throws CrlGenerationFailed {
        // given
        final X509CRL expiredCrl = generateExpiredCrl();

        // when-then
        assertFalse(sut.isValid(expiredCrl));
    }

    @Test
    void isValid_WithCrlWithoutNextUpdate_ReturnsFalse() throws CrlGenerationFailed {
        // given
        final var crlWithoutNextUpdate = generateCrlWithoutNextUpdate();

        // when-then
        assertFalse(sut.isValid(crlWithoutNextUpdate));
    }
}
