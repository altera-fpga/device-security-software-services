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

import com.intel.bkp.bkps.attestation.mapping.CacheCborMapper;
import com.intel.bkp.bkps.config.ApplicationProperties;
import com.intel.bkp.bkps.connector.DpConnector;
import com.intel.bkp.bkps.rest.prefetching.service.CorimPrefetchRepositoryService;
import com.intel.bkp.core.properties.DistributionPoint;
import com.upokecenter.cbor.CBORObject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Optional;

import static com.intel.bkp.utils.HexConverter.toHex;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class CacheCoRimFetcherTest {

    @Mock
    private CBORObject cborObj;

    @Mock
    private CorimPrefetchRepositoryService corimPrefetchRepositoryService;

    private ApplicationProperties applicationProperties;

    @Mock
    private DpConnector dpConnector;

    private CacheCoRimFetcher sut;

    @BeforeEach
    void prepareSut() {
        when(corimPrefetchRepositoryService.getMapper()).thenReturn(new CacheCborMapper());
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
        sut = new CacheCoRimFetcher(corimPrefetchRepositoryService, dpConnector, applicationProperties);
    }

    @Test
    void isValid_returnsTrue() {
        assertTrue(sut.isValid(cborObj));
    }

    @Test
    void fetchAsHex_CallsBaseFetchMethod_ReturnsFetchResultAsHex() {
        // given
        final String path = "https://somePath";
        final Optional<CBORObject> expected = Optional.of(cborObj);
        final var sutSpy = spy(sut);
        when(sutSpy.fetch(path)).thenReturn(expected);
        final byte[] cborBytes = {0x05, 0x07};
        when(cborObj.EncodeToBytes()).thenReturn(cborBytes);

        // when
        final var result = sutSpy.fetchAsHex(path);

        // then
        assertEquals(Optional.of(toHex(cborBytes)), result);
        verify(sutSpy).fetch(path);
    }
}
