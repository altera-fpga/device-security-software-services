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

import com.intel.bkp.bkps.attestation.mapping.CacheBytesMapper;
import com.intel.bkp.bkps.config.ApplicationProperties;
import com.intel.bkp.bkps.connector.DpConnector;
import com.intel.bkp.bkps.rest.prefetching.service.ZipPrefetchRepositoryService;
import com.intel.bkp.core.properties.DistributionPoint;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Optional;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class CacheZipFetcherTest {

    private static Stream<Arguments> getExampleZips() {
        return Stream.of(
            Arguments.of(new byte[]{0x01}),
            Arguments.of(new byte[]{0x01, 0x02, 0x03})
        );
    }

    @Mock
    private ZipPrefetchRepositoryService zipPrefetchRepositoryService;

    @Mock
    private DpConnector dpConnector;

    private ApplicationProperties applicationProperties;

    private CacheZipFetcher sut;

    @BeforeEach
    void prepareSut() {
        when(zipPrefetchRepositoryService.getMapper()).thenReturn(new CacheBytesMapper());
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
        sut = new CacheZipFetcher(zipPrefetchRepositoryService, dpConnector, applicationProperties);
    }

    @ParameterizedTest
    @NullAndEmptySource
    @MethodSource("getExampleZips")
    void isValid_ReturnsTrue(byte[] input) {
        assertTrue(sut.isValid(input));
    }

    @Test
    void fetchCertificate_CallsBaseFetchMethod() {
        // given
        final String path = "https://somePath";
        final Optional<byte[]> expected = Optional.of(new byte[]{0x02, 0x02});
        final var sutSpy = spy(sut);
        when(sutSpy.fetchSkipCache(path)).thenReturn(expected);

        // when
        final var result = sutSpy.fetchCertificate(path);

        // then
        assertEquals(expected, result);
        verify(sutSpy).fetchSkipCache(path);

    }
}
