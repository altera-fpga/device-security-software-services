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

package com.intel.bkp.bkps.connector;

import com.intel.bkp.bkps.config.ApplicationProperties;
import com.intel.bkp.core.properties.DistributionPoint;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import java.util.Optional;

import static com.intel.bkp.utils.HexConverter.toHex;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class DpConnectorTest {

    private static final String TEST_URL = "https://example.domain.com/test.cer";
    private static final String NEW_TEST_URL = "https://example.domain.new.com/test.cer";
    private static final Class<byte[]> RESPONSE_TYPE = byte[].class;
    private static final byte[] EXAMPLE_CERT_CONTENT = new byte[]{1, 2, 3, 4};

    @Mock
    private RestTemplateFactory restTemplateService;

    @Mock
    private RestTemplate restTemplate;

    @InjectMocks
    private DpConnector sut;

    @BeforeEach
    void setUp() {
        when(restTemplateService.getRestTemplate()).thenReturn(restTemplate);
        ApplicationProperties properties = new ApplicationProperties();
        properties.setDistributionPoint(new DistributionPoint(NEW_TEST_URL, "", "", "", "", null, null));
        sut = new DpConnector(restTemplate, properties);
    }

    @Test
    void tryGetBytes_WithValidResponse_Success() {
        // given
        when(restTemplate.getForEntity(NEW_TEST_URL, RESPONSE_TYPE))
            .thenReturn(ResponseEntity.of(Optional.of(EXAMPLE_CERT_CONTENT)));

        // when
        final Optional<byte[]> response = sut.tryGetBytes(TEST_URL);

        // then
        verify(restTemplate).getForEntity(NEW_TEST_URL, RESPONSE_TYPE);
        assertTrue(response.isPresent());
        response.ifPresent(bytes -> assertEquals(toHex(EXAMPLE_CERT_CONTENT), toHex(bytes)));
    }

    @Test
    void tryGetBytes_WithEmptyResponse_ReturnsEmpty() {
        // given
        when(restTemplate.getForEntity(NEW_TEST_URL, RESPONSE_TYPE))
            .thenReturn(ResponseEntity.of(Optional.empty()));

        // when
        final Optional<byte[]> response = sut.tryGetBytes(TEST_URL);

        // then
        verify(restTemplate).getForEntity(NEW_TEST_URL, RESPONSE_TYPE);
        assertFalse(response.isPresent());
    }

    @Test
    void tryGetBytes_WithWrongResponseCode_ReturnsEmpty() {
        // given
        when(restTemplate.getForEntity(NEW_TEST_URL, RESPONSE_TYPE))
            .thenThrow(HttpClientErrorException.create(HttpStatus.BAD_REQUEST, "test", new HttpHeaders(), null, null));

        // when
        final Optional<byte[]> response = sut.tryGetBytes(TEST_URL);

        // then
        verify(restTemplate).getForEntity(NEW_TEST_URL, RESPONSE_TYPE);
        assertFalse(response.isPresent());
    }
}
