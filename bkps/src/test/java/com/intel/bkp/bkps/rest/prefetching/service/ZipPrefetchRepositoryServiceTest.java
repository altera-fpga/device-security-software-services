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

import com.intel.bkp.bkps.domain.PrefetchEntity;
import com.intel.bkp.bkps.repository.PrefetchRepository;
import com.intel.bkp.bkps.rest.onboarding.model.DeviceId;
import com.intel.bkp.fpgacerts.model.Family;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Optional;

import static com.intel.bkp.bkps.domain.enumeration.PrefetchEntityType.CERT;
import static com.intel.bkp.bkps.domain.enumeration.PrefetchEntityType.ZIP;
import static com.intel.bkp.utils.HexConverter.toHex;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class ZipPrefetchRepositoryServiceTest {

    private static final String UID = "0102030405060708";
    private static final DeviceId DEVICE_ID = DeviceId.instance(Family.AGILEX, UID);
    private static final String ZIP_PATH_PATTERN = "34_0807060504030201";
    private static final String S10_PATH_PATTERN = "attestation_0807060504030201";

    @Mock
    private PrefetchRepository prefetchRepository;

    @InjectMocks
    private ZipPrefetchRepositoryService sut;

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void isZipPrefetched_ReturnsExpected(boolean expected) {
        // given
        when(prefetchRepository.existsByPathContainingIgnoreCaseAndType(ZIP_PATH_PATTERN, ZIP))
            .thenReturn(expected);
        // when
        final boolean result = sut.isZipPrefetched(DEVICE_ID);

        // then
        assertEquals(expected, result);
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void isS10Prefetched_ReturnsExpected(boolean expected) {
        // given
        when(prefetchRepository.existsByPathContainingIgnoreCaseAndType(S10_PATH_PATTERN, CERT))
            .thenReturn(expected);
        // when
        final boolean result = sut.isS10Prefetched(DEVICE_ID);

        // then
        assertEquals(expected, result);
    }

    @Test
    void find_WhenEntityExists_ReturnsZip() {
        // given
        final byte[] zipBytes = {1, 2, 3};
        final var entity = new PrefetchEntity(ZIP_PATH_PATTERN, toHex(zipBytes), ZIP);
        when(prefetchRepository.findByPathContainingIgnoreCaseAndType(ZIP_PATH_PATTERN, ZIP))
            .thenReturn(Optional.of(entity));

        // when
        final var result = sut.find(DEVICE_ID);

        // then
        assertArrayEquals(zipBytes, result.orElse(null));
    }

    @Test
    void find_WhenEntityDoesNotExist_ReturnsEmpty() {
        // given
        when(prefetchRepository.findByPathContainingIgnoreCaseAndType(ZIP_PATH_PATTERN, ZIP))
            .thenReturn(Optional.empty());

        // when
        final var result = sut.find(DEVICE_ID);

        // then
        assertEquals(Optional.empty(), result);
    }
}
