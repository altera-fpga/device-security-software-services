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

package com.intel.bkp.bkps.rest.onboarding.handler;

import com.intel.bkp.bkps.exception.PrefetchingStatusFailed;
import com.intel.bkp.bkps.rest.onboarding.event.PrefetchEventQueueService;
import com.intel.bkp.bkps.rest.onboarding.model.DeviceId;
import com.intel.bkp.bkps.rest.onboarding.model.PrefetchStatusRequestDTO;
import com.intel.bkp.bkps.rest.onboarding.model.PrefetchStatusResponseDTO;
import com.intel.bkp.bkps.rest.prefetching.service.ZipPrefetchRepositoryService;
import com.intel.bkp.fpgacerts.model.Family;
import com.intel.bkp.test.RandomUtils;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.stream.Stream;

import static com.intel.bkp.bkps.rest.errors.enums.ErrorCodeMap.PREFETCHING_STATUS_FAILED_INVALID_PARAMS;
import static com.intel.bkp.bkps.rest.onboarding.model.PrefetchStatusResponseDTO.PREFETCH_DONE;
import static com.intel.bkp.bkps.rest.onboarding.model.PrefetchStatusResponseDTO.PREFETCH_IN_PROGRESS;
import static com.intel.bkp.bkps.rest.onboarding.model.PrefetchStatusResponseDTO.PREFETCH_NOT_FOUND;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.CALLS_REAL_METHODS;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class PrefetchStatusServiceTest {

    private static final Family FAMILY = Family.AGILEX;
    private static final Family FAMILY_S10 = Family.S10;
    private static final String UID = RandomUtils.generateDeviceIdHex();
    private static final PrefetchStatusRequestDTO EMPTY_PARAMS = new PrefetchStatusRequestDTO(null, null);
    private static final PrefetchStatusRequestDTO VALID_PARAMS = new PrefetchStatusRequestDTO(FAMILY.getAsHex(), UID);
    private static final PrefetchStatusRequestDTO VALID_PARAMS_S10 =
        new PrefetchStatusRequestDTO(FAMILY_S10.getAsHex(), UID);
    private static final PrefetchStatusRequestDTO INVALID_PARAMS_EMPTY_UID =
        new PrefetchStatusRequestDTO(FAMILY.getAsHex(), null);
    private static final PrefetchStatusRequestDTO INVALID_PARAMS_EMPTY_FAMILY =
        new PrefetchStatusRequestDTO(null, UID);

    private static final DeviceId DEVICE_ID_AGILEX = DeviceId.instance(FAMILY, UID);
    private static final DeviceId DEVICE_ID_S10 = DeviceId.instance(FAMILY_S10, UID);

    @Mock
    private ZipPrefetchRepositoryService zipPrefetchRepositoryService;
    @Mock
    private PrefetchEventQueueService prefetchEventQueueService;

    @InjectMocks
    private PrefetchStatusService sut;

    private static Stream<Arguments> getInvalidParams() {
        return Stream.of(
            Arguments.of(INVALID_PARAMS_EMPTY_UID),
            Arguments.of(INVALID_PARAMS_EMPTY_FAMILY)
        );
    }

    @Test
    void isPrefetched_ForEmptyParamsAndEmptyQueue_ReturnsDone() {
        // given
        when(prefetchEventQueueService.isEmpty()).thenReturn(true);

        // when
        final PrefetchStatusResponseDTO result = sut.isPrefetched(EMPTY_PARAMS);

        // then
        assertEquals(PREFETCH_DONE, result);
    }

    @Test
    void isPrefetched_ForEmptyParamsAndNonEmptyQueue_ReturnsInProgress() {
        // given
        when(prefetchEventQueueService.isEmpty()).thenReturn(false);

        // when
        final PrefetchStatusResponseDTO result = sut.isPrefetched(EMPTY_PARAMS);

        // then
        assertEquals(PREFETCH_IN_PROGRESS, result);
    }

    @Test
    void isPrefetched_ForValidParamsAndPrefetchedZip_ReturnsDone() {
        // given
        when(zipPrefetchRepositoryService.isZipPrefetched(DEVICE_ID_AGILEX)).thenReturn(true);

        // when
        try (var deviceId = mockStatic(DeviceId.class, CALLS_REAL_METHODS)) {
            deviceId.when(() -> DeviceId.instance(any(), any())).thenReturn(DEVICE_ID_AGILEX);

            final PrefetchStatusResponseDTO result = sut.isPrefetched(VALID_PARAMS);

            // then
            assertEquals(PREFETCH_DONE, result);
        }
    }

    @Test
    void isPrefetched_WithS10AndNotReversedUid_ReturnsDone() {
        // given
        when(zipPrefetchRepositoryService.isS10Prefetched(DEVICE_ID_S10)).thenReturn(true);

        // when
        try (var deviceId = mockStatic(DeviceId.class, CALLS_REAL_METHODS)) {
            deviceId.when(() -> DeviceId.instance(any(), any())).thenReturn(DEVICE_ID_S10);

            final PrefetchStatusResponseDTO result = sut.isPrefetched(VALID_PARAMS_S10);

            // then
            assertEquals(PREFETCH_DONE, result);
        }
    }

    @Test
    void isPrefetched_ForValidParamsAndNotPrefetchedZipNotEmptyQueue_ReturnsInProgress() {
        // given
        when(zipPrefetchRepositoryService.isZipPrefetched(DEVICE_ID_AGILEX)).thenReturn(false);
        when(prefetchEventQueueService.isInProgress(DEVICE_ID_AGILEX)).thenReturn(true);

        // when
        try (var deviceId = mockStatic(DeviceId.class, CALLS_REAL_METHODS)) {
            deviceId.when(() -> DeviceId.instance(any(), any())).thenReturn(DEVICE_ID_AGILEX);

            final PrefetchStatusResponseDTO result = sut.isPrefetched(VALID_PARAMS);

            // then
            assertEquals(PREFETCH_IN_PROGRESS, result);
        }
    }

    @Test
    void isPrefetched_ForValidParamsAndNotPrefetchedZipEmptyQueue_ReturnsNotFound() {
        // given
        when(zipPrefetchRepositoryService.isZipPrefetched(DEVICE_ID_AGILEX)).thenReturn(false);
        when(prefetchEventQueueService.isInProgress(DEVICE_ID_AGILEX)).thenReturn(false);

        // when
        try (var deviceId = mockStatic(DeviceId.class, CALLS_REAL_METHODS)) {
            deviceId.when(() -> DeviceId.instance(any(), any())).thenReturn(DEVICE_ID_AGILEX);

            final PrefetchStatusResponseDTO result = sut.isPrefetched(VALID_PARAMS);

            // then
            assertEquals(PREFETCH_NOT_FOUND, result);
        }
    }

    @ParameterizedTest
    @MethodSource("getInvalidParams")
    void isPrefetched_ForInvalidParams_Throws(PrefetchStatusRequestDTO dto) {
        // when-then
        final var ex = assertThrows(PrefetchingStatusFailed.class, () -> sut.isPrefetched(dto));

        assertEquals(PREFETCHING_STATUS_FAILED_INVALID_PARAMS.getExternalMessage(), ex.getMessage());
    }
}
