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

package com.intel.bkp.bkps.rest.onboarding.event;

import com.intel.bkp.bkps.rest.onboarding.model.DeviceId;
import com.intel.bkp.bkps.rest.onboarding.service.ZipDataProvider;
import com.intel.bkp.fpgacerts.model.Family;
import com.intel.bkp.test.RandomUtils;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
class PrefetchEventListenerTest {

    private static final String UID = RandomUtils.generateDeviceIdHex();
    private static final String ID = RandomUtils.generateRandomHex(30);
    private static final Object EVENT_SOURCE = new Object();

    @Mock
    private ZipDataProvider zipDataProvider;

    @Mock
    private PrefetchEventQueueService prefetchEventQueueService;

    @InjectMocks
    private PrefetchEventListener sut;

    @Test
    void onApplicationEvent_WithS10_InvokesS10Prefetching() {
        // given
        final DeviceId deviceId = DeviceId.instance(Family.S10, UID, ID);
        final PrefetchEvent event = new PrefetchEvent(EVENT_SOURCE, deviceId);

        // when
        sut.onApplicationEvent(event);

        // then
        verify(prefetchEventQueueService).add(event);
        verify(prefetchEventQueueService).remove(event);
        verify(zipDataProvider).fetchS10(UID);
    }

    @ParameterizedTest
    @EnumSource(value = Family.class, names = {"AGILEX", "AGILEX_B", "EASIC_N5X"})
    void onApplicationEvent_WithSupportedPlatforms_InvokesDicePrefetching(Family family) {
        // given
        final DeviceId deviceId = DeviceId.instance(family, UID, ID);
        final PrefetchEvent event = new PrefetchEvent(EVENT_SOURCE, deviceId);

        // when
        sut.onApplicationEvent(event);

        // then
        verify(prefetchEventQueueService).add(event);
        verify(prefetchEventQueueService).remove(event);
        verify(zipDataProvider).fetchDice(deviceId.getDpUid(), family, deviceId.getId());
    }

    @ParameterizedTest
    @EnumSource(value = Family.class, names = {"MEV", "LKV", "CNV"})
    void onApplicationEvent_WithNotSupportedPlatform_ThrowsException(Family family) {
        // given
        final DeviceId deviceId = DeviceId.instance(family, UID, ID);
        final PrefetchEvent event = new PrefetchEvent(EVENT_SOURCE, deviceId);

        // when-then
        final IllegalArgumentException ex =
            assertThrows(IllegalArgumentException.class, () -> sut.onApplicationEvent(event));

        assertEquals("Prefetching is only supported for platforms: [S10, AGILEX, EASIC_N5X, AGILEX_B]",
            ex.getMessage());

        verify(prefetchEventQueueService).add(event);
        verify(prefetchEventQueueService).remove(event);
    }
}
