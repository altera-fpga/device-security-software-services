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

package com.intel.bkp.bkps.rest.provisioning.service;

import com.intel.bkp.bkps.domain.ServiceConfiguration;
import com.intel.bkp.bkps.exception.ExceededOvebuildException;
import com.intel.bkp.test.RandomUtils;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
public class OverbuildCounterManagerTest {

    private static final String DEVICE_ID = RandomUtils.generateDeviceIdHex();
    private static final Long CFG_ID = 1L;

    @Mock
    private IServiceConfiguration configurationCallback;

    @Mock
    private ServiceConfiguration configuration;

    @Mock
    private ProvisioningHistoryService provisioningHistoryService;

    @InjectMocks
    private OverbuildCounterManager sut;

    @Test
    void increment_UpdatePerformed_Success() {
        //given
        when(configurationCallback.getConfigurationAndUpdate(CFG_ID)).thenReturn(1);

        // when-then
        assertDoesNotThrow(() -> sut.increment(configurationCallback, CFG_ID));
    }

    @Test
    void increment_UpdateNotPerformed_Throws() {
        //given
        when(configurationCallback.getConfigurationAndUpdate(CFG_ID)).thenReturn(0);

        // when-then
        assertThrows(ExceededOvebuildException.class, () -> sut.increment(configurationCallback, CFG_ID));
    }

    @Test
    void verifyOverbuildCounter_WithOverbuildMax1AndCurrentOverbuild0_Success() {
        //given
        when(configuration.getOverbuildMax()).thenReturn(1);
        when(configuration.getOverbuildCurrent()).thenReturn(0);

        // when-then
        assertDoesNotThrow(() -> sut.verifyOverbuildCounter(configuration, DEVICE_ID));
    }

    @Test
    void verifyOverbuildCounter_WithOverbuildMax1AndCurrentOverbuild1_WithReProvisionedDevice_Success() {
        // given
        when(configuration.getOverbuildMax()).thenReturn(1);
        when(configuration.getOverbuildCurrent()).thenReturn(1);
        when(provisioningHistoryService.isProvisioned(any(), any())).thenReturn(true);

        // when-then
        assertDoesNotThrow(() -> sut.verifyOverbuildCounter(configuration, DEVICE_ID));
    }

    @Test
    void verifyOverbuildCounter_WithOverbuildMaxINTMAXAndCurrentOverbuild1_Success() {
        // given
        when(configuration.getOverbuildMax()).thenReturn(Integer.MAX_VALUE);
        when(configuration.getOverbuildCurrent()).thenReturn(1);

        // when-then
        assertDoesNotThrow(() -> sut.verifyOverbuildCounter(configuration, DEVICE_ID));
    }

    @Test
    void verifyOverbuildCounter_WithOverbuildMaxInfinite_Success() {
        // given
        when(configuration.getOverbuildMax()).thenReturn(ServiceConfiguration.OVERBUILD_MAX_INFINITE);
        when(configuration.getOverbuildCurrent()).thenReturn(100);

        // when-then
        assertDoesNotThrow(() -> sut.verifyOverbuildCounter(configuration, DEVICE_ID));
    }

    @Test
    void verifyOverbuildCounter_WithOverbuildMax1AndCurrentOverbuild1_WithNotProvisionedDevice_Throws() {
        // given
        when(configuration.getOverbuildMax()).thenReturn(1);
        when(configuration.getOverbuildCurrent()).thenReturn(1);
        when(provisioningHistoryService.isProvisioned(any(), any())).thenReturn(false);

        // when-then
        assertThrows(ExceededOvebuildException.class, () ->
            sut.verifyOverbuildCounter(configuration, DEVICE_ID));
    }

    @Test
    void verifyOverbuildCounter_ExceededOverbuildCounter_Throws() {
        // given
        when(configuration.getOverbuildMax()).thenReturn(0);
        when(configuration.getOverbuildCurrent()).thenReturn(1);

        // when-then
        assertThrows(ExceededOvebuildException.class, () ->
            sut.verifyOverbuildCounter(configuration, DEVICE_ID));
    }
}
