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

import com.intel.bkp.core.manufacturing.model.PufType;
import com.intel.bkp.test.RandomUtils;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
public class ProvisioningHistoryServiceTest {

    private static final String DEVICE_ID = RandomUtils.generateDeviceIdHex();
    private static final PufType PUF_TYPE = PufType.EFUSE;

    @Mock
    private ProvisioningHistoryRepositoryService provisioningHistoryRepositoryService;

    @InjectMocks
    private ProvisioningHistoryService sut;

    @Test
    void getCurrentProvisionedStatusAndUpdate_Success() {
        //given
        mockProvisioningState(false);

        // when
        final boolean result = sut.getCurrentProvisionedStatusAndUpdate(DEVICE_ID, PUF_TYPE);

        // then
        verify(provisioningHistoryRepositoryService).markProvisioned(DEVICE_ID, PUF_TYPE);
        assertTrue(result);
    }

    @Test
    void getCurrentProvisionedStatusAndUpdate_WithProvisionedDevice_Success() {
        //given
        mockProvisioningState(true);

        // when
        final boolean result = sut.getCurrentProvisionedStatusAndUpdate(DEVICE_ID, PUF_TYPE);

        // then
        verify(provisioningHistoryRepositoryService).markProvisioned(DEVICE_ID, PUF_TYPE);
        assertFalse(result);
    }

    @Test
    void isProvisioned_WithNotProvisionedDevice_ReturnsFalse() {
        //given
        mockIsProvisioned(false);

        // when
        boolean result = sut.isProvisioned(DEVICE_ID, PUF_TYPE);

        // then
        assertFalse(result);
    }

    @Test
    void isProvisioned_WithProvisionedDevice_ReturnsTrue() {
        //given
        mockIsProvisioned(true);

        // when
        boolean result = sut.isProvisioned(DEVICE_ID, PUF_TYPE);

        // then
        assertTrue(result);
    }

    private void mockProvisioningState(boolean isProvisioned) {
        when(provisioningHistoryRepositoryService.markProvisioned(any(String.class),
            any(PufType.class))).thenReturn(!isProvisioned);
    }

    private void mockIsProvisioned(boolean isProvisioned) {
        when(provisioningHistoryRepositoryService.isProvisioned(any(String.class),
            any(PufType.class))).thenReturn(isProvisioned);
    }
}
