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
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Isolation;
import org.springframework.transaction.annotation.Transactional;

@Service
@AllArgsConstructor
@Transactional(isolation = Isolation.SERIALIZABLE)
@Slf4j
public class ProvisioningHistoryService {

    private final ProvisioningHistoryRepositoryService provisioningHistoryRepositoryService;

    /**
     * Returns current provisioned flag and performs update provisioned status for pair - device id and puf type.
     *
     * @param deviceIdHex - chip id of the device in HEX format
     * @param pufType     - pufType from configuration
     * @return boolean - flag of current status before update
     */
    public boolean getCurrentProvisionedStatusAndUpdate(final String deviceIdHex, final PufType pufType) {
        final boolean isProvisionedFirstTime = provisioningHistoryRepositoryService
            .markProvisioned(deviceIdHex, pufType);
        if (!isProvisionedFirstTime) {
            log.info("Performing re-provisioning for device id: {} and puf type: {}", deviceIdHex, pufType);
        }
        return isProvisionedFirstTime;
    }

    public boolean isProvisioned(final String deviceIdHex, final PufType pufType) {
        return provisioningHistoryRepositoryService.isProvisioned(deviceIdHex, pufType);
    }
}
