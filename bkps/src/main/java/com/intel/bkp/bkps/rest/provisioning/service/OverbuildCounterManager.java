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
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Isolation;
import org.springframework.transaction.annotation.Transactional;

@Service
@AllArgsConstructor(access = AccessLevel.PACKAGE)
@Slf4j
@Transactional(isolation = Isolation.SERIALIZABLE)
public class OverbuildCounterManager {

    private final ProvisioningHistoryService provisioningHistoryService;

    public void increment(IServiceConfiguration configurationCallback, Long cfgId) throws ExceededOvebuildException {
        log.info("Updating overbuild counter ...");

        if (configurationCallback.getConfigurationAndUpdate(cfgId) != 1) {
            throw new ExceededOvebuildException();
        }
    }

    public void verifyOverbuildCounter(final ServiceConfiguration configuration, String deviceIdHex)
        throws ExceededOvebuildException {

        final int overbuildMax = configuration.getOverbuildMax();
        final int overbuildCurrent = configuration.getOverbuildCurrent();

        if (overbuildMax != ServiceConfiguration.OVERBUILD_MAX_INFINITE
            && overbuildCurrent >= overbuildMax
            && !provisioningHistoryService.isProvisioned(deviceIdHex, configuration.getPufType())) {
            throw new ExceededOvebuildException(overbuildMax, overbuildCurrent);
        }
    }

}
