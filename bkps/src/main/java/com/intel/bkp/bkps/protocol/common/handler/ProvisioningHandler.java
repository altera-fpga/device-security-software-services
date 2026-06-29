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

package com.intel.bkp.bkps.protocol.common.handler;

import com.intel.bkp.bkps.exception.SpdmProcessIsStillRunning;
import com.intel.bkp.bkps.rest.provisioning.model.dto.ProvisioningResponseDTO;
import com.intel.bkp.bkps.rest.provisioning.model.dto.ProvisioningTransferObject;
import dev.failsafe.RetryPolicy;
import lombok.Getter;
import lombok.Setter;

import java.time.Duration;

@Setter
@Getter
public abstract class ProvisioningHandler {

    protected ProvisioningHandler successor;

    protected final RetryPolicy<Object> retryPolicy = RetryPolicy.builder()
        .handle(SpdmProcessIsStillRunning.class)
        .withDelay(Duration.ofSeconds(1))
        .withMaxRetries(3)
        .build();

    protected final RetryPolicy<Object> retryPolicyLong = RetryPolicy.builder()
        .handle(SpdmProcessIsStillRunning.class)
        .withDelay(Duration.ofSeconds(1))
        .withMaxRetries(5)
        .build();

    public ProvisioningResponseDTO handle(ProvisioningTransferObject transferObject) {
        return successor.handle(transferObject);
    }

    protected String prepareLogEntry(String data) {
        return String.format("[PROVISIONING] %s", data);
    }
}
