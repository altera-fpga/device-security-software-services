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

import com.intel.bkp.bkps.exception.ProvisioningGenericException;
import com.intel.bkp.bkps.protocol.common.handler.ProvAdapterComponent;
import com.intel.bkp.bkps.protocol.common.handler.ProvCreateComponent;
import com.intel.bkp.bkps.protocol.common.handler.ProvDecisionComponent;
import com.intel.bkp.bkps.protocol.common.handler.ProvQuartusStatusVerifierComponent;
import com.intel.bkp.bkps.protocol.common.handler.ProvSupportedCommandsComponent;
import com.intel.bkp.bkps.protocol.common.handler.ProvisioningHandler;
import com.intel.bkp.bkps.rest.errors.enums.ErrorCodeMap;
import com.intel.bkp.bkps.rest.provisioning.model.dto.ProvisioningRequestDTO;
import com.intel.bkp.bkps.rest.provisioning.model.dto.ProvisioningResponseDTO;
import com.intel.bkp.bkps.rest.provisioning.model.dto.ProvisioningTransferObject;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.CannotAcquireLockException;
import org.springframework.retry.annotation.Backoff;
import org.springframework.retry.annotation.EnableRetry;
import org.springframework.retry.annotation.Recover;
import org.springframework.retry.annotation.Retryable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Isolation;
import org.springframework.transaction.annotation.Transactional;

import static lombok.AccessLevel.PACKAGE;

@Service
@RequiredArgsConstructor(access = PACKAGE)
@Slf4j
@EnableRetry
@Transactional(isolation = Isolation.SERIALIZABLE)
public class ProvisioningService {

    private final ServiceConfigurationProvider serviceConfigurationProvider;
    private final ProvSupportedCommandsComponent provSupportedCommandsComponent;
    private final ProvCreateComponent provCreateComponent;
    private final ProvAdapterComponent provAdapterComponent;
    private final ProvQuartusStatusVerifierComponent provQuartusStatusVerifierComponent;
    private final ProvDecisionComponent provDecisionComponent;

    @Setter(value = PACKAGE)
    private ProvisioningHandler provEntrypointComponent = new ProvisioningHandler() {
    };

    @PostConstruct
    void init() {
        provEntrypointComponent.setSuccessor(provSupportedCommandsComponent);
        provSupportedCommandsComponent.setSuccessor(provCreateComponent);
        provCreateComponent.setSuccessor(provAdapterComponent);
        provAdapterComponent.setSuccessor(provQuartusStatusVerifierComponent);
        provQuartusStatusVerifierComponent.setSuccessor(provDecisionComponent);
    }

    @Retryable(
        retryFor = CannotAcquireLockException.class,
        maxAttempts = 5,
        backoff = @Backoff(delay = 100, maxDelay = 2000, multiplier = 2, random = true)
    )
    public ProvisioningResponseDTO getNext(ProvisioningRequestDTO dto) {
        ProvisioningResponseDTO response = getNextInternal(dto);
        response.setApiVersion(dto.getApiVersion());
        return response;
    }

    private ProvisioningResponseDTO getNextInternal(ProvisioningRequestDTO dto) {
        return provEntrypointComponent.handle(ProvisioningTransferObject
            .builder()
            .dto(dto)
            .configurationCallback(serviceConfigurationProvider)
            .build()
        );
    }

    @Recover
    public ProvisioningResponseDTO throwOtherTransactionInProgress(Exception e)
        throws Exception {
        if (e instanceof CannotAcquireLockException) {
            throw new ProvisioningGenericException(ErrorCodeMap.OTHER_TRANSACTION_IN_PROGRESS);
        } else {
            throw e;
        }
    }
}
