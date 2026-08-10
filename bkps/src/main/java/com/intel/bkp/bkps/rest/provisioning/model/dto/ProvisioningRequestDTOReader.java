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

package com.intel.bkp.bkps.rest.provisioning.model.dto;

import com.intel.bkp.bkps.exception.ProvisioningConverterException;
import com.intel.bkp.bkps.programmer.model.ProgrammerResponse;
import com.intel.bkp.bkps.protocol.common.model.FlowStage;
import com.intel.bkp.bkps.protocol.common.model.ProtocolType;
import com.intel.bkp.bkps.protocol.common.model.ProvContext;
import com.intel.bkp.bkps.protocol.common.model.ProvContextWithFlow;
import com.intel.bkp.bkps.rest.provisioning.utils.ProvisioningContextConverter;
import com.intel.bkp.crypto.aesgcm.AesGcmProvider;
import com.intel.bkp.crypto.exceptions.EncryptionProviderException;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;

import java.util.List;

@Getter
@Setter
@Slf4j
public class ProvisioningRequestDTOReader {

    private final AesGcmProvider encryptionProvider;
    private final FlowStage flowStage;
    private final ProtocolType protocolType;
    private final byte[] contextData;
    private final ProvisioningRequestDTO dto;
    private final List<ProgrammerResponse> jtagResponses;

    public ProvisioningRequestDTOReader(AesGcmProvider encryptionProvider,
        ProvisioningRequestDTO dto) throws ProvisioningConverterException, EncryptionProviderException {
        this.dto = dto;
        this.encryptionProvider = encryptionProvider;

        final ProvContextWithFlow provContextWithFlow = readBase();
        this.flowStage = provContextWithFlow.getFlowStage();
        this.protocolType = provContextWithFlow.getProtocolType();
        this.contextData = provContextWithFlow.getContextData();
        this.jtagResponses = ProvisioningContextConverter.decodeResponses(dto.getJtagResponses());

        log.info("FLOW STAGE: " + flowStage.name());
    }

    private ProvContextWithFlow readBase() throws ProvisioningConverterException,
        EncryptionProviderException {
        final byte[] decoded = dto.getDecodedContext();
        final byte[] decrypted = encryptionProvider.decrypt(decoded);
        return ProvisioningContextConverter.deserializeBase(decrypted);
    }

    public ProvContext read(Class<? extends ProvContext> type) throws ProvisioningConverterException {
        return ProvisioningContextConverter.deserialize(contextData, type);
    }

    public Long getCfgId() {
        return dto.getCfgId();
    }
}
