/*
 * This project is licensed as below.
 *
 * **************************************************************************
 *
 * Copyright 2020-2025 Altera Corporation. All Rights Reserved.
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

package com.intel.bkp.bkps.protocol.sigma.wrapping;

import com.intel.bkp.bkps.domain.AesKey;
import com.intel.bkp.bkps.domain.ConfidentialData;
import com.intel.bkp.bkps.domain.ServiceConfiguration;
import com.intel.bkp.bkps.exception.InvalidConfigurationException;
import com.intel.bkp.bkps.programmer.model.MessageType;
import com.intel.bkp.bkps.rest.errors.enums.ErrorCodeMap;
import com.intel.bkp.bkps.rest.provisioning.service.IServiceConfiguration;
import com.intel.bkp.core.exceptions.BKPBadRequestException;
import com.intel.bkp.core.psgcertificate.enumerations.KeyWrappingType;
import com.intel.bkp.core.psgcertificate.enumerations.StorageType;
import lombok.extern.slf4j.Slf4j;

import java.util.List;
import java.util.Optional;

import static com.intel.bkp.core.psgcertificate.enumerations.KeyWrappingType.UDS_IID_PUF;
import static com.intel.bkp.core.psgcertificate.enumerations.KeyWrappingType.USER_IID_PUF;

@Slf4j
public class KeyWrappingManager {

    private final Long cfgId;
    private final AesKey aesKey;

    public KeyWrappingManager(IServiceConfiguration configurationCallback, Long cfgId) {
        this.cfgId = cfgId;
        this.aesKey = Optional.ofNullable(configurationCallback.getConfiguration(cfgId))
            .map(ServiceConfiguration::getConfidentialData)
            .map(ConfidentialData::getAesKey)
            .orElseThrow(() -> new InvalidConfigurationException(cfgId));
    }

    public boolean isKeyWrapping() {
        return StorageType.PUFSS.equals(aesKey.getStorage());
    }

    public MessageType getMessageType(int supportedCommands) {
        final KeyWrappingType wrappingType = aesKey.getKeyWrappingType();

        return switch (wrappingType) {
            case USER_IID_PUF -> getMessageTypeForWrappingType(supportedCommands,
                MessageType.PUSH_WRAPPED_KEY_USER_IID);
            case UDS_IID_PUF -> getMessageTypeForWrappingType(supportedCommands, MessageType.PUSH_WRAPPED_KEY_UDS_IID);
            default -> throw new InvalidConfigurationException(cfgId,
                "Wrap Selection Field for Off-chip provisioning (PUF Sealed Storage) must be one of: "
                    + List.of(USER_IID_PUF, UDS_IID_PUF));
        };
    }

    private static MessageType getMessageTypeForWrappingType(int supportedCommands, MessageType messageType) {
        if (isSupported(supportedCommands, messageType)) {
            return messageType;
        }

        if (isSupported(supportedCommands, MessageType.PUSH_WRAPPED_KEY)) {
            return MessageType.PUSH_WRAPPED_KEY;
        }

        throw new BKPBadRequestException(ErrorCodeMap.UNSUPPORTED_PROVISIONING_OPERATION_FOR_PUFSS);
    }

    private static boolean isSupported(int supportedCommands, MessageType messageType) {
        return messageType.isSetIn(supportedCommands);
    }
}
