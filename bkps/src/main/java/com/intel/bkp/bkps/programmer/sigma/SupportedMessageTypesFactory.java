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

package com.intel.bkp.bkps.programmer.sigma;

import com.intel.bkp.bkps.exception.PufActivationPufTypeNotSupported;
import com.intel.bkp.bkps.exception.SetAuthorityPufTypeNotSupported;
import com.intel.bkp.bkps.programmer.model.MessageType;
import com.intel.bkp.core.manufacturing.model.PufType;
import com.intel.bkp.core.psgcertificate.enumerations.KeyWrappingType;
import com.intel.bkp.core.psgcertificate.enumerations.StorageType;
import lombok.extern.slf4j.Slf4j;

import java.util.ArrayList;
import java.util.List;

import static com.intel.bkp.bkps.programmer.model.MessageType.PUSH_HELPER_DATA_UDS_IID;
import static com.intel.bkp.bkps.programmer.model.MessageType.PUSH_HELPER_DATA_UDS_INTEL;
import static com.intel.bkp.bkps.programmer.model.MessageType.PUSH_WRAPPED_KEY;
import static com.intel.bkp.bkps.programmer.model.MessageType.PUSH_WRAPPED_KEY_UDS_IID;
import static com.intel.bkp.bkps.programmer.model.MessageType.PUSH_WRAPPED_KEY_USER_IID;
import static com.intel.bkp.bkps.programmer.model.MessageType.SEND_PACKET;
import static com.intel.bkp.core.manufacturing.model.PufType.EFUSE;
import static com.intel.bkp.core.manufacturing.model.PufType.IID;
import static com.intel.bkp.core.manufacturing.model.PufType.INTEL;

@Slf4j
public class SupportedMessageTypesFactory {

    public static List<MessageType> getRequired() {
        return List.of(SEND_PACKET);
    }

    public static MessageType getForPufActivate(PufType pufType) {
        return switch (pufType) {
            case IID -> PUSH_HELPER_DATA_UDS_IID;
            case INTEL -> PUSH_HELPER_DATA_UDS_INTEL;
            default -> throw new PufActivationPufTypeNotSupported(List.of(IID, INTEL), pufType);
        };
    }

    public static MessageType getForSetAuthority(PufType pufType) {
        final List<PufType> supportedPufTypes = List.of(IID, INTEL, EFUSE);
        if (!supportedPufTypes.contains(pufType)) {
            throw new SetAuthorityPufTypeNotSupported(supportedPufTypes, pufType);
        }

        return SEND_PACKET;
    }

    public static List<MessageType> getForKeyWrapping(StorageType aesKeyStorage, KeyWrappingType keyWrappingType) {
        log.debug("Configuration details. StorageType: {}, KeyWrappingType: {}", aesKeyStorage, keyWrappingType);

        if (StorageType.PUFSS != aesKeyStorage) {
            return List.of();
        }

        final List<MessageType> expectedTypes = new ArrayList<>();
        expectedTypes.add(PUSH_WRAPPED_KEY);

        switch (keyWrappingType) {
            case USER_IID_PUF -> expectedTypes.add(PUSH_WRAPPED_KEY_USER_IID);
            case UDS_IID_PUF -> expectedTypes.add(PUSH_WRAPPED_KEY_UDS_IID);
        }

        return expectedTypes;
    }
}
