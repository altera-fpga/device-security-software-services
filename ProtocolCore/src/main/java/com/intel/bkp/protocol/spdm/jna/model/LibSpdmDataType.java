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

package com.intel.bkp.protocol.spdm.jna.model;

import lombok.AllArgsConstructor;
import lombok.Getter;

import java.util.EnumSet;
import java.util.Objects;

@Getter
@AllArgsConstructor
public enum LibSpdmDataType {

    // These values may change after libspdm version update
    LIBSPDM_DATA_CAPABILITY_FLAGS(0x02),
    LIBSPDM_DATA_CAPABILITY_CT_EXPONENT(0x03),
    LIBSPDM_DATA_MEASUREMENT_SPEC(0x08),
    LIBSPDM_DATA_BASE_ASYM_ALGO(0x0A),
    LIBSPDM_DATA_BASE_HASH_ALGO(0x0B),
    LIBSPDM_DATA_DHE_NAME_GROUP(0x0C),
    LIBSPDM_DATA_AEAD_CIPHER_SUITE(0x0D),
    LIBSPDM_DATA_REQ_BASE_ASYM_ALG(0x0E),
    LIBSPDM_DATA_KEY_SCHEDULE(0x0F),
    LIBSPDM_DATA_OTHER_PARAMS_SUPPORT(0x10),
    LIBSPDM_DATA_LOCAL_PUBLIC_CERT_CHAIN(0x14);

    private final Integer value;

    public static String paramNameFromValue(Integer value) {
        return EnumSet.allOf(LibSpdmDataType.class)
            .stream()
            .filter(type -> Objects.equals(type.getValue(), value))
            .findFirst()
            .map(Enum::name)
            .orElseThrow(IllegalArgumentException::new);
    }
}
