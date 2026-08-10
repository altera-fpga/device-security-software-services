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

package com.intel.bkp.core.psgcertificate.enumerations;

import com.intel.bkp.utils.HexConverter;
import lombok.AllArgsConstructor;
import lombok.Getter;

import java.util.EnumSet;

@Getter
@AllArgsConstructor
public enum KeyWrappingType {
    NOWRAP(0x00),
    INTERNAL(0x01), // ND/FM - BBRAM, EFUSE; SM - BBRAM, EFUSE and Offchip
    USER_IID_PUF(0x02), // (Intrinsic ID PUF)
    UDS_IID_PUF(0x03), // efuse based, FM only
    UDS_INTEL_PUF(0x04); // INTEL PUF (SM only)

    private final Integer type;

    public static KeyWrappingType fromValue(byte value) {
        return EnumSet.allOf(KeyWrappingType.class)
            .stream()
            .filter(type -> type.getType().byteValue() == value)
            .findFirst()
            .orElseThrow(IllegalArgumentException::new);
    }

    @Override
    public String toString() {
        return "%s (%s)".formatted(name(), HexConverter.toFormattedHex(getType()));
    }
}
