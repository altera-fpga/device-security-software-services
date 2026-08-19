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

package com.intel.bkp.core.helper;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AccessLevel;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.ToString;

import static com.intel.bkp.utils.FirstIntegerByteParser.toSingleByte;
import static java.lang.Byte.toUnsignedInt;

@Getter
@ToString
@EqualsAndHashCode
@RequiredArgsConstructor(access = AccessLevel.PRIVATE)
public class FwRimSigning {

    private static final FwRimSigning EMPTY = new FwRimSigning(null, null, null);

    private final String fwVersion;
    private final Integer familyId;
    private final String l1FwHash;

    @JsonCreator
    public static FwRimSigning from(@JsonProperty("fwVersion") String fwVersion,
                                    @JsonProperty("familyId") Integer familyId,
                                    @JsonProperty("l1FwHash") String l1FwHash) {
        return new FwRimSigning(fwVersion, familyId, l1FwHash);
    }

    public static FwRimSigning from(String fwVersion, byte familyId, String l1FwHash) {
        return FwRimSigning.from(fwVersion, toUnsignedInt(familyId), l1FwHash);
    }

    public static FwRimSigning from(String deviceId, byte[] familyId, String l1FwHash) {
        return FwRimSigning.from(deviceId, toSingleByte(familyId), l1FwHash);
    }

    public static FwRimSigning empty() {
        return EMPTY;
    }
}
