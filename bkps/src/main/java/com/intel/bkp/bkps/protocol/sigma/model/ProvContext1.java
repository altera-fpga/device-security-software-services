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

package com.intel.bkp.bkps.protocol.sigma.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.intel.bkp.bkps.protocol.common.model.ProvContext;
import com.intel.bkp.crypto.ecdh.EcdhKeyPair;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;

import java.util.Optional;

import static com.intel.bkp.utils.HexConverter.fromHex;

@Getter
@Setter
@ToString
@NoArgsConstructor
public class ProvContext1 implements ProvContext {
    private Long cfgId;
    private String chipId;
    private EcdhKeyPair ecdhKeyPair;
    private String deviceIdEnrollmentCert;

    public ProvContext1(Long cfgId, String chipId, EcdhKeyPair ecdhKeyPair) {
        this(cfgId, chipId, ecdhKeyPair, Optional.empty());
    }

    public ProvContext1(Long cfgId, String chipId, EcdhKeyPair ecdhKeyPair, Optional<String> deviceIdEnrollmentCert) {
        this.cfgId = cfgId;
        this.chipId = chipId;
        this.ecdhKeyPair = ecdhKeyPair;
        this.deviceIdEnrollmentCert = deviceIdEnrollmentCert
            .orElse("");
    }

    @JsonIgnore
    public byte[] getChipIdFromHex() {
        return fromHex(chipId);
    }
}
