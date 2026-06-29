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

package com.intel.bkp.core.psgcertificate.model;

import com.intel.bkp.core.endianness.StructureBuilder;
import com.intel.bkp.core.exceptions.ParseStructureException;
import com.intel.bkp.core.interfaces.IStructure;
import com.intel.bkp.core.psgcertificate.IPsgAesKeyBuilder;
import com.intel.bkp.core.psgcertificate.PsgAesKeyBuilderSDM12;
import com.intel.bkp.core.psgcertificate.PsgAesKeyBuilderSDM15;
import lombok.AllArgsConstructor;
import lombok.Getter;

import java.util.function.Supplier;
import java.util.stream.Stream;

@AllArgsConstructor
public enum PsgAesKeyType {
    SDM_1_2(0, true, PsgAesKeyBuilderSDM12::new),
    SDM_1_5(2, false, PsgAesKeyBuilderSDM15::new);

    @Getter
    private final int version;
    @Getter
    private final Boolean testprogramSupported;
    private final Supplier<IPsgAesKeyBuilder<? extends StructureBuilder<?, ? extends IStructure>>> builderSupplier;

    public IPsgAesKeyBuilder<? extends StructureBuilder<?, ? extends IStructure>> getBuilder() {
        return builderSupplier.get();
    }

    public static PsgAesKeyType fromValue(Integer value) {
        if (value == null) {
            throw new ParseStructureException("No certificate version specified");
        }
        return Stream.of(values())
            .filter(type -> value.equals(type.getVersion()))
            .findAny()
            .orElseThrow(
                () -> new ParseStructureException("Unknown certificate version specified: %s".formatted(value)));
    }
}
