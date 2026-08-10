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

package com.intel.bkp.core.endianness;

import com.intel.bkp.core.interfaces.IEndiannessMap;
import com.intel.bkp.utils.ByteSwap;
import com.intel.bkp.utils.ByteSwapOrder;
import lombok.Getter;

import java.util.Optional;

public abstract class EndiannessMapper {

    private final IStructureType structureType;

    private Optional<IEndiannessMap> endiannessMap;

    @Getter
    private EndiannessActor actor = EndiannessActor.SERVICE;

    protected EndiannessMapper(IStructureType structureType) {
        this.structureType = structureType;
        setEndiannessMap();
    }

    public final byte[] convert(int value, IStructureField structureName) {
        return ByteSwap.getSwappedArray(value, getByteOrder(structureName));
    }

    public final byte[] convert(byte[] value, IStructureField structureName) {
        return ByteSwap.getSwappedArrayByInt(value, getByteOrder(structureName));
    }

    protected void setEndiannessActor(EndiannessActor actor) {
        this.actor = actor;
        setEndiannessMap();
    }

    protected final int convertInt(int value, IStructureField structureName) {
        return ByteSwap.getSwappedInt(value, getByteOrder(structureName));
    }

    protected final int convertInt(byte[] value, IStructureField structureName) {
        return ByteSwap.getSwappedInt(value, getByteOrder(structureName));
    }

    protected final short convertShort(byte[] value, IStructureField structureName) {
        return ByteSwap.getSwappedShort(value, getByteOrder(structureName));
    }

    protected final short convertShort(short value, IStructureField structureName) {
        return ByteSwap.getSwappedShort(value, getByteOrder(structureName));
    }

    private ByteSwapOrder getByteOrder(IStructureField field) {
        return endiannessMap
            .map(map -> map.get(field))
            .orElseThrow(() -> new IllegalStateException("Endianness map is absent."));
    }

    private void setEndiannessMap() {
        endiannessMap = Optional.ofNullable(structureType)
            .map(type -> type.getEndiannessMap(actor));
    }
}
