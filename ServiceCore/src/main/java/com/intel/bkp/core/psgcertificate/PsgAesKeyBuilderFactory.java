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

package com.intel.bkp.core.psgcertificate;

import com.intel.bkp.core.endianness.EndiannessActor;
import com.intel.bkp.core.endianness.EndiannessMapper;
import com.intel.bkp.core.endianness.StructureBuilder;
import com.intel.bkp.core.endianness.StructureType;
import com.intel.bkp.core.interfaces.IStructure;
import com.intel.bkp.core.psgcertificate.model.EfuseTestFlag;
import com.intel.bkp.core.psgcertificate.model.PsgAesKeyType;
import com.intel.bkp.utils.ByteBufferSafe;
import lombok.extern.slf4j.Slf4j;

import java.util.Objects;
import java.util.Optional;

import static com.intel.bkp.core.endianness.StructureField.PSG_AES_KEY_CERT_VERSION;

@Slf4j
public class PsgAesKeyBuilderFactory extends EndiannessMapper {

    public PsgAesKeyBuilderFactory() {
        super(StructureType.PSG_AES_KEY_ENTRY);
    }

    public PsgAesKeyBuilderFactory withActor(EndiannessActor actor) {
        if (getActor() != actor) {
            setEndiannessActor(actor);
        }
        return this;
    }

    public IPsgAesKeyBuilder<? extends StructureBuilder<?, ? extends IStructure>> getPsgAesKeyBuilder(byte[] data) {
        return PsgAesKeyType.fromValue(getVersion(data)).getBuilder();
    }

    int getVersion(byte[] data) {
        byte[] certVersion = new byte[Integer.BYTES];
        ByteBufferSafe buffer = ByteBufferSafe.wrap(data);
        buffer.skipInteger(); //skip magic
        buffer.skipInteger(); //skip data length
        buffer.get(certVersion);
        return convertInt(certVersion, PSG_AES_KEY_CERT_VERSION);
    }
}
