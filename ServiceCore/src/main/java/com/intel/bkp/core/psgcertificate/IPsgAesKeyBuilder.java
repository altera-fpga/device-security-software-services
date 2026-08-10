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
import com.intel.bkp.core.endianness.StructureBuilder;
import com.intel.bkp.core.exceptions.ParseStructureException;
import com.intel.bkp.core.interfaces.IStructure;
import com.intel.bkp.core.psgcertificate.enumerations.KeyWrappingType;
import com.intel.bkp.core.psgcertificate.enumerations.StorageType;
import com.intel.bkp.core.psgcertificate.model.EfuseTestFlag;
import com.intel.bkp.core.psgcertificate.model.PsgAesKeyType;

import java.util.Arrays;

public interface IPsgAesKeyBuilder<T extends StructureBuilder<T, ? extends IStructure>> {

    int MAGIC = 0x25D04E7F;
    int USER_AES_CERT_MAGIC = 0xD0850CAA;
    int USER_INPUT_IV_LEN = 16;
    int USER_AES_ROOT_KEY_LEN = 32;

    default void checkIfArrayFilledWithZeros(byte[] array) {
        if (!Arrays.equals(array, new byte[array.length])) {
            throw new ParseStructureException("Reserved field contains value different than 0");
        }
    }

    default void checkIfCertHasCorrectVersion(int certVersionAsInt) {
        if (getAesKeyType().getVersion() != certVersionAsInt) {
            throw new ParseStructureException("Mismatch between certificate SDM version and Builder version. "
                + "Certificate SDM version: " +  certVersionAsInt + ". Builder/parser version: "
                + getAesKeyType().getVersion());
        }
    }

    PsgAesKeyType getAesKeyType();

    T withActor(EndiannessActor actor);

    EfuseTestFlag getTestFlag();

    StorageType getStorageType();

    KeyWrappingType getKeyWrappingType();

    default byte[] getMacTag() {
        return null;
    }

    default byte[] getMacData() {
        return null;
    }
}
