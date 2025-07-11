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

package com.intel.bkp.core.psgcertificate.model;

import com.intel.bkp.core.interfaces.IStructure;
import lombok.Getter;
import lombok.Setter;

import java.nio.ByteBuffer;

@Getter
@Setter
public class PsgQekHSM implements IStructure {

    private byte[] magic = new byte[0];
    private byte[] qekDataLength = new byte[0];
    private byte[] infoLength = new byte[0];
    private byte[] keyLength = new byte[0];
    private byte[] shaLength = new byte[0];
    private byte[] version = new byte[0];
    private byte[] keyTypeMagic = new byte[0];
    private byte[] maxKeyUses = new byte[0];
    private byte[] interKeyNum = new byte[0];
    private byte[] step = new byte[0];
    private byte[] totalKeyUses = new byte[0];
    private byte[] reservedNoSalt = new byte[0];
    private byte[] ivData = new byte[0];
    private byte[] encryptedAESKey = new byte[0];
    private byte[] encryptedKDK = new byte[0];
    private byte[] encryptedSHA384 = new byte[0];

    @Override
    public byte[] array() {
        final int capacity = magic.length + qekDataLength.length + infoLength.length + keyLength.length
            + shaLength.length + version.length + keyTypeMagic.length + maxKeyUses.length + interKeyNum.length
            + step.length + totalKeyUses.length + reservedNoSalt.length + ivData.length
            + encryptedAESKey.length + encryptedKDK.length + encryptedSHA384.length;

        return ByteBuffer.allocate(
                capacity)
            .put(magic)
            .put(qekDataLength)
            .put(infoLength)
            .put(keyLength)
            .put(shaLength)
            .put(version)
            .put(keyTypeMagic)
            .put(maxKeyUses)
            .put(interKeyNum)
            .put(step)
            .put(totalKeyUses)
            .put(reservedNoSalt)
            .put(ivData)
            .put(encryptedAESKey)
            .put(encryptedKDK)
            .put(encryptedSHA384)
            .array();
    }
}
