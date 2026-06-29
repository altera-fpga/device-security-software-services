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

package com.intel.bkp.bkps.protocol.common;

import com.intel.bkp.bkps.exception.ProvisioningGenericException;
import com.intel.bkp.utils.ByteBufferSafe;
import com.intel.bkp.utils.ByteSwap;
import com.intel.bkp.utils.ByteSwapOrder;
import lombok.Builder;
import lombok.Getter;

import static com.intel.bkp.bkps.protocol.common.EncryptedPayload.PAYLOAD_MAGIC_NUMBER;
import static com.intel.bkp.utils.HexConverter.toFormattedHex;

@Builder
@Getter
public class DecryptedPayload {

    static final int MAGIC_LEN = Integer.BYTES;
    static final int RESERVED_LEN = Integer.BYTES;

    private final int magic;
    private final byte[] reserved;
    private final byte[] value;
    private final byte[] padding;

    public static DecryptedPayload from(byte[] decryptedPayload, int paddingLen) {
        verifyPayloadLen(decryptedPayload, paddingLen);

        byte[] magic = new byte[MAGIC_LEN];
        byte[] reserved = new byte[RESERVED_LEN];
        byte[] value = new byte[decryptedPayload.length - MAGIC_LEN - RESERVED_LEN - paddingLen];
        byte[] padding = new byte[paddingLen];
        ByteBufferSafe.wrap(decryptedPayload).get(magic).get(reserved).get(value).getAll(padding);

        int magicToVerify = ByteBufferSafe.wrap(ByteSwap.getSwappedArrayByInt(magic, ByteSwapOrder.L2B)).getInt();
        verifyMagicNumber(magicToVerify);

        return DecryptedPayload.builder()
            .magic(magicToVerify)
            .reserved(reserved)
            .value(value)
            .padding(padding)
            .build();
    }

    private static void verifyPayloadLen(byte[] decryptedPayload, int paddingLen) {
        int payloadMinimumLen = MAGIC_LEN + RESERVED_LEN + paddingLen;
        if (decryptedPayload.length < payloadMinimumLen) {
            throw new ProvisioningGenericException(
                String.format("EncryptedPayload should be at least %d bytes len but is %d bytes len.",
                    payloadMinimumLen, decryptedPayload.length));
        }
    }

    private static void verifyMagicNumber(int magicToVerify) {
        if (PAYLOAD_MAGIC_NUMBER != magicToVerify) {
            throw new ProvisioningGenericException(
                String.format("Invalid magic number in EncryptedPayload. Expected: %s, Actual: %s.",
                    toFormattedHex(PAYLOAD_MAGIC_NUMBER), toFormattedHex(magicToVerify)));
        }
    }
}
