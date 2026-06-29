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

package com.intel.bkp.bkps.testutils;

import com.intel.bkp.command.MailboxCommandLayer;
import com.intel.bkp.command.header.FwErrorCodes;
import com.intel.bkp.utils.ByteBufferSafe;
import com.intel.bkp.utils.interfaces.BytesConvertible;

public class MailboxResponseLayer extends MailboxCommandLayer {

    public byte[] retrieve(byte[] data) {
        return ByteBufferSafe.wrap(data).skip(Integer.BYTES).getRemaining();
    }

    public byte[] create(BytesConvertible data) {
        return createInternal(data, FwErrorCodes.STATUS_OKAY);
    }

    public byte[] createUnknown(BytesConvertible data) {
        return createInternal(data, FwErrorCodes.UNKNOWN_COMMAND);
    }

    private byte[] createInternal(BytesConvertible data, FwErrorCodes errorCode) {
        final byte[] dataBytes = data.array();
        final int argumentsLen = getArgumentsLen(dataBytes);
        final byte[] header = buildCommandHeader(errorCode.getCode(), argumentsLen, 0, 0);
        return withAppendedHeaderAndPadding(argumentsLen, dataBytes, header);
    }
}
