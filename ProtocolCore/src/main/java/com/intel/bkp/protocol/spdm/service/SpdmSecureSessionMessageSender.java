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

package com.intel.bkp.protocol.spdm.service;

import com.intel.bkp.protocol.spdm.exceptions.SpdmCommandFailedException;
import com.intel.bkp.protocol.spdm.exceptions.SpdmRuntimeException;
import com.intel.bkp.protocol.spdm.jna.model.SpdmProtocol;
import com.intel.bkp.utils.ByteBufferSafe;
import com.intel.bkp.utils.ByteSwap;
import com.intel.bkp.utils.ByteSwapOrder;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.nio.ByteBuffer;

import static com.intel.bkp.utils.HexConverter.fromHex;
import static com.intel.bkp.utils.HexConverter.toHex;

@Slf4j
@AllArgsConstructor
public class SpdmSecureSessionMessageSender {

    private static final String VENDOR_DEFINED_REQUEST_HEADER = "12FE0000";
    private static final String USB_STANDARD_ID_LITTLE_ENDIAN = "0200";
    private static final String VENDOR_ID_LEN = "02";
    private static final String VENDOR_ID = "FB09"; // = 0x09FB - USB-blaster family
    private static final String SPDM_HEADER = VENDOR_DEFINED_REQUEST_HEADER + USB_STANDARD_ID_LITTLE_ENDIAN
        + VENDOR_ID_LEN + VENDOR_ID;
    public static final int SPDM_HEADER_ERROR_LEN = 4;
    private static final int SPDM_ERROR_CODE = 0x7F;
    private static final int OFFSET_FROM_HEADER_TO_RESPONSE_PAYLOAD = 7;

    private final SpdmProtocol spdmProtocol;

    public void startSession(int measurementSlotId, Boolean needMeasurementHash)
        throws SpdmCommandFailedException {
        log.info("*** STARTING SPDM SECURE SESSION ***");
        spdmProtocol.startSecureSession(measurementSlotId, needMeasurementHash);
    }

    public byte[] sendData(byte[] payload) throws SpdmCommandFailedException {
        log.info("*** SENDING DATA IN SECURE SESSION ***");

        final byte[] spdmHeader = fromHex(SPDM_HEADER);
        final short payloadLen = (short) payload.length;

        final byte[] vendorDefinedRequest = ByteBuffer.allocate(spdmHeader.length + Short.BYTES + payloadLen)
            .put(spdmHeader)
            .putShort(ByteSwap.getSwappedShort(payloadLen, ByteSwapOrder.B2L))
            .put(payload)
            .array();

        final byte[] vendorDefinedResponse = spdmProtocol.sendReceiveDataInSession(vendorDefinedRequest);
        final ByteBufferSafe responseBuffer = ByteBufferSafe.wrap(vendorDefinedResponse);

        final byte[] spdmResponseHeader = new byte[Integer.BYTES];
        responseBuffer.get(spdmResponseHeader);

        if (SPDM_ERROR_CODE == spdmResponseHeader[1]) {
            throw new SpdmRuntimeException("SPDM Command failed: %s".formatted(toHex(spdmResponseHeader)));
        }

        // :TODO - need to move this parsing of header and payload to CommandCore
        // :TODO - nice to have is to get respLen field and check if size of payload is correct
        return responseBuffer
            .skip(OFFSET_FROM_HEADER_TO_RESPONSE_PAYLOAD)
            .getRemaining();
    }

    public void endSession() throws SpdmCommandFailedException {
        log.info("*** ENDING SECURE SESSION ***");
        spdmProtocol.stopSecureSession();
    }
}
