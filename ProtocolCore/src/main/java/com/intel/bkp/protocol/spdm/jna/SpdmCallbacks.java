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

package com.intel.bkp.protocol.spdm.jna;

import com.intel.bkp.protocol.spdm.jna.model.LibSpdmReturn;
import com.intel.bkp.protocol.spdm.jna.model.MessageSender;
import com.intel.bkp.protocol.spdm.jna.model.NativeSize;
import com.intel.bkp.protocol.spdm.jna.model.Uint16;
import com.intel.bkp.protocol.spdm.jna.model.Uint32;
import com.intel.bkp.protocol.spdm.jna.model.Uint64;
import com.intel.bkp.protocol.spdm.jna.model.Uint8;
import com.sun.jna.Pointer;
import com.sun.jna.ptr.PointerByReference;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;

import java.nio.ByteBuffer;

import static com.intel.bkp.protocol.spdm.jna.SpdmUtils.copyBuffer;
import static com.intel.bkp.protocol.spdm.jna.SpdmUtils.getBytes;
import static com.intel.bkp.protocol.spdm.jna.model.LibSpdmReturn.LIBSPDM_STATUS_SPDM_INTERNAL_EXCEPTION;
import static com.intel.bkp.protocol.spdm.jna.model.LibSpdmReturn.LIBSPDM_STATUS_SPDM_NOT_SUPPORTED;
import static com.intel.bkp.protocol.spdm.jna.model.LibSpdmReturn.LIBSPDM_STATUS_SUCCESS;

@Slf4j
@RequiredArgsConstructor(access = AccessLevel.PACKAGE)
public class SpdmCallbacks {

    private final MessageSender messageSender;
    private final SignatureProvider signatureProvider;

    @Setter
    private long spdmContextSize = 0;

    public SpdmCallbacks(MessageSender messageSender) {
        this(messageSender, null);
    }

    public void printCallback(String message) {
        log.debug("[SPDM Wrapper] {}", message);
    }

    public LibSpdmReturn spdmDeviceSendMessage(Pointer spdmContext, NativeSize requestSize, Pointer request,
                                               Uint64 timeout) {
        try {
            final ByteBuffer buffer = request.getByteBuffer(0, requestSize.longValue());
            messageSender.sendMessage(spdmContext.getByteBuffer(0, spdmContextSize), buffer);
            return LIBSPDM_STATUS_SUCCESS;
        } catch (Exception e) {
            log.error("Sending message failed: {}", e.getMessage());
            log.debug("Stacktrace: ", e);
            return LIBSPDM_STATUS_SPDM_INTERNAL_EXCEPTION;
        }
    }

    public LibSpdmReturn spdmDeviceReceiveMessage(Pointer spdmContext, Pointer responseSize,
                                                  PointerByReference response,
                                                  Uint64 timeout) {
        try {
            return messageSender.receiveResponse()
                .map(possibleResponse -> spdmDeviceReceiveSuccess(responseSize, response, possibleResponse))
                .orElseGet(this::spdmDeviceReceiveMessageFailure);
        } catch (Exception e) {
            log.error("Receiving message failed: {}", e.getMessage());
            log.debug("Stacktrace: ", e);
            return LIBSPDM_STATUS_SPDM_INTERNAL_EXCEPTION;
        }
    }

    private LibSpdmReturn spdmDeviceReceiveSuccess(Pointer responseSize, PointerByReference response,
                                                   byte[] possibleResponse) {
        copyBuffer(ByteBuffer.wrap(possibleResponse), response, responseSize);
        return LIBSPDM_STATUS_SUCCESS;
    }

    private LibSpdmReturn spdmDeviceReceiveMessageFailure() {
        log.error("Response from SPDM Responder is empty.");
        return LIBSPDM_STATUS_SPDM_NOT_SUPPORTED;
    }

    public boolean spdmRequesterDataSignCallback(Uint16 spdmVersion, Uint8 opCode,
                                                 Uint16 reqBaseAsymAlg,
                                                 Uint32 baseHashAlgo, boolean isDataHash,
                                                 Pointer message, NativeSize messageSize,
                                                 Pointer signature, Pointer sigSize) {
        log.debug("Called SPDM Signature callback.");
        log.trace("Parameters.\nspdmVersion: {}, opCode: {}, reqBaseAsymAlg: {}, baseHashAlgo: {}, isDataHash: {}",
            spdmVersion, opCode, reqBaseAsymAlg, baseHashAlgo, isDataHash);

        if (signatureProvider == null) {
            log.error("Signature provider was not initialized but the signature was requested.");
            return false;
        }

        final byte[] dataToSign = getBytes(message, messageSize.intValue());
        final byte[] signatureBytes = signatureProvider.sign(dataToSign,
            reqBaseAsymAlg.intValue(), baseHashAlgo.intValue());

        final int signatureLen = signatureBytes.length;
        for (int i = 0; i < signatureLen; i++) {
            signature.setByte(i, signatureBytes[i]);
        }

        sigSize.setLong(0, signatureLen);

        log.debug("SPDM Signature callback finished.");

        return true;
    }
}
