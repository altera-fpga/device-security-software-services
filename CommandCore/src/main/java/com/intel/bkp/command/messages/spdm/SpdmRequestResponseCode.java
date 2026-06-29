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

package com.intel.bkp.command.messages.spdm;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

import java.util.Arrays;
import java.util.Optional;

@Getter
@RequiredArgsConstructor
public enum SpdmRequestResponseCode {
    // REQUEST CODE
    GET_DIGESTS((byte) 0x81),
    GET_CERTIFICATE((byte) 0x82),
    CHALLENGE((byte) 0x83),
    GET_VERSION((byte) 0x84),
    CHUNK_SEND((byte) 0x85),
    CHUNK_GET((byte) 0x86),
    GET_MEASUREMENTS((byte) 0xE0),
    GET_CAPABILITIES((byte) 0xE1),
    NEGOTIATE_ALGORITHMS((byte) 0xE3),
    KEY_EXCHANGE((byte) 0xE4),
    FINISH((byte) 0xE5),
    PSK_EXCHANGE((byte) 0xE6),
    PSK_FINISH((byte) 0xE7),
    HEARTBEAT((byte) 0xE8),
    KEY_UPDATE((byte) 0xE9),
    GET_ENCAPSULATED_REQUEST((byte) 0xEA),
    DELIVER_ENCAPSULATED_RESPONSE((byte) 0xEB),
    END_SESSION((byte) 0xEC),
    GET_CSR((byte) 0xED),
    SET_CERTIFICATE((byte) 0xEE),
    VENDOR_DEFINED_REQUEST((byte) 0xFE),
    RESPOND_IF_READY((byte) 0xFF),

    // RESPONSE CODE
    DIGESTS((byte) 0x01),
    CERTIFICATE((byte) 0x02),
    CHALLENGE_AUTH_RSP((byte) 0x03),
    VERSION((byte) 0x04),
    CHUNK_SEND_ACK((byte) 0x05),
    CHUNK_RESPONSE((byte) 0x06),
    MEASUREMENTS((byte) 0x60),
    CAPABILITIES((byte) 0x61),
    ALGORITHMS((byte) 0x63),
    KEY_EXCHANGE_RSP((byte) 0x64),
    FINISH_RSP((byte) 0x65),
    PSK_EXCHANGE_RSP((byte) 0x66),
    PSK_FINISH_RSP((byte) 0x67),
    HEARTBEAT_ACK((byte) 0x68),
    KEY_UPDATE_ACK((byte) 0x69),
    ENCAPSULATED_REQUEST((byte) 0x6A),
    ENCAPSULATED_RESPONSE_ACK((byte) 0x6B),
    END_SESSION_ACK((byte) 0x6C),
    CSR((byte) 0x6D),
    SET_CERTIFICATE_RSP((byte) 0x6E),
    VENDOR_DEFINED_RESPONSE((byte) 0x7E),
    ERROR((byte) 0x7F);

    private final byte value;

    private static Optional<SpdmRequestResponseCode> find(byte value) {
        return Arrays.stream(values())
            .filter(code -> code.getValue() == value)
            .findFirst();
    }

    public static String print(byte value) {
        return find(value).map(Enum::toString).orElse("<SPDM CODE NOT FOUND>");
    }
}
