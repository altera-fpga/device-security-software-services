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

package com.intel.bkp.bkps.programmer.model;

import lombok.AllArgsConstructor;
import lombok.Getter;

import java.util.List;

/**
 * Value field is explicit because of required compatibility with Quartus. Adding or removing a new field must hold
 * historical enumeration.
 */
@Getter
@AllArgsConstructor
public enum MessageType {
    SEND_PACKET(0),
    PUSH_WRAPPED_KEY(1), // S10, Agilex - save .wkey by Quartus to local machine
    PUSH_WRAPPED_KEY_USER_IID(2), // S10, Agilex - store .wkey directly to QSPI flash in location of USER IID PUF
    PUSH_WRAPPED_KEY_UDS_IID(3), // Agilex - store .wkey directly to QSPI flash in location of UDS IID PUF
    PUSH_HELPER_DATA_UDS_IID(4),
    PUSH_HELPER_DATA_UDS_INTEL(5);

    private final int value;

    // :TODO - replace with BitSet class
    public boolean isSetIn(int supportedCommands) {
        return isSetIn(getBinaryString(supportedCommands));
    }

    private boolean isSetIn(String supportedCommandsBinaryString) {
        return '1' == supportedCommandsBinaryString.charAt(supportedCommandsBinaryString.length() - value - 1);
    }

    public static boolean areSetIn(List<MessageType> messageTypes, int supportedCommands) {
        return areSetIn(messageTypes, getBinaryString(supportedCommands));
    }

    private static boolean areSetIn(List<MessageType> messageTypes, String supportedCommandsBinaryString) {
        return messageTypes
            .stream()
            .map(m -> m.isSetIn(supportedCommandsBinaryString))
            .reduce((m1, m2) -> m1 && m2)
            .orElse(true);
    }

    public static boolean atLeastOneIsSetIn(List<MessageType> messageTypes, int supportedCommands) {
        return atLeastOneIsSetIn(messageTypes, getBinaryString(supportedCommands));
    }

    private static boolean atLeastOneIsSetIn(List<MessageType> messageTypes, String supportedCommandsBinaryString) {
        return messageTypes
            .stream()
            .map(m -> m.isSetIn(supportedCommandsBinaryString))
            .reduce((m1, m2) -> m1 || m2)
            .orElse(true);
    }

    private static String getBinaryString(int supportedCommands) {
        return String.format("%32s", Integer.toBinaryString(supportedCommands)).replace(' ', '0');
    }
}
