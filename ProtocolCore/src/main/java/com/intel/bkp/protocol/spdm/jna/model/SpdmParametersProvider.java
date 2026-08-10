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

package com.intel.bkp.protocol.spdm.jna.model;

public interface SpdmParametersProvider {

    default Uint8 ctExponent() {
        return Uint8.ZERO;
    }

    default Uint32 capabilities() {
        return Uint32.ZERO;
    }

    default Uint8 measurementSpec() {
        return Uint8.ZERO;
    }

    default Uint32 baseAsymAlgo() {
        return Uint32.ZERO;
    }

    default Uint32 baseHashAlgo() {
        return Uint32.ZERO;
    }

    default Uint16 dheNameGroup() {
        return Uint16.ZERO;
    }

    default Uint16 aeadCipherSuite() {
        return Uint16.ZERO;
    }

    default Uint16 reqBaseAsymAlg() {
        return Uint16.ZERO;
    }

    default Uint16 keySchedule() {
        return Uint16.ZERO;
    }

    default Uint8 otherParamsSupport() {
        return Uint8.ZERO;
    }
}
