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

import lombok.EqualsAndHashCode;

@EqualsAndHashCode(callSuper = true)
public class LibSpdmReturn extends Uint32 {

    // Values taken from libspdm library
    public static final LibSpdmReturn LIBSPDM_STATUS_SUCCESS = LibSpdmReturn.from(0x0);
    // custom error code
    public static final LibSpdmReturn LIBSPDM_STATUS_SPDM_NOT_SUPPORTED = LibSpdmReturn.from(0x800100FD);
    // custom error code
    public static final LibSpdmReturn LIBSPDM_STATUS_SPDM_INTERNAL_EXCEPTION = LibSpdmReturn.from(0x800100FE);

    public LibSpdmReturn() {
        this(0);
    }

    private LibSpdmReturn(int value) {
        super(value);
    }

    public static LibSpdmReturn from(int value) {
        return new LibSpdmReturn(value);
    }

    public long asLong() {
        return this.longValue();
    }
}
