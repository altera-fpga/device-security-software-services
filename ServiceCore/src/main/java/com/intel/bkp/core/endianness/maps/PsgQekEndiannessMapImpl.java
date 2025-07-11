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

package com.intel.bkp.core.endianness.maps;

import com.intel.bkp.core.endianness.EndiannessActor;

import static com.intel.bkp.core.endianness.StructureField.PSG_QEK_DATA_LENGTH;
import static com.intel.bkp.core.endianness.StructureField.PSG_QEK_INFO_LENGTH;
import static com.intel.bkp.core.endianness.StructureField.PSG_QEK_INTER_KEY_NUM;
import static com.intel.bkp.core.endianness.StructureField.PSG_QEK_KEY_LENGTH;
import static com.intel.bkp.core.endianness.StructureField.PSG_QEK_KEY_VERSION;
import static com.intel.bkp.core.endianness.StructureField.PSG_QEK_KEY_TYPE_MAGIC;
import static com.intel.bkp.core.endianness.StructureField.PSG_QEK_MAGIC;
import static com.intel.bkp.core.endianness.StructureField.PSG_QEK_MAX_KEY_USES;
import static com.intel.bkp.core.endianness.StructureField.PSG_QEK_SHA_LENGTH;
import static com.intel.bkp.core.endianness.StructureField.PSG_QEK_STEP;
import static com.intel.bkp.core.endianness.StructureField.PSG_QEK_TOTAL_KEY_USES;
import static com.intel.bkp.utils.ByteSwapOrder.CONVERT;

public final class PsgQekEndiannessMapImpl extends BaseEndiannessMapImpl {

    public PsgQekEndiannessMapImpl(EndiannessActor actor) {
        super(actor);
    }

    @Override
    protected void populateFirmwareMap() {
        put(PSG_QEK_MAGIC, CONVERT);
        put(PSG_QEK_DATA_LENGTH, CONVERT);
        put(PSG_QEK_INFO_LENGTH, CONVERT);
        put(PSG_QEK_KEY_LENGTH, CONVERT);
        put(PSG_QEK_SHA_LENGTH, CONVERT);
        put(PSG_QEK_KEY_VERSION, CONVERT);
        put(PSG_QEK_KEY_TYPE_MAGIC, CONVERT);
        put(PSG_QEK_MAX_KEY_USES, CONVERT);
        put(PSG_QEK_INTER_KEY_NUM, CONVERT);
        put(PSG_QEK_STEP, CONVERT);
        put(PSG_QEK_TOTAL_KEY_USES, CONVERT);
    }

}
