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

package com.intel.bkp.bkps.rest.onboarding.model;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.intel.bkp.fpgacerts.model.Family;
import lombok.SneakyThrows;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class DeviceIdTest {

    private static final String UID = "0102030405060708";
    private static final String DEVICE_IDENTITY = "AABBCCDD0102030405060708AABBCCDD";

    @Test
    void toString_Agilex_Success() {
        // given
        final DeviceId instance = DeviceId.instance(Family.AGILEX, UID);

        // when
        final String result = instance.toString();

        // then
        assertEquals("DeviceId{ family=AGILEX uid=0102030405060708 dpUid=0807060504030201 }", result);
    }

    @Test
    void toString_S10_Success() {
        // given
        final DeviceId instance = DeviceId.instance(Family.S10, UID);

        // when
        final String result = instance.toString();

        // then
        assertEquals("DeviceId{ family=S10 uid=0102030405060708 dpUid=0102030405060708 }", result);
    }

    @Test
    @SneakyThrows
    void serializeDeserializeTest_Success() {
        // given
        final ObjectMapper mapper = new ObjectMapper();
        final DeviceId instance = DeviceId.instance(Family.AGILEX, UID, DEVICE_IDENTITY);

        // when
        final byte[] serialized = mapper.writeValueAsBytes(instance);
        final DeviceId result = mapper.readValue(serialized, DeviceId.class);

        // then
        assertEquals(instance, result);
    }
}
