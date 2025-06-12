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

package com.intel.bkp.bkps.protocol.sigma.model;

import com.intel.bkp.crypto.ecdh.EcdhKeyPair;
import com.intel.bkp.test.RandomUtils;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;


@ExtendWith(MockitoExtension.class)
public class ProvContext1Test {

    @Test
    void constructor_3ValidParams_ReturnValidObject() {
        // given
        final Long expectedCfgId = 100L;
        final byte[] expectedKey = new byte[]{1, 2, 3, 4};
        final String expectedChipId = RandomUtils.generateDeviceIdHex();
        final EcdhKeyPair ecdhKeyPair = new EcdhKeyPair(expectedKey, expectedKey);
        final String expectedCert = "";

        // when
        final ProvContext1 provContext =
            new ProvContext1(expectedCfgId, expectedChipId, ecdhKeyPair);

        // then
        assertNotNull(provContext);
        assertEquals(expectedCfgId, provContext.getCfgId());
        assertEquals(expectedChipId, provContext.getChipId());
        assertEquals(expectedCert, provContext.getDeviceIdEnrollmentCert());
        assertArrayEquals(expectedKey, provContext.getEcdhKeyPair().getPublicKey());
        assertArrayEquals(expectedKey, provContext.getEcdhKeyPair().getPrivateKey());
    }

    @Test
    void constructor_AllValidParams_ReturnValidObject() {
        // given
        final Long expectedCfgId = 100L;
        final byte[] expectedKey = new byte[] { 1, 2, 3, 4 };
        final String expectedChipId = RandomUtils.generateDeviceIdHex();
        final EcdhKeyPair ecdhKeyPair = new EcdhKeyPair(expectedKey, expectedKey);
        final String expectedCert = "CERT";
        final Optional<String> deviceIdEnrollmentCert = Optional.of(expectedCert);

        // when
        final ProvContext1 provContext =
            new ProvContext1(expectedCfgId, expectedChipId, ecdhKeyPair, deviceIdEnrollmentCert);

        // then
        assertNotNull(provContext);
        assertEquals(expectedCfgId, provContext.getCfgId());
        assertEquals(expectedChipId, provContext.getChipId());
        assertEquals(expectedCert, provContext.getDeviceIdEnrollmentCert());
        assertArrayEquals(expectedKey, provContext.getEcdhKeyPair().getPublicKey());
        assertArrayEquals(expectedKey, provContext.getEcdhKeyPair().getPrivateKey());
    }
}
