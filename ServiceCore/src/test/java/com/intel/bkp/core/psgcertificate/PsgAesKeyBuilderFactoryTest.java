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

package com.intel.bkp.core.psgcertificate;

import com.intel.bkp.core.endianness.EndiannessActor;
import com.intel.bkp.core.exceptions.ParseStructureException;
import com.intel.bkp.test.FileUtils;
import com.intel.bkp.test.enumeration.ResourceDir;
import com.intel.bkp.utils.exceptions.ByteBufferSafeException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
@ExtendWith(MockitoExtension.class)
class PsgAesKeyBuilderFactoryTest {

    private static final byte[] AES_KEY_VALID_VERSION = new byte[Integer.BYTES * 3];

    private static final byte[] AES_KEY_TOO_SHORT = new byte[Integer.BYTES];


    private final PsgAesKeyBuilderFactory sut = new PsgAesKeyBuilderFactory();

    @Test
    void getVersion_ByteArrayZeros_Success() {
        // when
        final var result = sut.getVersion(AES_KEY_VALID_VERSION);

        // then
        assertEquals(0, result);
    }

    @Test
    void getVersion_ByteArrayZeros_TooShort_Throws() {
        // when-then
        assertThrows(ByteBufferSafeException.class, () -> sut.getVersion(AES_KEY_TOO_SHORT));
    }

    @Test
    void getPsgAesKeyBuilder_SDM12CertificateWithWrongVersion_Throws() {
        // given
        final byte[] aesContent = FileUtils.loadBinary(ResourceDir.ROOT,
            ("signed_iid_sdm12_with_wrong_version_sdm15.ccert"));

        // when - then
        final var builder = sut.withActor(EndiannessActor.FIRMWARE).getPsgAesKeyBuilder(aesContent);
        final var exception = assertThrows(ParseStructureException.class, () -> builder
            .withActor(EndiannessActor.FIRMWARE)
            .parse(aesContent));

        // then
        assertEquals("Reserved field contains value different than 0", exception.getMessage());
    }

    @Test
    void getPsgAesKeyBuilder_SDM15CertificateWithWrongVersion_Throws() {
        // given
        final byte[] aesContent = FileUtils.loadBinary(ResourceDir.ROOT,
            ("signed_UDS_intelpuf_sdm15_with_wrong_version_sdm12.ccert"));

        // when - then
        final var builder = sut.withActor(EndiannessActor.FIRMWARE).getPsgAesKeyBuilder(aesContent);
        final var exception = assertThrows(IllegalArgumentException.class, () -> builder
            .withActor(EndiannessActor.FIRMWARE)
            .parse(aesContent));

        // then
        assertEquals("Cannot cast value 0 to any Storage Type", exception.getMessage());
    }
}
