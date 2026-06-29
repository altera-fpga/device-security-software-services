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
import com.intel.bkp.test.enumeration.ResourceDir;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;

import static com.intel.bkp.test.FileUtils.loadBinary;
import static com.intel.bkp.utils.HexConverter.fromHex;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class PsgQekHSMTest {

    byte[] qekBuffer;

    @BeforeEach
    void setUp() {
        qekBuffer = loadBinary(ResourceDir.ROOT, "aes_testmode1.qek");
    }

    @Test
    void parseQEK_Success() {
        PsgQekBuilderHSM builder = new PsgQekBuilderHSM();
        builder.withActor(EndiannessActor.FIRMWARE).parse(qekBuffer);
        assertEquals(0x367336E4, new BigInteger(builder.getMagic()).intValue());
        assertEquals(0xC0, new BigInteger(builder.getQekDataLength()).intValue());
        assertEquals(0x18, new BigInteger(builder.getInfoLength()).intValue());
        assertEquals(0x60, new BigInteger(builder.getKeyLength()).intValue());
        assertEquals(0x30, new BigInteger(builder.getShaLength()).intValue());
        assertEquals(0x4048534D, new BigInteger(builder.getKeyTypeMagic()).intValue());
        assertEquals(0x80, new BigInteger(builder.getMaxKeyUses()).intValue());
        assertEquals(0x3, new BigInteger(builder.getInterKeyNum()).intValue());
        assertEquals(0x1, new BigInteger(builder.getStep()).intValue());
        assertEquals(0, Arrays.compare(fromHex("E4B5B9B7D451BE2780D02D150A40EC17"), builder.getIvData()));

        byte[] retrieveArray = builder.build().array();
        assert Arrays.equals(retrieveArray, qekBuffer);
    }

    @Test
    void parseQEK_InvalidMagic() {
        byte[] trimmedBuffer = Arrays.copyOfRange(qekBuffer, 0, qekBuffer.length);
        ByteBuffer newBuffer = ByteBuffer.wrap(trimmedBuffer);
        newBuffer.order(ByteOrder.LITTLE_ENDIAN);
        newBuffer.position(0);
        int incorrectMagic = 0x12345678;
        newBuffer.putInt(incorrectMagic);
        PsgQekBuilderHSM builder = new PsgQekBuilderHSM();
        builder.withActor(EndiannessActor.FIRMWARE);
        final ParseStructureException exception = assertThrows(ParseStructureException.class, ()->builder.parse(newBuffer.array()));
        assertEquals(exception.getMessage(), "Invalid AES entry magic 0x%x, expected 0x%x".formatted(incorrectMagic, 0x367336E4));
    }

    @Test
    void parseQEK_InvalidLen() {
        int newTrimmedLen = 0x90;
        byte[] trimmedBuffer = Arrays.copyOfRange(qekBuffer, 0, newTrimmedLen);
        ByteBuffer newBuffer = ByteBuffer.wrap(trimmedBuffer);
        newBuffer.order(ByteOrder.LITTLE_ENDIAN);
        newBuffer.position(0x4);
        newBuffer.putInt(newTrimmedLen);
        PsgQekBuilderHSM builder = new PsgQekBuilderHSM();
        builder.withActor(EndiannessActor.FIRMWARE);
        final ParseStructureException exception = assertThrows(ParseStructureException.class, ()->builder.parse(newBuffer.array()));
        assertEquals(exception.getMessage(), "Invalid AES Root Key data length 0x%x, expected 0x%x".formatted(newTrimmedLen, 0xC0));
    }

    @Test
    void parseQEK_shaLen() {
        byte[] trimmedBuffer = Arrays.copyOfRange(qekBuffer, 0, qekBuffer.length);
        ByteBuffer newBuffer = ByteBuffer.wrap(trimmedBuffer);
        newBuffer.order(ByteOrder.LITTLE_ENDIAN);
        newBuffer.position(0x10);
        int newSHALength = 0x20;
        newBuffer.putInt(newSHALength);
        PsgQekBuilderHSM builder = new PsgQekBuilderHSM();
        builder.withActor(EndiannessActor.FIRMWARE);
        final ParseStructureException exception = assertThrows(ParseStructureException.class, ()->builder.parse(newBuffer.array()));
        assertEquals(exception.getMessage(), "Invalid SHA length 0x%x, expected 0x%x".formatted(newSHALength, 0x30));
    }

    @Test
    void parseQEK_KeyTypeMagic() {
        byte[] trimmedBuffer = Arrays.copyOfRange(qekBuffer, 0, qekBuffer.length);
        ByteBuffer newBuffer = ByteBuffer.wrap(trimmedBuffer);
        newBuffer.order(ByteOrder.LITTLE_ENDIAN);
        newBuffer.position(0x18);
        int incorrectMagic = 0x12345678;
        newBuffer.putInt(incorrectMagic);
        PsgQekBuilderHSM builder = new PsgQekBuilderHSM();
        builder.withActor(EndiannessActor.FIRMWARE);
        final ParseStructureException exception = assertThrows(ParseStructureException.class, ()->builder.parse(newBuffer.array()));
        assertEquals(exception.getMessage(), "Invalid AES Root Key type magic number 0x%x, expected 0x%x".formatted(incorrectMagic, 0x4048534D));
    }
}
