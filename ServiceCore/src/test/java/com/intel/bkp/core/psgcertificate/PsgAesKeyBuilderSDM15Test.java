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
import com.intel.bkp.core.psgcertificate.enumerations.KeyWrappingType;
import com.intel.bkp.core.psgcertificate.enumerations.StorageType;
import com.intel.bkp.core.psgcertificate.model.EfuseTestFlag;
import com.intel.bkp.core.psgcertificate.model.FIPSMode;
import com.intel.bkp.test.FileUtils;
import com.intel.bkp.test.enumeration.ResourceDir;
import lombok.AllArgsConstructor;
import lombok.Getter;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;
import java.util.BitSet;

import static com.intel.bkp.core.psgcertificate.model.FIPSMode.NON_FIPS;
import static com.intel.bkp.test.FileUtils.loadBinary;
import static com.intel.bkp.utils.HexConverter.toHex;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

class PsgAesKeyBuilderSDM15Test {

    @AllArgsConstructor
    @Getter
    private enum TestSuiteParams {
        NON_FIPS_TEST_FLAG_FALSE(NON_FIPS, EfuseTestFlag.PHYSICAL, (byte) 0b00000000),
        FIPS_LEVEL_1_TEST_FLAG_FALSE(FIPSMode.FIPS_LEVEL_1, EfuseTestFlag.PHYSICAL, (byte) 0b00100000),
        FIPS_LEVEL_2_TEST_FLAG_FALSE(FIPSMode.FIPS_LEVEL_2, EfuseTestFlag.PHYSICAL, (byte) 0b01000000),
        FIPS_LEVEL_3_TEST_FLAG_FALSE(FIPSMode.FIPS_LEVEL_3, EfuseTestFlag.PHYSICAL, (byte) 0b01100000),
        NON_FIPS_TEST_FLAG_TRUE(NON_FIPS, EfuseTestFlag.VIRTUAL, (byte) 0b10000000),
        FIPS_LEVEL_1_TEST_FLAG_TRUE(FIPSMode.FIPS_LEVEL_1, EfuseTestFlag.VIRTUAL, (byte) 0b10100000),
        FIPS_LEVEL_2_TEST_FLAG_TRUE(FIPSMode.FIPS_LEVEL_2, EfuseTestFlag.VIRTUAL, (byte) 0b11000000),
        FIPS_LEVEL_3_TEST_FLAG_TRUE(FIPSMode.FIPS_LEVEL_3, EfuseTestFlag.VIRTUAL, (byte) 0b11100000);

        private final FIPSMode fipsMode;
        private final EfuseTestFlag testFlag;
        private final byte byteValue;
    }

    private static final String MAC_TAG_E2E = "2F33DEBD62E05D0C28BC42C734261939FC650FA8FEEBED6CE3778067DC7E5A9A16AF298B6050640B07AC96B9165FBA54";
    byte[] ccertBuffer;

    @BeforeEach
    void setUp() {
        ccertBuffer = loadBinary(ResourceDir.ROOT, "signed_UDS_intelpuf_wrapped_aes_testmode1.ccert");
    }

    @Test
    void parseAESccertSDM15_Success() {
        PsgAesKeyBuilderSDM15 builder = new PsgAesKeyBuilderSDM15()
            .withActor(EndiannessActor.FIRMWARE)
            .parse(ccertBuffer);
        assertEquals(0x25D04E7F, new BigInteger(builder.getMagic()).intValue());
        assertEquals(2, new BigInteger(builder.getCertVersion()).intValue());
        assertEquals(2, new BigInteger(builder.getCertType()).intValue());
        assertEquals(0xD0850CAA, new BigInteger(builder.getUserAesCertMagic()).intValue());
        assertEquals(0, new BigInteger(builder.getReservedWithFlags()).intValue());
        assertEquals(StorageType.PUFSS, builder.getStorageType());
        assertEquals(KeyWrappingType.UDS_INTEL_PUF, builder.getKeyWrappingType());
        byte[] retrieveArray = builder.build().array();
        assert Arrays.equals(retrieveArray, ccertBuffer);
    }

    @Test
    void parseAESccertSDM15_InvalidMagic() {
        int newMagic = 0x12345678;
        ByteBuffer newBuffer = ByteBuffer.wrap(ccertBuffer);
        newBuffer.order(ByteOrder.LITTLE_ENDIAN);
        newBuffer.position(0);
        newBuffer.putInt(newMagic);
        PsgAesKeyBuilderSDM15 builder = new PsgAesKeyBuilderSDM15()
            .withActor(EndiannessActor.FIRMWARE);
        final ParseStructureException exception = assertThrows(ParseStructureException.class, ()->builder.parse(newBuffer.array()));
        assertEquals(exception.getMessage(), "Invalid entry magic 0x%x, expected 0x%x".formatted(newMagic, 0x25D04E7F));
    }

    @Test
    void parseAESccertSDM15_InvalidVersion() {
        int newVersion = 3;
        ByteBuffer byteBuffer = ByteBuffer.wrap(ccertBuffer);
        byteBuffer.order(ByteOrder.LITTLE_ENDIAN);
        byteBuffer.position(0x8);
        byteBuffer.putInt(newVersion);
        PsgAesKeyBuilderSDM15 builder = new PsgAesKeyBuilderSDM15()
            .withActor(EndiannessActor.FIRMWARE);
        final ParseStructureException exception = assertThrows(ParseStructureException.class, ()->builder.parse(byteBuffer.array()));
        assertEquals(exception.getMessage(), "Mismatch between certificate SDM version and Builder version. Certificate SDM version: %d. Builder/parser version: %d".formatted(newVersion, builder.getAesKeyType().getVersion()));
    }

    @Test
    void parseAESccertSDM15_InvalidUserAesTypeMagic() {
        int newMagic = 0x12345678;
        ByteBuffer newBuffer = ByteBuffer.wrap(ccertBuffer);
        newBuffer.order(ByteOrder.LITTLE_ENDIAN);
        newBuffer.position(0x10);
        newBuffer.putInt(newMagic);
        PsgAesKeyBuilderSDM15 builder = new PsgAesKeyBuilderSDM15()
            .withActor(EndiannessActor.FIRMWARE);
        final ParseStructureException exception = assertThrows(ParseStructureException.class, ()->builder.parse(newBuffer.array()));
        assertEquals(exception.getMessage(), "Invalid user aes entry magic 0x%x, expected 0x%x".formatted(newMagic, 0xD0850CAA));
    }

    @Test
    void parse_WithActualData_Success() {
        // given
        final byte[] aesContent = FileUtils.loadBinary(ResourceDir.ROOT, ("signed_UDS_intelpuf_wrapped_aes_testmode1.ccert"));

        // when
        PsgAesKeyBuilderSDM15 builder = new PsgAesKeyBuilderSDM15()
            .withActor(EndiannessActor.FIRMWARE)
            .parse(aesContent);

        // then
        commonAssert(aesContent, builder, StorageType.PUFSS, KeyWrappingType.UDS_INTEL_PUF);
        assertEquals(MAC_TAG_E2E, toHex(builder.getMacTag()));
        assertEquals(NON_FIPS, builder.getFipsMode());
        assertEquals(EfuseTestFlag.PHYSICAL, builder.getTestFlag());

    }

    @Test
    void parse_WithSDM12Certificate_Throws() {
        // given
        final byte[] aesContent = FileUtils.loadBinary(ResourceDir.ROOT, ("signed_efuse_aes.ccert"));

        // when - then
        final var exception = assertThrows(ParseStructureException.class, () -> new PsgAesKeyBuilderSDM15()
            .withActor(EndiannessActor.FIRMWARE)
            .parse(aesContent));

        // then
        assertEquals("Mismatch between certificate SDM version and Builder version. "
            + "Certificate SDM version: 0. Builder/parser version: 2", exception.getMessage());
    }

    @ParameterizedTest
    @EnumSource(TestSuiteParams.class)
    void parseReserved_Success(TestSuiteParams params) {
        // given
        final BitSet bitSet = BitSet.valueOf(new byte[] {(byte)0x00, (byte)0x00, (byte)0x00, params.byteValue});

        //when
        final var sut = new PsgAesKeyBuilderSDM15();
        sut.parseReservedWithFlags(bitSet);

        //then
        assertEquals(params.getFipsMode(), sut.getFipsMode());
        assertEquals(params.getTestFlag(), sut.getTestFlag());
    }

    private void commonAssert(byte[] content, PsgAesKeyBuilderSDM15 builder, StorageType storage, KeyWrappingType keyType) {
        assertNotNull(builder);
        assertEquals(storage, builder.getStorageType());
        assertEquals(keyType, builder.getKeyWrappingType());

        final String expected = toHex(content);
        final String actual = toHex(builder.build().array());
        assertEquals(expected, actual);
    }
}
