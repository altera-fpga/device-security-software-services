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

package com.intel.bkp.bkps.rest.provisioning.utils;

import com.intel.bkp.bkps.exception.ProvisioningConverterException;
import com.intel.bkp.bkps.programmer.model.ProgrammerMessage;
import com.intel.bkp.bkps.programmer.model.ProgrammerResponse;
import com.intel.bkp.bkps.programmer.model.dto.MessageDTO;
import com.intel.bkp.bkps.programmer.model.dto.ResponseDTO;
import com.intel.bkp.bkps.protocol.common.model.ProvContext;
import com.intel.bkp.bkps.rest.provisioning.model.dto.ContextDTO;
import com.intel.bkp.crypto.ecdh.EcdhKeyPair;
import com.intel.bkp.test.RandomUtils;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;
import org.apache.commons.lang3.ArrayUtils;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class ProvisioningContextConverterTest {

    private static final String TEST_COMMAND_STRING = "testCommand1";
    private static final String TEST_COMMAND_STRING_2 = "testCommand2";
    private static final long TEST_CFG_ID = 1555L;
    private static final String TEST_DEVICE_ID = RandomUtils.generateDeviceIdHex();
    private static final byte[] TEST_PUBLIC_KEY = new byte[]{1, 2, 3, 4};
    private static final byte[] TEST_PRIVATE_KEY = new byte[]{5, 6, 7, 8};

    private static final List<ProgrammerMessage> PROGRAMMER_COMMANDS = new ArrayList<>();
    private static final List<ResponseDTO> JTAG_ENCODED_COMMANDS_STRING = new ArrayList<>();
    private static final List<MessageDTO> JTAG_ENCODED_COMMANDS = new ArrayList<>();

    private static final byte[] CFG_ID_BYTES;
    private static final byte[] CHIP_ID_BYTES;

    static {
        PROGRAMMER_COMMANDS.add(new ProgrammerMessage(0, TEST_COMMAND_STRING.getBytes()));
        PROGRAMMER_COMMANDS.add(new ProgrammerMessage(0, TEST_COMMAND_STRING_2.getBytes()));
        JTAG_ENCODED_COMMANDS_STRING.add(ResponseDTO.from(TEST_COMMAND_STRING.getBytes()));
        JTAG_ENCODED_COMMANDS_STRING.add(ResponseDTO.from(TEST_COMMAND_STRING_2.getBytes()));
        JTAG_ENCODED_COMMANDS.add(MessageDTO.from(0, TEST_COMMAND_STRING.getBytes()));
        JTAG_ENCODED_COMMANDS.add(MessageDTO.from(0, TEST_COMMAND_STRING_2.getBytes()));

        CFG_ID_BYTES = String.valueOf(TEST_CFG_ID).getBytes();
        CHIP_ID_BYTES = TEST_DEVICE_ID.getBytes();
    }

    @Test
    void encodeCommands_SuccessEncoding() {
        // when
        List<MessageDTO> output = ProvisioningContextConverter.encodeMessages(PROGRAMMER_COMMANDS);

        // then
        assertEquals(2, output.size());
        assertEquals(JTAG_ENCODED_COMMANDS.get(0).getValue(), output.get(0).getValue());
        assertEquals(JTAG_ENCODED_COMMANDS.get(1).getValue(), output.get(1).getValue());
    }

    @Test
    void decodeCommands_SuccessDecoding() {
        // when
        List<ProgrammerResponse> output = ProvisioningContextConverter.decodeResponses(JTAG_ENCODED_COMMANDS_STRING);

        // then
        assertEquals(2, output.size());
        assertArrayEquals(PROGRAMMER_COMMANDS.get(0).getValue(), output.get(0).getValue());
        assertArrayEquals(PROGRAMMER_COMMANDS.get(1).getValue(), output.get(1).getValue());
    }

    @Test
    void serialize_OnlyPublicKey_Success() throws ProvisioningConverterException {
        // given
        ProvContext provContext = prepareProvContext(false);

        // when
        byte[] output = ProvisioningContextConverter.serialize(provContext);

        // then
        final List<Byte> outputBytesList = Arrays.asList(ArrayUtils.toObject(output));
        assertTrue(outputBytesList.containsAll(Arrays.asList(ArrayUtils.toObject(CFG_ID_BYTES))));
        assertTrue(outputBytesList.containsAll(Arrays.asList(ArrayUtils.toObject(CHIP_ID_BYTES))));
    }

    @Test
    void serialize_PublicAndPrivateKey_Success() throws ProvisioningConverterException {
        // given
        ProvContext provContext = prepareProvContext(true);

        // when
        byte[] output = ProvisioningContextConverter.serialize(provContext);

        // then
        final List<Byte> outputBytesList = Arrays.asList(ArrayUtils.toObject(output));
        assertTrue(outputBytesList.containsAll(Arrays.asList(ArrayUtils.toObject(CFG_ID_BYTES))));
        assertTrue(outputBytesList.containsAll(Arrays.asList(ArrayUtils.toObject(CHIP_ID_BYTES))));
    }

    @Test
    void deserialize_OnlyPublicKey_Success() throws ProvisioningConverterException {
        // given
        ProvContextTest provContext = prepareProvContext(false);
        byte[] serializedContext = ProvisioningContextConverter.serialize(provContext);

        // when
        ProvContextTest output = (ProvContextTest) ProvisioningContextConverter
            .deserialize(serializedContext, ProvContextTest.class);

        // then
        assertEquals(provContext.getCfgId(), output.getCfgId());
        assertEquals(provContext.getChipId(), output.getChipId());
        assertArrayEquals(provContext.getEcdhKeyPair().getPublicKey(),
            output.getEcdhKeyPair().getPublicKey());
    }

    @Test
    void deserialize_PublicAndPrivateKey_Success() throws ProvisioningConverterException {
        // given
        ProvContextTest provContext = prepareProvContext(true);
        byte[] serializedContext = ProvisioningContextConverter.serialize(provContext);

        // when
        ProvContextTest output = (ProvContextTest) ProvisioningContextConverter
            .deserialize(serializedContext, ProvContextTest.class);

        // then
        assertEquals(provContext.getCfgId(), output.getCfgId());
        assertEquals(provContext.getChipId(), output.getChipId());
        assertArrayEquals(provContext.getEcdhKeyPair().getPublicKey(),
            output.getEcdhKeyPair().getPublicKey());
        assertArrayEquals(provContext.getEcdhKeyPair().getPrivateKey(),
            output.getEcdhKeyPair().getPrivateKey());
    }

    @Test
    void serialize_encode_decode_deserialize_Success() throws ProvisioningConverterException {
        // given
        ProvContextTest provContext = prepareProvContext(true);

        // when
        byte[] serializedContext = ProvisioningContextConverter.serialize(provContext);
        ContextDTO encodedContext = ContextDTO.from(serializedContext);
        byte[] decodedContext = encodedContext.decoded();
        ProvContextTest output = (ProvContextTest) ProvisioningContextConverter
            .deserialize(decodedContext, ProvContextTest.class);

        // then
        assertEquals(provContext.getCfgId(), output.getCfgId());
        assertEquals(provContext.getChipId(), output.getChipId());
        assertArrayEquals(provContext.getEcdhKeyPair().getPublicKey(),
            output.getEcdhKeyPair().getPublicKey());
        assertArrayEquals(provContext.getEcdhKeyPair().getPrivateKey(),
            output.getEcdhKeyPair().getPrivateKey());
    }

    private ProvContextTest prepareProvContext(boolean setPrivate) {
        EcdhKeyPair ecdhKeyPair = new EcdhKeyPair();
        ecdhKeyPair.setPublicKey(TEST_PUBLIC_KEY);
        if (setPrivate) {
            ecdhKeyPair.setPrivateKey(TEST_PRIVATE_KEY);
        }
        return new ProvContextTest(TEST_CFG_ID, TEST_DEVICE_ID, ecdhKeyPair);
    }

    @Getter
    @Setter
    @ToString
    @NoArgsConstructor
    private static class ProvContextTest implements ProvContext {

        private Long cfgId;
        private String chipId;
        private EcdhKeyPair ecdhKeyPair;
        private String deviceIdEnrollmentCert;

        public ProvContextTest(Long cfgId, String chipId, EcdhKeyPair ecdhKeyPair) {
            this(cfgId, chipId, ecdhKeyPair, Optional.empty());
        }

        public ProvContextTest(Long cfgId, String chipId, EcdhKeyPair ecdhKeyPair,
                               Optional<String> deviceIdEnrollmentCert) {
            this.cfgId = cfgId;
            this.chipId = chipId;
            this.ecdhKeyPair = ecdhKeyPair;
            this.deviceIdEnrollmentCert = deviceIdEnrollmentCert
                .orElse("");
        }
    }
}
