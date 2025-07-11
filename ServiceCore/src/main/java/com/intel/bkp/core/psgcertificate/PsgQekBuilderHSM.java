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

package com.intel.bkp.core.psgcertificate;

import com.intel.bkp.core.endianness.StructureBuilder;
import com.intel.bkp.core.endianness.StructureType;
import com.intel.bkp.core.exceptions.ParseStructureException;
import com.intel.bkp.core.psgcertificate.model.PsgQekHSM;
import com.intel.bkp.utils.ByteBufferSafe;
import com.intel.bkp.utils.exceptions.ByteBufferSafeException;
import lombok.Getter;

import java.math.BigInteger;
import java.util.Arrays;

import static com.intel.bkp.core.endianness.StructureField.PSG_QEK_DATA_LENGTH;
import static com.intel.bkp.core.endianness.StructureField.PSG_QEK_INFO_LENGTH;
import static com.intel.bkp.core.endianness.StructureField.PSG_QEK_INTER_KEY_NUM;
import static com.intel.bkp.core.endianness.StructureField.PSG_QEK_KEY_LENGTH;
import static com.intel.bkp.core.endianness.StructureField.PSG_QEK_KEY_TYPE_MAGIC;
import static com.intel.bkp.core.endianness.StructureField.PSG_QEK_KEY_VERSION;
import static com.intel.bkp.core.endianness.StructureField.PSG_QEK_MAGIC;
import static com.intel.bkp.core.endianness.StructureField.PSG_QEK_MAX_KEY_USES;
import static com.intel.bkp.core.endianness.StructureField.PSG_QEK_SHA_LENGTH;
import static com.intel.bkp.core.endianness.StructureField.PSG_QEK_STEP;
import static com.intel.bkp.core.endianness.StructureField.PSG_QEK_TOTAL_KEY_USES;

@Getter
public class PsgQekBuilderHSM extends StructureBuilder<PsgQekBuilderHSM, PsgQekHSM> {

    public static final int TOTAL_KEY_USES_SIZE = 8;
    public static final int RESERVED_NO_SALT_LEN = 16;
    public static final int IV_DATA_LEN = 16;
    public static final int ENCRYPTED_AES_KEY_LEN = 32;
    public static final int ENCRYPTED_KDK_LEN = 32;
    public static final int ENCRYPTED_SHA_SIZE = 48;
    public static final int AES_ENTRY_MAGIC = 0x367336E4;
    public static final int QEK_DATA_LEN = 0xC0;
    public static final int SHA_LEN = 0x30;
    public static final int KEY_TYPE_MAGIC = 0x4048534D;

    private byte[] magic = new byte[Integer.BYTES];
    private byte[] qekDataLength = new byte[Integer.BYTES];
    private byte[] infoLength = new byte[Integer.BYTES];
    private byte[] keyLength = new byte[Integer.BYTES];
    private byte[] shaLength = new byte[Integer.BYTES];
    private byte[] version = new byte[Integer.BYTES];
    private byte[] keyTypeMagic = new byte[Integer.BYTES];
    private byte[] maxKeyUses = new byte[Integer.BYTES];
    private byte[] interKeyNum = new byte[Integer.BYTES];
    private byte[] step = new byte[Integer.BYTES];
    private byte[] totalKeyUses = new byte[TOTAL_KEY_USES_SIZE];
    private final byte[] reservedNoSalt = new byte[RESERVED_NO_SALT_LEN];
    private byte[] ivData = new byte[IV_DATA_LEN];
    private byte[] encryptedAESKey = new byte[ENCRYPTED_AES_KEY_LEN];
    private byte[] encryptedKDK = new byte[ENCRYPTED_KDK_LEN];
    private byte[] encryptedSHA384 = new byte[ENCRYPTED_SHA_SIZE];

    public PsgQekBuilderHSM() {
        super(StructureType.PSG_QEK_ENTRY);
    }

    @Override
    public PsgQekBuilderHSM self() {
        return this;
    }

    @Override
    public PsgQekHSM build() {
        final PsgQekHSM entry = new PsgQekHSM();

        entry.setMagic(convert(AES_ENTRY_MAGIC, PSG_QEK_MAGIC));
        entry.setQekDataLength(convert(qekDataLength, PSG_QEK_DATA_LENGTH));
        entry.setInfoLength(convert(infoLength, PSG_QEK_INFO_LENGTH));
        entry.setKeyLength(convert(keyLength, PSG_QEK_KEY_LENGTH));
        entry.setShaLength(convert(shaLength, PSG_QEK_SHA_LENGTH));
        entry.setVersion(version);
        entry.setKeyTypeMagic(convert(keyTypeMagic, PSG_QEK_KEY_TYPE_MAGIC));
        entry.setMaxKeyUses(convert(maxKeyUses, PSG_QEK_MAX_KEY_USES));
        entry.setInterKeyNum(convert(interKeyNum, PSG_QEK_INTER_KEY_NUM));
        entry.setStep(convert(step, PSG_QEK_STEP));
        entry.setTotalKeyUses(convert(totalKeyUses, PSG_QEK_TOTAL_KEY_USES));
        entry.setReservedNoSalt(reservedNoSalt);
        entry.setIvData(ivData);
        entry.setEncryptedAESKey(encryptedAESKey);
        entry.setEncryptedKDK(encryptedKDK);
        entry.setEncryptedSHA384(encryptedSHA384);

        return entry;
    }

    @Override
    public PsgQekBuilderHSM parse(ByteBufferSafe buffer) throws ParseStructureException {
        try {
            buffer.get(magic);

            magic = self().convert(magic, PSG_QEK_MAGIC);
            if (AES_ENTRY_MAGIC != new BigInteger(magic).intValue()) {
                throw new ParseStructureException("Invalid AES entry magic 0x%x, expected 0x%x".formatted(new BigInteger(magic).intValue(), AES_ENTRY_MAGIC));
            }

            buffer.get(qekDataLength);
            qekDataLength = convert(qekDataLength, PSG_QEK_DATA_LENGTH);
            int qekDataLen = new BigInteger(qekDataLength).intValue();
            if (qekDataLen != buffer.array().length || QEK_DATA_LEN != qekDataLen) {
                throw new ParseStructureException("Invalid AES Root Key data length 0x%x, expected 0x%x".formatted(new BigInteger(qekDataLength).intValue(), QEK_DATA_LEN));
            }

            buffer.get(infoLength);
            infoLength = convert(infoLength, PSG_QEK_INFO_LENGTH);
            buffer.get(keyLength);
            keyLength = convert(keyLength, PSG_QEK_KEY_LENGTH);
            buffer.get(shaLength);
            shaLength = convert(shaLength, PSG_QEK_SHA_LENGTH);
            if (SHA_LEN != new BigInteger(shaLength).intValue()) {
                throw new ParseStructureException("Invalid SHA length 0x%x, expected 0x%x".formatted(new BigInteger(shaLength).intValue(), SHA_LEN));
            }

            buffer.get(version);
            version = convert(version, PSG_QEK_KEY_VERSION);
            buffer.get(keyTypeMagic);
            keyTypeMagic = convert(keyTypeMagic, PSG_QEK_KEY_TYPE_MAGIC);
            if (KEY_TYPE_MAGIC != new BigInteger(keyTypeMagic).intValue()) {
                throw new ParseStructureException("Invalid AES Root Key type magic number 0x%x, expected 0x%x".formatted(new BigInteger(keyTypeMagic).intValue(), KEY_TYPE_MAGIC));
            }

            buffer.get(maxKeyUses);
            maxKeyUses = convert(maxKeyUses, PSG_QEK_MAX_KEY_USES);
            buffer.get(interKeyNum);
            interKeyNum = convert(interKeyNum, PSG_QEK_INTER_KEY_NUM);
            buffer.get(step);
            step = convert(step, PSG_QEK_STEP);
            buffer.get(totalKeyUses);
            totalKeyUses = convert(totalKeyUses, PSG_QEK_TOTAL_KEY_USES);
            buffer.get(reservedNoSalt);
            checkIfArrayFilledWithZeros(reservedNoSalt);
            buffer.get(ivData);
            buffer.get(encryptedAESKey);
            buffer.get(encryptedKDK);
            encryptedSHA384 = buffer.arrayFromRemaining();
            buffer.get(encryptedSHA384);

            return this;
        } catch (ByteBufferSafeException e) {
            throw new ParseStructureException("Invalid buffer during parsing entry", e);
        }
    }

    private void checkIfArrayFilledWithZeros(byte[] array) {
        if (!Arrays.equals(array, new byte[array.length])) {
            throw new ParseStructureException("Reserved field contains value different than 0");
        }
    }
}
