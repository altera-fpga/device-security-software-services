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

import com.intel.bkp.core.endianness.StructureBuilder;
import com.intel.bkp.core.endianness.StructureType;
import com.intel.bkp.core.exceptions.ParseStructureException;
import com.intel.bkp.core.psgcertificate.enumerations.KeyWrappingType;
import com.intel.bkp.core.psgcertificate.enumerations.StorageType;
import com.intel.bkp.core.psgcertificate.model.EfuseTestFlag;
import com.intel.bkp.core.psgcertificate.model.FIPSMode;
import com.intel.bkp.core.psgcertificate.model.PsgAesKeySDM15;
import com.intel.bkp.core.psgcertificate.model.PsgAesKeyType;
import com.intel.bkp.utils.BitUtils;
import com.intel.bkp.utils.ByteBufferSafe;
import com.intel.bkp.utils.exceptions.ByteBufferSafeException;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.Setter;

import java.math.BigInteger;
import java.util.BitSet;
import java.util.Optional;

import static com.intel.bkp.core.endianness.StructureField.PSG_AES_KEY_CERT_DATA_LENGTH;
import static com.intel.bkp.core.endianness.StructureField.PSG_AES_KEY_CERT_TYPE;
import static com.intel.bkp.core.endianness.StructureField.PSG_AES_KEY_CERT_VERSION;
import static com.intel.bkp.core.endianness.StructureField.PSG_AES_KEY_MAGIC;
import static com.intel.bkp.core.endianness.StructureField.PSG_AES_KEY_USER_AES_CERT_MAGIC;

@Getter
@Setter
public class PsgAesKeyBuilderSDM15 extends StructureBuilder<PsgAesKeyBuilderSDM15, PsgAesKeySDM15>
    implements IPsgAesKeyBuilder<PsgAesKeyBuilderSDM15> {

    public static final int TEST_FLAG_BIT_INDEX = 31;
    public static final int FIPS_MODE_BIT_INDEX_START = 29;
    public static final int RESERVED_WITH_FLAGS_LEN = 4;
    public static final int RESERVED_SECOND_LEN = 14;
    public static final int MAC_TAG_LEN = 48;
    public static final int MAC_DATA_LEN = 32;

    private byte[] magic = new byte[Integer.BYTES];
    private byte[] certDataLength = new byte[Integer.BYTES];
    private byte[] certVersion = new byte[Integer.BYTES];
    private byte[] certType = new byte[Integer.BYTES];
    private byte[] userAesCertMagic = new byte[Integer.BYTES];
    private final byte[] reservedWithFlags = new byte[RESERVED_WITH_FLAGS_LEN];
    private StorageType storageType;
    private KeyWrappingType keyWrappingType;
    private final byte[] reservedSecond = new byte[RESERVED_SECOND_LEN];
    private final byte[] userInputIV = new byte[USER_INPUT_IV_LEN];
    private final byte[] macTag = new byte[MAC_TAG_LEN];
    private final byte[] macData = new byte[MAC_DATA_LEN];
    private byte[] certSigningKeyChain = new byte[0];

    private FIPSMode fipsMode;

    @Getter(AccessLevel.NONE)
    private EfuseTestFlag testFlag;

    public PsgAesKeyBuilderSDM15() {
        super(StructureType.PSG_AES_KEY_ENTRY);
    }

    @Override
    public PsgAesKeyBuilderSDM15 self() {
        return this;
    }

    @Override
    public PsgAesKeySDM15 build() {
        final PsgAesKeySDM15 entry = new PsgAesKeySDM15();

        entry.setMagic(convert(MAGIC, PSG_AES_KEY_MAGIC));
        entry.setCertDataLength(convert(certDataLength, PSG_AES_KEY_CERT_DATA_LENGTH));
        entry.setCertVersion(convert(certVersion, PSG_AES_KEY_CERT_VERSION));
        entry.setCertType(convert(certType, PSG_AES_KEY_CERT_TYPE));
        entry.setUserAesCertMagic(convert(userAesCertMagic, PSG_AES_KEY_USER_AES_CERT_MAGIC));
        entry.setReservedWithFlags(reservedWithFlags);
        entry.setKeyStorageType(storageType.getType().byteValue());
        entry.setKeyWrappingType(keyWrappingType.getType().byteValue());
        entry.setReservedSecond(reservedSecond);
        entry.setUserInputIV(userInputIV);
        entry.setMacTag(macTag);
        entry.setMacData(macData);
        entry.setCertSigningKeyChain(certSigningKeyChain);

        return entry;
    }

    @Override
    public EfuseTestFlag getTestFlag() {
        return Optional.ofNullable(testFlag)
            .orElseThrow(() -> new ParseStructureException("Test Flag not parsed from certificate"));
    }

    @Override
    public PsgAesKeyType getAesKeyType() {
        return PsgAesKeyType.SDM_1_5;
    }

    @Override
    public PsgAesKeyBuilderSDM15 parse(ByteBufferSafe buffer) throws ParseStructureException {
        try {
            buffer.get(magic);
            magic = convert(magic, PSG_AES_KEY_MAGIC);
            if (MAGIC != new BigInteger(magic).intValue()) {
                throw new ParseStructureException("Invalid entry magic 0x%x, expected 0x%x".formatted(new BigInteger(magic).intValue(), MAGIC));
            }

            buffer.get(certDataLength);
            certDataLength = convert(certDataLength, PSG_AES_KEY_CERT_DATA_LENGTH);
            buffer.get(certVersion);
            checkIfCertHasCorrectVersion(convertInt(certVersion, PSG_AES_KEY_CERT_VERSION));
            certVersion = convert(certVersion, PSG_AES_KEY_CERT_VERSION);

            buffer.get(certType);
            certType = convert(certType, PSG_AES_KEY_CERT_TYPE);

            buffer.get(userAesCertMagic);
            userAesCertMagic = convert(userAesCertMagic, PSG_AES_KEY_USER_AES_CERT_MAGIC);
            if (USER_AES_CERT_MAGIC != new BigInteger(userAesCertMagic).intValue()) {
                throw new ParseStructureException("Invalid user aes entry magic 0x%x, expected 0x%x".formatted(new BigInteger(userAesCertMagic).intValue(), USER_AES_CERT_MAGIC));
            }

            buffer.get(reservedWithFlags);
            parseReservedWithFlags(BitSet.valueOf(reservedWithFlags));
            storageType = StorageType.fromValue(buffer.getByte());
            keyWrappingType = KeyWrappingType.fromValue(buffer.getByte());
            buffer.get(reservedSecond);
            buffer.get(userInputIV);
            buffer.get(macTag);
            buffer.get(macData);
            certSigningKeyChain = buffer.arrayFromRemaining();
            buffer.get(certSigningKeyChain);

            checkIfArrayFilledWithZeros(reservedSecond);

            return this;
        } catch (ByteBufferSafeException e) {
            throw new ParseStructureException("Invalid buffer during parsing entry", e);
        }
    }

    void parseReservedWithFlags(BitSet reservedBitSet) {
        checkIfBitSetFilledWithZeros(reservedBitSet.get(0, FIPS_MODE_BIT_INDEX_START));
        final var fipsModeRange = reservedBitSet.get(FIPS_MODE_BIT_INDEX_START, TEST_FLAG_BIT_INDEX);
        this.fipsMode = FIPSMode.fromValue(BitUtils.toInt(fipsModeRange));
        this.testFlag = EfuseTestFlag.fromValue(reservedBitSet.get(TEST_FLAG_BIT_INDEX));
    }

    private void checkIfBitSetFilledWithZeros(BitSet reservedBitSet) {
        if (reservedBitSet.cardinality() != 0) {
            throw new ParseStructureException("Reserved field contains value different than 0");
        }
    }
}
