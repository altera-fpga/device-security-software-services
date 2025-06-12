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

package com.intel.bkp.bkps.protocol.sigma.verification;

import com.intel.bkp.bkps.domain.AttestationConfiguration;
import com.intel.bkp.bkps.domain.BlackList;
import com.intel.bkp.bkps.domain.EfusesPublic;
import com.intel.bkp.bkps.domain.RomVersion;
import com.intel.bkp.bkps.domain.SdmBuildIdString;
import com.intel.bkp.bkps.domain.SdmSvn;
import com.intel.bkp.bkps.domain.ServiceConfiguration;
import com.intel.bkp.bkps.exception.ProvisioningGenericException;
import com.intel.bkp.command.responses.sigma.SigmaM2Message;
import com.intel.bkp.test.RandomUtils;
import com.intel.bkp.utils.MaskHelper;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.nio.charset.Charset;
import java.util.HashSet;

import static com.intel.bkp.test.AssertionUtils.verifyContainsExpectedMessage;
import static com.intel.bkp.test.AssertionUtils.verifyExpectedMessage;
import static com.intel.bkp.utils.ByteConverter.toBytes;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
public class SigmaM2WithServiceCfgVerifierTest {

    @Mock
    private ServiceConfiguration configuration;

    @Mock
    private SigmaM2Message sigmaM2Message;

    @Mock
    AttestationConfiguration attestationConfiguration;

    @Mock
    BlackList blackList;

    @Mock
    EfusesPublic efusesPublic;

    private byte[] outputEFuseValue;

    private SigmaM2WithServiceCfgVerifier sut;

    @BeforeEach
    void setUp() throws MaskHelper.MismatchedMaskLengthException {
        sut = new SigmaM2WithServiceCfgVerifier(configuration, sigmaM2Message);

        byte[] maskValue = RandomUtils.generateRandom256Bytes();
        outputEFuseValue = RandomUtils.generateRandom256Bytes();
        byte[] appliedMask = MaskHelper.applyMask(outputEFuseValue, maskValue);
        when(efusesPublic.getMask()).thenReturn(Hex.toHexString(maskValue));
        when(efusesPublic.getValue()).thenReturn(Hex.toHexString(appliedMask));
    }

    @Test
    void verify_Success() {
        // given
        prepareEmptyConfidentialData();
        prepareSigmaM2Answer(null);

        // when
        sut.verify();
    }

    @Test
    void verify_WithFailingRomVersionBlacklisted_ThrowsException() {
        // given
        int blackListedNum = 1;
        byte[] sdmFwBuildId = RandomUtils.generateRandomBytes(28);
        prepareConfidentialData(blackListedNum, new String(sdmFwBuildId, Charset.defaultCharset()), 1);
        prepareSigmaM2Answer(toBytes(blackListedNum), sdmFwBuildId, toBytes(2));

        // when-then
        final ProvisioningGenericException exception = assertThrows(ProvisioningGenericException.class,
            () -> sut.verify()
        );

        // then
        verifyExpectedMessage(exception, "ROM version is blacklisted.");
    }

    @Test
    void verify_WithSdmFwBuildIdBlacklisted_ThrowsException() {
        // given
        byte[] blackListedString = RandomUtils.generateRandomBytes(28);
        prepareConfidentialData(1, new String(blackListedString, Charset.defaultCharset()), 1);
        prepareSigmaM2Answer(toBytes(2), blackListedString, toBytes(2));

        // when-then
        final ProvisioningGenericException exception = assertThrows(ProvisioningGenericException.class,
            () -> sut.verify()
        );

        // then
        verifyExpectedMessage(exception, "SDM FW build identifier is blacklisted.");
    }

    @Test
    void verify_WithSdmSvnBlacklisted_ThrowsException() {
        // given
        int blackListedNum = 1;
        prepareConfidentialData(1, new String(RandomUtils.generateRandomBytes(28), Charset.defaultCharset()), blackListedNum);
        prepareSigmaM2Answer(toBytes(2), RandomUtils.generateRandomBytes(28), toBytes(blackListedNum));

        // when-then
        final ProvisioningGenericException exception = assertThrows(ProvisioningGenericException.class,
            () -> sut.verify()
        );

        // then
        verifyExpectedMessage(exception, "SDM SVN is blacklisted.");
    }

    @Test
    void verify_WithInvalidMaskedValue_ThrowsException() {
        // given
        prepareEmptyConfidentialData();
        prepareSigmaM2Answer(RandomUtils.generateRandom256Bytes());

        // when-then
        final ProvisioningGenericException exception = assertThrows(ProvisioningGenericException.class,
            () -> sut.verify()
        );

        // then
        verifyContainsExpectedMessage(exception, "Invalid Efuse response from M2 Message.");
    }

    private void prepareSigmaM2Answer(byte[] outputEFuseVal) {
        if (outputEFuseVal == null) {
            outputEFuseVal = outputEFuseValue;
        }
        when(sigmaM2Message.getRomVersionNum()).thenReturn(toBytes(RandomUtils.generateRandomInteger()));
        when(sigmaM2Message.getSdmFwBuildId()).thenReturn(RandomUtils.generateRandomBytes(28));
        when(sigmaM2Message.getSdmFwSecurityVersionNum()).thenReturn(toBytes(RandomUtils.generateRandomInteger()));
        when(sigmaM2Message.getPublicEfuseValues()).thenReturn(outputEFuseVal);
    }

    private void prepareSigmaM2Answer(byte[] romVersion, byte[] sdmFwBuildId, byte[] sdmSvnVer) {
        when(sigmaM2Message.getRomVersionNum()).thenReturn(romVersion);
        when(sigmaM2Message.getSdmFwBuildId()).thenReturn(sdmFwBuildId);
        when(sigmaM2Message.getSdmFwSecurityVersionNum()).thenReturn(sdmSvnVer);
    }

    private void prepareEmptyConfidentialData() {
        when(configuration.getAttestationConfig()).thenReturn(attestationConfiguration);
        when(attestationConfiguration.getBlackList()).thenReturn(blackList);
        when(configuration.getAttestationConfig().getEfusesPublic()).thenReturn(efusesPublic);
        when(blackList.getRomVersions()).thenReturn(new HashSet<>());
        when(blackList.getSdmBuildIdStrings()).thenReturn(new HashSet<>());
        when(blackList.getSdmSvns()).thenReturn(new HashSet<>());
    }

    private void prepareConfidentialData(int romVersion, String sdmBuildId, int sdmSvnVersion) {
        when(configuration.getAttestationConfig()).thenReturn(attestationConfiguration);
        when(attestationConfiguration.getBlackList()).thenReturn(blackList);

        HashSet<RomVersion> romVersions = new HashSet<>();
        RomVersion localRomVersion = new RomVersion();
        localRomVersion.setValue(romVersion);
        romVersions.add(localRomVersion);
        when(blackList.getRomVersions()).thenReturn(romVersions);

        HashSet<SdmBuildIdString> sdmBuildIdStrings = new HashSet<>();
        SdmBuildIdString sdmBuildIdString = new SdmBuildIdString();
        sdmBuildIdString.setValue(sdmBuildId);
        sdmBuildIdStrings.add(sdmBuildIdString);
        when(blackList.getSdmBuildIdStrings()).thenReturn(sdmBuildIdStrings);

        HashSet<SdmSvn> sdmSvns = new HashSet<>();
        SdmSvn sdmSvn = new SdmSvn();
        sdmSvn.setValue(sdmSvnVersion);
        sdmSvns.add(sdmSvn);
        when(blackList.getSdmSvns()).thenReturn(sdmSvns);
    }
}
