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

import com.intel.bkp.bkps.domain.BlackList;
import com.intel.bkp.bkps.domain.EfusesPublic;
import com.intel.bkp.bkps.domain.RomVersion;
import com.intel.bkp.bkps.domain.SdmBuildIdString;
import com.intel.bkp.bkps.domain.SdmSvn;
import com.intel.bkp.bkps.domain.ServiceConfiguration;
import com.intel.bkp.bkps.exception.InvalidEfuseResponseFromM2Exception;
import com.intel.bkp.bkps.exception.ProvisioningGenericException;
import com.intel.bkp.command.responses.sigma.SigmaM2Message;
import com.intel.bkp.utils.MaskHelper;
import lombok.AllArgsConstructor;

import java.math.BigInteger;
import java.nio.charset.Charset;
import java.util.Arrays;
import java.util.Set;

import static com.intel.bkp.utils.HexConverter.fromHex;

@AllArgsConstructor
public class SigmaM2WithServiceCfgVerifier {

    private ServiceConfiguration configuration;
    private SigmaM2Message sigmaM2Message;

    public void verify() {
        BlackList blackList = configuration.getAttestationConfig().getBlackList();

        verifyRomVersionWithCfg(sigmaM2Message.getRomVersionNum(), blackList.getRomVersions());
        verifySdmFwBuildIdWithCfg(sigmaM2Message.getSdmFwBuildId(), blackList.getSdmBuildIdStrings());
        verifySdmSvnWithCfg(sigmaM2Message.getSdmFwSecurityVersionNum(), blackList.getSdmSvns());
        verifyPubEfusesWithCfg(sigmaM2Message.getPublicEfuseValues(),
            configuration.getAttestationConfig().getEfusesPublic());
    }

    private void verifyRomVersionWithCfg(byte[] romVerNum, Set<RomVersion> romVersions) {
        final Integer m2RomVersion = new BigInteger(romVerNum).intValue();
        boolean isRomVersionBlackListed = romVersions
            .stream()
            .map(RomVersion::getValue)
            .anyMatch(val -> val.equals(m2RomVersion));
        if (isRomVersionBlackListed) {
            throw new ProvisioningGenericException("ROM version is blacklisted.");
        }
    }

    private void verifySdmFwBuildIdWithCfg(byte[] sdmFwBuildId, Set<SdmBuildIdString> sdmBuildIdStrings) {
        final String m2SdmFwBuildId = new String(sdmFwBuildId, Charset.defaultCharset());
        boolean isSdmFwBuildIdBlackListed = sdmBuildIdStrings
            .stream()
            .map(SdmBuildIdString::getValue)
            .anyMatch(val -> val.equals(m2SdmFwBuildId));

        if (isSdmFwBuildIdBlackListed) {
            throw new ProvisioningGenericException("SDM FW build identifier is blacklisted.");
        }
    }

    private void verifySdmSvnWithCfg(byte[] sdmFwSecurityVersionNum, Set<SdmSvn> sdmSvns) {
        final Integer m2SdmSvn = new BigInteger(sdmFwSecurityVersionNum).intValue();
        boolean isSdmSvnBlackListed = sdmSvns
            .stream()
            .map(SdmSvn::getValue)
            .anyMatch(val -> val.equals(m2SdmSvn));

        if (isSdmSvnBlackListed) {
            throw new ProvisioningGenericException("SDM SVN is blacklisted.");
        }
    }

    private void verifyPubEfusesWithCfg(byte[] m2SigmaEfusesPublic, EfusesPublic cfgEfusesPublic) {
        final byte[] decodedMask = fromHex(cfgEfusesPublic.getMask());
        final byte[] decodedReferenceValue = fromHex(cfgEfusesPublic.getValue());
        final byte[] maskedValue;

        try {
            maskedValue = MaskHelper.applyMask(m2SigmaEfusesPublic, decodedMask);
        } catch (MaskHelper.MismatchedMaskLengthException e) {
            throw new InvalidEfuseResponseFromM2Exception(e);
        }

        if (!Arrays.equals(decodedReferenceValue, maskedValue)) {
            throw new InvalidEfuseResponseFromM2Exception(decodedReferenceValue, maskedValue);
        }
    }
}
