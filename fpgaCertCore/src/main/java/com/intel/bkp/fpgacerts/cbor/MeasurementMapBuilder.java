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

package com.intel.bkp.fpgacerts.cbor;

import com.intel.bkp.fpgacerts.cbor.rim.comid.EnvironmentMap;
import com.intel.bkp.fpgacerts.cbor.rim.comid.MeasurementMap;
import com.intel.bkp.fpgacerts.cbor.rim.comid.MeasurementVersion;
import com.intel.bkp.fpgacerts.cbor.rim.comid.mapping.DigestsToFwIdFieldMapper;
import com.intel.bkp.fpgacerts.dice.tcbinfo.FwIdField;
import com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfoValue;
import com.intel.bkp.fpgacerts.dice.tcbinfo.vendorinfo.MaskedVendorInfo;
import com.upokecenter.cbor.CBORObject;
import lombok.AllArgsConstructor;

import java.util.Optional;

import static com.intel.bkp.fpgacerts.cbor.rim.comid.MeasurementMap.CBOR_TAGGED_SVN_LOWER;
import static com.intel.bkp.utils.HexConverter.fromHex;
import static com.intel.bkp.utils.HexConverter.toHex;

/**
 * Builds a CBOR representation of the Measurement Map from TcbInfo.
 */
@AllArgsConstructor
public class MeasurementMapBuilder {
    private static final Integer CBOR_VERSION_SCHEME = 3;

    public static CBORObject from(TcbInfoValue tcbInfoValue) {
        CBORObject valueMap = CBORObject.NewOrderedMap();
        // version
        tcbInfoValue.getVersion()
            .ifPresent(version -> valueMap.Add(MeasurementMap.CBOR_MEAS_VERSION_KEY, getVersion(version, CBOR_VERSION_SCHEME)));
        // svn
        tcbInfoValue.getSvn()
            .ifPresent(svn -> valueMap.Add(MeasurementMap.CBOR_SVN_KEY, CBORObject.FromObjectAndTag(svn, CBOR_TAGGED_SVN_LOWER)));
        // digests
        tcbInfoValue.getFwid()
            .ifPresent(fwIdField -> valueMap.Add(MeasurementMap.CBOR_DIGESTS_KEY, getDigest(fwIdField)));
        // raw value
        tcbInfoValue.getMaskedVendorInfo()
            .ifPresent(info -> Optional.ofNullable(info.getVendorInfo())
                .ifPresent(vendorInfo -> {
                    valueMap.Add(MeasurementMap.CBOR_RAW_VALUE_KEY, CBORObject.FromObject(fromHex(vendorInfo)));
                    Optional.ofNullable(info.getVendorInfoMask())
                        .filter(vendorInfoMask -> !vendorInfoMask.isEmpty())
                        .ifPresent(vendorInfoMask -> valueMap.Add(MeasurementMap.CBOR_RAW_VALUE_MASK_KEY, fromHex(vendorInfoMask)));
                })
            );
        return valueMap;
    }

    public static TcbInfoValue to(CBORObject cbor) {
        return TcbInfoValue.builder()
                .version(Optional.ofNullable(cbor.get(MeasurementMap.CBOR_MEAS_VERSION_KEY))
                    .map(versionMap -> versionMap.get(MeasurementVersion.CBOR_VERSION_KEY))
                    .map(version -> version.AsString()))
                .svn(Optional.ofNullable(cbor.get(MeasurementMap.CBOR_SVN_KEY))
                    .filter(classIDType -> classIDType.HasMostOuterTag(CBOR_TAGGED_SVN_LOWER))
                    .map(svn -> svn.AsInt32Value()))
                .fwid(Optional.ofNullable(cbor.get(MeasurementMap.CBOR_DIGESTS_KEY))
                    .map(digests -> digests.get(0))
                    .filter(digests -> digests.size() == 2)
                    .map(digests -> FwIdField.builder()
                        .hashAlg(DigestsToFwIdFieldMapper.HashAlgorithmRegistry.getOidById(digests.get(0).AsInt32Value()))
                        .digest(toHex(digests.get(1).GetByteString()))
                        .build()))
                .maskedVendorInfo(Optional.ofNullable(cbor.get(MeasurementMap.CBOR_RAW_VALUE_KEY))
                    .map(rawValue -> new MaskedVendorInfo(
                        rawValue.AsString(),
                        Optional.ofNullable(cbor.get(MeasurementMap.CBOR_RAW_VALUE_MASK_KEY))
                            .map(rawValueMask -> rawValueMask.AsString())
                            .orElse(null))))
                .build();
    }

    private static CBORObject getVersion(String version, Integer versionScheme) {
        CBORObject versionMap = CBORObject.NewOrderedMap();
        versionMap.Add(MeasurementVersion.CBOR_VERSION_KEY, version);
        versionMap.Add(MeasurementVersion.CBOR_VERSION_SCHEME_KEY, versionScheme);
        return versionMap;
    }

    private static CBORObject getDigest(FwIdField fwIdField) {
        CBORObject digestsArr = CBORObject.NewArray();
        CBORObject digestArr = CBORObject.NewArray();
        digestArr.Add(CBORObject.FromObject(DigestsToFwIdFieldMapper.HashAlgorithmRegistry.getIdByOid(fwIdField.getHashAlg())));
        digestArr.Add(CBORObject.FromObject(fromHex(fwIdField.getDigest())));
        digestsArr.Add(digestArr);
        return digestsArr;
    }
}
