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

package com.intel.bkp.fpgacerts.ect;

import com.intel.bkp.fpgacerts.cbor.CborObjectParser;
import com.intel.bkp.fpgacerts.cbor.rim.comid.MeasurementMap;
import com.intel.bkp.fpgacerts.cbor.rim.comid.mapping.DigestsToFwIdFieldMapper;
import com.intel.bkp.fpgacerts.dice.tcbinfo.vendorinfo.MaskedVendorInfo;
import com.intel.bkp.fpgacerts.dice.tcbinfo.vendorinfo.MaskedVendorInfoComparator;
import com.upokecenter.cbor.CBORObject;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;

import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

import static com.intel.bkp.utils.HexConverter.toHex;

@Getter
@Builder
@AllArgsConstructor
public class ElementMap {
    private final CBORObject elementClaims;

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }

        // Check for null and if the classes are the same
        if (obj == null || !(obj instanceof ElementMap)) {
            return false;
        }

        // Perform the cast safely.
        ElementMap other = (ElementMap) obj;

        if (other.getElementClaims() == null) {
            return false;
        }

        CBORObject sourceClaim = CborObjectParser.instance().parse(elementClaims);
        CBORObject targetClaim = CborObjectParser.instance().parse(other.getElementClaims());

        boolean result = true;

        if (sourceClaim.get(MeasurementMap.CBOR_MEAS_VERSION_KEY) != null) {
            if (targetClaim.get(MeasurementMap.CBOR_MEAS_VERSION_KEY) != null) {
                result = Arrays.equals(sourceClaim.get(MeasurementMap.CBOR_MEAS_VERSION_KEY).EncodeToBytes(),
                    targetClaim.get(MeasurementMap.CBOR_MEAS_VERSION_KEY).EncodeToBytes());
            } else {
                return false;
            }
        }

        if (result) {
            if (sourceClaim.get(MeasurementMap.CBOR_SVN_KEY) != null) {
                if (targetClaim.get(MeasurementMap.CBOR_SVN_KEY) != null) {
                    result = sourceClaim.get(MeasurementMap.CBOR_SVN_KEY).equals(
                            targetClaim.get(MeasurementMap.CBOR_SVN_KEY));
                } else {
                    return false;
                }
            }
        }

        if (result) {
            if (sourceClaim.get(MeasurementMap.CBOR_DIGESTS_KEY) != null) {
                if (targetClaim.get(MeasurementMap.CBOR_DIGESTS_KEY) != null) {
                    result = sourceClaim.get(MeasurementMap.CBOR_DIGESTS_KEY).getValues()
                            .stream()
                            .allMatch(
                                srcDigest -> (srcDigest != null) && targetClaim.get(MeasurementMap.CBOR_DIGESTS_KEY)
                                    .getValues()
                                    .stream()
                                    .anyMatch(targetDigest -> {
                                        if (targetDigest == null) {
                                            return false;
                                        }
                                        List<CBORObject> srcElementList = srcDigest.getValues().stream().toList();
                                        List<CBORObject> targetElementList = targetDigest.getValues().stream().toList();
                                        if (srcElementList.size() != 2
                                            || targetElementList.size() != 2) {
                                            return false;
                                        }
                                        var oid =
                                            DigestsToFwIdFieldMapper.HashAlgorithmRegistry.getOidById(
                                                srcElementList.get(0).AsInt32());
                                        return oid.equals(DigestsToFwIdFieldMapper.HashAlgorithmRegistry.getOidById(targetElementList.get(0).AsInt32()))
                                                && Arrays.equals(srcElementList.get(1).EncodeToBytes(), targetElementList.get(1).EncodeToBytes());
                                    })
                            );
                } else {
                    return false;
                }
            }
        }

        if (result) {
            if (sourceClaim.get(MeasurementMap.CBOR_RAW_VALUE_KEY) != null) {
                if (targetClaim.get(MeasurementMap.CBOR_RAW_VALUE_KEY) != null) {
                    final var rawValue = toHex(sourceClaim.get(MeasurementMap.CBOR_RAW_VALUE_KEY).GetByteString());
                    final var targetValue = toHex(targetClaim.get(MeasurementMap.CBOR_RAW_VALUE_KEY).GetByteString());
                    final var rawMask = sourceClaim.get(MeasurementMap.CBOR_RAW_VALUE_MASK_KEY);
                    final var targetMask = targetClaim.get(MeasurementMap.CBOR_RAW_VALUE_MASK_KEY);
                    result = new MaskedVendorInfoComparator(
                        rawMask == null ? new MaskedVendorInfo(rawValue) : new MaskedVendorInfo(rawValue, toHex(rawMask.GetByteString())),
                        targetMask == null ? new MaskedVendorInfo(targetValue) : new MaskedVendorInfo(targetValue, toHex(targetMask.GetByteString()))).areEqual();
                } else {
                    return false;
                }
            }
        }

        return result;
    }

    @Override
    public int hashCode() { // Must be implemented as well
        return Objects.hash(elementClaims);
    }

    @Override
    public String toString() {
        return Optional.ofNullable(elementClaims).map(CBORObject::toString).orElse("null");
    }
}
