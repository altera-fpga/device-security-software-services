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
import com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfoKey;
import com.intel.bkp.fpgacerts.utils.OidConverter;
import com.upokecenter.cbor.CBORObject;
import lombok.AllArgsConstructor;

import java.util.Optional;

import static com.intel.bkp.utils.HexConverter.toHex;
import static java.util.Optional.ofNullable;
import static com.intel.bkp.utils.HexConverter.fromHex;

/**
 * Builds a CBOR representation of the Environment Map from TcbInfo.
 */
@AllArgsConstructor
public class EnvironmentMapBuilder {

    public static CBORObject from(TcbInfoKey tcbKey) {
        CBORObject classMap = CBORObject.NewOrderedMap();
        if (tcbKey.getType() != null) {
            String classIdHex;
            try {
                classIdHex = OidConverter.decimalToHexNotation(tcbKey.getType());
            } catch (Exception e) {
                classIdHex = tcbKey.getType();
            }
            // class ID
            CBORObject classOid = CBORObject.FromObjectAndTag(fromHex(classIdHex), EnvironmentMap.CBOR_CLASS_ID_TAG);
            classMap.Add(EnvironmentMap.CBOR_CLASS_ID_KEY, classOid);
        }
        // vendor
        ofNullable(tcbKey.getVendor())
            .ifPresent(vendor -> classMap.Add(EnvironmentMap.CBOR_VENDOR_KEY, CBORObject.FromObject(vendor)));
        // model
        ofNullable(tcbKey.getModel())
            .ifPresent(model -> classMap.Add(EnvironmentMap.CBOR_MODEL_KEY, CBORObject.FromObject(model)));
        // layer
        ofNullable(tcbKey.getLayer())
            .ifPresent(layer -> classMap.Add(EnvironmentMap.CBOR_LAYER_KEY, CBORObject.FromObject(layer)));
        // index
        ofNullable(tcbKey.getIndex())
            .ifPresent(index -> classMap.Add(EnvironmentMap.CBOR_INDEX_KEY, CBORObject.FromObject(index)));

        CBORObject environmentMap = CBORObject.NewOrderedMap();
        environmentMap.Add(EnvironmentMap.CBOR_CLASS_ID_KEY, classMap);
        return environmentMap;
    }

    public static TcbInfoKey to(CBORObject cbor) {
        return Optional.ofNullable(cbor.get(EnvironmentMap.CBOR_CLASS_ID_KEY))
                .map(classID -> {
                    return TcbInfoKey.builder()
                        .type(Optional.ofNullable(classID.get(EnvironmentMap.CBOR_CLASS_ID_KEY))
                            .filter(classIDType -> classIDType.HasMostOuterTag(EnvironmentMap.CBOR_CLASS_ID_TAG))
                            .map(classIDType -> OidConverter.fromHexOid(toHex(classIDType.GetByteString())))
                            .orElse(null))
                        .vendor(Optional.ofNullable(classID.get(EnvironmentMap.CBOR_VENDOR_KEY))
                            .map(vendor -> vendor.AsString())
                            .orElse(null))
                        .model(Optional.ofNullable(classID.get(EnvironmentMap.CBOR_MODEL_KEY))
                            .map(model -> model.AsString())
                            .orElse(null))
                        .layer(Optional.ofNullable(classID.get(EnvironmentMap.CBOR_LAYER_KEY))
                            .map(layer -> layer.AsInt32Value())
                            .orElse(null))
                        .index(Optional.ofNullable(classID.get(EnvironmentMap.CBOR_INDEX_KEY))
                            .map(index -> index.AsInt32Value())
                            .orElse(null))
                        .build();
                })
                .orElse(null);
    }
}
