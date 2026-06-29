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

package com.intel.bkp.fpgacerts.rim;

import com.intel.bkp.fpgacerts.dice.subject.DiceCertificateSubject;
import com.intel.bkp.fpgacerts.dice.tcbinfo.FirmwareHashRetriever;
import com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfoKey;
import com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfoValue;
import com.intel.bkp.fpgacerts.url.DistributionPointAddressProvider;
import com.intel.bkp.fpgacerts.url.params.RimSignedDataParams;
import lombok.RequiredArgsConstructor;

import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static com.intel.bkp.utils.OptionalUtils.mapIfBothPresent;

@RequiredArgsConstructor
public class RimUrlProvider {

    private static final String LAYER = "L1";
    private final DistributionPointAddressProvider addressProvider;

    public String getRimUrl(List<X509Certificate> chain, Map<TcbInfoKey, TcbInfoValue> measurements) {
        final Optional<String> familyName = getFamilyName(chain);
        final Optional<String> firmwareHash = getFirmwareHash(familyName, measurements);

        return mapIfBothPresent(familyName, firmwareHash, this::getRimUrl).orElse(null);
    }

    private String getRimUrl(String familyName, String fwHash) {
        return addressProvider.getRimSignedDataUrl(new RimSignedDataParams(familyName, LAYER, fwHash));
    }

    private Optional<String> getFamilyName(List<X509Certificate> chain) {
        for (X509Certificate cert : chain) {
            final String subject = cert.getSubjectX500Principal().getName();
            final Optional<String> familyName = DiceCertificateSubject.tryParse(subject)
                .map(DiceCertificateSubject::familyName);
            if (familyName.isPresent()) {
                return familyName;
            }
        }
        return Optional.empty();
    }

    private Optional<String> getFirmwareHash(Optional<String> familyNameOpt,
                                             Map<TcbInfoKey, TcbInfoValue> measurements) {
        return familyNameOpt.map(familyName -> getFirmwareHash(familyName, measurements))
            .filter(Optional::isPresent)
            .map(Optional::get);
    }

    private Optional<String> getFirmwareHash(String familyName, Map<TcbInfoKey, TcbInfoValue> measurements) {
        return FirmwareHashRetriever.instance(measurements)
            .getFirmwareHashInBase64Url(familyName);
    }
}
