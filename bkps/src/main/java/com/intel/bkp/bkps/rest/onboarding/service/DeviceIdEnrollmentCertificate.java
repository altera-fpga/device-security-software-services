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

package com.intel.bkp.bkps.rest.onboarding.service;

import com.intel.bkp.fpgacerts.url.params.DiceEnrollmentParams;
import com.intel.bkp.fpgacerts.url.params.DiceParams;
import com.intel.bkp.fpgacerts.url.params.parsing.DiceEnrollmentParamsIssuerParser;
import com.intel.bkp.fpgacerts.url.params.parsing.DiceParamsSubjectParser;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;

import java.security.cert.X509Certificate;

import static com.intel.bkp.utils.HexConverter.fromHexSingle;
import static java.lang.Byte.toUnsignedInt;
import static java.util.Objects.isNull;

@RequiredArgsConstructor(access = AccessLevel.PRIVATE)
public class DeviceIdEnrollmentCertificate {

    private final X509Certificate x509Cert;

    private DiceEnrollmentParams issuerParams;
    private DiceParams subjectParams;

    public static DeviceIdEnrollmentCertificate from(X509Certificate cert) {
        return new DeviceIdEnrollmentCertificate(cert);
    }

    public int getSvn() {
        return toUnsignedInt(fromHexSingle(getSvnAsHex()));
    }

    private String getSvnAsHex() {
        return getIssuerParams().getSvn();
    }

    public String getKeyIdentifierBasedOnSvn() {
        return isInitialSvn()
               ? getSubjectKeyIdentifierInBase64Url()
               : getAuthorityKeyIdentifierInBase64Url();
    }

    private boolean isInitialSvn() {
        return 0 == getSvn();
    }

    private String getAuthorityKeyIdentifierInBase64Url() {
        return getIssuerParams().getId();
    }

    private String getSubjectKeyIdentifierInBase64Url() {
        return getSubjectParams().getId();
    }

    private DiceEnrollmentParams getIssuerParams() {
        if (isNull(issuerParams)) {
            issuerParams = DiceEnrollmentParamsIssuerParser.instance().parse(x509Cert);
        }
        return issuerParams;
    }

    private DiceParams getSubjectParams() {
        if (isNull(subjectParams)) {
            subjectParams = DiceParamsSubjectParser.instance().parse(x509Cert);
        }
        return subjectParams;
    }
}
