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

package com.intel.bkp.bkps.rest.onboarding.handler;

import com.intel.bkp.bkps.exception.SetAuthorityGenericException;
import com.intel.bkp.core.manufacturing.model.PufType;
import com.intel.bkp.crypto.exceptions.X509CertificateParsingException;
import com.intel.bkp.crypto.x509.parsing.X509CertificateParser;
import com.intel.bkp.crypto.x509.utils.KeyIdentifierUtils;
import com.intel.bkp.crypto.x509.validation.AuthorityKeyIdentifierVerifier;
import lombok.extern.slf4j.Slf4j;

import java.security.cert.X509Certificate;
import java.util.Optional;

import static com.intel.bkp.crypto.x509.utils.KeyIdentifierUtils.getSubjectKeyIdentifier;
import static com.intel.bkp.utils.HexConverter.toHex;

@Slf4j
public enum SetAuthorityFlow {
    IID,
    DEVICE_ID,
    ENROLLMENT;

    private static final String SVN_0 = "00";

    public static SetAuthorityFlow getSetAuthorityFlowStrategy(PufType pufType, Optional<byte[]> deviceIdCert,
                                                               X509Certificate enrollmentDeviceIdCert,
                                                               Optional<byte[]> ipcsEnrollmentCert, String svn,
                                                               boolean isForceEnrollment,
                                                               AuthorityKeyIdentifierVerifier akiVerifier,
                                                               CertificatesFromZipPathsHolder pathHolder) {

        return switch (pufType) {
            case IID -> IID;
            case INTEL, EFUSE -> getFlowStrategyInternal(deviceIdCert, enrollmentDeviceIdCert, ipcsEnrollmentCert, svn,
                isForceEnrollment, akiVerifier, pathHolder);
            default -> throw new SetAuthorityGenericException("Not supported Puf Type: %s".formatted(pufType));
        };
    }

    private static SetAuthorityFlow getFlowStrategyInternal(Optional<byte[]> deviceIdCert,
                                                            X509Certificate enrollmentDeviceIdCert,
                                                            Optional<byte[]> ipcsEnrollmentCert, String svn,
                                                            boolean isForceEnrollment,
                                                            AuthorityKeyIdentifierVerifier akiVerifier,
                                                            CertificatesFromZipPathsHolder pathHolder) {

        if (!SVN_0.equals(svn) || isForceEnrollment) {
            log.debug("Verify enrollment flow. Check if certificate from device AKI matches parent SKI.");
            checkIfCertificateFromDeviceAKIMatchIpcsEnrollmentCertSKI(akiVerifier, enrollmentDeviceIdCert,
                ipcsEnrollmentCert, pathHolder);
            return ENROLLMENT;
        } else {
            log.debug("Verify device id flow. Check if certificate from device SKI equals device id certificate SKI.");
            checkIfCertificateFromDeviceSKIMatchDeviceIdCertSKI(deviceIdCert, enrollmentDeviceIdCert, pathHolder);
            return DEVICE_ID;
        }
    }

    private static void checkIfCertificateFromDeviceAKIMatchIpcsEnrollmentCertSKI(
        AuthorityKeyIdentifierVerifier akiVerifier, X509Certificate enrollmentDeviceIdCert,
        Optional<byte[]> ipcsEnrollmentCert, CertificatesFromZipPathsHolder pathHolder) {

        final var isVerified = ipcsEnrollmentCert.map(ipcsCert -> akiVerifier.verify(enrollmentDeviceIdCert,
            parseCertificate(pathHolder.getEnrollmentDeviceIdCer(), ipcsCert)))
            .orElseThrow(() -> new SetAuthorityGenericException("IPCS Enrollment SVN cert is absent."));

        if (!isVerified) {
            throw new SetAuthorityGenericException("Device enrollment id certificate AKI doesn't match IPCS "
                + "enrollment certificate SKI.");
        }
    }

    private static void checkIfCertificateFromDeviceSKIMatchDeviceIdCertSKI(
        Optional<byte[]> deviceIdCert, X509Certificate enrollmentDeviceIdCert,
        CertificatesFromZipPathsHolder pathHolder) {

        final byte[] deviceIdSki = deviceIdCert
            .map(cert -> KeyIdentifierUtils.getSubjectKeyIdentifier(parseCertificate(pathHolder.getDeviceIdCer(),
                cert)))
            .orElseThrow(() -> new SetAuthorityGenericException("Device ID cert is invalid - missing SKI."));

        final byte[] enrollmentDeviceIdSki =
            Optional.ofNullable(getSubjectKeyIdentifier(enrollmentDeviceIdCert))
                .orElseThrow(() -> new SetAuthorityGenericException(
                    "Enrollment Device ID cert is invalid - missing SKI."));

        final String deviceIdSkiHex = toHex(deviceIdSki);
        final String enrollmentDeviceIdSkiHex = toHex(enrollmentDeviceIdSki);
        log.debug("Comparing deviceId SKI ({}) with enrollmentDeviceId SKI ({}).",
            deviceIdSkiHex, enrollmentDeviceIdSkiHex);

        if (!deviceIdSkiHex.equals(enrollmentDeviceIdSkiHex)) {
            throw new SetAuthorityGenericException("SKI of certificate from device does not equal device id "
                + "certificate SKI.");
        }
    }

    private static X509Certificate parseCertificate(String name, byte[] certContent) {
        try {
            return X509CertificateParser.toX509Certificate(certContent);
        } catch (X509CertificateParsingException e) {
            throw new SetAuthorityGenericException("Failed to parse X509 certificate from ZIP: %s".formatted(name));
        }
    }
}
