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
import com.intel.bkp.bkps.rest.onboarding.model.DeviceId;
import com.intel.bkp.bkps.rest.prefetching.service.ZipPrefetchRepositoryService;
import com.intel.bkp.bkps.rest.provisioning.utils.ZipUtil;
import com.intel.bkp.core.manufacturing.model.PufType;
import com.intel.bkp.crypto.exceptions.X509CertificateParsingException;
import com.intel.bkp.crypto.x509.parsing.X509CertificateParser;
import com.intel.bkp.crypto.x509.validation.AuthorityKeyIdentifierVerifier;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@Component
@Slf4j
@RequiredArgsConstructor(access = AccessLevel.PRIVATE)
public class CertificateChainProvider {

    private static final String FILE_REQUIRED = "Mandatory file %s is missing from prefeched zip.";

    private final ZipPrefetchRepositoryService zipPrefetchRepositoryService;

    private final AuthorityKeyIdentifierVerifier akiVerifier;

    @Autowired
    public CertificateChainProvider(ZipPrefetchRepositoryService zipPrefetchRepositoryService) {
        this(zipPrefetchRepositoryService, new AuthorityKeyIdentifierVerifier());
    }

    private static byte[] extractFileFromZip(byte[] zip, String pathInZip) {
        return tryExtractFileFromZip(zip, pathInZip)
            .orElseThrow(() -> throwFileRequired(pathInZip));
    }

    private static Optional<byte[]> tryExtractFileFromZip(byte[] zip, String pathInZip) {
        return Optional.ofNullable(ZipUtil.extractFileFromZip(zip, pathInZip)
            .orElseGet(() -> {
                log.debug("File not found in ZIP: {}", pathInZip);
                return null;
            }));
    }

    Optional<List<byte[]>> get(DeviceId deviceId, PufType pufType, String svn,
                                      X509Certificate enrollmentDeviceIdCert, boolean isForceEnrollment) {
        return zipPrefetchRepositoryService.find(deviceId)
                .flatMap(zip -> {
                    return prepareCertificateChain(deviceId, pufType, svn, zip, enrollmentDeviceIdCert,
                        isForceEnrollment);
                });
    }

    boolean isAvailable(DeviceId deviceId) {
        return zipPrefetchRepositoryService.isZipPrefetched(deviceId);
    }

    private Optional<List<byte[]>> prepareCertificateChain(DeviceId deviceId, PufType pufType, String svn, byte[] zip,
                                                           X509Certificate enrollmentDeviceIdCert,
                                                           boolean isForceEnrollment) {
        final List<String> zipContentFiles = ZipUtil.listZipContentFilenames(zip);
        log.debug("ZIP content listing: {}", zipContentFiles);

        final List<byte[]> certificateChain = new ArrayList<>();

        final var pathsHolder = new CertificatesFromZipPathsHolder(pufType, svn, deviceId.getFamily());

        certificateChain.add(extractFileFromZip(zip, pathsHolder.getDiceRootCaCer()));
        certificateChain.add(extractFileFromZip(zip, pathsHolder.getIpcsFamilyCer()));

        final Optional<byte[]> deviceIdCert = tryExtractFileFromZip(zip, pathsHolder.getDeviceIdCer());

        final Optional<byte[]> ipcsEnrollmentCert = tryExtractFileFromZip(zip,
            pathsHolder.getEnrollmentDeviceIdCer());

        final var flow = SetAuthorityFlow.getSetAuthorityFlowStrategy(pufType, deviceIdCert,
            enrollmentDeviceIdCert, ipcsEnrollmentCert, svn, isForceEnrollment, akiVerifier, pathsHolder);

        log.debug("Perform {} flow.", flow.name());

        try {
            switch (flow) {
                case IID -> certificateChain.add(extractFileFromZip(zip, pathsHolder.getEfuseIidudsCer()));
                case ENROLLMENT -> {
                    final var cert = ipcsEnrollmentCert.orElseThrow(
                        () -> throwFileRequired(pathsHolder.getEnrollmentDeviceIdCer()));
                    certificateChain.add(cert);
                    certificateChain.add(enrollmentDeviceIdCert.getEncoded());
                }
                case DEVICE_ID -> {
                    final var cert = deviceIdCert.orElseThrow(
                        () -> throwFileRequired(pathsHolder.getDeviceIdCer()));
                    certificateChain.add(cert);
                }
            }
        } catch (CertificateEncodingException e) {
            throw new SetAuthorityGenericException("Could not encode certificate to byte array.", e);
        }

        return Optional.of(certificateChain);
    }

    private X509Certificate parseCertificate(String name, byte[] certContent) {
        try {
            return X509CertificateParser.toX509Certificate(certContent);
        } catch (X509CertificateParsingException e) {
            throw new SetAuthorityGenericException("Failed to parse X509 certificate from ZIP: %s".formatted(name));
        }
    }

    private static SetAuthorityGenericException throwFileRequired(String path) {
        return new SetAuthorityGenericException(FILE_REQUIRED.formatted(path));
    }
}
