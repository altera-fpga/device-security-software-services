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

package com.intel.bkp.bkps.rest.provisioning.chain;

import com.intel.bkp.bkps.exception.CertificateRequestTypeMismatchException;
import com.intel.bkp.bkps.exception.ProvisioningGenericException;
import com.intel.bkp.bkps.programmer.utils.ProgrammerResponseToDataAdapter;
import com.intel.bkp.bkps.rest.errors.enums.ErrorCodeMap;
import com.intel.bkp.bkps.rest.prefetching.model.PrefetchChainDataDTO;
import com.intel.bkp.bkps.rest.prefetching.service.ChainDataProvider;
import com.intel.bkp.command.logger.CommandLogger;
import com.intel.bkp.command.model.CertificateRequestType;
import com.intel.bkp.command.model.CommandIdentifier;
import com.intel.bkp.command.model.CommandLayer;
import com.intel.bkp.command.responses.common.GetCertificateResponse;
import com.intel.bkp.command.responses.common.GetCertificateResponseBuilder;
import com.intel.bkp.crypto.exceptions.X509CertificateParsingException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.security.cert.X509Certificate;
import java.util.LinkedList;

import static com.intel.bkp.command.logger.CommandLoggerValues.GET_ATTESTATION_CERTIFICATE_RESPONSE;
import static com.intel.bkp.command.model.CertificateRequestType.FIRMWARE;
import static com.intel.bkp.command.model.CertificateRequestType.UDS_EFUSE_BKP;
import static com.intel.bkp.command.model.CertificateRequestType.UDS_IID_PUF_BKP;
import static com.intel.bkp.crypto.x509.parsing.X509CertificateParser.toX509Certificate;
import static com.intel.bkp.fpgacerts.chain.DistributionPointCertificate.getX509Certificates;
import static com.intel.bkp.utils.HexConverter.toHex;

@Component
@RequiredArgsConstructor
@Slf4j
public class CertificateChainCreator {

    private final ChainDataProvider chainDataProvider;
    private final CommandLayer commandLayer;

    public CertificateChainDTO createS10Chain(String deviceId) {
        log.info("Preparing S10 certificates chain...");
        final var fetchedChain = chainDataProvider.fetchS10(deviceId);
        final var fullChain = getX509Certificates(fetchedChain.getCertificates());
        return new CertificateChainDTO(fullChain, fetchedChain.getCrls());
    }

    public CertificateChainDTO createDiceChain(ProgrammerResponseToDataAdapter adapter, byte[] deviceIdEnrollmentBytes,
                                               boolean requireIidUds) {
        log.info("Preparing DICE certificates chain...");
        final var deviceIdEnrollmentCert = parseCertificate(deviceIdEnrollmentBytes);
        final var fetchedChain = chainDataProvider.fetchDice(deviceIdEnrollmentCert);
        final var fullEfuseChain = createDiceEfuseChain(adapter, fetchedChain, deviceIdEnrollmentCert);
        final var fullIidChain = createDiceIidChain(adapter, fetchedChain, requireIidUds);
        return new CertificateChainDTO(fullEfuseChain, fullIidChain, fetchedChain.getCrls());
    }

    private X509Certificate parseCertificate(byte[] certBytes) {
        try {
            return toX509Certificate(certBytes);
        } catch (X509CertificateParsingException e) {
            log.error(String.format("Failed to parse certificate bytes: %s", toHex(certBytes)), e);
            throw new ProvisioningGenericException(ErrorCodeMap.FAILED_TO_PARSE_CERTIFICATE_FROM_DEVICE);
        }
    }

    private LinkedList<X509Certificate> createDiceEfuseChain(ProgrammerResponseToDataAdapter adapter,
                                                             PrefetchChainDataDTO fetchedChain,
                                                             X509Certificate deviceIdEnrollmentCert) {
        final ChainWrapper chainWrapper = new ChainWrapper();
        chainWrapper.add(getCertificateFromResponse(adapter, UDS_EFUSE_BKP));
        final X509Certificate firmwareCert = getCertificateFromResponse(adapter, FIRMWARE);
        chainWrapper.add(firmwareCert);

        if (isEnrollmentFlow(firmwareCert, fetchedChain)) {
            log.debug("This is enrollment certificate chain flow, adding deviceIdEnrollment certificate to chain.");
            chainWrapper.add(deviceIdEnrollmentCert);
        }

        final var fetchedEfuseChain = getX509Certificates(fetchedChain.getCertificates());
        chainWrapper.addAll(fetchedEfuseChain);

        return fetchedEfuseChain.isEmpty() ? new LinkedList<>() : chainWrapper.getChain();
    }

    private LinkedList<X509Certificate> createDiceIidChain(ProgrammerResponseToDataAdapter adapter,
                                                           PrefetchChainDataDTO fetchedChain, boolean requireIidUds) {
        final ChainWrapper chainWrapper = new ChainWrapper();
        final var fetchedIidChain = getX509Certificates(fetchedChain.getCertificatesIID());

        if (requireIidUds) {
            log.debug("This is IID certificate chain flow.");
            chainWrapper.add(getCertificateFromResponse(adapter, UDS_IID_PUF_BKP));
            chainWrapper.addAll(fetchedIidChain);
        }

        return fetchedIidChain.isEmpty() ? new LinkedList<>() : chainWrapper.getChain();
    }

    private X509Certificate getCertificateFromResponse(ProgrammerResponseToDataAdapter adapter,
                                                       CertificateRequestType certificateRequestType) {
        final byte[] certBytes = parseGetCertificateResponse(adapter, certificateRequestType);
        return parseCertificate(certBytes);
    }

    private byte[] parseGetCertificateResponse(ProgrammerResponseToDataAdapter adapter,
                                               CertificateRequestType certificateRequestType) {
        final GetCertificateResponse certificateResponse = new GetCertificateResponseBuilder()
            .parse(retrieveGetCertificate(adapter))
            .build();
        CommandLogger.log(certificateResponse, GET_ATTESTATION_CERTIFICATE_RESPONSE, this.getClass());

        verifyMatch(certificateRequestType, certificateResponse.getCertificateTypeValue());

        return certificateResponse.getCertificateBlob();
    }

    private void verifyMatch(CertificateRequestType expected, CertificateRequestType actual) {
        if (expected != actual) {
            throw new CertificateRequestTypeMismatchException(expected, actual);
        }
    }

    private byte[] retrieveGetCertificate(ProgrammerResponseToDataAdapter adapter) {
        return commandLayer.retrieve(adapter.getNext(), CommandIdentifier.GET_ATTESTATION_CERTIFICATE);
    }

    private boolean isEnrollmentFlow(X509Certificate firmwareCert, PrefetchChainDataDTO fetchedChain) {
        return EnrollmentFlowDetector.instance(firmwareCert, fetchedChain).isEnrollmentFlow();
    }
}
