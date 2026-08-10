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

package com.intel.bkp.bkps.rest.initialization.service;

import com.intel.bkp.bkps.domain.CustomerRootSigningKey;
import com.intel.bkp.bkps.exception.CertificateChainValidationFailed;
import com.intel.bkp.bkps.exception.RootSigningKeyNotExistException;
import com.intel.bkp.bkps.repository.RootSigningKeyRepository;
import com.intel.bkp.bkps.rest.errors.enums.ErrorCodeMap;
import com.intel.bkp.bkps.rest.initialization.model.dto.SigningKeyDTO;
import com.intel.bkp.bkps.rest.initialization.model.dto.SigningKeyResponseDTO;
import com.intel.bkp.bkps.rest.util.PsgCertificateManager;
import com.intel.bkp.core.exceptions.BKPBadRequestException;
import com.intel.bkp.core.exceptions.ParseStructureException;
import com.intel.bkp.core.exceptions.PublicKeyHelperException;
import com.intel.bkp.core.psgcertificate.PsgCertificateForBkpsAdapter;
import com.intel.bkp.core.psgcertificate.PsgCertificateHelper;
import com.intel.bkp.core.psgcertificate.PsgCertificateRootEntryBuilder;
import com.intel.bkp.core.psgcertificate.exceptions.PsgCertificateChainWrongSizeException;
import com.intel.bkp.core.psgcertificate.exceptions.PsgInvalidRootCertificateException;
import com.intel.bkp.core.psgcertificate.model.CertificateEntryWrapper;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.text.StringEscapeUtils;
import org.springframework.stereotype.Service;

import java.security.interfaces.ECPublicKey;
import java.util.List;

import static lombok.AccessLevel.PACKAGE;

@Service
@RequiredArgsConstructor(access = PACKAGE)
@Slf4j
public class SigningKeyService {

    private final SigningKeyRepositoryService signingKeyRepositoryService;
    private final RootSigningKeyRepository rootSigningKeyRepository;

    @Setter
    private PsgCertificateManager certificateManager = new PsgCertificateManager();

    public SigningKeyDTO createSigningKey() {
        return signingKeyRepositoryService.createSigningKey();
    }

    public List<SigningKeyResponseDTO> getAllSigningKeys() {
        return signingKeyRepositoryService.getList();
    }

    public String getSigningKeyPublicPart(Long signingKeyId) {
        return signingKeyRepositoryService.getSigningKeyPublicPartPem(signingKeyId);
    }

    public void activateSigningKey(Long signingKeyId) {
        signingKeyRepositoryService.activate(signingKeyId);
    }

    public void addRootSigningPublicKey(String rootCertificate) {
        log.debug("Add root signing public key for data: {}", StringEscapeUtils.escapeJava(rootCertificate));

        final var parsedCertChain = convertEndiannessInCertificateChain(rootCertificate);
        try {
            final PsgCertificateRootEntryBuilder parsedCertificateBuilder =
                certificateManager.findRootCertificateInChain(parsedCertChain);

            final String certificateFingerprint = PsgCertificateHelper.generateFingerprint(parsedCertificateBuilder);
            if (rootSigningKeyRepository.existsByCertificateHash(certificateFingerprint)) {
                throw new BKPBadRequestException(ErrorCodeMap.ROOT_SIGNING_KEY_ALREADY_EXISTS);
            }

            rootSigningKeyRepository.save(
                new CustomerRootSigningKey(parsedCertificateBuilder.build().array(), certificateFingerprint)
            );
        } catch (PsgInvalidRootCertificateException | PsgCertificateChainWrongSizeException | ParseStructureException
                 | PublicKeyHelperException e) {
            throw new BKPBadRequestException(ErrorCodeMap.FAILED_TO_PARSE_ROOT_PUBLIC_KEY);
        }
    }

    public void uploadSigningKeyChain(Long signingKeyId, String singleRootChain, String multiRootChain) throws PublicKeyHelperException {
        log.info("Upload signing key chain for signing key: {}.", signingKeyId);
        log.debug("Single root chain content: {}.", StringEscapeUtils.escapeJava(singleRootChain));
        log.debug("Multi root chain content: {}.", StringEscapeUtils.escapeJava(multiRootChain));

        final List<CertificateEntryWrapper> chainList = convertEndiannessInCertificateChain(singleRootChain);
        final List<CertificateEntryWrapper> multiChainList = convertEndiannessInCertificateChain(multiRootChain);

        final ECPublicKey signingKeyPublic = signingKeyRepositoryService.getSigningKeyPublicPart(signingKeyId);

        verifyChain(chainList, signingKeyPublic);
        verifyChain(multiChainList, signingKeyPublic);

        signingKeyRepositoryService.addChainToSigningKey(signingKeyId, chainList, multiChainList);
    }

    List<CertificateEntryWrapper> convertEndiannessInCertificateChain(String certChain) {
        final List<CertificateEntryWrapper> parsedChain = PsgCertificateForBkpsAdapter.parse(certChain);
        if (parsedChain.isEmpty()) {
            throw new BKPBadRequestException(ErrorCodeMap.PSG_CERTIFICATE_EXCEPTION, "Certificate chain is empty");
        }
        return parsedChain;
    }

    private void verifyChain(List<CertificateEntryWrapper> chainList, ECPublicKey signingKeyPublic) throws PublicKeyHelperException {
        certificateManager.verifyChainListSize(chainList);
        certificateManager.verifyLeafCertificateMatchesSigningKeyPub(chainList, signingKeyPublic);
        certificateManager.verifyLeafCertificatePermissions(chainList);
        certificateManager.verifyRootCertificate(chainList, getCustomerRootSigningKey(chainList).getCertificate());
        certificateManager.verifyParentsInChainByPubKey(chainList);
    }

    private CustomerRootSigningKey getCustomerRootSigningKey(List<CertificateEntryWrapper> chainList) {
        try {
            final PsgCertificateRootEntryBuilder rootCertificateInChain = certificateManager
                .findRootCertificateInChain(chainList);
            return rootSigningKeyRepository.findOne(rootSigningKeyRepository
                    .findByFingerprint(PsgCertificateHelper.generateFingerprint(rootCertificateInChain)))
                .orElseThrow(RootSigningKeyNotExistException::new);
        } catch (PsgCertificateChainWrongSizeException e) {
            throw new BKPBadRequestException(ErrorCodeMap.CERTIFICATE_CHAIN_WRONG_SIZE);
        } catch (PsgInvalidRootCertificateException e) {
            throw new CertificateChainValidationFailed(e);
        } catch (PublicKeyHelperException e) {
            throw new RuntimeException(e);
        }
    }
}
