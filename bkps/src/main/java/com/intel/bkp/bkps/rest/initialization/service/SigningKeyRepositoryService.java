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

import com.intel.bkp.bkps.domain.SigningKeyCertificate;
import com.intel.bkp.bkps.domain.SigningKeyEntity;
import com.intel.bkp.bkps.domain.SigningKeyMultiCertificate;
import com.intel.bkp.bkps.domain.enumeration.SigningKeyStatus;
import com.intel.bkp.bkps.exception.SigningKeyCertificateNotExistException;
import com.intel.bkp.bkps.exception.SigningKeyNotExistException;
import com.intel.bkp.bkps.repository.SigningKeyRepository;
import com.intel.bkp.bkps.rest.errors.enums.ErrorCodeMap;
import com.intel.bkp.bkps.rest.initialization.model.dto.SigningKeyDTO;
import com.intel.bkp.bkps.rest.initialization.model.dto.SigningKeyResponseDTO;
import com.intel.bkp.bkps.rest.initialization.model.mapper.SigningKeyMapper;
import com.intel.bkp.core.exceptions.BKPBadRequestException;
import com.intel.bkp.core.exceptions.BKPInternalServerException;
import com.intel.bkp.core.psgcertificate.model.CertificateEntryWrapper;
import com.intel.bkp.core.psgcertificate.model.PsgCertificateType;
import com.intel.bkp.core.security.ISecurityProvider;
import com.intel.bkp.crypto.CryptoUtils;
import com.intel.bkp.crypto.constants.SecurityKeyType;
import com.intel.bkp.crypto.pem.PemFormatEncoder;
import com.intel.bkp.crypto.pem.PemFormatHeader;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Isolation;
import org.springframework.transaction.annotation.Transactional;

import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.LinkedList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Collectors;

import static lombok.AccessLevel.PACKAGE;

@Service
@AllArgsConstructor(access = PACKAGE)
@Slf4j
@Transactional
public class SigningKeyRepositoryService {

    private final ISecurityProvider securityService;
    private final SigningKeyRepository signingKeyRepository;
    private final SigningKeyMapper signingKeyMapper;

    public SigningKeyDTO createSigningKey() {
        final String securityObjectId = "signing-key-" + UUID.randomUUID();
        final KeyPair keyPair = (KeyPair) securityService.createSecurityObject(SecurityKeyType.EC, securityObjectId);

        final SigningKeyEntity signingKeyEntity = new SigningKeyEntity()
            .name(securityObjectId)
            .status(SigningKeyStatus.DISABLED)
            .fingerprint(CryptoUtils.generateFingerprint(keyPair.getPublic().getEncoded()));
        signingKeyRepository.save(signingKeyEntity);

        return signingKeyMapper.toDto(signingKeyEntity);
    }

    public SigningKeyEntity getActiveSigningKey() {
        final SigningKeyEntity signingKeyEntity = signingKeyRepository.findOne(signingKeyRepository.getEnabled())
            .orElseThrow(SigningKeyNotExistException::new);

        if (!securityService.existsSecurityObject(signingKeyEntity.getName())) {
            throw new SigningKeyNotExistException();
        }

        if (!hasChain(signingKeyEntity)) {
            throw new SigningKeyCertificateNotExistException();
        }

        return signingKeyEntity;
    }

    public String getSigningKeyPublicPartPem(Long signingKeyId) {
        final PublicKey publicKey = getSigningKeyPublicPart(signingKeyId);
        return PemFormatEncoder.encode(PemFormatHeader.PUBLIC_KEY, publicKey.getEncoded());
    }

    public ECPublicKey getSigningKeyPublicPart(Long signingKeyId) {
        final SigningKeyEntity signingKeyEntity = getSigningKey(signingKeyId);
        final byte[] pubKeyBytes = securityService.getPubKeyFromSecurityObject(signingKeyEntity.getName());
        try {
            return (ECPublicKey) CryptoUtils.toPublicEncodedBC(pubKeyBytes, SecurityKeyType.EC.name());
        } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
            throw new BKPInternalServerException(ErrorCodeMap.UNABLE_TO_RETRIEVE_PUBLIC_KEY, e);
        }
    }

    @Transactional(readOnly = true)
    public List<SigningKeyResponseDTO> getList() {
        log.debug("Request to get all signing keys");
        return signingKeyRepository.findAll().stream()
            .map(signingKeyMapper::toResultDto)
            .collect(Collectors.toCollection(LinkedList::new));
    }

    @Transactional(isolation = Isolation.SERIALIZABLE)
    public void activate(Long signingKeyId) {
        final SigningKeyEntity signingKeyEntity = getSigningKey(signingKeyId);

        if (signingKeyEntity.getStatus() == SigningKeyStatus.ENABLED) {
            throw new BKPBadRequestException(ErrorCodeMap.SIGNING_KEY_ALREADY_ACTIVATED);
        } else if (!hasChain(signingKeyEntity)) {
            throw new BKPBadRequestException(ErrorCodeMap.SIGNING_KEY_IS_NOT_CONFIGURED_MISSING_CHAIN);
        }

        signingKeyRepository.findAll(signingKeyRepository.getEnabled())
            .forEach(entity -> {
                entity.setStatus(SigningKeyStatus.DISABLED);
                signingKeyRepository.save(entity);
            });

        signingKeyEntity.status(SigningKeyStatus.ENABLED);
        signingKeyRepository.save(signingKeyEntity);
    }

    @Transactional(isolation = Isolation.SERIALIZABLE)
    public void addChainToSigningKey(Long signingKeyId, List<CertificateEntryWrapper> chainList,
                                     List<CertificateEntryWrapper> multiChainList) {

        final SigningKeyEntity signingKeyEntity = getSigningKey(signingKeyId);

        if (hasChain(signingKeyEntity)) {
            throw new BKPBadRequestException(ErrorCodeMap.SIGNING_KEY_CHAIN_ALREADY_EXISTS);
        }

        chainList.forEach(entryHelper -> signingKeyEntity.getChain()
            .add(new SigningKeyCertificate(entryHelper.getType(), entryHelper.getContent()))
        );

        multiChainList.forEach(entryHelper -> signingKeyEntity.getMultiChain()
            .add(new SigningKeyMultiCertificate(entryHelper.getType(), entryHelper.getContent()))
        );

        signingKeyRepository.save(signingKeyEntity);
    }

    public List<CertificateEntryWrapper> getActiveSigningKeyChain() {
        return getActiveSigningKey()
            .getChain()
            .stream()
            .map(cer -> getCertificateEntryWrapper(cer.getCertificateType(), cer.getCertificate()))
            .collect(Collectors.toList());
    }

    public List<CertificateEntryWrapper> getActiveSigningKeyMultiChain() {
        return getActiveSigningKey()
            .getMultiChain()
            .stream()
            .map(cer -> getCertificateEntryWrapper(cer.getCertificateType(), cer.getCertificate()))
            .collect(Collectors.toList());
    }

    private CertificateEntryWrapper getCertificateEntryWrapper(PsgCertificateType certificateType, byte[] certificate) {
        return new CertificateEntryWrapper(certificateType, certificate);
    }

    SigningKeyEntity getSigningKey(long id) {
        final SigningKeyEntity entity = signingKeyRepository.findById(id).orElseThrow(SigningKeyNotExistException::new);
        if (securityService.existsSecurityObject(entity.getName())) {
            return entity;
        } else {
            throw new SigningKeyNotExistException();
        }
    }

    private boolean hasChain(SigningKeyEntity signingKeyEntity) {
        return hasChain(signingKeyEntity.getChain()) && hasChain(signingKeyEntity.getMultiChain());
    }

    private boolean hasChain(List<?> chain) {
        return Optional.ofNullable(chain)
                .map(list -> !list.isEmpty())
                .orElse(false);
    }
}
