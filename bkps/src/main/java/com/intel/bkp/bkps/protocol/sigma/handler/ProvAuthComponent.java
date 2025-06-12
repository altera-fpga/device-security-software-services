/*
 * This project is licensed as below.
 *
 * **************************************************************************
 *
 * Copyright 2020-2025 Altera Corporation. All Rights Reserved.
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

package com.intel.bkp.bkps.protocol.sigma.handler;

import com.intel.bkp.bkps.crypto.aesgcm.AesGcmContextProviderImpl;
import com.intel.bkp.bkps.domain.ServiceConfiguration;
import com.intel.bkp.bkps.exception.ProgrammerResponseNumberException;
import com.intel.bkp.bkps.exception.ProvisioningConverterException;
import com.intel.bkp.bkps.exception.ProvisioningGenericException;
import com.intel.bkp.bkps.programmer.model.ProgrammerMessage;
import com.intel.bkp.bkps.programmer.utils.ProgrammerResponseToDataAdapter;
import com.intel.bkp.bkps.protocol.common.handler.ProvisioningHandler;
import com.intel.bkp.bkps.protocol.common.model.FlowStage;
import com.intel.bkp.bkps.protocol.common.service.SigningKeyManager;
import com.intel.bkp.bkps.protocol.sigma.model.ProvContext1;
import com.intel.bkp.bkps.protocol.sigma.model.ProvContextEnc;
import com.intel.bkp.bkps.protocol.sigma.verification.SigmaM2BkpsPubKeyVerifier;
import com.intel.bkp.bkps.protocol.sigma.verification.SigmaM2DeviceIdVerifier;
import com.intel.bkp.bkps.protocol.sigma.verification.SigmaM2IntegrityVerifier;
import com.intel.bkp.bkps.protocol.sigma.verification.SigmaM2SignatureVerifier;
import com.intel.bkp.bkps.protocol.sigma.verification.SigmaM2WithServiceCfgVerifier;
import com.intel.bkp.bkps.rest.provisioning.chain.CertificateChainCreator;
import com.intel.bkp.bkps.rest.provisioning.chain.CertificateChainVerifier;
import com.intel.bkp.bkps.rest.provisioning.model.dto.ProvisioningRequestDTOReader;
import com.intel.bkp.bkps.rest.provisioning.model.dto.ProvisioningResponseDTO;
import com.intel.bkp.bkps.rest.provisioning.model.dto.ProvisioningResponseDTOBuilder;
import com.intel.bkp.bkps.rest.provisioning.model.dto.ProvisioningTransferObject;
import com.intel.bkp.bkps.rest.provisioning.service.IServiceConfiguration;
import com.intel.bkp.command.logger.CommandLogger;
import com.intel.bkp.command.messages.sigma.SigmaM3Message;
import com.intel.bkp.command.messages.sigma.SigmaM3MessageBuilder;
import com.intel.bkp.command.model.CommandIdentifier;
import com.intel.bkp.command.model.CommandLayer;
import com.intel.bkp.command.responses.sigma.SigmaM2Message;
import com.intel.bkp.command.responses.sigma.SigmaM2MessageBuilder;
import com.intel.bkp.core.endianness.EndiannessActor;
import com.intel.bkp.core.exceptions.ParseStructureException;
import com.intel.bkp.crypto.ecdh.EcdhKeyPair;
import com.intel.bkp.crypto.exceptions.EcdhKeyPairException;
import com.intel.bkp.crypto.exceptions.EncryptionProviderException;
import com.intel.bkp.crypto.exceptions.HMacProviderException;
import com.intel.bkp.crypto.exceptions.KeystoreGenericException;
import com.intel.bkp.crypto.sigma.HMacSigmaProviderImpl;
import com.intel.bkp.crypto.sigma.SigmaProvider;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.stereotype.Component;

import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Collections;

import static com.intel.bkp.bkps.programmer.model.MessageType.SEND_PACKET;
import static com.intel.bkp.bkps.programmer.utils.ProgrammerResponsesNumberVerifier.verifyNumberOfResponses;
import static com.intel.bkp.command.logger.CommandLoggerValues.PSGSIGMA_M2;
import static com.intel.bkp.command.logger.CommandLoggerValues.PSGSIGMA_M3_MESSAGE;
import static com.intel.bkp.utils.HexConverter.fromHex;

@Component
@RequiredArgsConstructor(access = AccessLevel.PACKAGE)
@Slf4j
public class ProvAuthComponent extends ProvisioningHandler {

    private static final int EXPECTED_NUMBER_OF_RESPONSES_S10 = 1;
    private static final int EXPECTED_NUMBER_OF_RESPONSES_FM_MIN = 3;
    private static final int EXPECTED_NUMBER_OF_RESPONSES_FM_MAX = 4;

    private final AesGcmContextProviderImpl contextEncryptionProvider;
    private final SigningKeyManager signingKeyManager;
    private final CommandLayer commandLayer;
    private final CertificateChainCreator chainCreator;
    private final CertificateChainVerifier chainVerifier;

    @Override
    public ProvisioningResponseDTO handle(ProvisioningTransferObject transferObject) {
        final ProvisioningRequestDTOReader dtoReader = transferObject.getDtoReader();
        if (FlowStage.SIGMA_INIT_DATA.equals(dtoReader.getFlowStage())) {
            try {
                return perform(transferObject, dtoReader, transferObject.getConfigurationCallback());
            } catch (ProgrammerResponseNumberException e) {
                throw new ProvisioningGenericException(e.getMessage());
            }
        }
        return successor.handle(transferObject);
    }

    private ProvisioningResponseDTO perform(ProvisioningTransferObject transferObject,
                                            ProvisioningRequestDTOReader dtoReader, IServiceConfiguration callback)
        throws ProgrammerResponseNumberException {

        final ProvContext1 provContext = recoverProvisioningContext(dtoReader);

        log.info(prepareLogEntry("Starting Provisioning..."));
        log.info(prepareLogEntry("Authorization for device id: %s and configuration id: %d"
            .formatted(provContext.getChipId(), provContext.getCfgId())));

        final ServiceConfiguration configuration = callback.getConfiguration(provContext.getCfgId());
        final ProgrammerResponseToDataAdapter adapter =
            new ProgrammerResponseToDataAdapter(dtoReader.getJtagResponses());
        final PublicKey m2VerificationPubKey =
            getM2VerificationCertPubKey(dtoReader, provContext, adapter, configuration);
        final SigmaM2Message sigmaM2Message = buildSigmaM2Message(adapter);
        final SigmaProvider sigmaProvider = getSigmaProvider(provContext, sigmaM2Message);
        verifyM2Integrity(configuration, provContext, m2VerificationPubKey, sigmaM2Message, sigmaProvider);
        final byte[] sigmaM3Bytes = buildSigmaM3Command(provContext, sigmaM2Message, sigmaProvider);
        final ProvContextEnc context = buildContext(provContext, sigmaM2Message, sigmaProvider);
        return buildResponse(transferObject, sigmaM3Bytes, context);
    }

    private SigmaProvider getSigmaProvider(ProvContext1 provContext, SigmaM2Message sigmaM2Message) {
        final SigmaProvider sigmaProvider;
        try {
            sigmaProvider = new SigmaProvider(provContext.getEcdhKeyPair(),
                EcdhKeyPair.fromPublicBytes(sigmaM2Message.getDeviceDhPubKey()));
            sigmaProvider.establishSigmaProtocol();
        } catch (EcdhKeyPairException | HMacProviderException | KeystoreGenericException e) {
            throw new ProvisioningGenericException(e);
        }
        return sigmaProvider;
    }

    private ProvContextEnc buildContext(ProvContext1 provContext, SigmaM2Message sigmaM2Message,
                                        SigmaProvider sigmaProvider) {
        return ProvContextEnc.builder()
            .cfgId(provContext.getCfgId())
            .chipId(provContext.getChipIdFromHex())
            .sessionEncryptionKey(sigmaProvider.getSek())
            .sessionMacKey(sigmaProvider.getSmk())
            .sdmSessionId(sigmaM2Message.getSdmSessionId())
            .build();
    }

    private ProvisioningResponseDTO buildResponse(ProvisioningTransferObject transferObject,
                                                  byte[] sigmaM3Bytes, ProvContextEnc context) {
        try {
            return new ProvisioningResponseDTOBuilder()
                .context(context)
                .withMessages(Collections.singletonList(ProgrammerMessage.from(SEND_PACKET, sigmaM3Bytes)))
                .flowStage(FlowStage.SIGMA_AUTH_DATA)
                .protocolType(transferObject.getProtocolType())
                .encryptionProvider(contextEncryptionProvider)
                .build();
        } catch (ProvisioningConverterException | EncryptionProviderException e) {
            throw new ProvisioningGenericException(e);
        }
    }

    private void verifyM2Integrity(final ServiceConfiguration configuration, ProvContext1 provContext,
                                   PublicKey m2VerificationPubKey, SigmaM2Message sigmaM2Message,
                                   SigmaProvider sigmaProvider) {
        try {
            log.info(prepareLogEntry("Performing M2 Integrity verification..."));
            new SigmaM2IntegrityVerifier(sigmaProvider.getPmk(), sigmaM2Message).verify();

            log.info(prepareLogEntry("Performing M2 deviceId verification..."));
            new SigmaM2DeviceIdVerifier(provContext.getChipId(), sigmaM2Message).verify();

            verifyM2Signature(m2VerificationPubKey, sigmaM2Message);

            log.info(prepareLogEntry("Performing M2 BKPS Pub key verification."));
            new SigmaM2BkpsPubKeyVerifier(provContext.getEcdhKeyPair(), sigmaM2Message).verify();

            log.info(prepareLogEntry("Performing M2 with Service configuration verification."));
            new SigmaM2WithServiceCfgVerifier(configuration, sigmaM2Message).verify();
        } catch (HMacProviderException e) {
            throw new ProvisioningGenericException(e);
        }
    }

    // This is extracted to perform integration tests where we cannot create a fake certificate chain
    public void verifyM2Signature(PublicKey m2VerificationPubKey,
                                  SigmaM2Message sigmaM2Message) {
        log.info(prepareLogEntry("Performing M2 signature verification..."));
        new SigmaM2SignatureVerifier(m2VerificationPubKey, sigmaM2Message).verify();
    }

    private SigmaM2Message buildSigmaM2Message(ProgrammerResponseToDataAdapter adapter) {
        final SigmaM2MessageBuilder sigmaM2MessageBuilder = new SigmaM2MessageBuilder();
        final SigmaM2Message sigmaM2Message;
        try {
            sigmaM2Message = sigmaM2MessageBuilder
                .withActor(EndiannessActor.FIRMWARE)
                .parse(retrieveSigmaM1(adapter))
                .withActor(EndiannessActor.SERVICE)
                .build();
        } catch (ParseStructureException e) {
            throw new ProvisioningGenericException(e);
        }

        CommandLogger.log(sigmaM2MessageBuilder.withActor(EndiannessActor.FIRMWARE).build(), PSGSIGMA_M2,
            this.getClass());
        return sigmaM2Message;
    }

    private PublicKey getM2VerificationCertPubKey(ProvisioningRequestDTOReader dtoReader, ProvContext1 context,
                                                  ProgrammerResponseToDataAdapter adapter,
                                                  ServiceConfiguration configuration)
        throws ProgrammerResponseNumberException {

        final X509Certificate m2VerificationCert;
        if (StringUtils.isNotBlank(context.getDeviceIdEnrollmentCert())) {
            log.debug(prepareLogEntry("This board supports DICE certificate chain."));
            verifyNumberOfResponses(dtoReader.getJtagResponses(),
                EXPECTED_NUMBER_OF_RESPONSES_FM_MIN, EXPECTED_NUMBER_OF_RESPONSES_FM_MAX);
            m2VerificationCert =
                buildAndValidateDiceChain(context.getChipId(), adapter, fromHex(context.getDeviceIdEnrollmentCert()),
                    configuration.isRequireIidUds(), configuration.isTestModeSecrets());

        } else {
            log.debug(prepareLogEntry("This is S10 board."));
            verifyNumberOfResponses(dtoReader.getJtagResponses(), EXPECTED_NUMBER_OF_RESPONSES_S10);
            m2VerificationCert = buildAndValidateS10Chain(context.getChipId());
        }
        return m2VerificationCert.getPublicKey();
    }

    private byte[] buildSigmaM3Command(ProvContext1 provContext, SigmaM2Message sigmaM2Message,
                                       SigmaProvider sigmaProvider) {
        log.info(prepareLogEntry("Preparing M3 ..."));
        final SigmaM3Message sigmaM3Message;
        try {
            sigmaM3Message = new SigmaM3MessageBuilder()
                .sdmSessionId(sigmaM2Message.getSdmSessionId())
                .bkpsDhPubKey(provContext.getEcdhKeyPair().getPublicKey())
                .deviceDhPubKey(sigmaProvider.getDeviceDhKeyPair().getPublicKey())
                .signature(signingKeyManager::getSignature)
                .mac(new HMacSigmaProviderImpl(sigmaProvider.getPmk()))
                .build();
        } catch (HMacProviderException | IllegalArgumentException e) {
            throw new ProvisioningGenericException(e);
        }

        final byte[] sigmaM3Bytes = commandLayer.create(sigmaM3Message, CommandIdentifier.SIGMA_M3);
        CommandLogger.log(sigmaM3Message, PSGSIGMA_M3_MESSAGE, this.getClass());
        return sigmaM3Bytes;
    }

    private X509Certificate buildAndValidateDiceChain(String deviceId, ProgrammerResponseToDataAdapter adapter,
                                                      byte[] deviceIdEnrollmentCert, boolean requireIidUds,
                                                      boolean testModeSecrets) {
        final var chain = chainCreator.createDiceChain(adapter, deviceIdEnrollmentCert, requireIidUds);
        chainVerifier.verifyDiceChain(deviceId, chain, requireIidUds, testModeSecrets);
        return chain.getCertificates().getFirst();
    }

    private X509Certificate buildAndValidateS10Chain(String deviceId) {
        final var chain = chainCreator.createS10Chain(deviceId);
        chainVerifier.verifyS10Chain(deviceId, chain);
        return chain.getCertificates().getFirst();
    }

    private byte[] retrieveSigmaM1(ProgrammerResponseToDataAdapter adapter) {
        return commandLayer.retrieve(adapter.getNext(), CommandIdentifier.SIGMA_M1);
    }

    private ProvContext1 recoverProvisioningContext(ProvisioningRequestDTOReader requestDTOReader) {
        try {
            return (ProvContext1) requestDTOReader.read(ProvContext1.class);
        } catch (ProvisioningConverterException e) {
            throw new ProvisioningGenericException(e);
        }
    }

}
