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

import com.intel.bkp.bkps.command.CommandLayerService;
import com.intel.bkp.bkps.crypto.aesgcm.AesGcmContextProviderImpl;
import com.intel.bkp.bkps.domain.ServiceConfiguration;
import com.intel.bkp.bkps.exception.ExceededOvebuildException;
import com.intel.bkp.bkps.exception.ProgrammerResponseNumberException;
import com.intel.bkp.bkps.exception.ProvisioningConverterException;
import com.intel.bkp.bkps.exception.ProvisioningGenericException;
import com.intel.bkp.bkps.programmer.model.ProgrammerMessage;
import com.intel.bkp.bkps.programmer.utils.ProgrammerResponseToDataAdapter;
import com.intel.bkp.bkps.protocol.common.handler.ProvisioningHandler;
import com.intel.bkp.bkps.protocol.common.model.FlowStage;
import com.intel.bkp.bkps.protocol.common.model.RootChainTypeProvider;
import com.intel.bkp.bkps.protocol.common.service.BkpsDHCertBuilder;
import com.intel.bkp.bkps.protocol.common.service.BkpsDhEntryManager;
import com.intel.bkp.bkps.protocol.common.service.GetChipIdMessageSender;
import com.intel.bkp.bkps.protocol.sigma.model.ProvContext1;
import com.intel.bkp.bkps.rest.prefetching.service.ChainDataProvider;
import com.intel.bkp.bkps.rest.provisioning.model.dto.ProvisioningRequestDTOReader;
import com.intel.bkp.bkps.rest.provisioning.model.dto.ProvisioningResponseDTO;
import com.intel.bkp.bkps.rest.provisioning.model.dto.ProvisioningResponseDTOBuilder;
import com.intel.bkp.bkps.rest.provisioning.model.dto.ProvisioningTransferObject;
import com.intel.bkp.bkps.rest.provisioning.service.IServiceConfiguration;
import com.intel.bkp.bkps.rest.provisioning.service.OverbuildCounterManager;
import com.intel.bkp.command.exception.JtagUnknownCommandResponseException;
import com.intel.bkp.command.logger.CommandLogger;
import com.intel.bkp.command.messages.common.GetCertificateMessage;
import com.intel.bkp.command.messages.common.GetCertificateMessageBuilder;
import com.intel.bkp.command.messages.sigma.SigmaM1Message;
import com.intel.bkp.command.messages.sigma.SigmaM1MessageBuilder;
import com.intel.bkp.command.model.CertificateRequestType;
import com.intel.bkp.command.model.CommandIdentifier;
import com.intel.bkp.command.responses.common.GetCertificateResponse;
import com.intel.bkp.command.responses.common.GetCertificateResponseBuilder;
import com.intel.bkp.command.responses.sigma.SigmaTeardownResponse;
import com.intel.bkp.command.responses.sigma.SigmaTeardownResponseBuilder;
import com.intel.bkp.core.manufacturing.model.PufType;
import com.intel.bkp.crypto.ecdh.EcdhKeyPair;
import com.intel.bkp.crypto.exceptions.EcdhKeyPairException;
import com.intel.bkp.crypto.exceptions.EncryptionProviderException;
import com.intel.bkp.crypto.exceptions.X509CertificateParsingException;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.Optional;

import static com.intel.bkp.bkps.programmer.model.MessageType.SEND_PACKET;
import static com.intel.bkp.bkps.programmer.utils.ProgrammerResponsesNumberVerifier.verifyNumberOfResponses;
import static com.intel.bkp.command.logger.CommandLoggerValues.GET_ATTESTATION_CERTIFICATE_RESPONSE;
import static com.intel.bkp.command.logger.CommandLoggerValues.PSGSIGMA_M1;
import static com.intel.bkp.command.logger.CommandLoggerValues.PSGSIGMA_TEARDOWN_RESPONSE;
import static com.intel.bkp.command.model.CertificateRequestType.FIRMWARE;
import static com.intel.bkp.command.model.CertificateRequestType.UDS_EFUSE_BKP;
import static com.intel.bkp.command.model.CertificateRequestType.UDS_IID_PUF_BKP;
import static com.intel.bkp.crypto.x509.parsing.X509CertificateParser.toX509Certificate;
import static com.intel.bkp.utils.HexConverter.toHex;

@Component
@RequiredArgsConstructor(access = AccessLevel.PACKAGE)
@Slf4j
public class ProvInitComponent extends ProvisioningHandler {

    private static final int EXPECTED_NUMBER_OF_RESPONSES = 3;

    private final GetChipIdMessageSender getChipIdMessageSender;
    private final BkpsDHCertBuilder bkpsDHCertBuilder;
    private final BkpsDhEntryManager bkpsDhEntryManager;
    private final AesGcmContextProviderImpl contextEncryptionProvider;
    private final OverbuildCounterManager overbuildCounterManager;
    private final ChainDataProvider chainDataProvider;
    private final CommandLayerService commandLayer;

    @Override
    public ProvisioningResponseDTO handle(ProvisioningTransferObject transferObject) {
        try {
            final ProvisioningRequestDTOReader dtoReader = transferObject.getDtoReader();
            if (FlowStage.SIGMA_CREATE_SESSION.equals(dtoReader.getFlowStage())) {
                return perform(transferObject, dtoReader, transferObject.getConfigurationCallback());
            }
        } catch (ProvisioningGenericException e) {
            throw e;
        } catch (Exception e) {
            throw new ProvisioningGenericException(e);
        }

        return successor.handle(transferObject);
    }

    private ProvisioningResponseDTO perform(ProvisioningTransferObject transferObject,
                                            ProvisioningRequestDTOReader dtoReader,
                                            IServiceConfiguration configurationCallback)
        throws ExceededOvebuildException, ProgrammerResponseNumberException, X509CertificateParsingException {

        final Long cfgId = dtoReader.getCfgId();

        log.info(prepareLogEntry("parsing quartus responses..."));

        verifyNumberOfResponses(dtoReader.getJtagResponses(), EXPECTED_NUMBER_OF_RESPONSES);

        final ProgrammerResponseToDataAdapter adapter =
            new ProgrammerResponseToDataAdapter(dtoReader.getJtagResponses());

        final String deviceIdHex = getChipIdMessageSender.retrieve(adapter.getNext());
        log.info(prepareLogEntry("action will be performed for device: " + deviceIdHex));

        verifyTeardownResponse(adapter);

        log.info(prepareLogEntry("Fetch configuration data for cfg id: " + cfgId));
        final ServiceConfiguration configuration = configurationCallback.getConfiguration(cfgId);

        log.info(prepareLogEntry("Verify overbuild counter"));
        overbuildCounterManager.verifyOverbuildCounter(configuration, deviceIdHex);

        final List<ProgrammerMessage> programmerMessages = new ArrayList<>();
        Optional<String> deviceIdEnrollmentCert = Optional.empty();
        RootChainTypeProvider typeProvider;

        try {
            final GetCertificateResponse certificateResponse = buildGetCertificateResponse(adapter);

            log.debug(prepareLogEntry("This board supports DICE certificate chain."));

            typeProvider = RootChainTypeProvider.agilex();
            chainDataProvider.fetchDice(toX509Certificate(certificateResponse.getCertificateBlob()));
            programmerMessages.addAll(getCertificateCommands(configuration.isRequireIidUds()));
            deviceIdEnrollmentCert = Optional.of(toHex(certificateResponse.getCertificateBlob()));
        } catch (JtagUnknownCommandResponseException e) {
            log.debug(prepareLogEntry("This is S10 board: " + e.getMessage()));
            typeProvider = RootChainTypeProvider.stratix10();
            chainDataProvider.fetchS10(deviceIdHex);
        }

        log.info(prepareLogEntry("Preparing M1 ..."));
        final EcdhKeyPair ecdhKeyPair = generateEcdhKeyPair();

        programmerMessages.add(getSigmaM1Command(configuration, ecdhKeyPair, typeProvider));

        try {
            return new ProvisioningResponseDTOBuilder()
                .context(new ProvContext1(cfgId, deviceIdHex, ecdhKeyPair, deviceIdEnrollmentCert))
                .withMessages(programmerMessages)
                .flowStage(FlowStage.SIGMA_INIT_DATA)
                .protocolType(transferObject.getProtocolType())
                .encryptionProvider(contextEncryptionProvider)
                .build();
        } catch (ProvisioningConverterException | EncryptionProviderException e) {
            throw new ProvisioningGenericException(e);
        }
    }

    private ProgrammerMessage getSigmaM1Command(ServiceConfiguration configuration, EcdhKeyPair ecdhKeyPair,
                                                RootChainTypeProvider typeProvider) {
        final SigmaM1Message sigmaM1Message = buildSigmaM1Msg(ecdhKeyPair, configuration.getPufType(), typeProvider);
        final byte[] sigmaM1MessageBytes = commandLayer.create(sigmaM1Message, CommandIdentifier.SIGMA_M1);
        CommandLogger.log(sigmaM1Message, PSGSIGMA_M1, this.getClass());
        return ProgrammerMessage.from(SEND_PACKET, sigmaM1MessageBytes);
    }

    private GetCertificateResponse buildGetCertificateResponse(ProgrammerResponseToDataAdapter adapter) {
        final GetCertificateResponse certificateResponse = new GetCertificateResponseBuilder()
            .parse(retrieve(adapter, CommandIdentifier.GET_ATTESTATION_CERTIFICATE))
            .build();
        CommandLogger.log(certificateResponse, GET_ATTESTATION_CERTIFICATE_RESPONSE, this.getClass());
        return certificateResponse;
    }

    private void verifyTeardownResponse(ProgrammerResponseToDataAdapter adapter) {
        final SigmaTeardownResponse sigmaTeardownResponse = new SigmaTeardownResponseBuilder()
            .parse(retrieve(adapter, CommandIdentifier.SIGMA_TEARDOWN))
            .build();
        CommandLogger.log(sigmaTeardownResponse, PSGSIGMA_TEARDOWN_RESPONSE, this.getClass());
    }

    private List<ProgrammerMessage> getCertificateCommands(boolean requireIidUds) {
        log.info(prepareLogEntry("Preparing GET_ATTESTATION_CERTIFICATE commands ..."));

        final List<ProgrammerMessage> list = new LinkedList<>();
        list.add(getCertificateCommand(UDS_EFUSE_BKP));
        list.add(getCertificateCommand(FIRMWARE));
        if (requireIidUds) {
            list.add(getCertificateCommand(UDS_IID_PUF_BKP));
        }
        return list;
    }

    private ProgrammerMessage getCertificateCommand(CertificateRequestType type) {
        log.debug(prepareLogEntry("Preparing GET_ATTESTATION_CERTIFICATE with type " + type.name()));
        final GetCertificateMessage message = new GetCertificateMessageBuilder().withType(type).build();
        final byte[] getCertificateBytes = commandLayer.create(message, CommandIdentifier.GET_ATTESTATION_CERTIFICATE);
        return ProgrammerMessage.from(SEND_PACKET, getCertificateBytes);
    }

    private byte[] retrieve(ProgrammerResponseToDataAdapter adapter, CommandIdentifier commandIdentifier) {
        return commandLayer.retrieve(adapter.getNext(), commandIdentifier);
    }

    public EcdhKeyPair generateEcdhKeyPair() {
        try {
            return EcdhKeyPair.generate();
        } catch (EcdhKeyPairException e) {
            throw new ProvisioningGenericException(e);
        }
    }

    private SigmaM1Message buildSigmaM1Msg(EcdhKeyPair ecdhKeyPair, PufType pufType,
                                           RootChainTypeProvider typeProvider) {
        byte[] parentKeyChain = bkpsDHCertBuilder.getChain(typeProvider.getRootChainType());
        return new SigmaM1MessageBuilder()
            .bkpsDhPubKey(ecdhKeyPair.getPublicKey())
            .pufType(pufType)
            .userKeyChain(parentKeyChain, bkpsDhEntryManager::getDhEntry)
            .build();
    }
}
