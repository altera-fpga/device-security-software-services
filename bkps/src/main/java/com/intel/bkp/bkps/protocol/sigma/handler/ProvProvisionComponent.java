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

import com.intel.bkp.bkps.crypto.aesctr.AesCtrSigmaEncProviderImpl;
import com.intel.bkp.bkps.crypto.aesgcm.AesGcmContextProviderImpl;
import com.intel.bkp.bkps.exception.ProgrammerResponseNumberException;
import com.intel.bkp.bkps.exception.ProvisioningConverterException;
import com.intel.bkp.bkps.exception.ProvisioningGenericException;
import com.intel.bkp.bkps.programmer.model.ProgrammerMessage;
import com.intel.bkp.bkps.programmer.model.ProgrammerResponse;
import com.intel.bkp.bkps.programmer.utils.ProgrammerResponseToDataAdapter;
import com.intel.bkp.bkps.protocol.common.DecryptedPayload;
import com.intel.bkp.bkps.protocol.common.handler.ProvisioningHandler;
import com.intel.bkp.bkps.protocol.common.model.FlowStage;
import com.intel.bkp.bkps.protocol.sigma.model.ProvContextEnc;
import com.intel.bkp.bkps.protocol.sigma.session.IMessageResponseCounterProvider;
import com.intel.bkp.bkps.protocol.sigma.session.SecureSessionIvProvider;
import com.intel.bkp.bkps.protocol.sigma.wrapping.KeyWrappingManager;
import com.intel.bkp.bkps.rest.provisioning.model.dto.ProvisioningRequestDTO;
import com.intel.bkp.bkps.rest.provisioning.model.dto.ProvisioningRequestDTOReader;
import com.intel.bkp.bkps.rest.provisioning.model.dto.ProvisioningResponseDTO;
import com.intel.bkp.bkps.rest.provisioning.model.dto.ProvisioningResponseDTOBuilder;
import com.intel.bkp.bkps.rest.provisioning.model.dto.ProvisioningTransferObject;
import com.intel.bkp.bkps.rest.provisioning.service.IServiceConfiguration;
import com.intel.bkp.command.logger.CommandLogger;
import com.intel.bkp.command.messages.sigma.SigmaTeardownMessage;
import com.intel.bkp.command.messages.sigma.SigmaTeardownMessageBuilder;
import com.intel.bkp.command.model.CommandIdentifier;
import com.intel.bkp.command.model.CommandLayer;
import com.intel.bkp.command.responses.common.CertificateResponse;
import com.intel.bkp.command.responses.common.CertificateResponseBuilder;
import com.intel.bkp.command.responses.sigma.SigmaEncResponse;
import com.intel.bkp.command.responses.sigma.SigmaEncResponseBuilder;
import com.intel.bkp.core.endianness.EndiannessActor;
import com.intel.bkp.crypto.exceptions.EncryptionProviderException;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static com.intel.bkp.bkps.programmer.model.MessageType.SEND_PACKET;
import static com.intel.bkp.bkps.programmer.utils.ProgrammerResponsesNumberVerifier.verifyNumberOfResponses;
import static com.intel.bkp.command.logger.CommandLoggerValues.CERTIFICATE_RESPONSE;
import static com.intel.bkp.command.logger.CommandLoggerValues.PSGSIGMA_ENC_RESPONSE;
import static com.intel.bkp.command.logger.CommandLoggerValues.PSGSIGMA_TEARDOWN_MESSAGE;
import static com.intel.bkp.command.logger.CommandLoggerValues.WRAPPED_AES_KEY_DATA;
import static com.intel.bkp.utils.HexConverter.toHex;

@Component
@RequiredArgsConstructor(access = AccessLevel.PACKAGE)
@Slf4j
public class ProvProvisionComponent extends ProvisioningHandler {

    private static final int EXPECTED_NUMBER_OF_RESPONSES = 1;

    private final AesGcmContextProviderImpl contextEncryptionProvider;
    private final CommandLayer commandLayer;

    @Override
    public ProvisioningResponseDTO handle(ProvisioningTransferObject transferObject) {
        final ProvisioningRequestDTOReader dtoReader = transferObject.getDtoReader();
        if (FlowStage.SIGMA_ENC_ASSET.equals(dtoReader.getFlowStage())) {
            return perform(transferObject, dtoReader, transferObject.getConfigurationCallback());
        }

        return successor.handle(transferObject);
    }

    private ProvisioningResponseDTO perform(ProvisioningTransferObject transferObject,
                                            ProvisioningRequestDTOReader dtoReader,
                                            IServiceConfiguration callback) {
        final ProvContextEnc provContext = recoverProvisioningContext(dtoReader);
        log.info(prepareLogEntry(" provision for device id: " + toHex(provContext.getChipId())));

        verifyResponses(dtoReader.getJtagResponses());
        final ProgrammerResponseToDataAdapter adapter =
            new ProgrammerResponseToDataAdapter(dtoReader.getJtagResponses());
        final SigmaEncResponse sigmaEncResponse = buildSigmaEncResponse(adapter);

        final List<ProgrammerMessage> programmerMessages = new ArrayList<>();
        programmerMessages.add(getSigmaTeardownCommand(sigmaEncResponse.getSdmSessionId()));
        buildCertificateResponse(callback, provContext, sigmaEncResponse, dtoReader.getDto())
            .ifPresent(programmerMessages::add);

        try {
            return new ProvisioningResponseDTOBuilder()
                .withMessages(programmerMessages)
                .flowStage(FlowStage.PROV_RESULT)
                .protocolType(transferObject.getProtocolType())
                .encryptionProvider(contextEncryptionProvider)
                .build();
        } catch (ProvisioningConverterException | EncryptionProviderException e) {
            throw new ProvisioningGenericException(e);
        }
    }

    private Optional<ProgrammerMessage> buildCertificateResponse(IServiceConfiguration callback,
                                                                 ProvContextEnc provContext,
                                                                 SigmaEncResponse sigmaEncResponse,
                                                                 ProvisioningRequestDTO dto) {
        if (!sigmaEncResponse.hasEncryptedResponse()) {
            return Optional.empty();
        }

        final byte[] decryptedPayloadValue = getSigmaEncResponseDecryptedPayload(provContext, sigmaEncResponse)
            .getValue();

        final CertificateResponse certificateResponse = buildCertificateResponse(decryptedPayloadValue);
        verifyProcessCompleted(certificateResponse);

        final KeyWrappingManager keyWrappingManager = new KeyWrappingManager(callback, provContext.getCfgId());
        if (keyWrappingManager.isKeyWrapping()) {
            final byte[] wrappedAesKeyData = certificateResponse.getResponseData();
            CommandLogger.log(wrappedAesKeyData, WRAPPED_AES_KEY_DATA, this.getClass());

            return Optional.of(
                ProgrammerMessage.from(keyWrappingManager.getMessageType(dto.getSupportedCommands()), wrappedAesKeyData)
            );
        }

        return Optional.empty();
    }

    private CertificateResponse buildCertificateResponse(byte[] decryptedPayloadValue) {
        final CertificateResponseBuilder certificateResponseBuilder = new CertificateResponseBuilder();
        final CertificateResponse certificateResponse = certificateResponseBuilder
            .withActor(EndiannessActor.FIRMWARE)
            .parse(commandLayer.retrieve(decryptedPayloadValue, CommandIdentifier.CERTIFICATE))
            .withActor(EndiannessActor.SERVICE)
            .build();

        CommandLogger.log(certificateResponseBuilder.withActor(EndiannessActor.FIRMWARE).build(),
            CERTIFICATE_RESPONSE, this.getClass());
        return certificateResponse;
    }

    private SigmaEncResponse buildSigmaEncResponse(ProgrammerResponseToDataAdapter adapter) {
        final SigmaEncResponseBuilder sigmaEncResponseBuilder = new SigmaEncResponseBuilder();
        final SigmaEncResponse sigmaEncResponse = sigmaEncResponseBuilder
            .withActor(EndiannessActor.FIRMWARE)
            .parse(commandLayer.retrieve(adapter.getNext(), CommandIdentifier.SIGMA_ENC))
            .withActor(EndiannessActor.SERVICE)
            .build();

        CommandLogger.log(sigmaEncResponseBuilder.withActor(EndiannessActor.FIRMWARE).build(),
            PSGSIGMA_ENC_RESPONSE, this.getClass());
        return sigmaEncResponse;
    }

    private void verifyResponses(List<ProgrammerResponse> responses) {
        try {
            verifyNumberOfResponses(responses, EXPECTED_NUMBER_OF_RESPONSES);
        } catch (ProgrammerResponseNumberException e) {
            throw new ProvisioningGenericException(e.getMessage());
        }
    }

    private void verifyProcessCompleted(CertificateResponse certificateResponse) {
        if (certificateResponse.processCompleted()) {
            log.info(prepareLogEntry("Certificate provisioning process completed."));
        } else {
            throw new ProvisioningGenericException(
                String.format("Certificate provisioning process error: %s",
                    toHex(certificateResponse.getCertificateProcessStatus())));
        }
    }

    private DecryptedPayload getSigmaEncResponseDecryptedPayload(ProvContextEnc provContext,
                                                                 SigmaEncResponse sigmaEncResponse) {
        log.info(prepareLogEntry("Decrypting Sigma ENC payload..."));
        final byte[] sek = provContext.getSessionEncryptionKey();

        final SigmaEncResponseBuilder builder = new SigmaEncResponseBuilder()
            .withActor(EndiannessActor.SERVICE)
            .parse(sigmaEncResponse.array());

        byte[] decryptedPayload = getSigmaEncCommandsResponse(builder)
            .decrypt(new AesCtrSigmaEncProviderImpl(sek, getIvProvider(sigmaEncResponse)));

        return DecryptedPayload.from(decryptedPayload, sigmaEncResponse.getNumberOfPaddingBytes());
    }

    private ProgrammerMessage getSigmaTeardownCommand(byte[] sdmSessionId) {
        log.info(prepareLogEntry("Preparing SIGMA_TEARDOWN ..."));
        final SigmaTeardownMessage sigmaTeardown = new SigmaTeardownMessageBuilder()
            .sdmSessionId(sdmSessionId)
            .build();
        final byte[] sigmaTeardownBytes = commandLayer.create(sigmaTeardown, CommandIdentifier.SIGMA_TEARDOWN);
        CommandLogger.log(sigmaTeardown, PSGSIGMA_TEARDOWN_MESSAGE, this.getClass());
        return ProgrammerMessage.from(SEND_PACKET, sigmaTeardownBytes);
    }

    private ProvContextEnc recoverProvisioningContext(ProvisioningRequestDTOReader requestDTOReader) {
        try {
            return (ProvContextEnc) requestDTOReader.read(ProvContextEnc.class);
        } catch (ProvisioningConverterException e) {
            throw new ProvisioningGenericException(e);
        }
    }

    private SigmaEncCommandsResponse getSigmaEncCommandsResponse(SigmaEncResponseBuilder builder) {
        return new SigmaEncCommandsResponse(builder.getDataToDecrypt());
    }

    private static SecureSessionIvProvider getIvProvider(SigmaEncResponse sigmaEncResponse) {
        return new SecureSessionIvProvider(new IMessageResponseCounterProvider() {
            @Override
            public byte[] getInitialIv() {
                return sigmaEncResponse.getInitialIv();
            }

            @Override
            public byte[] getMessageResponseCounter() {
                return sigmaEncResponse.getMessageResponseCounter();
            }
        });
    }
}
