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
import com.intel.bkp.bkps.crypto.hmac.HMacSigmaEncProviderImpl;
import com.intel.bkp.bkps.domain.ServiceConfiguration;
import com.intel.bkp.bkps.exception.ExceededOvebuildException;
import com.intel.bkp.bkps.exception.ProvisioningConverterException;
import com.intel.bkp.bkps.exception.ProvisioningGenericException;
import com.intel.bkp.bkps.programmer.model.ProgrammerMessage;
import com.intel.bkp.bkps.protocol.common.EncryptedPayload;
import com.intel.bkp.bkps.protocol.common.EncryptedPayloadProvider;
import com.intel.bkp.bkps.protocol.common.MessagesForSigmaEncPayload;
import com.intel.bkp.bkps.protocol.common.handler.ProvisioningHandler;
import com.intel.bkp.bkps.protocol.common.model.FlowStage;
import com.intel.bkp.bkps.protocol.sigma.model.ProvContextEnc;
import com.intel.bkp.bkps.protocol.sigma.session.IMessageResponseCounterProvider;
import com.intel.bkp.bkps.protocol.sigma.session.MessageResponseCounterManager;
import com.intel.bkp.bkps.protocol.sigma.session.SecureSessionIvProvider;
import com.intel.bkp.bkps.rest.provisioning.model.dto.ProvisioningRequestDTOReader;
import com.intel.bkp.bkps.rest.provisioning.model.dto.ProvisioningResponseDTO;
import com.intel.bkp.bkps.rest.provisioning.model.dto.ProvisioningResponseDTOBuilder;
import com.intel.bkp.bkps.rest.provisioning.model.dto.ProvisioningTransferObject;
import com.intel.bkp.bkps.rest.provisioning.service.IServiceConfiguration;
import com.intel.bkp.bkps.rest.provisioning.service.OverbuildCounterManager;
import com.intel.bkp.bkps.rest.provisioning.service.ProvisioningHistoryService;
import com.intel.bkp.command.logger.CommandLogger;
import com.intel.bkp.command.messages.sigma.SigmaEncMessage;
import com.intel.bkp.command.messages.sigma.SigmaEncMessageBuilder;
import com.intel.bkp.command.model.CommandIdentifier;
import com.intel.bkp.command.model.CommandLayer;
import com.intel.bkp.core.manufacturing.model.PufType;
import com.intel.bkp.crypto.aesctr.AesCtrIvProvider;
import com.intel.bkp.crypto.exceptions.EncryptionProviderException;
import com.intel.bkp.crypto.exceptions.HMacProviderException;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.Collections;
import java.util.Optional;

import static com.intel.bkp.bkps.programmer.model.MessageType.SEND_PACKET;
import static com.intel.bkp.command.logger.CommandLoggerValues.PSGSIGMA_ENC_MESSAGE;
import static com.intel.bkp.utils.HexConverter.toHex;

@Component
@AllArgsConstructor(access = AccessLevel.PACKAGE)
@Slf4j
public class ProvEncAssetComponent extends ProvisioningHandler {

    private final AesGcmContextProviderImpl contextEncryptionProvider;
    private final MessagesForSigmaEncPayload messagesForSigmaEncPayload;
    private final ProvisioningHistoryService provisioningHistoryService;
    private final OverbuildCounterManager overbuildCounterManager;
    private final CommandLayer commandLayer;

    @Override
    public ProvisioningResponseDTO handle(ProvisioningTransferObject transferObject) {
        final ProvisioningRequestDTOReader dtoReader = transferObject.getDtoReader();
        FlowStage flowStage = dtoReader.getFlowStage();
        if ((FlowStage.SIGMA_AUTH_DATA.equals(flowStage) || FlowStage.SIGMA_ENC.equals(flowStage))) {
            return perform(transferObject, dtoReader, transferObject.getConfigurationCallback());
        }

        return successor.handle(transferObject);
    }

    private ProvisioningResponseDTO perform(ProvisioningTransferObject transferObject,
                                            ProvisioningRequestDTOReader dtoReader,
                                            IServiceConfiguration configurationCallback) {
        log.info(prepareLogEntry("Preparing Sigma ENC command ..."));
        final ProvContextEnc context = recoverProvisioningContext(dtoReader);
        ServiceConfiguration configuration = configurationCallback.getConfiguration(context.getCfgId());

        byte[] iv = Optional.ofNullable(context.getSigmaEncIv()).orElseGet(() -> new AesCtrIvProvider().generate());

        final ProgrammerMessage sigmaEncCommand = getSigmaEncCommand(context, configuration, iv);
        return buildResponse(transferObject, context, iv, sigmaEncCommand,
            () -> incrementOverbuildCounter(configurationCallback, context, configuration));
    }

    private ProvisioningResponseDTO buildResponse(ProvisioningTransferObject transferObject,
                                                  ProvContextEnc provContext, byte[] iv,
                                                  ProgrammerMessage sigmaEncMessage,
                                                  IOverbuildIncrement callback) {
        try {
            final ProvisioningResponseDTO responseDTO = new ProvisioningResponseDTOBuilder()
                .context(buildContext(provContext, iv))
                .withMessages(Collections.singletonList(sigmaEncMessage))
                .flowStage(FlowStage.SIGMA_ENC_ASSET)
                .protocolType(transferObject.getProtocolType())
                .encryptionProvider(contextEncryptionProvider)
                .build();
            callback.done();
            return responseDTO;
        } catch (ProvisioningConverterException | EncryptionProviderException e) {
            throw new ProvisioningGenericException(e);
        }
    }

    private ProvContextEnc buildContext(ProvContextEnc provContext, byte[] iv) {
        return ProvContextEnc.builder()
            .cfgId(provContext.getCfgId())
            .chipId(provContext.getChipId())
            .sessionEncryptionKey(provContext.getSessionEncryptionKey())
            .sessionMacKey(provContext.getSessionMacKey())
            .sdmSessionId(provContext.getSdmSessionId())
            .sigmaEncIv(iv)
            .messageResponseCounter(MessageResponseCounterManager.forEncryption(provContext))
            .build();
    }

    private ProgrammerMessage getSigmaEncCommand(ProvContextEnc provContext, ServiceConfiguration configuration,
                                                 byte[] iv) {
        try {
            final SigmaEncMessage sigmaEncMessage = getSigmaEncMessage(configuration, provContext, iv);
            final byte[] sigmaEncBytes = commandLayer.create(sigmaEncMessage, CommandIdentifier.SIGMA_ENC);
            CommandLogger.log(sigmaEncMessage, PSGSIGMA_ENC_MESSAGE, this.getClass());
            return ProgrammerMessage.from(SEND_PACKET, sigmaEncBytes);
        } catch (HMacProviderException e) {
            throw new ProvisioningGenericException(e);
        }
    }

    private void incrementOverbuildCounter(IServiceConfiguration configurationCallback, ProvContextEnc provContext,
                                           ServiceConfiguration configuration) {
        log.info(prepareLogEntry("Setting device as provisioned ..."));
        if (markDeviceProvisioned(toHex(provContext.getChipId()), configuration.getPufType())) {
            try {
                overbuildCounterManager.increment(configurationCallback, provContext.getCfgId());
            } catch (ExceededOvebuildException e) {
                throw new ProvisioningGenericException(e);
            }
        }
    }

    private SigmaEncMessage getSigmaEncMessage(ServiceConfiguration configuration, ProvContextEnc provContext,
                                               byte[] iv) throws HMacProviderException {
        final byte[] sigmaEncPayload = messagesForSigmaEncPayload.prepareFrom(configuration);
        final EncryptedPayload payloadToBeEncrypted = EncryptedPayload.from(sigmaEncPayload);
        final EncryptedPayloadProvider encryptedPayloads =
            new EncryptedPayloadProvider(payloadToBeEncrypted.build(),
                new AesCtrSigmaEncProviderImpl(provContext.getSessionEncryptionKey(),
                    getSecureSessionIvProvider(provContext, iv)));
        return buildSigmaEncCommand(provContext.getSdmSessionId(), iv, provContext.getSessionMacKey(),
            MessageResponseCounterManager.forEncryption(provContext), encryptedPayloads.build(),
            payloadToBeEncrypted.getPaddingLength());
    }

    private SecureSessionIvProvider getSecureSessionIvProvider(ProvContextEnc provContext, byte[] iv) {
        return new SecureSessionIvProvider(new IMessageResponseCounterProvider() {
            @Override
            public byte[] getInitialIv() {
                return iv;
            }

            @Override
            public byte[] getMessageResponseCounter() {
                return MessageResponseCounterManager.forEncryptionBytes(provContext);
            }
        });
    }

    private SigmaEncMessage buildSigmaEncCommand(byte[] sdmSessionId, byte[] iv, byte[] smk,
                                                 int messageResponseCounter, byte[] sigmaEncCommandsBuild,
                                                 byte paddingBytes) throws HMacProviderException {
        return new SigmaEncMessageBuilder()
            .sdmSessionId(sdmSessionId)
            .messageResponseCounter(messageResponseCounter)
            .encryptedPayload(sigmaEncCommandsBuild)
            .numberOfPaddingBytes(paddingBytes)
            .initialIv(iv)
            .mac(new HMacSigmaEncProviderImpl(smk))
            .build();
    }

    private ProvContextEnc recoverProvisioningContext(ProvisioningRequestDTOReader dtoReader) {
        try {
            return (ProvContextEnc) dtoReader.read(ProvContextEnc.class);
        } catch (ProvisioningConverterException e) {
            throw new ProvisioningGenericException(e);
        }
    }

    private boolean markDeviceProvisioned(String deviceIdHex, PufType pufType) {
        return provisioningHistoryService.getCurrentProvisionedStatusAndUpdate(deviceIdHex, pufType);
    }

    private interface IOverbuildIncrement {

        void done();
    }
}
