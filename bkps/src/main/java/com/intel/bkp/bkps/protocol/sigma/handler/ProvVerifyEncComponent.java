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
import com.intel.bkp.bkps.exception.ProgrammerResponseNumberException;
import com.intel.bkp.bkps.exception.ProvisioningConverterException;
import com.intel.bkp.bkps.exception.ProvisioningGenericException;
import com.intel.bkp.bkps.programmer.model.ProgrammerResponse;
import com.intel.bkp.bkps.programmer.utils.ProgrammerResponseToDataAdapter;
import com.intel.bkp.bkps.protocol.common.DecryptedPayload;
import com.intel.bkp.bkps.protocol.common.handler.ProvisioningHandler;
import com.intel.bkp.bkps.protocol.common.model.FlowStage;
import com.intel.bkp.bkps.protocol.sigma.model.ProvContextEnc;
import com.intel.bkp.bkps.protocol.sigma.session.IMessageResponseCounterProvider;
import com.intel.bkp.bkps.protocol.sigma.session.MessageResponseCounterManager;
import com.intel.bkp.bkps.protocol.sigma.session.SecureSessionIvProvider;
import com.intel.bkp.bkps.protocol.sigma.verification.SigmaEncIntegrityVerifier;
import com.intel.bkp.bkps.protocol.sigma.verification.SigmaEncResponseCounterIvVerifier;
import com.intel.bkp.bkps.rest.provisioning.model.dto.ProvisioningRequestDTOReader;
import com.intel.bkp.bkps.rest.provisioning.model.dto.ProvisioningResponseDTO;
import com.intel.bkp.bkps.rest.provisioning.model.dto.ProvisioningTransferObject;
import com.intel.bkp.command.header.CommandHeaderManager;
import com.intel.bkp.command.logger.CommandLogger;
import com.intel.bkp.command.model.CommandIdentifier;
import com.intel.bkp.command.model.CommandLayer;
import com.intel.bkp.command.responses.sigma.SigmaEncResponse;
import com.intel.bkp.command.responses.sigma.SigmaEncResponseBuilder;
import com.intel.bkp.core.endianness.EndiannessActor;
import com.intel.bkp.crypto.exceptions.HMacProviderException;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.List;

import static com.intel.bkp.bkps.programmer.utils.ProgrammerResponsesNumberVerifier.verifyNumberOfResponses;
import static com.intel.bkp.command.logger.CommandLoggerValues.PSGSIGMA_ENC_PAYLOAD_RESPONSE;
import static com.intel.bkp.command.logger.CommandLoggerValues.PSGSIGMA_ENC_RESPONSE;

@Component
@Slf4j
@RequiredArgsConstructor(access = AccessLevel.PACKAGE)
public class ProvVerifyEncComponent extends ProvisioningHandler {

    private static final int EXPECTED_NUMBER_OF_RESPONSES = 1;
    private static final String SIGMA_ENC_PAYLOAD = "SigmaEncPayload";

    private final CommandLayer commandLayer;

    @Override
    public ProvisioningResponseDTO handle(ProvisioningTransferObject transferObject) {
        final ProvisioningRequestDTOReader dtoReader = transferObject.getDtoReader();
        FlowStage flowStage = dtoReader.getFlowStage();
        if (FlowStage.SIGMA_ENC.equals(flowStage) || FlowStage.SIGMA_ENC_ASSET.equals(flowStage)) {
            perform(dtoReader);
        }

        return successor.handle(transferObject);
    }

    private void perform(ProvisioningRequestDTOReader dtoReader) {
        final ProvContextEnc provContext = recoverProvisioningContext(dtoReader);
        verifyResponses(dtoReader.getJtagResponses());
        final ProgrammerResponseToDataAdapter adapter =
            new ProgrammerResponseToDataAdapter(dtoReader.getJtagResponses());
        final SigmaEncResponse sigmaEncResponse = buildSigmaEncResponse(adapter);
        try {
            if (sigmaEncResponse.hasEncryptedResponse()) {
                performSigmaEncResponseVerification(provContext, sigmaEncResponse);
                DecryptedPayload decryptedPayload = getSigmaEncResponseDecryptedPayload(provContext, sigmaEncResponse);
                CommandLogger.log(decryptedPayload.getValue(), PSGSIGMA_ENC_PAYLOAD_RESPONSE, this.getClass());

                performPayloadHeaderVerification(decryptedPayload);
            }
        } catch (HMacProviderException e) {
            throw new ProvisioningGenericException(e);
        }
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

    private void performSigmaEncResponseVerification(ProvContextEnc provContext,
                                                     SigmaEncResponse sigmaEncResponse) throws HMacProviderException {
        log.info(prepareLogEntry("Performing Sigma ENC Integrity verification..."));
        final byte[] smk = provContext.getSessionMacKey();
        new SigmaEncIntegrityVerifier(smk, sigmaEncResponse).verify();

        log.info(prepareLogEntry("Performing Sigma ENC response counter and iv verification..."));
        new SigmaEncResponseCounterIvVerifier(provContext.getSigmaEncIv(),
            MessageResponseCounterManager.forVerification(provContext), sigmaEncResponse).verify();
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

    private void performPayloadHeaderVerification(DecryptedPayload decryptedPayload) {
        log.info(prepareLogEntry("Performing Sigma ENC payload header verification..."));
        CommandHeaderManager.validateCommandHeaderCode(decryptedPayload.getValue(), SIGMA_ENC_PAYLOAD);
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
