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

package com.intel.bkp.bkps.protocol.spdm.handler;

import com.intel.bkp.bkps.crypto.aesgcm.AesGcmContextProviderImpl;
import com.intel.bkp.bkps.domain.ServiceConfiguration;
import com.intel.bkp.bkps.exception.ExceededOvebuildException;
import com.intel.bkp.bkps.exception.ProgrammerResponseNumberException;
import com.intel.bkp.bkps.exception.ProvisioningConverterException;
import com.intel.bkp.bkps.exception.ProvisioningGenericException;
import com.intel.bkp.bkps.programmer.model.ProgrammerMessage;
import com.intel.bkp.bkps.programmer.model.ProgrammerResponse;
import com.intel.bkp.bkps.programmer.utils.ProgrammerResponseToDataAdapter;
import com.intel.bkp.bkps.protocol.common.handler.ProvisioningHandler;
import com.intel.bkp.bkps.protocol.common.model.FlowStage;
import com.intel.bkp.bkps.protocol.common.service.GetChipIdMessageSender;
import com.intel.bkp.bkps.protocol.spdm.model.ProvSpdmContext;
import com.intel.bkp.bkps.rest.onboarding.model.SpdmMessageDTO;
import com.intel.bkp.bkps.rest.provisioning.model.dto.ProvisioningRequestDTOReader;
import com.intel.bkp.bkps.rest.provisioning.model.dto.ProvisioningResponseDTO;
import com.intel.bkp.bkps.rest.provisioning.model.dto.ProvisioningResponseDTOBuilder;
import com.intel.bkp.bkps.rest.provisioning.model.dto.ProvisioningTransferObject;
import com.intel.bkp.bkps.rest.provisioning.service.IServiceConfiguration;
import com.intel.bkp.bkps.rest.provisioning.service.OverbuildCounterManager;
import com.intel.bkp.bkps.spdm.model.UnrecoverableMessageFromQueueEmpty;
import com.intel.bkp.bkps.spdm.service.SpdmBackgroundService;
import com.intel.bkp.crypto.exceptions.EncryptionProviderException;
import dev.failsafe.Failsafe;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.List;

import static com.intel.bkp.bkps.programmer.model.MessageType.SEND_PACKET;
import static com.intel.bkp.bkps.programmer.utils.ProgrammerResponsesNumberVerifier.verifyNumberOfResponses;
import static io.micrometer.common.util.StringUtils.isBlank;

@Component
@AllArgsConstructor(access = AccessLevel.PACKAGE)
@Slf4j
public class ProvSpdmCreateComponent extends ProvisioningHandler {

    private static final int EXPECTED_NUMBER_OF_RESPONSES = 1;

    private final GetChipIdMessageSender getChipIdMessageSender;
    private final SpdmBackgroundService spdmBackgroundService;
    private final AesGcmContextProviderImpl contextEncryptionProvider;
    private final OverbuildCounterManager overbuildCounterManager;

    @Override
    public ProvisioningResponseDTO handle(ProvisioningTransferObject transferObject) {
        final ProvisioningRequestDTOReader dtoReader = transferObject.getDtoReader();
        final FlowStage flowStage = dtoReader.getFlowStage();
        if (FlowStage.SPDM_GET_CHIPID.equals(flowStage)) {
            return perform(dtoReader, transferObject);
        }

        return successor.handle(transferObject);
    }

    private ProvisioningResponseDTO perform(ProvisioningRequestDTOReader dtoReader,
                                            ProvisioningTransferObject transferObject) {
        log.info(prepareLogEntry("create SPDM protocol."));

        Failsafe.with(retryPolicy).run(spdmBackgroundService::ensureProcessIsNotRunning);

        log.info(prepareLogEntry("parsing quartus responses..."));

        final List<ProgrammerResponse> jtagResponses = dtoReader.getJtagResponses();

        try {
            verifyNumberOfResponses(jtagResponses, EXPECTED_NUMBER_OF_RESPONSES);
        } catch (ProgrammerResponseNumberException e) {
            throw new ProvisioningGenericException(e.getMessage());
        }

        final var adapter = new ProgrammerResponseToDataAdapter(jtagResponses);
        final String deviceIdHex = getChipIdMessageSender.retrieve(adapter.getNext());
        log.info(prepareLogEntry("action will be performed for device: " + deviceIdHex));

        final IServiceConfiguration configurationCallback = transferObject.getConfigurationCallback();
        final Long cfgId = dtoReader.getCfgId();
        log.info(prepareLogEntry("Fetch configuration data for cfg id: " + cfgId));
        final ServiceConfiguration configuration = configurationCallback.getConfiguration(cfgId);

        ensureOverbuildCounterNotExceeded(deviceIdHex, configuration);

        spdmBackgroundService.startSecureSessionThread(deviceIdHex, cfgId, configurationCallback);

        try {
            final SpdmMessageDTO messageFromQueue = spdmBackgroundService.getMessageFromQueue();

            return new ProvisioningResponseDTOBuilder()
                .context(new ProvSpdmContext(deviceIdHex, cfgId))
                .withMessages(List.of(ProgrammerMessage.from(SEND_PACKET, messageFromQueue.getMessage())))
                .flowStage(FlowStage.SPDM_SESSION)
                .protocolType(transferObject.getProtocolType())
                .encryptionProvider(contextEncryptionProvider)
                .build();
        } catch (EncryptionProviderException e) {
            throw new ProvisioningGenericException("Preparing response failed.", e);
        } catch (ProvisioningConverterException e) {
            throw new ProvisioningGenericException(e);
        } catch (UnrecoverableMessageFromQueueEmpty e) {
            throw new ProvisioningGenericException("No response from SPDM Service.");
        }
    }

    private void ensureOverbuildCounterNotExceeded(String deviceIdHex, ServiceConfiguration configuration) {
        log.info(prepareLogEntry("Verify overbuild counter"));
        try {
            overbuildCounterManager.verifyOverbuildCounter(configuration, deviceIdHex);
        } catch (ExceededOvebuildException e) {
            throw new ProvisioningGenericException(e);
        }
    }
}
