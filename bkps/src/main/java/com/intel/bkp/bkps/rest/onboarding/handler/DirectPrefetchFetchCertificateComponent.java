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

import com.intel.bkp.bkps.exception.PrefetchingGenericException;
import com.intel.bkp.bkps.exception.ProgrammerResponseNumberException;
import com.intel.bkp.bkps.programmer.model.ProgrammerResponse;
import com.intel.bkp.bkps.programmer.utils.ProgrammerResponseToDataAdapter;
import com.intel.bkp.bkps.protocol.common.service.GetAttestationCertificateMessageSender;
import com.intel.bkp.bkps.protocol.common.service.GetChipIdMessageSender;
import com.intel.bkp.bkps.protocol.common.service.GetDeviceIdentityMessageSender;
import com.intel.bkp.bkps.protocol.common.service.GetIdCodeMessageSender;
import com.intel.bkp.bkps.rest.onboarding.model.DeviceId;
import com.intel.bkp.bkps.rest.onboarding.model.DirectPrefetchResponseDTO;
import com.intel.bkp.bkps.rest.onboarding.model.DirectPrefetchTransferObject;
import com.intel.bkp.bkps.rest.onboarding.service.PrefetchService;
import com.intel.bkp.fpgacerts.model.Family;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Optional;

import static com.intel.bkp.bkps.programmer.utils.ProgrammerResponsesNumberVerifier.verifyNumberOfResponses;

@Component
@Slf4j
@RequiredArgsConstructor
public class DirectPrefetchFetchCertificateComponent extends DirectPrefetchHandler {

    private static final int EXPECTED_NUMBER_OF_RESPONSES = 4;

    private final GetChipIdMessageSender getChipIdMessageSender;
    private final GetIdCodeMessageSender getIdCodeMessageSender;
    private final GetDeviceIdentityMessageSender getDeviceIdentityMessageSender;
    private final GetAttestationCertificateMessageSender getAttestationCertificateMessageSender;
    private final PrefetchService prefetchService;

    @Override
    public DirectPrefetchResponseDTO handle(DirectPrefetchTransferObject transferObject) {
        perform(transferObject.getDtoReader().getJtagResponses());
        return successor.handle(transferObject);
    }

    private void perform(List<ProgrammerResponse> jtagResponses) {
        log.info(prepareLogEntry("parsing quartus responses..."));

        try {
            verifyNumberOfResponses(jtagResponses, EXPECTED_NUMBER_OF_RESPONSES);
        } catch (ProgrammerResponseNumberException e) {
            throw new PrefetchingGenericException(e.getMessage());
        }

        final var adapter = new ProgrammerResponseToDataAdapter(jtagResponses);
        final String uid = getChipIdMessageSender.retrieve(adapter.getNext());
        final Family family = getIdCodeMessageSender.retrieve(adapter.getNext());
        final String deviceIdentity = getDeviceIdentityMessageSender.retrieve(adapter.getNext());
        final DeviceId deviceId = DeviceId.instance(family, uid, deviceIdentity);

        log.info(prepareLogEntry("action will be performed for device: " + deviceId));

        final Optional<byte[]> cert = getAttestationCertificateMessageSender.retrieve(adapter.getNext());
        prefetchService.enqueue(deviceId, cert);
    }
}
