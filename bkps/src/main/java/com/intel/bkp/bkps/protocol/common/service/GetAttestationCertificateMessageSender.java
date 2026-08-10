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

package com.intel.bkp.bkps.protocol.common.service;

import com.intel.bkp.bkps.exception.GetAttestationCertificateException;
import com.intel.bkp.bkps.programmer.model.ProgrammerMessage;
import com.intel.bkp.bkps.protocol.BaseMessageSender;
import com.intel.bkp.command.exception.JtagUnknownCommandResponseException;
import com.intel.bkp.command.logger.CommandLogger;
import com.intel.bkp.command.messages.common.GetCertificateMessageBuilder;
import com.intel.bkp.command.model.CommandIdentifier;
import com.intel.bkp.command.model.CommandLayer;
import com.intel.bkp.command.responses.common.GetCertificateResponse;
import com.intel.bkp.command.responses.common.GetCertificateResponseBuilder;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.Optional;

import static com.intel.bkp.bkps.programmer.model.MessageType.SEND_PACKET;
import static com.intel.bkp.command.logger.CommandLoggerValues.GET_ATTESTATION_CERTIFICATE_MESSAGE;
import static com.intel.bkp.command.logger.CommandLoggerValues.GET_ATTESTATION_CERTIFICATE_RESPONSE;
import static com.intel.bkp.command.model.CertificateRequestType.DEVICE_ID_ENROLLMENT;

@Slf4j
@Component
@RequiredArgsConstructor
public class GetAttestationCertificateMessageSender implements BaseMessageSender<Optional<byte[]>> {

    private final CommandLayer commandLayer;

    public ProgrammerMessage create() {
        log.debug("Preparing GET_ATTESTATION_CERTIFICATE ...");
        final var message = new GetCertificateMessageBuilder()
            .withType(DEVICE_ID_ENROLLMENT)
            .build();

        final byte[] payload = commandLayer.create(message, CommandIdentifier.GET_ATTESTATION_CERTIFICATE);
        CommandLogger.log(message, GET_ATTESTATION_CERTIFICATE_MESSAGE, this.getClass());
        return ProgrammerMessage.from(SEND_PACKET, payload);
    }

    public Optional<byte[]> retrieve(byte[] response) {
        try {
            final GetCertificateResponse certificateResponse = new GetCertificateResponseBuilder()
                .parse(commandLayer.retrieve(response, CommandIdentifier.GET_ATTESTATION_CERTIFICATE))
                .build();
            CommandLogger.log(certificateResponse, GET_ATTESTATION_CERTIFICATE_RESPONSE, this.getClass());
            return Optional.of(certificateResponse.getCertificateBlob());
        } catch (JtagUnknownCommandResponseException e) {
            log.warn("Retrieving certificate failed, but this might be expected for S10: {}", e.getMessage());
            return Optional.empty();
        } catch (Exception e) {
            throw new GetAttestationCertificateException(e.getMessage());
        }
    }
}
