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

package com.intel.bkp.bkps.spdm.service;

import com.intel.bkp.bkps.command.CommandLayerService;
import com.intel.bkp.bkps.rest.onboarding.model.SpdmMessageDTO;
import com.intel.bkp.bkps.spdm.jna.SpdmMessageResponseHandler;
import com.intel.bkp.command.exception.JtagUnknownCommandResponseException;
import com.intel.bkp.command.messages.spdm.MctpMessage;
import com.intel.bkp.command.messages.spdm.MctpMessageParser;
import com.intel.bkp.command.model.CommandIdentifier;
import com.intel.bkp.protocol.spdm.exceptions.SpdmRuntimeException;
import com.intel.bkp.protocol.spdm.jna.model.MessageLogger;
import com.intel.bkp.protocol.spdm.jna.model.MessageSender;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.nio.ByteBuffer;
import java.util.Optional;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

@Slf4j
@Service
@RequiredArgsConstructor(access = AccessLevel.PACKAGE)
public class SpdmMessageSenderService implements MessageSender {

    @Value("${lib-spdm-params.network-communication-timeout}")
    private int communicationTimeout;

    @Value("${lib-spdm-params.library-communication-timeout}")
    private int libspdmProtocolTimeout;

    private final CommandLayerService commandLayer;
    private final BlockingQueue<SpdmMessageDTO> messageQueue;
    private final BlockingQueue<byte[]> responseQueue;
    private final MessageLogger messageLogger;
    private final MctpMessageParser mctpMessageParser;

    @Autowired
    public SpdmMessageSenderService(CommandLayerService commandLayer) {
        this(commandLayer, new LinkedBlockingQueue<>(), new LinkedBlockingQueue<>(), new SpdmMessageResponseHandler(),
            new MctpMessageParser());
    }

    @Override
    public void sendMessage(ByteBuffer spdmContext, ByteBuffer buffer) {
        messageLogger.logMessage(buffer);
        final MctpMessage mctpMessage = mctpMessageParser.parse(buffer);
        final byte[] command = commandLayer.create(mctpMessage, CommandIdentifier.MCTP);

        if (!messageQueue.offer(new SpdmMessageDTO(command))) {
            log.error("Pushing message to queue failed, thread: {}", Thread.currentThread().getName());
        }
    }

    @Override
    public Optional<byte[]> receiveResponse() throws SpdmRuntimeException {
        try {
            return Optional.ofNullable(responseQueue.poll(communicationTimeout, TimeUnit.SECONDS))
                .map(response -> commandLayer.retrieve(response, CommandIdentifier.MCTP))
                .map(rsp -> {
                    messageLogger.logResponse(ByteBuffer.wrap(rsp));
                    return rsp;
                })
                .map(Optional::of)
                .orElseThrow(() -> new SpdmRuntimeException("No response from SPDM Responder."));
        } catch (JtagUnknownCommandResponseException e) {
            log.warn("SPDM is not supported on this platform. Error message: {}", e.getMessage());
            return Optional.empty();
        } catch (InterruptedException e) {
            throw new SpdmRuntimeException("Receive interrupted.", e);
        }
    }

    public SpdmMessageDTO getMessageFromQueue() throws InterruptedException {
        return messageQueue.poll(libspdmProtocolTimeout, TimeUnit.SECONDS);
    }

    public void pushResponseToQueue(SpdmMessageDTO spdmMessageDto) {
        if (!responseQueue.offer(spdmMessageDto.getMessage())) {
            log.error("Pushing response to queue failed, thread: {}", Thread.currentThread().getName());
        }
    }

    public void clear() {
        messageQueue.clear();
        responseQueue.clear();
    }
}
