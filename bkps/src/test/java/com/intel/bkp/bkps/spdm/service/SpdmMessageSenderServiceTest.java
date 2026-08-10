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

import ch.qos.logback.classic.Level;
import com.intel.bkp.bkps.command.CommandLayerService;
import com.intel.bkp.bkps.rest.onboarding.model.SpdmMessageDTO;
import com.intel.bkp.command.exception.JtagUnknownCommandResponseException;
import com.intel.bkp.command.messages.spdm.MctpMessage;
import com.intel.bkp.command.messages.spdm.MctpMessageParser;
import com.intel.bkp.protocol.spdm.exceptions.SpdmRuntimeException;
import com.intel.bkp.protocol.spdm.jna.model.MessageLogger;
import com.intel.bkp.test.LoggerTestUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.nio.ByteBuffer;
import java.util.Optional;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.TimeUnit;

import static ch.qos.logback.classic.Level.WARN;
import static com.intel.bkp.command.model.CommandIdentifier.MCTP;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class SpdmMessageSenderServiceTest {

    private static final byte[] PAYLOAD = {1, 2, 3, 4};
    private static final byte[] RESPONSE = {2, 3, 4};

    @Mock
    private CommandLayerService commandLayer;

    @Mock
    private BlockingQueue<byte[]> responseQueue;

    @Mock
    private BlockingQueue<SpdmMessageDTO> messageQueue;

    @Mock
    private MessageLogger messageLogger;

    @Mock
    private MctpMessageParser mctpMessageParser;

    @Mock
    private MctpMessage mctpMessage;

    private LoggerTestUtil loggerTestUtil;

    private SpdmMessageSenderService sut;


    @BeforeEach
    void setup() {
        sut =
            new SpdmMessageSenderService(commandLayer, messageQueue, responseQueue, messageLogger, mctpMessageParser);
        loggerTestUtil = LoggerTestUtil.instance(sut.getClass());
    }

    @Test
    void sendMessage_WhenMessageAddedToQueue_DoesNotLogError() {
        // given
        final var buffer = ByteBuffer.wrap(PAYLOAD);
        when(mctpMessageParser.parse(buffer)).thenReturn(mctpMessage);
        when(commandLayer.create(mctpMessage, MCTP)).thenReturn(PAYLOAD);
        when(messageQueue.offer(new SpdmMessageDTO(PAYLOAD))).thenReturn(true);

        // when-then
        assertDoesNotThrow(() -> sut.sendMessage(null, buffer));

        // then
        assertEquals(0, loggerTestUtil.getSize(Level.ERROR));
    }

    @Test
    void sendMessage_WhenQueueIsFullAndMessageNotAddedToQueue_LogsError() {
        // given
        final var buffer = ByteBuffer.wrap(PAYLOAD);
        when(mctpMessageParser.parse(buffer)).thenReturn(mctpMessage);
        when(commandLayer.create(mctpMessage, MCTP)).thenReturn(PAYLOAD);
        when(messageQueue.offer(new SpdmMessageDTO(PAYLOAD))).thenReturn(false);

        // when-then
        assertDoesNotThrow(() -> sut.sendMessage(null, buffer));

        // then
        verifyLogExists(Level.ERROR, "Pushing message to queue failed");
    }

    @Test
    void receiveResponse_WhenResponseRetrievedFromQueue_ReturnsResponse() throws InterruptedException {
        // given
        when(responseQueue.poll(anyLong(), eq(TimeUnit.SECONDS))).thenReturn(PAYLOAD);
        when(commandLayer.retrieve(PAYLOAD, MCTP)).thenReturn(RESPONSE);

        // when
        final var result = sut.receiveResponse();

        // then
        assertEquals(Optional.of(RESPONSE), result);
        verify(messageLogger).logResponse(ByteBuffer.wrap(RESPONSE));
    }

    @Test
    void receiveResponse_WhenResponseNotAvailableInQueueBeforeTimeout_Throws() throws InterruptedException {
        // given
        when(responseQueue.poll(anyLong(), eq(TimeUnit.SECONDS))).thenReturn(null);

        // when
        final var ex = assertThrows(SpdmRuntimeException.class, () -> sut.receiveResponse());

        // then
        assertEquals("No response from SPDM Responder.", ex.getMessage());
        verifyNoInteractions(commandLayer);
        verifyNoInteractions(messageLogger);
    }

    @Test
    void receiveResponse_WhenInterruptedWhilePollingFromQueue_Throws() throws InterruptedException {
        // given
        when(responseQueue.poll(anyLong(), eq(TimeUnit.SECONDS))).thenThrow(new InterruptedException());

        // when
        final var ex = assertThrows(SpdmRuntimeException.class, () -> sut.receiveResponse());

        // then
        assertEquals("Receive interrupted.", ex.getMessage());
        verifyNoInteractions(commandLayer);
        verifyNoInteractions(messageLogger);
    }

    @Test
    void receiveResponse_WhenSpdmNotSupported_ReturnsEmpty() throws InterruptedException {
        // given
        final String errorMsg = "error";
        when(responseQueue.poll(anyLong(), eq(TimeUnit.SECONDS))).thenReturn(PAYLOAD);
        when(commandLayer.retrieve(PAYLOAD, MCTP)).thenThrow(new JtagUnknownCommandResponseException(errorMsg));

        // when
        final var result = sut.receiveResponse();

        // then
        assertEquals(Optional.empty(), result);
        verifyNoInteractions(messageLogger);
        verifyLogExists(WARN, "SPDM is not supported on this platform. Error message: " + errorMsg);
    }

    @Test
    void getMessageFromQueue_ReturnsMessage() throws InterruptedException {
        // given
        final var message = new SpdmMessageDTO(PAYLOAD);
        when(messageQueue.poll(anyLong(), eq(TimeUnit.SECONDS))).thenReturn(message);

        // when
        final var result = sut.getMessageFromQueue();

        // then
        assertEquals(message, result);
    }

    @Test
    void pushResponseToQueue_WhenResponseAddedToQueue_DoesNotLogError() {
        // given
        final var message = new SpdmMessageDTO(PAYLOAD);
        when(responseQueue.offer(PAYLOAD)).thenReturn(true);

        // when-then
        assertDoesNotThrow(() -> sut.pushResponseToQueue(message));

        // then
        assertEquals(0, loggerTestUtil.getSize(Level.ERROR));
    }

    @Test
    void pushResponseToQueue_WhenQueueIsFullAndResponseNotAddedToQueue_LogsError() {
        // given
        final var message = new SpdmMessageDTO(PAYLOAD);
        when(responseQueue.offer(PAYLOAD)).thenReturn(false);

        // when-then
        assertDoesNotThrow(() -> sut.pushResponseToQueue(message));

        // then
        verifyLogExists(Level.ERROR, "Pushing response to queue failed");
    }

    private void verifyLogExists(Level level, String expectedLog) {
        assertTrue(loggerTestUtil.contains(expectedLog, level));
    }
}
