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

import com.intel.bkp.bkps.exception.SpdmProcessIsStillRunning;
import com.intel.bkp.bkps.rest.onboarding.model.SpdmMessageDTO;
import com.intel.bkp.bkps.rest.provisioning.service.IServiceConfiguration;
import com.intel.bkp.bkps.spdm.model.MessageFromQueueEmpty;
import com.intel.bkp.bkps.spdm.model.SpdmThreadError;
import com.intel.bkp.bkps.spdm.model.UnrecoverableMessageFromQueueEmpty;
import com.intel.bkp.bkps.utils.MdcHelper;
import dev.failsafe.Failsafe;
import dev.failsafe.RetryPolicy;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.List;
import java.util.Optional;

@Slf4j
@RequiredArgsConstructor
@Service
public class SpdmBackgroundService {

    private final SpdmMessageSenderService spdmMessageSenderService;
    private final AsyncSpdmActions asyncSpdmActions;

    private final RetryPolicy<Object> retryPolicy = RetryPolicy.builder()
        .handle(MessageFromQueueEmpty.class)
        .withDelay(Duration.ofSeconds(1))
        .withMaxRetries(3)
        .onRetry(e -> log.debug("Waiting for SPDM process ..."))
        .abortOn(UnrecoverableMessageFromQueueEmpty.class)
        .build();

    public SpdmMessageDTO getMessageFromQueue() throws UnrecoverableMessageFromQueueEmpty {
        try {
            return tryGetMessageFromQueue()
                .orElseThrow(UnrecoverableMessageFromQueueEmpty::new);
        } catch (MessageFromQueueEmpty e) {
            throw new UnrecoverableMessageFromQueueEmpty();
        }
    }

    public Optional<SpdmMessageDTO> tryGetMessageFromQueue() throws MessageFromQueueEmpty {
        return Failsafe.with(retryPolicy).get(() -> {
            final Optional<SpdmMessageDTO> messageFromQueue = Optional.ofNullable(
                spdmMessageSenderService.getMessageFromQueue());

            if (messageFromQueue.isEmpty()) {
                if (asyncSpdmActions.isProcessing()) {
                    throw new MessageFromQueueEmpty();
                } else {
                    return messageFromQueue;
                }
            }

            return messageFromQueue;
        });
    }

    public void ensureProcessIsNotRunning() {
        if (asyncSpdmActions.isProcessing()) {
            throw new SpdmProcessIsStillRunning();
        }
    }

    public void startGetVersion() {
        spdmMessageSenderService.clear();
        asyncSpdmActions.getVersionThread(MdcHelper.get());
    }

    public void startSetAuthority(List<byte[]> certificateChain, int slotId, Boolean isMctpEncapsulateSupported) {
        spdmMessageSenderService.clear();
        asyncSpdmActions.setAuthorityThread(MdcHelper.get(), certificateChain, slotId, isMctpEncapsulateSupported);
    }

    public void startVcaForProvisioningThread() {
        spdmMessageSenderService.clear();
        asyncSpdmActions.vcaForSecureSessionThread(MdcHelper.get());
    }

    public void startSecureSessionThread(String uid, Long cfgId, IServiceConfiguration configurationCallback) {
        spdmMessageSenderService.clear();
        asyncSpdmActions.secureSessionThread(MdcHelper.get(), uid, cfgId, configurationCallback);
    }

    public void pushResponseToQueue(SpdmMessageDTO spdmMessageDto) {
        spdmMessageSenderService.pushResponseToQueue(spdmMessageDto);
    }

    public boolean isProcessResult() {
        return asyncSpdmActions.isProcessResult();
    }

    public Optional<SpdmThreadError> getProcessResult() {
        return asyncSpdmActions.getProcessResult();
    }

    public boolean isProcessing() {
        return asyncSpdmActions.isProcessing();
    }
}
