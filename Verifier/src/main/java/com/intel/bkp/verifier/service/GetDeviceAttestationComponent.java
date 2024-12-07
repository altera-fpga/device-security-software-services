/*
 * This project is licensed as below.
 *
 * **************************************************************************
 *
 * Copyright 2020-2024 Intel Corporation. All Rights Reserved.
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

package com.intel.bkp.verifier.service;

import com.intel.bkp.command.model.CommandLayer;
import com.intel.bkp.fpgacerts.exceptions.SpdmAttestationException;
import com.intel.bkp.protocol.spdm.exceptions.SpdmCommandFailedException;
import com.intel.bkp.protocol.spdm.exceptions.SpdmNotSupportedException;
import com.intel.bkp.protocol.spdm.exceptions.UnsupportedSpdmVersionException;
import com.intel.bkp.protocol.spdm.jna.model.SpdmProtocol;
import com.intel.bkp.protocol.spdm.service.SpdmGetVersionMessageSender;
import com.intel.bkp.protocol.spdm.service.SpdmVcaMessageSender;
import com.intel.bkp.protocol.spdm.service.SpdmVersionVerifier;
import com.intel.bkp.verifier.exceptions.VerifierRuntimeException;
import com.intel.bkp.verifier.model.VerifierExchangeResponse;
import com.intel.bkp.verifier.protocol.sigma.service.GpS10AttestationComponent;
import com.intel.bkp.verifier.protocol.sigma.service.TeardownMessageSender;
import com.intel.bkp.verifier.protocol.spdm.jna.SpdmProtocol12Impl;
import com.intel.bkp.verifier.protocol.spdm.service.SpdmDiceAttestationComponent;
import com.intel.bkp.verifier.service.certificate.AppContext;
import com.intel.bkp.verifier.transport.model.TransportLayer;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@AllArgsConstructor(access = AccessLevel.PACKAGE)
public class GetDeviceAttestationComponent {

    private static final String SPDM_SUPPORTED_VERSION = "12";

    private final GpS10AttestationComponent gpS10AttestationComponent;
    private final SpdmGetVersionMessageSender spdmGetVersionMessageSender;
    private final TeardownMessageSender teardownMessageSender;
    private final SpdmDiceAttestationComponent spdmDiceAttestationComponent;
    private final SpdmVcaMessageSender spdmVcaMessageSender;
    private final SpdmVersionVerifier spdmVersionVerifier;

    public GetDeviceAttestationComponent() {
        this.gpS10AttestationComponent = new GpS10AttestationComponent();
        this.teardownMessageSender = new TeardownMessageSender();

        final SpdmProtocol spdmProtocol = new SpdmProtocol12Impl();
        this.spdmGetVersionMessageSender = new SpdmGetVersionMessageSender(spdmProtocol);
        this.spdmVcaMessageSender = new SpdmVcaMessageSender(spdmProtocol);
        this.spdmDiceAttestationComponent = new SpdmDiceAttestationComponent(spdmProtocol);
        this.spdmVersionVerifier = new SpdmVersionVerifier(SPDM_SUPPORTED_VERSION);
    }

    public VerifierExchangeResponse perform(String refMeasurementHex, byte[] deviceId) {
        return perform(AppContext.instance(), refMeasurementHex, deviceId);
    }

    VerifierExchangeResponse perform(AppContext appContext, String refMeasurementHex, byte[] deviceId) {
        final TransportLayer transportLayer = appContext.getTransportLayer();
        final CommandLayer commandLayer = appContext.getCommandLayer();

        if (spdmSupported()) {
            return runSpdmAttestation(refMeasurementHex, deviceId);
        } else {
            return runGpAttestation(refMeasurementHex, deviceId, transportLayer, commandLayer);
        }
    }

    private boolean spdmSupported() {
        try {
            final String responderVersion = spdmGetVersionMessageSender.send();
            log.debug("SPDM Responder version: {}", responderVersion);

            spdmVersionVerifier.ensureVersionIsSupported(responderVersion);
            return true;
        } catch (SpdmNotSupportedException e) {
            log.debug("SPDM is not supported: ", e);
            return false;
        } catch (UnsupportedSpdmVersionException e) {
            throw new VerifierRuntimeException("SPDM is in unsupported version: %s".formatted(e.getMessage()), e);
        } catch (VerifierRuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new VerifierRuntimeException("Failed to verify if SPDM is supported.", e);
        }
    }

    private VerifierExchangeResponse runGpAttestation(String refMeasurementHex, byte[] deviceId,
                                                      TransportLayer transportLayer, CommandLayer commandLayer) {
        log.info("Assuming that it is S10 board, running GP Attestation.");
        teardownMessageSender.send(transportLayer, commandLayer);

        return gpS10AttestationComponent.perform(refMeasurementHex, deviceId);
    }

    private VerifierExchangeResponse runSpdmAttestation(String refMeasurementHex, byte[] deviceId) {
        log.debug("Running SPDM Attestation.");
        initializeSpdmConnection();
        final var attestationResult = spdmDiceAttestationComponent.perform(refMeasurementHex, deviceId);
        return VerifierExchangeResponse.from(attestationResult);
    }

    private void initializeSpdmConnection() {
        try {
            final String responderVersion = spdmVcaMessageSender.send();
            log.debug("SPDM Responder version: {}", responderVersion);
        } catch (SpdmCommandFailedException e) {
            throw new SpdmAttestationException("SPDM not supported: ", e);
        }
    }
}
