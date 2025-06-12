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

package com.intel.bkp.verifier.service;

import com.intel.bkp.command.model.CommandLayer;
import com.intel.bkp.verifier.model.VerifierExchangeResponse;
import com.intel.bkp.verifier.protocol.sigma.service.GpS10AttestationComponent;
import com.intel.bkp.verifier.protocol.sigma.service.TeardownMessageSender;
import com.intel.bkp.verifier.service.certificate.AppContext;
import com.intel.bkp.verifier.transport.model.TransportLayer;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@AllArgsConstructor(access = AccessLevel.PACKAGE)
public class GetDeviceAttestationComponentSigma extends GetDeviceAttestationComponent {

    private final GpS10AttestationComponent gpS10AttestationComponent;
    private final TeardownMessageSender teardownMessageSender;

    public GetDeviceAttestationComponentSigma() {
        this.gpS10AttestationComponent = new GpS10AttestationComponent();
        this.teardownMessageSender = new TeardownMessageSender();
    }

    public VerifierExchangeResponse perform(String refMeasurementHex, byte[] deviceId) {
        return perform(AppContext.instance(), refMeasurementHex, deviceId);
    }

    VerifierExchangeResponse perform(AppContext appContext, String refMeasurementHex, byte[] deviceId) {
        final TransportLayer transportLayer = appContext.getTransportLayer();
        final CommandLayer commandLayer = appContext.getCommandLayer();

        return runGpAttestation(refMeasurementHex, deviceId, transportLayer, commandLayer);
    }

    private VerifierExchangeResponse runGpAttestation(String refMeasurementHex, byte[] deviceId,
                                                      TransportLayer transportLayer, CommandLayer commandLayer) {
        log.info("Assuming that it is S10 board, running GP Attestation.");
        teardownMessageSender.send(transportLayer, commandLayer);

        return gpS10AttestationComponent.perform(refMeasurementHex, deviceId);
    }
}
