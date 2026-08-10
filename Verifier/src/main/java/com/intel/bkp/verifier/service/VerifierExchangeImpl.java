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

package com.intel.bkp.verifier.service;

import com.intel.bkp.core.manufacturing.model.PufType;
import com.intel.bkp.protocol.spdm.exceptions.SpdmNotSupportedException;
import com.intel.bkp.protocol.spdm.exceptions.UnsupportedSpdmVersionException;
import com.intel.bkp.protocol.spdm.jna.model.SpdmProtocol;
import com.intel.bkp.protocol.spdm.service.SpdmGetVersionMessageSender;
import com.intel.bkp.protocol.spdm.service.SpdmVersionVerifier;
import com.intel.bkp.verifier.exceptions.VerifierRuntimeException;
import com.intel.bkp.verifier.interfaces.VerifierExchange;
import com.intel.bkp.verifier.model.dto.VerifierExchangeResponseDTO;
import com.intel.bkp.verifier.protocol.spdm.jna.SpdmProtocol12Impl;
import com.intel.bkp.verifier.service.certificate.AppContext;
import com.intel.bkp.verifier.transport.model.TransportLayer;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import static com.intel.bkp.verifier.service.GetDeviceAttestationComponentSpdm.SPDM_SUPPORTED_VERSION;
import static com.intel.bkp.verifier.model.VerifierExchangeResponse.ERROR;
import static com.intel.bkp.verifier.service.VerifierExchangeProtocol.logAttestationResult;

@Slf4j
@AllArgsConstructor(access = AccessLevel.PACKAGE)
public class VerifierExchangeImpl implements VerifierExchange {

    private final SpdmProtocol spdmProtocol = new SpdmProtocol12Impl();
    private final SpdmVersionVerifier spdmVersionVerifier = new SpdmVersionVerifier(SPDM_SUPPORTED_VERSION);
    private final VerifierExchangeProtocolSpdm verifierExchangeProtocolSpdm;
    private final VerifierExchangeProtocolSigma verifierExchangeProtocolSigma;
    private final SpdmGetVersionMessageSender spdmGetVersionMessageSender;

    public VerifierExchangeImpl() {
        this.verifierExchangeProtocolSpdm = new VerifierExchangeProtocolSpdm();
        this.verifierExchangeProtocolSigma = new VerifierExchangeProtocolSigma();
        this.spdmGetVersionMessageSender = new SpdmGetVersionMessageSender(spdmProtocol);
    }

    @Override
    public int createDeviceAttestationSubKey(String transportId, String context, String pufType) {
        try (AppContext appContext = AppContext.instance()) {
            appContext.init();
            final TransportLayer transportLayer = appContext.getTransportLayer();

            try {
                transportLayer.initialize(transportId);
                return getProtocol().createSubKeyInternal(context, PufType.valueOf(pufType));
            } catch (Exception e) {
                log.error("Create attestation subkey failed: {}", e.getMessage());
                log.debug("Stacktrace: ", e);
                return ERROR.getCode();
            } finally {
                transportLayer.disconnect();
            }
        } catch (Exception e) {
            log.error("Create attestation subkey failed: {}", e.getMessage());
            log.debug("Stacktrace: ", e);
            return ERROR.getCode();
        }
    }

    @Override
    public VerifierExchangeResponseDTO getDeviceAttestation(String transportId, String refMeasurementHex) {
        var attestationResult = new VerifierExchangeResponseDTO(ERROR.getCode(), "");

        try (AppContext appContext = AppContext.instance()) {
            appContext.init();
            final TransportLayer transportLayer = appContext.getTransportLayer();

            try {
                transportLayer.initialize(transportId);
                attestationResult = getProtocol().getAttestationInternal(refMeasurementHex);
            } catch (Exception e) {
                log.error("Device attestation failed: {}", e.getMessage());
                log.debug("Stacktrace: ", e);
            } finally {
                transportLayer.disconnect();
            }
        } catch (Exception e) {
            log.error("Device attestation failed: {}", e.getMessage());
            log.debug("Stacktrace: ", e);
        }

        logAttestationResult(attestationResult);

        return attestationResult;
    }

    @Override
    public int healthCheck(String transportId) {
        try (AppContext appContext = AppContext.instance()) {
            appContext.init();
            final TransportLayer transportLayer = appContext.getTransportLayer();

            try {
                transportLayer.initialize(transportId);
                return getProtocol().healthCheckInternal(transportLayer);
            } catch (Exception e) {
                log.error("Health check failed: {}", e.getMessage());
                log.debug("Stacktrace: ", e);
                return ERROR.getCode();
            } finally {
                transportLayer.disconnect();
            }
        } catch (Exception e) {
            log.error("Health check failed: {}", e.getMessage());
            log.debug("Stacktrace: ", e);
            return ERROR.getCode();
        }
    }

    public VerifierExchangeProtocol getProtocol() {
        final VerifierExchangeProtocol protocol;

        if (spdmSupported()) {
            protocol = this.verifierExchangeProtocolSpdm;
        } else {
            protocol = this.verifierExchangeProtocolSigma;
        }
        return protocol;
    }

    public boolean spdmSupported() {
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
}
