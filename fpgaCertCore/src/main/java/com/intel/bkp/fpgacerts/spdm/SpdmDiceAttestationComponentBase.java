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

package com.intel.bkp.fpgacerts.spdm;

import com.intel.bkp.fpgacerts.dice.DiceChainMeasurementsCollector;
import com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfoKey;
import com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfoMeasurement;
import com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfoMeasurementsAggregator;
import com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfoValue;
import com.intel.bkp.fpgacerts.exceptions.SpdmAttestationException;
import com.intel.bkp.fpgacerts.measurements.IDeviceMeasurementsProvider;
import com.intel.bkp.fpgacerts.measurements.SpdmDeviceMeasurementsProvider;
import com.intel.bkp.fpgacerts.measurements.SpdmDeviceMeasurementsRequest;
import com.intel.bkp.fpgacerts.rim.IRimHandlersProvider;
import com.intel.bkp.fpgacerts.rim.RimUrlProvider;
import com.intel.bkp.fpgacerts.verification.EvidenceVerifier;
import com.intel.bkp.fpgacerts.verification.VerificationResult;
import com.intel.bkp.protocol.spdm.jna.model.SpdmProtocol;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Supplier;

import static com.intel.bkp.fpgacerts.model.DiceChainType.ATTESTATION;
import static com.intel.bkp.fpgacerts.model.DiceChainType.IID;
import static com.intel.bkp.protocol.spdm.jna.model.SpdmConstants.DEFAULT_SLOT_ID;

@Slf4j
@AllArgsConstructor(access = AccessLevel.PACKAGE)
public abstract class SpdmDiceAttestationComponentBase {

    private final IDeviceMeasurementsProvider<SpdmDeviceMeasurementsRequest> deviceMeasurementsProvider;
    private final EvidenceVerifier evidenceVerifier;
    private final Supplier<TcbInfoMeasurementsAggregator> tcbInfoMeasurementsAggregator;
    private final DiceChainMeasurementsCollector measurementsCollector;
    private final SpdmChainSearcher spdmChainSearcher;
    private final RimUrlProvider rimUrlProvider;

    protected abstract boolean withMeasurementsSignatureVerification();

    public SpdmDiceAttestationComponentBase(SpdmProtocol spdmProtocol, SpdmChainSearcher spdmChainSearcher,
                                            IRimHandlersProvider rimHandlersProvider, RimUrlProvider rimUrlProvider) {
        this.deviceMeasurementsProvider = new SpdmDeviceMeasurementsProvider(spdmProtocol);
        this.evidenceVerifier = new EvidenceVerifier(rimHandlersProvider);
        this.tcbInfoMeasurementsAggregator = TcbInfoMeasurementsAggregator::new;
        this.measurementsCollector = new DiceChainMeasurementsCollector();
        this.spdmChainSearcher = spdmChainSearcher;
        this.rimUrlProvider = rimUrlProvider;
    }

    public VerificationResult perform(String refMeasurementHex, byte[] deviceId) {
        return perform(() -> refMeasurementHex, deviceId).verificationResult();
    }

    public SpdmAttestationResult perform(Supplier<String> refMeasurementHexSupplier, byte[] deviceId) {
        final TcbInfoMeasurementsAggregator tcbInfoMeasurementsAggregator = this.tcbInfoMeasurementsAggregator.get();
        Integer slotId = null;

        try {
            if (withMeasurementsSignatureVerification()) {
                final SpdmValidChains validChains = spdmChainSearcher.searchValidChains(deviceId);

                final var measurementsFromCertChain = getMeasurementsFromChain(validChains.get(ATTESTATION));
                final var iidUdsChainMeasurements = getMeasurementsFromChain(validChains.get(IID));
                slotId = getSlotId(validChains);
                final var measurementsFromDevice = getMeasurementsFromDevice(slotId);

                log.info("*** COLLECTING EVIDENCE FROM CERTIFICATES AND DEVICE ***");
                tcbInfoMeasurementsAggregator.add(measurementsFromCertChain);
                tcbInfoMeasurementsAggregator.add(iidUdsChainMeasurements);
                tcbInfoMeasurementsAggregator.add(measurementsFromDevice);

                logExpectedRimUrl(validChains.get(ATTESTATION).chain(), tcbInfoMeasurementsAggregator.getMap());
            } else {
                log.warn("Chain verification and measurements signature verification turned off!");

                log.info("*** COLLECTING EVIDENCE FROM DEVICE ***");
                slotId = DEFAULT_SLOT_ID;
                tcbInfoMeasurementsAggregator.add(getMeasurementsFromDevice(slotId));
            }

            final VerificationResult verificationResult =
                evidenceVerifier.verify(tcbInfoMeasurementsAggregator, refMeasurementHexSupplier.get());
            return new SpdmAttestationResult(verificationResult, slotId);
        } catch (Exception e) {
            log.error("Exception occurred during attestation: " + e.getMessage());
            log.debug("Stacktrace: ", e);
            return new SpdmAttestationResult(VerificationResult.ERROR, slotId);
        }
    }

    private void logExpectedRimUrl(List<X509Certificate> chain, Map<TcbInfoKey, TcbInfoValue> evidence) {
        Optional.ofNullable(rimUrlProvider)
            .map(p -> p.getRimUrl(chain, evidence))
            .ifPresent(url ->
                log.info("Based on certificate chain and gathered evidence, URL to matching RIM is: {}", url));
    }

    private Integer getSlotId(SpdmValidChains validChains) {
        return Optional.ofNullable(validChains.get(ATTESTATION))
            .map(SpdmCertificateChainHolder::slotId)
            .orElseThrow(() -> new SpdmAttestationException("Valid attestation chain not found."));
    }

    private List<TcbInfoMeasurement> getMeasurementsFromChain(SpdmCertificateChainHolder chainHolder) {
        return Optional.ofNullable(chainHolder)
            .map(SpdmCertificateChainHolder::chain)
            .map(measurementsCollector::getMeasurementsFromCertChain)
            .orElse(List.of());
    }

    private List<TcbInfoMeasurement> getMeasurementsFromDevice(int slotId) {
        final var measurementsRequest = new SpdmDeviceMeasurementsRequest(slotId);
        try {
            return deviceMeasurementsProvider.getMeasurementsFromDevice(measurementsRequest);
        } catch (Exception e) {
            throw new SpdmAttestationException("Failed to retrieve measurements from device.", e);
        }
    }
}
