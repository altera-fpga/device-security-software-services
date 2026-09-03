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

import ch.qos.logback.classic.Level;
import com.intel.bkp.fpgacerts.dice.DiceChainMeasurementsCollector;
import com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfo;
import com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfoKey;
import com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfoMeasurement;
import com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfoMeasurementsAggregator;
import com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfoValue;
import com.intel.bkp.fpgacerts.measurements.IDeviceMeasurementsProvider;
import com.intel.bkp.fpgacerts.measurements.SpdmDeviceMeasurementsRequest;
import com.intel.bkp.fpgacerts.rim.RimUrlProvider;
import com.intel.bkp.fpgacerts.verification.EvidenceVerifier;
import com.intel.bkp.test.LoggerTestUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;

import static com.intel.bkp.fpgacerts.model.DiceChainType.ATTESTATION;
import static com.intel.bkp.fpgacerts.verification.VerificationResult.ERROR;
import static com.intel.bkp.fpgacerts.verification.VerificationResult.PASSED;
import static com.intel.bkp.protocol.spdm.jna.model.SpdmConstants.DEFAULT_SLOT_ID;
import static com.intel.bkp.test.CertificateUtils.generateCertificate;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class SpdmDiceAttestationComponentBaseTest {

    private static class SpdmDiceAttestationComponentTestImpl extends SpdmDiceAttestationComponentBase {

        private final boolean withMeasurementsSignatureVerification;

        SpdmDiceAttestationComponentTestImpl(
                boolean withMeasurementsSignatureVerification,
                IDeviceMeasurementsProvider<SpdmDeviceMeasurementsRequest> deviceMeasurementsProvider,
                EvidenceVerifier evidenceVerifier,
                Supplier<TcbInfoMeasurementsAggregator> tcbInfoMeasurementsAggregator,
                DiceChainMeasurementsCollector measurementsCollector,
                SpdmChainSearcherBase spdmChainSearcher,
                RimUrlProvider rimUrlProvider
        ) {
            super(deviceMeasurementsProvider, evidenceVerifier, tcbInfoMeasurementsAggregator, measurementsCollector,
                spdmChainSearcher, rimUrlProvider);
            this.withMeasurementsSignatureVerification = withMeasurementsSignatureVerification;
        }

        @Override
        protected boolean withMeasurementsSignatureVerification() {
            return withMeasurementsSignatureVerification;
        }
    }

    private static final X509Certificate CERT = generateCertificate();
    private static final List<X509Certificate> CERT_CHAIN_FROM_DEVICE = List.of(CERT);
    private static final byte[] DEVICE_ID = {1, 2};
    private static final String REF_MEASUREMENT = "aabbccdd";
    private static final List<TcbInfoMeasurement> TCB_INFOS_FROM_CHAIN = List.of(new TcbInfoMeasurement(new TcbInfo()));
    private static final List<TcbInfoMeasurement> TCB_INFOS_FROM_MEASUREMENTS =
        List.of(new TcbInfoMeasurement(new TcbInfo()), new TcbInfoMeasurement(new TcbInfo()));
    private static final int SLOT_ID = 1;
    private static final String RIM_URL = "some/url.corim";

    private LoggerTestUtil loggerTestUtil;
    @Mock
    private IDeviceMeasurementsProvider<SpdmDeviceMeasurementsRequest> deviceMeasurementsProvider;
    @Mock
    private EvidenceVerifier evidenceVerifier;
    @Mock
    private TcbInfoMeasurementsAggregator tcbInfoMeasurementsAggregator;
    @Mock
    private DiceChainMeasurementsCollector measurementsCollector;
    @Mock
    private SpdmChainSearcherBase spdmChainSearcher;
    @Mock
    private SpdmValidChains validChainResponse;
    @Mock
    private Map<TcbInfoKey, TcbInfoValue> measurementsMap;
    @Mock
    private RimUrlProvider rimUrlProvider;

    @BeforeEach
    void setup() {
        loggerTestUtil = LoggerTestUtil.instance(SpdmDiceAttestationComponentBase.class);
    }

    @Test
    void perform_RequestSignatureFalse_OnlyMeasurements_ReturnsDefaultSlotId() throws Exception {
        // given
        final SpdmDiceAttestationComponentBase sut = prepareSutWithSignatureVerificationSkipped();

        when(deviceMeasurementsProvider.getMeasurementsFromDevice(any())).thenReturn(TCB_INFOS_FROM_MEASUREMENTS);
        when(evidenceVerifier.verify(tcbInfoMeasurementsAggregator, REF_MEASUREMENT)).thenReturn(PASSED);

        // when
        final var result = sut.perform(() -> REF_MEASUREMENT, DEVICE_ID);

        // then
        assertEquals(PASSED, result.verificationResult());
        assertEquals(DEFAULT_SLOT_ID, result.slotId());
        verify(spdmChainSearcher, never()).searchValidChains(DEVICE_ID);
        verify(measurementsCollector, never()).getMeasurementsFromCertChain(CERT_CHAIN_FROM_DEVICE);
        verify(tcbInfoMeasurementsAggregator, never()).add(TCB_INFOS_FROM_CHAIN);
        verify(tcbInfoMeasurementsAggregator).add(TCB_INFOS_FROM_MEASUREMENTS);
    }

    @Test
    void perform_RequestSignatureTrue_GetCertificatesAndMeasurements_ReturnsMatchingSlotId() throws Exception {
        // given
        final SpdmDiceAttestationComponentBase sut = prepareSutWithSignatureVerificationRequired();

        when(spdmChainSearcher.searchValidChains(DEVICE_ID)).thenReturn(validChainResponse);
        when(validChainResponse.get(ATTESTATION))
            .thenReturn(new SpdmCertificateChainHolder(SLOT_ID, ATTESTATION, CERT_CHAIN_FROM_DEVICE));
        when(measurementsCollector.getMeasurementsFromCertChain(CERT_CHAIN_FROM_DEVICE))
            .thenReturn(TCB_INFOS_FROM_CHAIN);
        when(deviceMeasurementsProvider.getMeasurementsFromDevice(new SpdmDeviceMeasurementsRequest(SLOT_ID)))
            .thenReturn(TCB_INFOS_FROM_MEASUREMENTS);
        when(tcbInfoMeasurementsAggregator.getMap()).thenReturn(measurementsMap);
        when(rimUrlProvider.getRimUrl(CERT_CHAIN_FROM_DEVICE, measurementsMap)).thenReturn(RIM_URL);
        when(evidenceVerifier.verify(tcbInfoMeasurementsAggregator, REF_MEASUREMENT)).thenReturn(PASSED);

        // when
        final var result = sut.perform(() -> REF_MEASUREMENT, DEVICE_ID);

        // then
        assertEquals(PASSED, result.verificationResult());
        assertEquals(SLOT_ID, result.slotId());
        verify(tcbInfoMeasurementsAggregator).add(TCB_INFOS_FROM_CHAIN);
        verify(tcbInfoMeasurementsAggregator).add(TCB_INFOS_FROM_MEASUREMENTS);
        verify(evidenceVerifier).verify(tcbInfoMeasurementsAggregator, REF_MEASUREMENT);
        verifyRimUrlLog();
    }

    @Test
    void perform_WithFailureToGetRefMeasurement_FirstCollectsMeasurementsThenReturnsError() throws Exception {
        // given
        final SpdmDiceAttestationComponentBase sut = prepareSutWithSignatureVerificationRequired();

        when(spdmChainSearcher.searchValidChains(DEVICE_ID)).thenReturn(validChainResponse);
        when(validChainResponse.get(ATTESTATION))
            .thenReturn(new SpdmCertificateChainHolder(SLOT_ID, ATTESTATION, CERT_CHAIN_FROM_DEVICE));
        when(measurementsCollector.getMeasurementsFromCertChain(CERT_CHAIN_FROM_DEVICE))
            .thenReturn(TCB_INFOS_FROM_CHAIN);
        when(deviceMeasurementsProvider.getMeasurementsFromDevice(new SpdmDeviceMeasurementsRequest(SLOT_ID)))
            .thenReturn(TCB_INFOS_FROM_MEASUREMENTS);

        // when
        final var result = sut.perform(() -> {
            throw new RuntimeException();
        }, DEVICE_ID);

        // then
        assertEquals(ERROR, result.verificationResult());
        assertEquals(SLOT_ID, result.slotId());
        verify(tcbInfoMeasurementsAggregator).add(TCB_INFOS_FROM_CHAIN);
        verify(tcbInfoMeasurementsAggregator).add(TCB_INFOS_FROM_MEASUREMENTS);
        verify(evidenceVerifier, never()).verify(any(), any());
    }

    private SpdmDiceAttestationComponentBase prepareSutWithSignatureVerificationSkipped() {
        return prepareSut(false);
    }

    private SpdmDiceAttestationComponentBase prepareSutWithSignatureVerificationRequired() {
        return prepareSut(true);
    }

    private SpdmDiceAttestationComponentBase prepareSut(boolean withMeasurementsSignatureVerification) {
        return new SpdmDiceAttestationComponentTestImpl(
            withMeasurementsSignatureVerification, deviceMeasurementsProvider, evidenceVerifier,
            () -> tcbInfoMeasurementsAggregator, measurementsCollector, spdmChainSearcher, rimUrlProvider
        );
    }

    private void verifyRimUrlLog() {
        assertTrue(loggerTestUtil.contains(
            "Based on certificate chain and gathered evidence, URL to matching RIM is: " + RIM_URL, Level.INFO
        ));
    }
}
