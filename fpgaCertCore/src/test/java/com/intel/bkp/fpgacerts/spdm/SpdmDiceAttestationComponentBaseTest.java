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
import com.intel.bkp.fpgacerts.cbor.signer.cose.CborKeyPair;
import com.intel.bkp.fpgacerts.cbor.signer.cose.exception.CoseException;
import com.intel.bkp.fpgacerts.dice.DiceChainMeasurementsCollector;
import com.intel.bkp.fpgacerts.dice.tcbinfo.FwIdField;
import com.intel.bkp.fpgacerts.dice.tcbinfo.MeasurementType;
import com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfo;
import com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfoConstants;
import com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfoField;
import com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfoKey;
import com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfoMeasurement;
import com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfoMeasurementsAggregator;
import com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfoValue;
import com.intel.bkp.fpgacerts.dp.IDistributionPointConnector;
import com.intel.bkp.fpgacerts.ect.ECTMap;
import com.intel.bkp.fpgacerts.ect.IECTMapStorage;
import com.intel.bkp.fpgacerts.measurements.IDeviceMeasurementsProvider;
import com.intel.bkp.fpgacerts.measurements.SpdmDeviceMeasurementsRequest;
import com.intel.bkp.fpgacerts.rim.RimUrlProvider;
import com.intel.bkp.fpgacerts.url.FetchDataSchemeBroker;
import com.intel.bkp.fpgacerts.verification.EvidenceVerifier;
import com.intel.bkp.test.LoggerTestUtil;
import com.intel.bkp.test.rim.OneKeyGenerator;
import com.intel.bkp.test.rim.RimGenerator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;

import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Supplier;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static com.intel.bkp.utils.HexConverter.toHex;
import static com.intel.bkp.fpgacerts.cbor.signer.cose.model.AlgorithmId.ECDSA_384;
import static com.intel.bkp.fpgacerts.model.DiceChainType.ATTESTATION;
import static com.intel.bkp.fpgacerts.model.DiceChainType.IID;
import static com.intel.bkp.fpgacerts.verification.VerificationResult.ERROR;
import static com.intel.bkp.fpgacerts.verification.VerificationResult.PASSED;
import static com.intel.bkp.protocol.spdm.jna.model.SpdmConstants.DEFAULT_SLOT_ID;
import static com.intel.bkp.test.CertificateUtils.generateCertificate;
import static com.intel.bkp.test.RandomUtils.generateRandomHex;
import static com.intel.bkp.utils.HexConverter.toLowerCaseHex;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.same;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class SpdmDiceAttestationComponentBaseTest {

    private static class SpdmDiceAttestationComponentTestImpl extends SpdmDiceAttestationComponentBase {

        private final boolean withMeasurementsSignatureVerification;
        private final IDistributionPointConnector dpConnector;

        SpdmDiceAttestationComponentTestImpl(
            boolean withMeasurementsSignatureVerification,
            IDeviceMeasurementsProvider<SpdmDeviceMeasurementsRequest> deviceMeasurementsProvider,
            EvidenceVerifier evidenceVerifier,
            Supplier<TcbInfoMeasurementsAggregator> tcbInfoMeasurementsAggregator,
            DiceChainMeasurementsCollector measurementsCollector,
            SpdmChainSearcherBase spdmChainSearcher,
            RimUrlProvider rimUrlProvider,
            RimUrlProvider newRimUrlProvider,
            List<ECTMap> acsECTMapList,
            IDistributionPointConnector dpConnector
        ) {
            super(deviceMeasurementsProvider, evidenceVerifier, tcbInfoMeasurementsAggregator, measurementsCollector,
                spdmChainSearcher, rimUrlProvider, newRimUrlProvider, dpConnector, acsECTMapList);
            this.withMeasurementsSignatureVerification = withMeasurementsSignatureVerification;
            this.dpConnector = dpConnector;
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
    private static final List<String> trustedRootHash = List.of("35E08599DD52CB7533764DEE65C915BBAFD0E35E6252BCCD77F3A694390F618B");
    private static final List<TcbInfoMeasurement> TCB_INFOS_FROM_CHAIN = List.of(new TcbInfoMeasurement(new TcbInfo()));
    private static final List<TcbInfoMeasurement> TCB_INFOS_FROM_MEASUREMENTS = List.of(new TcbInfoMeasurement(new TcbInfo()), new TcbInfoMeasurement(new TcbInfo()));
    private static final List<ECTMap> ECT_MAPS_FROM_CHAIN = new ArrayList<>();
    private static final List<ECTMap> ECT_MAPS_FROM_MEASUREMENTS = new ArrayList<>();
    private static final int SLOT_ID = 1;
    private static final String NEW_RIM_URL = "some/newurl.corim";
    private static final String RIM_URL = "some/url.corim";
    private static CborKeyPair signingKey;
    private static final String issuerKeyId = generateRandomHex(RimGenerator.ISSUER_KEY_LEN);
    private static final String layer0Digest = "6BAE8B8D60F65E825D5BD4011084C7B7C51FE290621BB4B5846AA38BD8D9A67624AFB6"
        + "7AC93E991363829123D52963C0E60AD3B89C36EFDDCFFE72A67FDB75E6";
    private static final String layer1Digest = "B59D6688BC2B5D22073D1A8A14DC5D76583A5B7BCD1E27B811FDE319F25305B18A632D"
        + "24B83AD6EA5125B6CD529C98D3";
    private static final String TYPE = MeasurementType.FIRMWARE_VERSION.getOid();
    private static final String VENDOR = TcbInfoConstants.VENDOR;
    private static final String VERSION = "release-2023.28.1.1";
    private static final String HASH_ALG = "2.16.840.1.101.3.4.2.2";
    private static final String FWID_DIGEST = "20FF681A0882E29B481953888936209CB53DF9C5AAEC606A2C24A0FB138595124B8E3F24A12771BC3854CC68B40361AD";
    private static final String MODEL = "Agilex";
    private static final int INDEX = 0;
    private static final int LAYER = 1;

    private LoggerTestUtil loggerTestUtil;
    @Mock
    private IDeviceMeasurementsProvider<SpdmDeviceMeasurementsRequest> deviceMeasurementsProvider;
    @Mock
    private EvidenceVerifier evidenceVerifier;
    @Spy
    private List<ECTMap> acsEctMaps = new ArrayList<>();
    @Mock
    private IECTMapStorage appraisalPolicy;
    @Mock
    private IECTMapStorage evidenceStorageFromAttestationChain;
    @Mock
    private IECTMapStorage evidenceStorageFromIidChain;
    @Mock
    private IECTMapStorage evidenceStorageFromMeasurements;
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
    @Mock
    private RimUrlProvider newRimUrlProvider;
    @Mock
    private IDistributionPointConnector dpConnector;

    @BeforeEach
    void setup() throws CoseException {

        loggerTestUtil = LoggerTestUtil.instance(SpdmDiceAttestationComponentBase.class);
        signingKey = OneKeyGenerator.generate(ECDSA_384);
    }

    @Test
    void perform_RequestSignatureFalse_OnlyMeasurements_ReturnsDefaultSlotId() throws Exception {
        try (MockedStatic<ECTMap> ectMapMockedStatic = mockStatic(ECTMap.class)) {
            // given
            final SpdmDiceAttestationComponentBase sut = prepareSutWithSignatureVerificationSkipped();

            when(deviceMeasurementsProvider.getMeasurementsFromDevice(any())).thenReturn(TCB_INFOS_FROM_MEASUREMENTS);
            when(spdmChainSearcher.getTrustedRootHashes()).thenReturn(trustedRootHash.toArray(new String[0]));
            when(evidenceStorageFromMeasurements.getAddition()).thenReturn(ECT_MAPS_FROM_MEASUREMENTS);
            ectMapMockedStatic.when(() -> ECTMap.createAeECTMap(TCB_INFOS_FROM_MEASUREMENTS, trustedRootHash)).thenReturn(
                evidenceStorageFromMeasurements);
            ectMapMockedStatic.when(() -> ECTMap.createPolicyECTMap(TCB_INFOS_FROM_MEASUREMENTS, trustedRootHash, ECTMap.CMType.REFERENCE_VALUES)).thenReturn(
                appraisalPolicy);
            when(evidenceVerifier.verify(ECT_MAPS_FROM_MEASUREMENTS, REF_MEASUREMENT)).thenReturn(PASSED);

            // when
            final var result = sut.perform(() -> REF_MEASUREMENT, null, DEVICE_ID);

            // then
            assertEquals(PASSED, result.verificationResult());
            assertEquals(DEFAULT_SLOT_ID, result.slotId());
            verify(spdmChainSearcher, never()).searchValidChains(DEVICE_ID);
            verify(measurementsCollector, never()).getMeasurementsFromCertChain(CERT_CHAIN_FROM_DEVICE);
            verify(evidenceVerifier, times(1)).setPolicyECTMapStorage(same(null));
            verify(acsEctMaps, never()).addAll(same(ECT_MAPS_FROM_CHAIN));
            verify(acsEctMaps).addAll(same(ECT_MAPS_FROM_MEASUREMENTS));
        }
    }

    @Test
    void perform_RequestSignatureTrue_GetCertificatesAndMeasurements_WithoutCorim_ReturnsMatchingSlotId() throws Exception {
        try (var fetchDataSchemeBrokerMockedStatic = mockStatic(FetchDataSchemeBroker.class)) {
            // given
            final SpdmDiceAttestationComponentBase sut = prepareSutWithSignatureVerificationRequired();
            List<TcbInfo> deviceTcbInfo = List.of(prepareTcbInfoWithFwId());
            List<TcbInfoMeasurement> deviceTcbInfoMeasurements = deviceTcbInfo.stream().map(TcbInfoMeasurement::new)
                .collect(Collectors.toList());
            final byte[] fwCoRIMData = generateSignedRim(true, false);
            fetchDataSchemeBrokerMockedStatic.when(()-> FetchDataSchemeBroker.fetchData(eq(NEW_RIM_URL), any()))
                .thenReturn(Optional.ofNullable(fwCoRIMData));
            when(spdmChainSearcher.searchValidChains(DEVICE_ID)).thenReturn(validChainResponse);
            when(validChainResponse.get(ATTESTATION))
                .thenReturn(new SpdmCertificateChainHolder(SLOT_ID, ATTESTATION, CERT_CHAIN_FROM_DEVICE));
            when(validChainResponse.get(IID))
                .thenReturn(null);
            when(measurementsCollector.getMeasurementsFromCertChain(CERT_CHAIN_FROM_DEVICE))
                .thenReturn(deviceTcbInfoMeasurements);
            when(deviceMeasurementsProvider.getMeasurementsFromDevice(new SpdmDeviceMeasurementsRequest(SLOT_ID)))
                .thenReturn(deviceTcbInfoMeasurements);
            when(spdmChainSearcher.getTrustedRootHashes()).thenReturn(trustedRootHash.toArray(new String[0]));
            when(tcbInfoMeasurementsAggregator.getMap()).thenReturn(measurementsMap);
            final var evidenceECTMap = ECTMap.createAeECTMap(deviceTcbInfoMeasurements, trustedRootHash);
            when(newRimUrlProvider.getRimUrl(CERT_CHAIN_FROM_DEVICE, measurementsMap)).thenReturn(NEW_RIM_URL);
            when(evidenceVerifier.verify(any(), any())).thenReturn(PASSED);
            // when
            final SpdmAttestationResult result = sut.perform((Supplier<String>) null, null, DEVICE_ID);

            // then
            assertEquals(PASSED, result.verificationResult());
            assertEquals(SLOT_ID, result.slotId());
            ArgumentCaptor<Collection<ECTMap>> captor = ArgumentCaptor.forClass(Collection.class);
            verify(acsEctMaps, times(3)).addAll(captor.capture());
            List<Collection<ECTMap>> allArgs = captor.getAllValues();
            assertTrue(allArgs.get(0).equals(evidenceECTMap.getAddition()));
            assertEquals(allArgs.get(1), List.of());
            assertTrue(allArgs.get(0).equals(evidenceECTMap.getAddition()));
            ArgumentCaptor<IECTMapStorage> captorPolicy = ArgumentCaptor.forClass(IECTMapStorage.class);
            verify(evidenceVerifier, times(1)).setPolicyECTMapStorage(captorPolicy.capture());
            List<TcbInfo> fwVersionTcbInfo = List.of(prepareTcbInfoWithFirmwareVersion());
            List<TcbInfoMeasurement> fwVersionTcbInfoMeasurements = fwVersionTcbInfo.stream().map(TcbInfoMeasurement::new)
                .collect(Collectors.toList());
            final var appraisalPolicies = ECTMap.createPolicyECTMap(fwVersionTcbInfoMeasurements, trustedRootHash, ECTMap.CMType.ENDORSEMENTS);
            assertTrue(captorPolicy.getAllValues().get(0).getCondition().equals(appraisalPolicies.getCondition()));
            assertTrue(captorPolicy.getAllValues().get(0).getAddition() == null);
            List<ECTMap> evList = Stream.of(evidenceECTMap.getAddition(), evidenceECTMap.getAddition())
                .flatMap(List::stream)
                .collect(Collectors.toList());
            verify(evidenceVerifier).verify(evList, toLowerCaseHex(fwCoRIMData));
            verifyRimUrlLog(NEW_RIM_URL);
        }
    }

    @Test
    void perform_RequestSignatureTrue_GetCertificatesAndMeasurements_WithNewFwCorim_ReturnsMatchingSlotId() throws Exception {
        try (var fetchDataSchemeBrokerMockedStatic = mockStatic(FetchDataSchemeBroker.class)) {
            // given
            final SpdmDiceAttestationComponentBase sut = prepareSutWithSignatureVerificationRequired();
            List<TcbInfo> deviceTcbInfo = List.of(prepareTcbInfoWithFwId());
            List<TcbInfoMeasurement> deviceTcbInfoMeasurements = deviceTcbInfo.stream().map(TcbInfoMeasurement::new)
                .collect(Collectors.toList());
            final byte[] fwCoRIMData = generateSignedRim(true, false);
            fetchDataSchemeBrokerMockedStatic.when(()-> FetchDataSchemeBroker.fetchData(eq(NEW_RIM_URL), any()))
                    .thenReturn(Optional.ofNullable(fwCoRIMData));
            when(spdmChainSearcher.searchValidChains(DEVICE_ID)).thenReturn(validChainResponse);
            when(validChainResponse.get(ATTESTATION))
                .thenReturn(new SpdmCertificateChainHolder(SLOT_ID, ATTESTATION, CERT_CHAIN_FROM_DEVICE));
            when(validChainResponse.get(IID))
                .thenReturn(null);
            when(measurementsCollector.getMeasurementsFromCertChain(CERT_CHAIN_FROM_DEVICE))
                .thenReturn(deviceTcbInfoMeasurements);
            when(deviceMeasurementsProvider.getMeasurementsFromDevice(new SpdmDeviceMeasurementsRequest(SLOT_ID)))
                .thenReturn(deviceTcbInfoMeasurements);
            when(spdmChainSearcher.getTrustedRootHashes()).thenReturn(trustedRootHash.toArray(new String[0]));
            when(tcbInfoMeasurementsAggregator.getMap()).thenReturn(measurementsMap);
            final var evidenceECTMap = ECTMap.createAeECTMap(deviceTcbInfoMeasurements, trustedRootHash);
            when(newRimUrlProvider.getRimUrl(CERT_CHAIN_FROM_DEVICE, measurementsMap)).thenReturn(NEW_RIM_URL);
            when(evidenceVerifier.verify(any(), eq(REF_MEASUREMENT))).thenReturn(PASSED);
            // when
            final var result = sut.perform(() -> REF_MEASUREMENT, null, DEVICE_ID);

            // then
            assertEquals(PASSED, result.verificationResult());
            assertEquals(SLOT_ID, result.slotId());
            ArgumentCaptor<Collection<ECTMap>> captor = ArgumentCaptor.forClass(Collection.class);
            verify(acsEctMaps, times(3)).addAll(captor.capture());
            List<Collection<ECTMap>> allArgs = captor.getAllValues();
            assertTrue(allArgs.get(0).equals(evidenceECTMap.getAddition()));
            assertEquals(allArgs.get(1), List.of());
            assertTrue(allArgs.get(0).equals(evidenceECTMap.getAddition()));
            ArgumentCaptor<IECTMapStorage> captorPolicy = ArgumentCaptor.forClass(IECTMapStorage.class);
            verify(evidenceVerifier, times(1)).setPolicyECTMapStorage(captorPolicy.capture());
            List<TcbInfo> fwVersionTcbInfo = List.of(prepareTcbInfoWithFirmwareVersion());
            List<TcbInfoMeasurement> fwVersionTcbInfoMeasurements = fwVersionTcbInfo.stream().map(TcbInfoMeasurement::new)
                .collect(Collectors.toList());
            final var appraisalPolicies = ECTMap.createPolicyECTMap(fwVersionTcbInfoMeasurements, trustedRootHash, ECTMap.CMType.ENDORSEMENTS);
            assertTrue(captorPolicy.getAllValues().get(0).getCondition().equals(appraisalPolicies.getCondition()));
            assertTrue(captorPolicy.getAllValues().get(0).getAddition() == null);
            List<ECTMap> evList = Stream.of(evidenceECTMap.getAddition(), evidenceECTMap.getAddition())
                .flatMap(List::stream)
                .collect(Collectors.toList());
            verify(evidenceVerifier).verify(evList, REF_MEASUREMENT);
            verifyRimUrlLog(NEW_RIM_URL);
        }
    }

    @Test
    void perform_RequestSignatureTrue_GetCertificatesAndMeasurements_ReturnsMatchingSlotId() throws Exception {
        try (var fetchDataSchemeBrokerMockedStatic = mockStatic(FetchDataSchemeBroker.class)) {
            // given
            final SpdmDiceAttestationComponentBase sut = prepareSutWithSignatureVerificationRequired();
            List<TcbInfo> deviceTcbInfo = List.of(prepareTcbInfoWithFwId());
            List<TcbInfoMeasurement> deviceTcbInfoMeasurements = deviceTcbInfo.stream().map(TcbInfoMeasurement::new)
                .collect(Collectors.toList());
            final byte[] fwCoRIMData = generateSignedRim(false, true);
            fetchDataSchemeBrokerMockedStatic.when(()-> FetchDataSchemeBroker.fetchData(eq(RIM_URL), any()))
                .thenReturn(Optional.ofNullable(fwCoRIMData));
            when(spdmChainSearcher.searchValidChains(DEVICE_ID)).thenReturn(validChainResponse);
            when(validChainResponse.get(ATTESTATION))
                .thenReturn(new SpdmCertificateChainHolder(SLOT_ID, ATTESTATION, CERT_CHAIN_FROM_DEVICE));
            when(validChainResponse.get(IID))
                .thenReturn(null);
            when(measurementsCollector.getMeasurementsFromCertChain(CERT_CHAIN_FROM_DEVICE))
                .thenReturn(deviceTcbInfoMeasurements);
            when(deviceMeasurementsProvider.getMeasurementsFromDevice(new SpdmDeviceMeasurementsRequest(SLOT_ID)))
                .thenReturn(deviceTcbInfoMeasurements);
            when(spdmChainSearcher.getTrustedRootHashes()).thenReturn(trustedRootHash.toArray(new String[0]));
            when(tcbInfoMeasurementsAggregator.getMap()).thenReturn(measurementsMap);
            final var evidenceECTMap = ECTMap.createAeECTMap(deviceTcbInfoMeasurements, trustedRootHash);
            when(newRimUrlProvider.getRimUrl(CERT_CHAIN_FROM_DEVICE, measurementsMap)).thenReturn(NEW_RIM_URL);
            when(rimUrlProvider.getRimUrl(CERT_CHAIN_FROM_DEVICE, measurementsMap)).thenReturn(RIM_URL);
            when(evidenceVerifier.verify(any(), eq(REF_MEASUREMENT))).thenReturn(PASSED);
            // when
            final var result = sut.perform(() -> REF_MEASUREMENT, null, DEVICE_ID);

            // then
            assertEquals(PASSED, result.verificationResult());
            assertEquals(SLOT_ID, result.slotId());
            ArgumentCaptor<Collection<ECTMap>> captor = ArgumentCaptor.forClass(Collection.class);
            verify(acsEctMaps, times(3)).addAll(captor.capture());
            List<Collection<ECTMap>> allArgs = captor.getAllValues();
            assertTrue(allArgs.get(0).equals(evidenceECTMap.getAddition()));
            assertEquals(allArgs.get(1), List.of());
            assertTrue(allArgs.get(0).equals(evidenceECTMap.getAddition()));
            ArgumentCaptor<IECTMapStorage> captorPolicy = ArgumentCaptor.forClass(IECTMapStorage.class);
            verify(evidenceVerifier, times(1)).setPolicyECTMapStorage(captorPolicy.capture());
            List<TcbInfo> fwVersionTcbInfo = List.of(prepareTcbInfoWithFirmwareVersion());
            List<TcbInfoMeasurement> fwVersionTcbInfoMeasurements = fwVersionTcbInfo.stream().map(TcbInfoMeasurement::new)
                .collect(Collectors.toList());
            final var appraisalPolicies = ECTMap.createPolicyECTMap(fwVersionTcbInfoMeasurements, trustedRootHash, ECTMap.CMType.ENDORSEMENTS);
            assertTrue(captorPolicy.getAllValues().get(0).getCondition().equals(appraisalPolicies.getCondition()));
            assertTrue(captorPolicy.getAllValues().get(0).getAddition() == null);
            List<ECTMap> evList = Stream.of(evidenceECTMap.getAddition(), evidenceECTMap.getAddition())
                .flatMap(List::stream)
                .collect(Collectors.toList());
            verify(evidenceVerifier).verify(evList, REF_MEASUREMENT);
            verifyRimUrlLog(RIM_URL);
        }
    }

    @Test
    void perform_RequestSignatureTrue_GetCertificatesAndMeasurements_WithJSONrim_ReturnsMatchingSlotId() throws Exception {
        // given
        final SpdmDiceAttestationComponentBase sut = prepareSutWithSignatureVerificationRequired();
        List<TcbInfo> deviceTcbInfo = List.of(prepareTcbInfoWithFwId());
        List<TcbInfoMeasurement> deviceTcbInfoMeasurements = deviceTcbInfo.stream().map(TcbInfoMeasurement::new)
            .collect(Collectors.toList());
        when(spdmChainSearcher.searchValidChains(DEVICE_ID)).thenReturn(validChainResponse);
        when(validChainResponse.get(ATTESTATION))
            .thenReturn(new SpdmCertificateChainHolder(SLOT_ID, ATTESTATION, CERT_CHAIN_FROM_DEVICE));
        when(validChainResponse.get(IID))
            .thenReturn(null);
        when(measurementsCollector.getMeasurementsFromCertChain(CERT_CHAIN_FROM_DEVICE))
            .thenReturn(deviceTcbInfoMeasurements);
        when(deviceMeasurementsProvider.getMeasurementsFromDevice(new SpdmDeviceMeasurementsRequest(SLOT_ID)))
            .thenReturn(deviceTcbInfoMeasurements);
        when(spdmChainSearcher.getTrustedRootHashes()).thenReturn(trustedRootHash.toArray(new String[0]));
        final var evidenceECTMap = ECTMap.createAeECTMap(deviceTcbInfoMeasurements, trustedRootHash);
        String jsonRimData = """
            {
                "measurement records": {
                    "tcbinfo": [
                        {
                            "//": "Hash of layer 1 (mutable firmware)",
                            "vendor": "intel.com",
                            "model": "Agilex",
                            "layer": "1",
                            "fwids": [
                                {
                                    "hashAlg": "2.16.840.1.101.3.4.2.2",
                                    "digest": "20FF681A0882E29B481953888936209CB53DF9C5AAEC606A2C24A0FB138595124B8E3F24A12771BC3854CC68B40361AD"
                                }
                            ]
                        }
                    ]
                }
            }
            """;
        String refMeasurementsHex = HexFormat.of().formatHex(jsonRimData.getBytes(StandardCharsets.UTF_8));
        when(evidenceVerifier.verify(any(), eq(refMeasurementsHex))).thenReturn(PASSED);

        // when
        final var result = sut.perform(() -> refMeasurementsHex, null, DEVICE_ID);

        // then
        assertEquals(PASSED, result.verificationResult());
        assertEquals(SLOT_ID, result.slotId());
        ArgumentCaptor<Collection<ECTMap>> captor = ArgumentCaptor.forClass(Collection.class);
        verify(acsEctMaps, times(3)).addAll(captor.capture());
        List<Collection<ECTMap>> allArgs = captor.getAllValues();
        assertTrue(allArgs.get(0).equals(evidenceECTMap.getAddition()));
        assertEquals(allArgs.get(1), List.of());
        assertTrue(allArgs.get(0).equals(evidenceECTMap.getAddition()));
        verify(evidenceVerifier, times(1)).setPolicyECTMapStorage(null);
        List<ECTMap> evList = Stream.of(evidenceECTMap.getAddition(), evidenceECTMap.getAddition())
            .flatMap(List::stream)
            .collect(Collectors.toList());
        verify(evidenceVerifier).verify(evList, HexFormat.of().formatHex(jsonRimData.getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void perform_WithFailureToGetRefMeasurement_FirstCollectsMeasurementsThenReturnsError() throws Exception {
        try (MockedStatic<ECTMap> ectMapMockedStatic = mockStatic(ECTMap.class)) {
            // given
            final SpdmDiceAttestationComponentBase sut = prepareSutWithSignatureVerificationRequired();

            when(spdmChainSearcher.searchValidChains(DEVICE_ID)).thenReturn(validChainResponse);
            when(validChainResponse.get(ATTESTATION))
                .thenReturn(new SpdmCertificateChainHolder(SLOT_ID, ATTESTATION, CERT_CHAIN_FROM_DEVICE));
            when(validChainResponse.get(IID))
                .thenReturn(null);
            when(measurementsCollector.getMeasurementsFromCertChain(CERT_CHAIN_FROM_DEVICE))
                .thenReturn(TCB_INFOS_FROM_CHAIN);
            when(deviceMeasurementsProvider.getMeasurementsFromDevice(new SpdmDeviceMeasurementsRequest(SLOT_ID)))
                .thenReturn(TCB_INFOS_FROM_MEASUREMENTS);
            when(spdmChainSearcher.getTrustedRootHashes()).thenReturn(trustedRootHash.toArray(new String[0]));
            when(evidenceStorageFromAttestationChain.getAddition()).thenReturn(ECT_MAPS_FROM_CHAIN);
            ectMapMockedStatic.when(() -> ECTMap.createAeECTMap(TCB_INFOS_FROM_CHAIN, trustedRootHash)).thenReturn(
                evidenceStorageFromAttestationChain);
            when(evidenceStorageFromIidChain.getAddition()).thenReturn(new ArrayList<>());
            ectMapMockedStatic.when(() -> ECTMap.createAeECTMap(List.of(), trustedRootHash)).thenReturn(
                evidenceStorageFromIidChain);
            when(evidenceStorageFromMeasurements.getAddition()).thenReturn(ECT_MAPS_FROM_MEASUREMENTS);
            ectMapMockedStatic.when(
                () -> ECTMap.createAeECTMap(TCB_INFOS_FROM_MEASUREMENTS, trustedRootHash)).thenReturn(
                evidenceStorageFromMeasurements);

            // when
            final var result = sut.perform(() -> {
                throw new RuntimeException();
            }, null, DEVICE_ID);

            // then
            assertEquals(ERROR, result.verificationResult());
            assertEquals(SLOT_ID, result.slotId());
            verify(acsEctMaps, times(1)).addAll(same(ECT_MAPS_FROM_CHAIN));
            verify(acsEctMaps, times(1)).addAll(same(ECT_MAPS_FROM_MEASUREMENTS));
            verify(tcbInfoMeasurementsAggregator).add(TCB_INFOS_FROM_CHAIN);
            verify(tcbInfoMeasurementsAggregator).add(TCB_INFOS_FROM_MEASUREMENTS);
            verify(evidenceVerifier, never()).verify(any(), any());
        }
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
            () -> tcbInfoMeasurementsAggregator, measurementsCollector, spdmChainSearcher, rimUrlProvider,
            newRimUrlProvider, acsEctMaps, dpConnector
        );
    }

    private void verifyRimUrlLog(String urlPath) {
        assertTrue(loggerTestUtil.contains(
            "Based on certificate chain and gathered evidence, URL to matching RIM is: " + urlPath, Level.INFO
        ));
    }

    private static byte[] generateSignedRim(boolean newCorimFormat,
                                            boolean includeProfile) {
        final byte[] signed = RimGenerator.instance()
            .privateKey(signingKey.getPrivateKey())
            .publicKey(signingKey.getPublicKey())
            .newCorimFormat(newCorimFormat)
            .issuerKeyId(issuerKeyId)
            .layer0Digest(layer0Digest)
            .layer1Digest(layer1Digest)
            .includeProfile(includeProfile)
            .generate();
        return signed;
    }

    private TcbInfo prepareTcbInfoWithFirmwareVersion() {
        final Map<TcbInfoField, Object> map = Map.of(
            TcbInfoField.TYPE, TYPE,
            TcbInfoField.VENDOR, VENDOR,
            TcbInfoField.LAYER, LAYER,
            TcbInfoField.VERSION, VERSION
        );
        return new TcbInfo(map);
    }

    private TcbInfo prepareTcbInfoWithFwId() {
        final var map = Map.of(
            TcbInfoField.VENDOR, VENDOR,
            TcbInfoField.MODEL, MODEL,
            TcbInfoField.LAYER, LAYER,
            TcbInfoField.INDEX, INDEX,
            TcbInfoField.FWIDS, new FwIdField(HASH_ALG, FWID_DIGEST)
        );
        return new TcbInfo(map);
    }
}
