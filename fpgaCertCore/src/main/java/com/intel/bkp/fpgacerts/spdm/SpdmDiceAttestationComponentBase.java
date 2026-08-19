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

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.intel.bkp.fpgacerts.appraisalpolicy.AppraisalPolicy;
import com.intel.bkp.fpgacerts.appraisalpolicy.parser.AppraisalPolicyParser;
import com.intel.bkp.fpgacerts.cbor.exception.RimVerificationException;
import com.intel.bkp.fpgacerts.cbor.rim.RimSigned;
import com.intel.bkp.fpgacerts.cbor.rim.RimUnsigned;
import com.intel.bkp.fpgacerts.cbor.rim.comid.ConditionalEndorsedTriple;
import com.intel.bkp.fpgacerts.cbor.rim.comid.MeasurementMap;
import com.intel.bkp.fpgacerts.cbor.rim.comid.MeasurementVersion;
import com.intel.bkp.fpgacerts.cbor.rim.comid.ReferenceTriple;
import com.intel.bkp.fpgacerts.cbor.rim.parser.RimSignedParser;
import com.intel.bkp.fpgacerts.dice.DiceChainMeasurementsCollector;
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
import com.intel.bkp.fpgacerts.exceptions.SpdmAttestationException;
import com.intel.bkp.fpgacerts.measurements.IDeviceMeasurementsProvider;
import com.intel.bkp.fpgacerts.measurements.SpdmDeviceMeasurementsProvider;
import com.intel.bkp.fpgacerts.measurements.SpdmDeviceMeasurementsRequest;
import com.intel.bkp.fpgacerts.rim.IRimHandlersProvider;
import com.intel.bkp.fpgacerts.rim.RimUrlProvider;
import com.intel.bkp.fpgacerts.url.FetchDataSchemeBroker;
import com.intel.bkp.fpgacerts.verification.EvidenceVerifier;
import com.intel.bkp.fpgacerts.verification.VerificationResult;
import com.intel.bkp.protocol.spdm.jna.model.SpdmProtocol;
import com.intel.bkp.utils.HexConverter;
import com.upokecenter.cbor.CBORObject;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Supplier;

import static com.intel.bkp.fpgacerts.dice.tcbinfo.MeasurementType.FIRMWARE_VERSION;
import static com.intel.bkp.fpgacerts.model.DiceChainType.ATTESTATION;
import static com.intel.bkp.fpgacerts.model.DiceChainType.IID;
import static com.intel.bkp.protocol.spdm.jna.model.SpdmConstants.DEFAULT_SLOT_ID;
import static com.intel.bkp.utils.HexConverter.fromHex;

@Slf4j
@AllArgsConstructor(access = AccessLevel.PACKAGE)
public abstract class SpdmDiceAttestationComponentBase {

    private final IDeviceMeasurementsProvider<SpdmDeviceMeasurementsRequest> deviceMeasurementsProvider;
    private final EvidenceVerifier evidenceVerifier;
    private final Supplier<TcbInfoMeasurementsAggregator> tcbInfoMeasurementsAggregator;
    private final DiceChainMeasurementsCollector measurementsCollector;
    private final SpdmChainSearcherBase spdmChainSearcher;
    private final RimUrlProvider rimUrlProvider;
    private final RimUrlProvider newRimUrlProvider;
    private final IDistributionPointConnector dpConnector;
    private List<ECTMap> acsECTMapList = new ArrayList<>();
    private static final ObjectMapper objectMapper = new ObjectMapper();

    protected abstract boolean withMeasurementsSignatureVerification();

    public SpdmDiceAttestationComponentBase(SpdmProtocol spdmProtocol, SpdmChainSearcherBase spdmChainSearcher,
                                            IRimHandlersProvider rimHandlersProvider, RimUrlProvider rimUrlProvider,
                                            RimUrlProvider newRimUrlProvider, IDistributionPointConnector dpConnector) {
        this.deviceMeasurementsProvider = new SpdmDeviceMeasurementsProvider(spdmProtocol);
        this.evidenceVerifier = new EvidenceVerifier(rimHandlersProvider);
        this.tcbInfoMeasurementsAggregator = TcbInfoMeasurementsAggregator::new;
        this.measurementsCollector = new DiceChainMeasurementsCollector();
        this.spdmChainSearcher = spdmChainSearcher;
        this.rimUrlProvider = rimUrlProvider;
        this.newRimUrlProvider = newRimUrlProvider;
        this.dpConnector = dpConnector;
    }

    public VerificationResult perform(String refMeasurementHex,
                                      String policyContent,
                                      byte[] deviceId) {
        return perform(() -> refMeasurementHex,
                       policyContent,
                       deviceId).verificationResult();
    }

    public SpdmAttestationResult perform(Supplier<String> refMeasurementHexSupplier,
                                         String policyContent,
                                         byte[] deviceId) {
        final TcbInfoMeasurementsAggregator tcbInfoMeasurementsAggregator = this.tcbInfoMeasurementsAggregator.get();
        Integer slotId = null;
        String refMeasurements = null;
        IECTMapStorage appraisalPolicies = null;
        try {

            if (withMeasurementsSignatureVerification()) {
                final SpdmValidChains validChains = spdmChainSearcher.searchValidChains(deviceId);

                final var measurementsFromCertChain = getMeasurementsFromChain(validChains.get(ATTESTATION));
                final var iidUdsChainMeasurements = getMeasurementsFromChain(validChains.get(IID));
                slotId = getSlotId(validChains);
                final var measurementsFromDevice = getMeasurementsFromDevice(slotId);
                final var measurementsFromCertChainECTMaps = ECTMap.createAeECTMap(
                    measurementsFromCertChain,
                    Arrays.asList(spdmChainSearcher.getTrustedRootHashes())
                );
                final var iidUdsChainMeasurementsECTMaps = ECTMap.createAeECTMap(
                    iidUdsChainMeasurements,
                    Arrays.asList(spdmChainSearcher.getTrustedRootHashes())
                );
                final var measurementsFromDeviceECTMaps = ECTMap.createAeECTMap(
                    measurementsFromDevice,
                    Arrays.asList(spdmChainSearcher.getTrustedRootHashes())
                );

                log.info("*** COLLECTING EVIDENCE FROM CERTIFICATES AND DEVICE ***");
                // Phase 2 - Evidence Augmentation
                // Augments evidence ECTs to acsECTMaps list
                acsECTMapList.addAll(measurementsFromCertChainECTMaps.getAddition());
                acsECTMapList.addAll(iidUdsChainMeasurementsECTMaps.getAddition());
                acsECTMapList.addAll(measurementsFromDeviceECTMaps.getAddition());
                tcbInfoMeasurementsAggregator.add(measurementsFromCertChain);
                tcbInfoMeasurementsAggregator.add(iidUdsChainMeasurements);
                tcbInfoMeasurementsAggregator.add(measurementsFromDevice);

                if (refMeasurementHexSupplier == null
                    || !isValidJson(refMeasurementHexSupplier.get())) {

                    if (refMeasurementHexSupplier == null) {
                        // Auto fetch firmware corim based on current running firmware version
                        // Fetch firmware CoRIM from new CoRIM path (IPCS/rims_v2), if not present, then fetch from old CoRIM path (IPCS/rims)
                        refMeasurements = fetchFwCorimContent(validChains, tcbInfoMeasurementsAggregator);
                    }

                    // Prepare Appraisal Policy
                    appraisalPolicies = buildAppraisalPolicy(policyContent);

                    if (appraisalPolicies == null) {
                        // Build Appraisal Policy based on current running firmware version
                        // Fetch firmware CoRIM from new CoRIM path (IPCS/rims_v2), if not present, then fetch from old CoRIM path (IPCS/rims)
                        String measurements = refMeasurements;
                        if (measurements == null) {
                            measurements = fetchFwCorimContent(validChains, tcbInfoMeasurementsAggregator);
                        }

                        // Parse CoRIM to extract the firmware version
                        RimSigned rimSigned = RimSignedParser.instance().parse(CBORObject.DecodeFromBytes(fromHex(measurements)));
                        String firmwareVersion = Optional.ofNullable(rimSigned.getPayload())
                            .map(RimUnsigned::getComIds)
                            .map(comids -> Optional.ofNullable(comids.get(0).getClaims())
                                .map(claim -> Optional.ofNullable(claim.getConditionalEndorsedTriples())
                                    .map(ConditionalEndorsedTriple::getEndorsements)
                                    .or(() -> Optional.ofNullable(claim.getEndorsedTriples()))
                                    .orElse(null))
                                .map(endorsements -> endorsements.stream()
                                    .map(ReferenceTriple::getMeasurementMap)
                                    .map(MeasurementMap::getVersion)
                                    .map(MeasurementVersion::getVersion)
                                    .findFirst()
                                    .orElse(null))
                                .orElse(null))
                            .orElseThrow(() -> new SpdmAttestationException(
                                "Failed to retrieve firmware version from firmware CoRIM file."));

                        // Building Firmware version TcbInfo
                        final Map<TcbInfoField, Object> tcbInfoMap = Map.of(
                            TcbInfoField.TYPE, FIRMWARE_VERSION.getOid(),
                            TcbInfoField.VENDOR, TcbInfoConstants.VENDOR,
                            TcbInfoField.LAYER, FIRMWARE_VERSION.getLayer(),
                            TcbInfoField.VERSION, firmwareVersion
                        );

                        List<TcbInfoMeasurement> policies = List.of(new TcbInfoMeasurement(new TcbInfo(tcbInfoMap)));
                        appraisalPolicies = ECTMap.createPolicyECTMap(
                            policies,
                            Arrays.stream(spdmChainSearcher.getTrustedRootHashes()).toList(),
                            ECTMap.CMType.ENDORSEMENTS
                        );
                    }
                }
            } else {
                log.warn("Chain verification and measurements signature verification turned off!");

                log.info("*** COLLECTING EVIDENCE FROM DEVICE ***");
                slotId = DEFAULT_SLOT_ID;
                List<TcbInfoMeasurement> deviceMeasurements = getMeasurementsFromDevice(slotId);
                final var measurementsFromDeviceECTMaps = ECTMap.createAeECTMap(
                    deviceMeasurements,
                    Arrays.asList(spdmChainSearcher.getTrustedRootHashes()));
                acsECTMapList.addAll(measurementsFromDeviceECTMaps.getAddition());
            }
            evidenceVerifier.setPolicyECTMapStorage(appraisalPolicies);
            final VerificationResult verificationResult =
                evidenceVerifier.verify(
                    acsECTMapList,
                    Optional.ofNullable(refMeasurementHexSupplier)
                        .map(Supplier::get)
                        .orElse(refMeasurements));
            return new SpdmAttestationResult(verificationResult, slotId);
        } catch (Exception e) {
            log.error("Exception occurred during attestation: " + e.getMessage());
            log.debug("Stacktrace: ", e);
            return new SpdmAttestationResult(VerificationResult.ERROR, slotId);
        }
    }

    private IECTMapStorage buildAppraisalPolicy(String policyContent) throws JsonProcessingException {
        if (policyContent != null && !policyContent.isEmpty()) {
            AppraisalPolicy appraisalPolicy = AppraisalPolicyParser.instance().parse(policyContent);
            final var policies = appraisalPolicy.getPolicies().stream()
                .map(policy -> new TcbInfoMeasurement(policy))
                .toList();
            return ECTMap.createPolicyECTMap(
                policies,
                Arrays.stream(spdmChainSearcher.getTrustedRootHashes()).toList(),
                ECTMap.CMType.ENDORSEMENTS
            );
        }
        return null;
    }

    private boolean isValidJson(String jsonDataHex) {
        try {
            byte[] bytes = HexFormat.of().parseHex(jsonDataHex);

            // Convert byte array to string using UTF-8 encoding
            String jsonData = new String(bytes, StandardCharsets.UTF_8);

            objectMapper.readTree(jsonData);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private String fetchFwCorimContent(SpdmValidChains validChains, TcbInfoMeasurementsAggregator tcbInfoMeasurementsAggregator) {
        Optional<String> rimUrl = getNewRimUrl(validChains.get(ATTESTATION).chain(), tcbInfoMeasurementsAggregator.getMap());
        var measurements = FetchDataSchemeBroker.fetchData(rimUrl.orElse(null), dpConnector)
            .map(HexConverter::toLowerCaseHex)
            .orElse(null);

        if (measurements == null || measurements.isEmpty()) {
            rimUrl = getRimUrl(validChains.get(ATTESTATION).chain(), tcbInfoMeasurementsAggregator.getMap());
            measurements = rimUrl
                .map(url -> FetchDataSchemeBroker.fetchData(url, dpConnector)
                    .map(HexConverter::toLowerCaseHex)
                    .orElseThrow(() -> new RimVerificationException(
                        "failed to download data from path: %s".formatted(url))))
                .orElseThrow(() -> new RimVerificationException(
                    "failed to download CoRIM data, URL is empty"));
        }

        rimUrl.ifPresent(url -> log.info("Based on certificate chain and gathered evidence, URL to matching RIM is: {}", url));
        return measurements;
    }

    private Optional<String> getRimUrl(List<X509Certificate> chain, Map<TcbInfoKey, TcbInfoValue> evidence) {
        return Optional.ofNullable(rimUrlProvider)
            .map(p -> p.getRimUrl(chain, evidence));
    }

    private Optional<String> getNewRimUrl(List<X509Certificate> chain, Map<TcbInfoKey, TcbInfoValue> evidence) {
        return Optional.ofNullable(newRimUrlProvider)
                .map(p -> p.getRimUrl(chain, evidence));
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
