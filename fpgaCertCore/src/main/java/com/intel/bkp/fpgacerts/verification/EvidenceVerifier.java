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

package com.intel.bkp.fpgacerts.verification;

import com.intel.bkp.fpgacerts.dice.tcbinfo.MeasurementHolder;
import com.intel.bkp.fpgacerts.ect.ECTMap;
import com.intel.bkp.fpgacerts.ect.IECTMapStorage;
import com.intel.bkp.fpgacerts.rim.IRimHandlersProvider;
import com.intel.bkp.fpgacerts.rim.RimService;
import com.upokecenter.cbor.CBORObject;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

import static com.intel.bkp.fpgacerts.verification.VerificationResult.ERROR;
import static com.intel.bkp.fpgacerts.verification.VerificationResult.FAILED;
import static com.intel.bkp.fpgacerts.verification.VerificationResult.PASSED;

@Setter
@Slf4j
@RequiredArgsConstructor(access = AccessLevel.PACKAGE)
public class EvidenceVerifier {

    private final RimService rimService;
    private IECTMapStorage policyECTMapStorage;

    public EvidenceVerifier(IRimHandlersProvider rimHandlersProvider) {
        this(new RimService(rimHandlersProvider.getRimHandlers()));
    }

    public VerificationResult verify(List<ECTMap> acsECTMaps,
                                     String refMeasurementHex) {
        log.debug("Received TcbInfos from device: {}", acsECTMaps);

        try {
            return Optional.ofNullable(refMeasurementHex)
                .filter(StringUtils::isNotBlank)
                .map(rimService::getMeasurements)
                .map(holder -> verifyInternal(acsECTMaps, policyECTMapStorage, holder))
                .orElseGet(this::getResponseForEmptyRim);
        } catch (Exception e) {
            log.error("Exception occurred: {}", e.getMessage());
            log.debug("Stacktrace: ", e);
            return ERROR;
        }
    }

    private void measurementsAugmentation(List<ECTMap> acsECTMaps, List<IECTMapStorage> storages) {
        storages.stream()
            .filter(ect -> ect.getCondition() != null && !ect.getCondition().isEmpty())
            .filter(ect -> ect.getAddition() != null && !ect.getAddition().isEmpty())
            .filter(ect -> {
                log.info("Processing measurement: {}", ect.getCondition().stream()
                    .map(ECTMap::getEnvironment)
                    .map(CBORObject::toString)
                    .toList());
                var conditions = ect.getCondition();
                var additions = ect.getAddition();
                List<Integer> indexToBeRemoved = new ArrayList<>();
                boolean conditionsSatisfied = conditions.stream()
                    .allMatch(e -> {
                        if (e.getEnvironment() == null
                            || e.getElementList() == null) {
                            return false;
                        }
                        return !acsECTMaps.isEmpty() && acsECTMaps.stream()
                            .filter(acs -> acs.getEnvironment() != null)
                            .filter(acs -> acs.getElementList() != null && !acs.getElementList().isEmpty())
                            .filter(acs -> acs.getCmtype()
                                .map(cmType -> ECTMap.CMType.valueOf(cmType) == ECTMap.CMType.EVIDENCE
                                || ECTMap.CMType.valueOf(cmType) == ECTMap.CMType.REFERENCE_VALUES
                                || ECTMap.CMType.valueOf(cmType) == ECTMap.CMType.ENDORSEMENTS)
                                .orElse(false))
                            .anyMatch(acs -> {
                                boolean matchEnv = Arrays.equals(e.getEnvironment().EncodeToBytes(),
                                    acs.getEnvironment().EncodeToBytes());
                                boolean matchClaim = false;
                                if (matchEnv) {
                                    log.debug("Appraisal Claims Set (ACS) contains expected key.");
                                    log.debug("Condition measurement: {}", e.getElementList());
                                    log.debug("ACS measurement: {}", acs.getElementList());
                                    matchClaim = e.getElementList().equals(acs.getElementList());
                                    if (!matchClaim) {
                                        indexToBeRemoved.add(acsECTMaps.indexOf(acs));
                                    }
                                }

                                return matchEnv && matchClaim;
                            });
                    });

                if (conditionsSatisfied) {
                    log.info("""
                            Conditions are satisfied.
                            Addition measurements will be added to the Appraisal Claims Set (ACS).
                            Additions: {}
                            """, additions);
                    acsECTMaps.addAll(additions);
                } else {
                    log.warn("""
                            Failed to find matching condition measurements in Appraisal Claims Set (ACS).
                            Conditions are not satisfied.
                            Skip adding the addition measurements to the Appraisal Claims Set (ACS).
                            The corresponding measurements will be removed from Appraisal Claims Set (ACS) as well.
                            Conditions: {}
                            """, conditions);
                    for (Integer index : indexToBeRemoved) {
                        acsECTMaps.remove(index.intValue());
                    }
                }

                return conditionsSatisfied;
            })
            .toList();
    }

    private void phase3ReferenceValuesAugmentation(List<ECTMap> acsECTMaps,
                                                   MeasurementHolder measurementHolder) {

        if (!measurementHolder.getReferenceMeasurements().isEmpty()) {
            log.info("*** VERIFYING EVIDENCE AGAINST RIM ***");
            measurementsAugmentation(acsECTMaps, measurementHolder.getReferenceMeasurements());
        } else {
            getResponseForEmptyRim();
        }
    }

    private void phase4EndorsedValuesAugmentation(List<ECTMap> acsECTMaps,
                                                  MeasurementHolder measurementHolder) {

        if (!measurementHolder.getConditionalEndorsedMeasurements().isEmpty()) {
            log.info("*** PROCESSING ENDORSED MEASUREMENTS ***");

            List<IECTMapStorage> storages = new ArrayList<>(measurementHolder.getConditionalEndorsedMeasurements());
            // Reverse the order to process conditional-endorsed-triple from the highest nested level.
            Collections.reverse(storages);
            measurementsAugmentation(acsECTMaps, storages);
        }
    }

    private VerificationResult phase7AttestationResultsVerify(List<ECTMap> acsECTMaps,
                                                              MeasurementHolder measurementHolder,
                                                              IECTMapStorage appraisalPolicies) {
        log.info("*** VERIFYING ATTESTATION RESULTS ***");
        boolean matched = false;

        if (appraisalPolicies != null) {
            log.info("""
                Match Appraisal Claims Set (ACS) against policy set.
                Policies: {}
                """, appraisalPolicies.getCondition());
            matched = Optional.ofNullable(appraisalPolicies.getCondition())
                .map(condition -> condition.stream().allMatch(ectMap -> !acsECTMaps.isEmpty() && acsECTMaps.stream()
                    .anyMatch(ectMap::equals)))
                .orElse(false);
        } else {
            // Default method if appraisalPolicy is null at this stage
            if (!measurementHolder.getConditionalEndorsedMeasurements().isEmpty()) {
                matched = measurementHolder.getConditionalEndorsedMeasurements().stream()
                    .allMatch(condMeasurement -> !condMeasurement.getAddition().isEmpty()
                        && condMeasurement.getAddition().stream()
                            .allMatch(addition -> !acsECTMaps.isEmpty() && acsECTMaps.stream()
                                .anyMatch(addition::equals)));
            } else if (!measurementHolder.getReferenceMeasurements().isEmpty()) {
                matched = measurementHolder.getReferenceMeasurements().stream()
                    .allMatch(refMeasurement -> !refMeasurement.getAddition().isEmpty()
                        && refMeasurement.getAddition().stream()
                            .allMatch(addition -> !acsECTMaps.isEmpty() && acsECTMaps.stream()
                                .anyMatch(addition::equals)));

            }
        }

        return matched ? PASSED : FAILED;
    }

    private VerificationResult verifyInternal(List<ECTMap> acsECTMaps,
                                              IECTMapStorage policyECTMapStorage,
                                              MeasurementHolder measurementHolder) {

        phase3ReferenceValuesAugmentation(acsECTMaps, measurementHolder);
        phase4EndorsedValuesAugmentation(acsECTMaps, measurementHolder);

        VerificationResult result = phase7AttestationResultsVerify(acsECTMaps, measurementHolder, policyECTMapStorage);

        return result;
    }

    private VerificationResult getResponseForEmptyRim() {
        log.warn("List of expected measurements in RIM is empty.");
        return PASSED;
    }
}
