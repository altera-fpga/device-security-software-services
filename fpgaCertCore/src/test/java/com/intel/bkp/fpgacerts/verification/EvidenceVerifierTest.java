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

import ch.qos.logback.classic.Level;
import com.intel.bkp.fpgacerts.appraisalpolicy.AppraisalPolicy;
import com.intel.bkp.fpgacerts.appraisalpolicy.parser.AppraisalPolicyParser;
import com.intel.bkp.fpgacerts.dice.tcbinfo.FwIdField;
import com.intel.bkp.fpgacerts.dice.tcbinfo.MeasurementHolder;
import com.intel.bkp.fpgacerts.dice.tcbinfo.MeasurementType;
import com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfo;
import com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfoField;
import com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfoMeasurement;
import com.intel.bkp.fpgacerts.dice.tcbinfo.vendorinfo.MaskedVendorInfo;
import com.intel.bkp.fpgacerts.ect.ECTMap;
import com.intel.bkp.fpgacerts.ect.IECTMapStorage;
import com.intel.bkp.fpgacerts.rim.RimService;
import com.intel.bkp.test.FileUtils;
import com.intel.bkp.test.LoggerTestUtil;
import com.upokecenter.cbor.CBORObject;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

import static ch.qos.logback.classic.Level.DEBUG;
import static ch.qos.logback.classic.Level.INFO;
import static ch.qos.logback.classic.Level.WARN;
import static com.intel.bkp.fpgacerts.verification.VerificationResult.ERROR;
import static com.intel.bkp.fpgacerts.verification.VerificationResult.FAILED;
import static com.intel.bkp.fpgacerts.verification.VerificationResult.PASSED;
import static com.intel.bkp.test.FileUtils.TEST_FOLDER;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class EvidenceVerifierTest {

    private static final String REF_MEASUREMENT = "test";
    private static final String TYPE = MeasurementType.FIRMWARE_VERSION.getOid();
    private static final String VENDOR = "intel.com";
    private static final String VERSION = "fw-version";
    private static final String VENDOR_INFO = "0000000003000000";
    private static final String VENDOR_INFO_MASK = "FFFFFFFF000000FF";
    private static final String MODEL = "Agilex";
    private static final int INDEX = 0;
    private static final int LAYER = 1;
    private static final String HASH_ALG = "2.16.840.1.101.3.4.2.2";
    private static final String FWID_DIGEST = "20FF681A0882E29B481953888936209CB53DF9C5AAEC606A2C24A0FB138595124B8E3F24A12771BC3854CC68B40361AD";
    private static final String OWNER_SECURITY_FUSES_TYPE = "6086480186F84D010F0411";
    private final List<String> trustedRootHash = List.of("35E08599DD52CB7533764DEE65C915BBAFD0E35E6252BCCD77F3A694390F618B");

    @Mock
    private RimService rimService;

    @Mock
    private List<ECTMap> acsEctMapList;

    private EvidenceVerifier sut;

    private LoggerTestUtil loggerTestUtil;

    @BeforeEach
    void setUpClass() {
        sut = new EvidenceVerifier(rimService);
        loggerTestUtil = LoggerTestUtil.instance(sut.getClass());
    }

    @AfterEach
    void clearLogs() {
        loggerTestUtil.reset();
    }

    @Test
    void verify_WithEmptyRim_ReturnsOk() {
        // when
        final VerificationResult result = sut.verify(acsEctMapList, "");

        // then
        assertEquals(PASSED, result);
        verifyLogExists("List of expected measurements in RIM is empty.", WARN);
    }

    @Test
    void verify_ThrowsException_ReturnsError() {
        // given
        doThrow(new IllegalArgumentException()).when(rimService).getMeasurements(REF_MEASUREMENT);

        // when
        final VerificationResult result = sut.verify(acsEctMapList, REF_MEASUREMENT);

        // then
        assertEquals(ERROR, result);
    }

    @Test
    void verify_ResponseWithoutEndorsements_Failed() throws Exception {
        // given
        final var tcbInfo = prepareTcbInfoWithOwnerSecurityFuses(VENDOR_INFO);
        final var referenceMeasurements = prepareReferenceMeasurements(tcbInfo);
        final var evidenceMeasurements = prepareEvidenceMeasurements(tcbInfo);
        when(rimService.getMeasurements(REF_MEASUREMENT)).thenReturn(referenceMeasurements);
        final var policyECTMap = prepareAppraisalPolicies("test_appraisal_policy_fw_only.txt", ECTMap.CMType.ENDORSEMENTS);

        // when
        sut.setPolicyECTMapStorage(policyECTMap);
        final VerificationResult result = sut.verify(evidenceMeasurements, REF_MEASUREMENT);

        // then
        assertEquals(FAILED, result);
        verifyLogExists("*** VERIFYING EVIDENCE AGAINST RIM ***", INFO);
        verifyLogExists("Processing measurement: %s".formatted(referenceMeasurements
            .getReferenceMeasurements()
            .get(0)
            .getCondition()
            .stream()
            .map(ECTMap::getEnvironment)
            .map(CBORObject::toString)
            .toList()), INFO);
        verifyLogExists("Condition measurement: %s".formatted(referenceMeasurements
            .getReferenceMeasurements()
            .get(0)
            .getCondition()
            .get(0)
            .getElementList()
        ), DEBUG);
        verifyLogExists("ACS measurement: %s".formatted(evidenceMeasurements
            .get(0)
            .getElementList()), DEBUG);
        verifyLogExists("Conditions are satisfied.\n" +
            "Addition measurements will be added to the Appraisal Claims Set (ACS).\n" +
            "Additions: %s".formatted(referenceMeasurements
                .getReferenceMeasurements()
                .stream()
                .map(IECTMapStorage::getAddition)
                .flatMap(List::stream)
                .toList()), INFO);
        assertTrue(referenceMeasurements
            .getReferenceMeasurements()
            .stream()
            .map(IECTMapStorage::getAddition)
            .flatMap(List::stream)
            .anyMatch(e -> evidenceMeasurements.contains(e)));
    }

    @Test
    void verify_ResponseContainsMoreMeasurementsThanReference_Passed() throws Exception {
        // given
        final var tcbInfo1Masked = prepareTcbInfoWithOwnerSecurityFusesMasked(VENDOR_INFO);
        final var tcbInfo2 = prepareTcbInfoWithFwId();
        final var endorsedTcbInfo = prepareTcbInfoWithFirmwareVersion();
        final var referenceMeasurements = prepareReferenceMeasurements(tcbInfo1Masked);
        referenceMeasurements.add(prepareEndorsedMeasurements(List.of(tcbInfo1Masked), List.of(endorsedTcbInfo)));
        final var evidenceMeasurements = prepareEvidenceMeasurements(tcbInfo1Masked, tcbInfo2);
        when(rimService.getMeasurements(REF_MEASUREMENT)).thenReturn(referenceMeasurements);
        final var policyECTMap = prepareAppraisalPolicies("test_appraisal_policy_fw_only.txt", ECTMap.CMType.ENDORSEMENTS);

        // when
        sut.setPolicyECTMapStorage(policyECTMap);
        final VerificationResult result = sut.verify(evidenceMeasurements, REF_MEASUREMENT);

        // then
        assertEquals(PASSED, result);
        verifyLogExists("*** VERIFYING EVIDENCE AGAINST RIM ***", INFO);
        verifyLogExists("Processing measurement: %s".formatted(referenceMeasurements
            .getReferenceMeasurements()
            .get(0)
            .getCondition()
            .stream()
            .map(ECTMap::getEnvironment)
            .map(CBORObject::toString)
            .toList()), INFO);
        verifyLogExists("Condition measurement: %s".formatted(referenceMeasurements
            .getReferenceMeasurements()
            .get(0)
            .getCondition()
            .get(0)
            .getElementList()
        ), DEBUG);
        verifyLogExists("ACS measurement: %s".formatted(evidenceMeasurements
            .get(0)
            .getElementList()), DEBUG);
        verifyLogExists("Conditions are satisfied.\n" +
            "Addition measurements will be added to the Appraisal Claims Set (ACS).\n" +
            "Additions: %s".formatted(referenceMeasurements
                .getReferenceMeasurements()
                .stream()
                .map(IECTMapStorage::getAddition)
                .flatMap(List::stream)
                .toList()), INFO);
        verifyLogExists("*** PROCESSING ENDORSED MEASUREMENTS ***", INFO);
        verifyLogExists("Processing measurement: %s".formatted(referenceMeasurements
            .getConditionalEndorsedMeasurements()
            .stream()
            .map(IECTMapStorage::getCondition)
            .flatMap(List::stream)
            .map(ECTMap::getEnvironment)
            .map(CBORObject::toString)
            .toList()), INFO);
        verifyLogExists("Condition measurement: %s".formatted(referenceMeasurements
            .getConditionalEndorsedMeasurements()
            .get(0)
            .getCondition()
            .get(0)
            .getElementList()
        ), DEBUG);
        verifyLogExists("ACS measurement: %s".formatted(evidenceMeasurements
            .get(0)
            .getElementList()), DEBUG);
        verifyLogExists("Conditions are satisfied.\n" +
            "Addition measurements will be added to the Appraisal Claims Set (ACS).\n" +
            "Additions: %s".formatted(referenceMeasurements
                .getConditionalEndorsedMeasurements()
                .stream()
                .map(IECTMapStorage::getAddition)
                .flatMap(List::stream)
                .toList()), INFO);
        assertTrue(referenceMeasurements
            .getReferenceMeasurements()
            .stream()
            .map(IECTMapStorage::getAddition)
            .flatMap(List::stream)
            .allMatch(e -> evidenceMeasurements.contains(e)));
        assertTrue(referenceMeasurements
            .getConditionalEndorsedMeasurements()
            .stream()
            .map(IECTMapStorage::getAddition)
            .flatMap(List::stream)
            .allMatch(ectMap -> evidenceMeasurements
                .stream()
                .anyMatch(acsECTMap -> acsECTMap.equals(ectMap)))
        );
    }

    @Test
    void verify_ResponseContainsLessMeasurementsThanReference_Failed() throws Exception {
        // given
        final var tcbInfo1Masked = prepareTcbInfoWithOwnerSecurityFusesMasked(VENDOR_INFO);
        final var tcbInfo2 = prepareTcbInfoWithFwId();
        final var endorsedTcbInfo = prepareTcbInfoWithFirmwareVersion();
        final var referenceMeasurements = prepareReferenceMeasurements(tcbInfo1Masked, tcbInfo2);
        referenceMeasurements.add(prepareEndorsedMeasurements(List.of(tcbInfo1Masked, tcbInfo2), List.of(endorsedTcbInfo)));
        final var evidenceMeasurements = prepareEvidenceMeasurements(tcbInfo1Masked);
        when(rimService.getMeasurements(REF_MEASUREMENT)).thenReturn(referenceMeasurements);
        final var policyECTMap = prepareAppraisalPolicies("test_appraisal_policy_fw_only.txt", ECTMap.CMType.ENDORSEMENTS);

        // when
        sut.setPolicyECTMapStorage(policyECTMap);
        final VerificationResult result = sut.verify(evidenceMeasurements, REF_MEASUREMENT);

        // then
        assertEquals(FAILED, result);
        verifyLogExists("*** VERIFYING EVIDENCE AGAINST RIM ***", INFO);
        verifyLogExists("Processing measurement: %s".formatted(referenceMeasurements
            .getReferenceMeasurements()
            .get(0)
            .getCondition()
            .stream()
            .map(ECTMap::getEnvironment)
            .map(CBORObject::toString)
            .toList()), INFO);
        verifyLogExists("Condition measurement: %s".formatted(referenceMeasurements
            .getReferenceMeasurements()
            .get(0)
            .getCondition()
            .get(0)
            .getElementList()
        ), DEBUG);
        verifyLogExists("ACS measurement: %s".formatted(evidenceMeasurements
            .get(0)
            .getElementList()), DEBUG);
        verifyLogExists("Conditions are satisfied.\n" +
            "Addition measurements will be added to the Appraisal Claims Set (ACS).\n" +
            "Additions: %s".formatted(referenceMeasurements
                .getReferenceMeasurements()
                .get(0)
                .getAddition()), INFO);
        verifyLogExists("Failed to find matching condition measurements in Appraisal Claims Set (ACS).\n" +
            "Conditions are not satisfied.\n" +
            "Skip adding the addition measurements to the Appraisal Claims Set (ACS).\n" +
            "The corresponding measurements will be removed from Appraisal Claims Set (ACS) as well.\n" +
            "Conditions: %s".formatted(referenceMeasurements
                .getConditionalEndorsedMeasurements()
                .stream()
                .map(IECTMapStorage::getCondition)
                .flatMap(List::stream)
                .toList()), WARN);
        assertTrue(referenceMeasurements
            .getReferenceMeasurements()
            .get(0)
            .getAddition()
            .stream()
            .allMatch(e -> evidenceMeasurements.contains(e)));
        assertFalse(referenceMeasurements
            .getConditionalEndorsedMeasurements()
            .stream()
            .map(IECTMapStorage::getAddition)
            .flatMap(List::stream)
            .allMatch(ectMap -> evidenceMeasurements
                .stream()
                .anyMatch(acsECTMap -> acsECTMap.equals(ectMap)))
        );
    }

    @Test
    void verify_ResponseContainsEndorsedButNoReference_Passed() throws Exception {
        // given
        final var tcbInfo1Masked = prepareTcbInfoWithOwnerSecurityFusesMasked(VENDOR_INFO);
        final var endorsedTcbInfo = prepareTcbInfoWithFirmwareVersion();
        final var endorsedMeasurements = prepareEndorsedMeasurements(List.of(tcbInfo1Masked), List.of(endorsedTcbInfo));
        final var evidenceMeasurements = prepareEvidenceMeasurements(tcbInfo1Masked);
        when(rimService.getMeasurements(REF_MEASUREMENT)).thenReturn(endorsedMeasurements);
        final var policyECTMap = prepareAppraisalPolicies("test_appraisal_policy_fw_only.txt", ECTMap.CMType.ENDORSEMENTS);

        // when
        sut.setPolicyECTMapStorage(policyECTMap);
        final VerificationResult result = sut.verify(evidenceMeasurements, REF_MEASUREMENT);

        // then
        assertEquals(PASSED, result);
        verifyLogExists("List of expected measurements in RIM is empty.", WARN);
        verifyLogExists("*** PROCESSING ENDORSED MEASUREMENTS ***", INFO);
        verifyLogExists("Processing measurement: %s"
            .formatted(endorsedMeasurements
                .getConditionalEndorsedMeasurements()
                .get(0)
                .getCondition()
                .stream()
                .map(ECTMap::getEnvironment)
                .map(CBORObject::toString)
                .toList()), INFO);
        verifyLogExists("Condition measurement: %s".formatted(endorsedMeasurements
            .getConditionalEndorsedMeasurements()
            .get(0)
            .getCondition()
            .get(0)
            .getElementList()
        ), DEBUG);
        verifyLogExists("ACS measurement: %s".formatted(evidenceMeasurements
            .get(0)
            .getElementList()), DEBUG);
        verifyLogExists("Conditions are satisfied.\n" +
            "Addition measurements will be added to the Appraisal Claims Set (ACS).\n" +
            "Additions: %s".formatted(endorsedMeasurements
                .getConditionalEndorsedMeasurements()
                .stream()
                .map(IECTMapStorage::getAddition)
                .flatMap(List::stream)
                .toList()), INFO);
        assertTrue(endorsedMeasurements
                .getConditionalEndorsedMeasurements()
                .stream()
                .map(IECTMapStorage::getAddition)
                .flatMap(List::stream)
                .allMatch(ectMap -> evidenceMeasurements
                    .stream()
                    .anyMatch(acsECTMap -> acsECTMap.equals(ectMap)))
        );
    }

    @Test
    void verify_ResponseContainsEndorsedButNoReference_WithEmptyEvidence_Failed() throws Exception {
        // given
        final var tcbInfo1Masked = prepareTcbInfoWithOwnerSecurityFusesMasked(VENDOR_INFO);
        final var endorsedTcbInfo = prepareTcbInfoWithFirmwareVersion();
        final var endorsedMeasurements = prepareEndorsedMeasurements(List.of(tcbInfo1Masked), List.of(endorsedTcbInfo));
        when(rimService.getMeasurements(REF_MEASUREMENT)).thenReturn(endorsedMeasurements);
        final var policyECTMap = prepareAppraisalPolicies("test_appraisal_policy_fw_only.txt", ECTMap.CMType.ENDORSEMENTS);

        // when
        sut.setPolicyECTMapStorage(policyECTMap);
        sut.verify(acsEctMapList, REF_MEASUREMENT);

        // then
        verifyLogExists("List of expected measurements in RIM is empty.", WARN);
        verifyLogExists("*** PROCESSING ENDORSED MEASUREMENTS ***", INFO);
        verifyLogExists("Processing measurement: %s"
            .formatted(endorsedMeasurements.getConditionalEndorsedMeasurements().get(0).getCondition()
                .stream()
                .map(ECTMap::getEnvironment)
                .map(CBORObject::toString)
                .toList()), INFO);
        verifyLogDoesNotExist("Conditions are satisfied.\n" +
                "Addition measurements will be added to the Appraisal Claims Set (ACS).\n", INFO);
        assertFalse(endorsedMeasurements
            .getConditionalEndorsedMeasurements()
            .stream()
            .map(IECTMapStorage::getAddition)
            .flatMap(List::stream)
            .allMatch(ectMap -> acsEctMapList
                .stream()
                .anyMatch(acsECTMap -> acsECTMap.equals(ectMap)))
        );
    }

    @Test
    void verify_ResponseContainsMoreMeasurementsThanEndorsed_Passed() throws Exception {
        // given
        final var tcbInfo1Masked = prepareTcbInfoWithOwnerSecurityFusesMasked(VENDOR_INFO);
        final var tcbInfo2 = prepareTcbInfoWithFwId();
        final var endorsedTcbInfo = prepareTcbInfoWithFirmwareVersion();
        final var endorsedMeasurements = prepareEndorsedMeasurements(List.of(tcbInfo1Masked), List.of(endorsedTcbInfo));
        final var evidenceMeasurements = prepareEvidenceMeasurements(tcbInfo1Masked, tcbInfo2);
        when(rimService.getMeasurements(REF_MEASUREMENT)).thenReturn(endorsedMeasurements);
        final var policyECTMap = prepareAppraisalPolicies("test_appraisal_policy_fw_only.txt", ECTMap.CMType.ENDORSEMENTS);

        // when
        sut.setPolicyECTMapStorage(policyECTMap);
        final VerificationResult result = sut.verify(evidenceMeasurements, REF_MEASUREMENT);

        // then
        assertEquals(PASSED, result);
        verifyLogExists("*** PROCESSING ENDORSED MEASUREMENTS ***", INFO);
        verifyLogExists("Processing measurement: %s"
            .formatted(endorsedMeasurements
                .getConditionalEndorsedMeasurements()
                .get(0)
                .getCondition()
                .stream()
                .map(ECTMap::getEnvironment)
                .map(CBORObject::toString)
                .toList()), INFO);
        verifyLogExists("Condition measurement: %s".formatted(endorsedMeasurements
            .getConditionalEndorsedMeasurements()
            .get(0)
            .getCondition()
            .get(0)
            .getElementList()), DEBUG);
        verifyLogExists("ACS measurement: %s".formatted(evidenceMeasurements
            .get(0)
            .getElementList()), DEBUG);
        verifyLogExists("Conditions are satisfied.\n" +
            "Addition measurements will be added to the Appraisal Claims Set (ACS).\n" +
            "Additions: %s".formatted(endorsedMeasurements
                .getConditionalEndorsedMeasurements()
                .stream()
                .map(IECTMapStorage::getAddition)
                .flatMap(List::stream)
                .toList()), INFO);
        assertTrue(endorsedMeasurements
            .getConditionalEndorsedMeasurements()
            .stream()
            .map(IECTMapStorage::getAddition)
            .flatMap(List::stream)
            .allMatch(ectMap -> evidenceMeasurements
                .stream()
                .anyMatch(acsECTMap -> acsECTMap.equals(ectMap)))
        );
    }

    @Test
    void verify_ResponseContainsLessMeasurementsThanEndorsed_Failed() throws Exception {
        // given
        final var tcbInfo1Masked = prepareTcbInfoWithOwnerSecurityFusesMasked(VENDOR_INFO);
        final var tcbInfo2 = prepareTcbInfoWithFwId();
        final var endorsedTcbInfo = prepareTcbInfoWithFirmwareVersion();
        final var endorsedMeasurements = prepareEndorsedMeasurements(List.of(tcbInfo1Masked, tcbInfo2), List.of(endorsedTcbInfo));
        final var evidenceMeasurements = prepareEvidenceMeasurements(tcbInfo1Masked);
        when(rimService.getMeasurements(REF_MEASUREMENT)).thenReturn(endorsedMeasurements);
        final var policyECTMap = prepareAppraisalPolicies("test_appraisal_policy_fw_only.txt", ECTMap.CMType.ENDORSEMENTS);

        // when
        sut.setPolicyECTMapStorage(policyECTMap);
        final VerificationResult result = sut.verify(evidenceMeasurements, REF_MEASUREMENT);

        // then
        assertEquals(FAILED, result);
        verifyLogExists("*** PROCESSING ENDORSED MEASUREMENTS ***", INFO);
        verifyLogExists("Processing measurement: %s"
            .formatted(endorsedMeasurements
                .getConditionalEndorsedMeasurements()
                .get(0)
                .getCondition()
                .stream()
                .map(ECTMap::getEnvironment)
                .map(CBORObject::toString)
                .toList()), INFO);
        verifyLogExists("Condition measurement: %s".formatted(
            endorsedMeasurements
                .getConditionalEndorsedMeasurements()
                .get(0)
                .getCondition()
                .get(0)
                .getElementList()
        ), DEBUG);
        verifyLogExists("ACS measurement: %s".formatted(evidenceMeasurements
            .get(0)
            .getElementList()), DEBUG);
        verifyLogExists("Failed to find matching condition measurements in Appraisal Claims Set (ACS).\n" +
            "Conditions are not satisfied.\n" +
            "Skip adding the addition measurements to the Appraisal Claims Set (ACS).\n" +
            "The corresponding measurements will be removed from Appraisal Claims Set (ACS) as well.\n" +
            "Conditions: %s".formatted(endorsedMeasurements
                .getConditionalEndorsedMeasurements()
                .get(0)
                .getCondition()), WARN);
        assertFalse(endorsedMeasurements
            .getConditionalEndorsedMeasurements()
            .stream()
            .map(IECTMapStorage::getAddition)
            .flatMap(List::stream)
            .allMatch(ectMap -> evidenceMeasurements
                .stream()
                .anyMatch(acsECTMap -> acsECTMap.equals(ectMap)))
        );
    }

    @Test
    void verify_MeasurementInResponseContainsLesserValueThanReferenceMeasurement_Failed() throws Exception {
        // given
        final var tcbInfo = prepareTcbInfoWithFwId();
        final var tcbInfoWithAdditionalValue = prepareTcbInfoWithFwIdAndAdditionalVendorInfo();
        final var endorsedTcbInfo = prepareTcbInfoWithFirmwareVersion();
        final var referenceMeasurements = prepareReferenceMeasurements(tcbInfoWithAdditionalValue);
        final var endorsedMeasurements = prepareEndorsedMeasurements(List.of(tcbInfoWithAdditionalValue), List.of(endorsedTcbInfo));
        referenceMeasurements.add(endorsedMeasurements);
        final var evidenceMeasurements = prepareEvidenceMeasurements(tcbInfo);
        final var evidenceMeasurementsBackup = prepareEvidenceMeasurements(tcbInfo);
        when(rimService.getMeasurements(REF_MEASUREMENT)).thenReturn(referenceMeasurements);
        final var policyECTMap = prepareAppraisalPolicies("test_appraisal_policy_fw_only.txt", ECTMap.CMType.ENDORSEMENTS);

        // when
        sut.setPolicyECTMapStorage(policyECTMap);
        final VerificationResult result = sut.verify(evidenceMeasurements, REF_MEASUREMENT);

        // then
        assertEquals(FAILED, result);
        verifyLogExists("*** PROCESSING ENDORSED MEASUREMENTS ***", INFO);
        verifyLogExists("Processing measurement: %s"
            .formatted(endorsedMeasurements
                .getConditionalEndorsedMeasurements()
                .get(0)
                .getCondition()
                .stream()
                .map(ECTMap::getEnvironment)
                .map(CBORObject::toString)
                .toList()), INFO);
        verifyLogExists("Condition measurement: %s".formatted(
            endorsedMeasurements
                .getConditionalEndorsedMeasurements()
                .get(0)
                .getCondition()
                .get(0)
                .getElementList()
        ), DEBUG);
        verifyLogExists("ACS measurement: %s".formatted(evidenceMeasurementsBackup.get(0).getElementList()), DEBUG);
        verifyLogExists("Failed to find matching condition measurements in Appraisal Claims Set (ACS).\n" +
            "Conditions are not satisfied.\n" +
            "Skip adding the addition measurements to the Appraisal Claims Set (ACS).\n" +
            "The corresponding measurements will be removed from Appraisal Claims Set (ACS) as well.\n" +
            "Conditions: %s".formatted(endorsedMeasurements
                .getConditionalEndorsedMeasurements()
                .get(0)
                .getCondition()), WARN);
        assertFalse(endorsedMeasurements
            .getConditionalEndorsedMeasurements()
            .stream()
            .map(IECTMapStorage::getAddition)
            .flatMap(List::stream)
            .allMatch(ectMap -> evidenceMeasurementsBackup
                .stream()
                .anyMatch(acsECTMap -> acsECTMap.equals(ectMap)))
        );
    }

    @Test
    void verify_MeasurementInResponseContainsAdditionalValueNotPresentInReferenceMeasurement_Passed() throws Exception {
        // given
        final var tcbInfo = prepareTcbInfoWithFwId();
        final var tcbInfoWithAdditionalValue = prepareTcbInfoWithFwIdAndAdditionalVendorInfo();
        final var endorsedTcbInfo = prepareTcbInfoWithFirmwareVersion();
        final var referenceMeasurements = prepareReferenceMeasurements(tcbInfo);
        referenceMeasurements.add(prepareEndorsedMeasurements(List.of(tcbInfo), List.of(endorsedTcbInfo)));
        final var evidenceMeasurements = prepareEvidenceMeasurements(tcbInfoWithAdditionalValue);
        when(rimService.getMeasurements(REF_MEASUREMENT)).thenReturn(referenceMeasurements);
        final var policyECTMap = prepareAppraisalPolicies("test_appraisal_policy_fw_only.txt", ECTMap.CMType.ENDORSEMENTS);

        // when
        sut.setPolicyECTMapStorage(policyECTMap);
        final VerificationResult result = sut.verify(evidenceMeasurements, REF_MEASUREMENT);

        // then
        assertEquals(PASSED, result);
        verifyLogExists("Processing measurement: %s".formatted(referenceMeasurements
            .getReferenceMeasurements()
            .get(0)
            .getCondition()
            .stream()
            .map(ECTMap::getEnvironment)
            .map(CBORObject::toString)
            .toList()), INFO);
        verifyLogExists("Condition measurement: %s".formatted(referenceMeasurements
            .getReferenceMeasurements()
            .get(0)
            .getCondition()
            .get(0)
            .getElementList()
        ), DEBUG);
        verifyLogExists("ACS measurement: %s".formatted(evidenceMeasurements
            .get(0)
            .getElementList()), DEBUG);
        verifyLogExists("Conditions are satisfied.\n" +
            "Addition measurements will be added to the Appraisal Claims Set (ACS).\n" +
            "Additions: %s".formatted(referenceMeasurements
                .getReferenceMeasurements()
                .stream()
                .map(IECTMapStorage::getAddition)
                .flatMap(List::stream)
                .toList()), INFO);
        verifyLogExists("*** PROCESSING ENDORSED MEASUREMENTS ***", INFO);
        verifyLogExists("Processing measurement: %s".formatted(referenceMeasurements
            .getConditionalEndorsedMeasurements()
            .stream()
            .map(IECTMapStorage::getCondition)
            .flatMap(List::stream)
            .map(ECTMap::getEnvironment)
            .map(CBORObject::toString)
            .toList()), INFO);
        verifyLogExists("Condition measurement: %s".formatted(referenceMeasurements
            .getConditionalEndorsedMeasurements()
            .get(0)
            .getCondition()
            .get(0)
            .getElementList()
        ), DEBUG);
        verifyLogExists("ACS measurement: %s".formatted(evidenceMeasurements
            .get(0)
            .getElementList()), DEBUG);
        verifyLogExists("Conditions are satisfied.\n" +
            "Addition measurements will be added to the Appraisal Claims Set (ACS).\n" +
            "Additions: %s".formatted(referenceMeasurements
                .getConditionalEndorsedMeasurements()
                .stream()
                .map(IECTMapStorage::getAddition)
                .flatMap(List::stream)
                .toList()), INFO);
        assertTrue(referenceMeasurements
            .getReferenceMeasurements()
            .stream()
            .map(IECTMapStorage::getAddition)
            .flatMap(List::stream)
            .allMatch(e -> evidenceMeasurements.contains(e)));
        assertTrue(referenceMeasurements
            .getConditionalEndorsedMeasurements()
            .stream()
            .map(IECTMapStorage::getAddition)
            .flatMap(List::stream)
            .allMatch(ectMap -> evidenceMeasurements
                .stream()
                .anyMatch(acsECTMap -> acsECTMap.equals(ectMap)))
        );
    }

    @Test
    void verify_MissingMeasurementInResponse_WithReferenceOnly_Failed() {
        // given
        final var tcbInfo = prepareTcbInfoWithOwnerSecurityFuses(VENDOR_INFO);
        final var referenceMeasurements = prepareReferenceMeasurements(tcbInfo);
        when(rimService.getMeasurements(REF_MEASUREMENT)).thenReturn(referenceMeasurements);

        // when
        final VerificationResult result = sut.verify(acsEctMapList, REF_MEASUREMENT);

        // then
        assertEquals(FAILED, result);
        verifyLogExists("*** VERIFYING EVIDENCE AGAINST RIM ***", INFO);
        verifyLogExists("Processing measurement: %s".formatted(referenceMeasurements
            .getReferenceMeasurements()
            .stream()
            .map(IECTMapStorage::getCondition)
            .flatMap(List::stream)
            .map(ECTMap::getEnvironment)
            .map(CBORObject::toString)
            .toList()), INFO);
        verifyLogExists("Failed to find matching condition measurements in Appraisal Claims Set (ACS).\n" +
            "Conditions are not satisfied.\n" +
            "Skip adding the addition measurements to the Appraisal Claims Set (ACS).\n" +
            "The corresponding measurements will be removed from Appraisal Claims Set (ACS) as well.\n" +
            "Conditions: %s".formatted(referenceMeasurements
                .getReferenceMeasurements()
                .stream()
                .map(IECTMapStorage::getCondition)
                .flatMap(List::stream)
                .toList()), WARN);
    }

    private List<ECTMap> prepareEvidenceMeasurements(TcbInfo... tcbInfos) {
        List<TcbInfoMeasurement> tcbInfoMeasurements = Arrays.stream(tcbInfos).map(TcbInfoMeasurement::new)
            .collect(Collectors.toList());
        var evidence = ECTMap.createAeECTMap(tcbInfoMeasurements, trustedRootHash);
        return evidence.getAddition();
    }

    private MeasurementHolder prepareReferenceMeasurements(TcbInfo... tcbInfos) {
        final var holder = new MeasurementHolder();
        List<TcbInfoMeasurement> tcbInfoMeasurements = Arrays.stream(tcbInfos).map(TcbInfoMeasurement::new)
                                                        .collect(Collectors.toList());
        holder.setReferenceMeasurements(ECTMap.createRvECTMap(tcbInfoMeasurements, trustedRootHash));
        return holder;
    }

    private MeasurementHolder prepareEndorsedMeasurements(List<TcbInfo> condTcbInfos, List<TcbInfo> endTcbInfos) {
        final var holder = new MeasurementHolder();
        List<TcbInfoMeasurement> condTcbInfoMeasurements = condTcbInfos.stream().map(TcbInfoMeasurement::new)
                                                        .collect(Collectors.toList());
        List<TcbInfoMeasurement> endTcbInfoMeasurements = endTcbInfos.stream().map(TcbInfoMeasurement::new)
            .collect(Collectors.toList());
        holder.setConditionalEndorsedMeasurements(List.of(ECTMap.createEvECTMap(condTcbInfoMeasurements, endTcbInfoMeasurements, trustedRootHash)));
        return holder;
    }

    private static String removeSlashPatterns(String jsonString) {
        // Regex matches: slash + spaces + non-slash chars + spaces + slash
        String pattern = "/\\s*[^/]+\\s*/";

        // Remove all occurrences of the pattern
        return jsonString.replaceAll(pattern, "");
    }

    private IECTMapStorage prepareAppraisalPolicies(String policyTemplate, ECTMap.CMType cmType) throws Exception {
        String jsonWithPattern = FileUtils.readFromResourcesAsString(TEST_FOLDER, policyTemplate);
        String cleanedJson = removeSlashPatterns(jsonWithPattern);
        AppraisalPolicy appraisalPolicies = AppraisalPolicyParser.instance().parse(cleanedJson);
        var policies = Optional.ofNullable(appraisalPolicies)
            .map(AppraisalPolicy::getPolicies)
            .stream()
            .flatMap(List::stream)
            .map(policy -> new TcbInfoMeasurement(policy))
            .toList();
        final var policyECTMap = ECTMap.createPolicyECTMap(policies, trustedRootHash, cmType);
        return policyECTMap;
    }

    private TcbInfo prepareTcbInfoWithOwnerSecurityFusesMasked(String ownerSecurityFuses) {
        return prepareTcbInfoWithOwnerSecurityFuses(new MaskedVendorInfo(ownerSecurityFuses, VENDOR_INFO_MASK));
    }

    private TcbInfo prepareTcbInfoWithOwnerSecurityFuses(String ownerSecurityFuses) {
        return prepareTcbInfoWithOwnerSecurityFuses(new MaskedVendorInfo(ownerSecurityFuses));
    }

    private TcbInfo prepareTcbInfoWithOwnerSecurityFuses(MaskedVendorInfo vendorInfo) {
        final Map<TcbInfoField, Object> map = Map.of(
            TcbInfoField.VENDOR, VENDOR,
            TcbInfoField.LAYER, LAYER,
            TcbInfoField.VENDOR_INFO, vendorInfo,
            TcbInfoField.TYPE, OWNER_SECURITY_FUSES_TYPE
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

    private TcbInfo prepareTcbInfoWithFwIdAndAdditionalVendorInfo() {
        final var map = Map.of(
            TcbInfoField.VENDOR, VENDOR,
            TcbInfoField.MODEL, MODEL,
            TcbInfoField.LAYER, LAYER,
            TcbInfoField.INDEX, INDEX,
            TcbInfoField.FWIDS, new FwIdField(HASH_ALG, FWID_DIGEST),
            TcbInfoField.VENDOR_INFO, VENDOR_INFO
        );
        return new TcbInfo(map);
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

    private void verifyLogExists(String log, Level level) {
        assertTrue(loggerTestUtil.contains(log, level));
    }

    private void verifyLogDoesNotExist(String log, Level level) {
        assertFalse(loggerTestUtil.contains(log, level));
    }
}
