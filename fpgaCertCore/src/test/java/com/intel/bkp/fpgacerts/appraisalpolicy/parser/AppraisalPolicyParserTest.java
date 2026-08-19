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

package com.intel.bkp.fpgacerts.appraisalpolicy.parser;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.intel.bkp.fpgacerts.appraisalpolicy.AppraisalPolicy;
import com.intel.bkp.fpgacerts.appraisalpolicy.Environment;
import com.intel.bkp.fpgacerts.appraisalpolicy.Measurement;
import com.intel.bkp.fpgacerts.appraisalpolicy.Policy;
import com.intel.bkp.fpgacerts.cbor.rim.comid.MeasurementMap;
import com.intel.bkp.fpgacerts.cbor.rim.comid.MeasurementVersion;
import com.intel.bkp.fpgacerts.dice.tcbinfo.MeasurementType;
import com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfoMeasurement;
import com.intel.bkp.fpgacerts.ect.ECTMap;
import com.intel.bkp.test.FileUtils;
import com.upokecenter.cbor.CBORObject;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.List;

import static com.intel.bkp.fpgacerts.utils.OidConverter.decimalToHexNotation;
import static com.intel.bkp.test.FileUtils.TEST_FOLDER;
import static com.intel.bkp.utils.HexConverter.toHex;
import static com.intel.bkp.fpgacerts.cbor.rim.comid.EnvironmentMap.*;
import static java.util.Optional.ofNullable;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AppraisalPolicyParserTest {

    private final List<String> trustedRootHash = List.of("8C17A32952D42FE6FD2C3BF3D2C621E3CBA6DF2401E47713FEA645435BE3CC31");
    private final String VENDOR = "intel.com";
    private final Integer LAYER = 1;
    private final String FW_VERSION = "fw-version";
    private final String DESIGN_VERSION = "design-version";

    @Test
    void parse_Success() throws Exception {
        AppraisalPolicy appraisalPolicies = prepareAppraisalPolicies("test_appraisal_policy.txt");
        final var policies = appraisalPolicies.getPolicies();
        assertEquals(appraisalPolicies.getName(), "Appraisal policy template");
        assertEquals(policies.size(), 2);
        assertEquals(policies.get(0).getEnvironment().getClassId(), MeasurementType.FIRMWARE_VERSION.getOid());
        assertEquals(policies.get(0).getEnvironment().getVendor(), VENDOR);
        assertEquals(policies.get(0).getEnvironment().getLayer(), LAYER);
        assertEquals(policies.get(0).getElementList().size(), 1);
        assertEquals(policies.get(0).getElementList().get(0).getVersion(), FW_VERSION);
        assertEquals(policies.get(0).getElementList().get(0).getVersionScheme(), "3");
        assertEquals(policies.get(0).getAuthority(), trustedRootHash);
        assertEquals(policies.get(0).getCmtype(), ECTMap.CMType.ENDORSEMENTS.name().toUpperCase());

        assertEquals(policies.get(1).getEnvironment().getClassId(), "2.16.840.1.113741.1.15.4.201");
        assertEquals(policies.get(1).getEnvironment().getVendor(), VENDOR);
        assertEquals(policies.get(1).getEnvironment().getLayer(), null);
        assertEquals(policies.get(1).getElementList().size(), 1);
        assertEquals(policies.get(1).getElementList().get(0).getVersion(), DESIGN_VERSION);
        assertEquals(policies.get(1).getElementList().get(0).getVersionScheme(), null);
        assertEquals(policies.get(1).getAuthority(), trustedRootHash);
        assertEquals(policies.get(1).getCmtype(), ECTMap.CMType.ENDORSEMENTS.name().toUpperCase());

        final var policiesCbor = ofNullable(appraisalPolicies)
            .map(AppraisalPolicy::getPolicies)
            .stream()
            .flatMap(List::stream)
            .map(policy -> new TcbInfoMeasurement(policy))
            .toList();
        final var ectMap = ECTMap.createPolicyECTMap(policiesCbor, trustedRootHash, ECTMap.CMType.ENDORSEMENTS);

        verifyMeasurementClaim(ectMap.getCondition().get(0), MeasurementType.FIRMWARE_VERSION.getOid(), FW_VERSION);
        verifyMeasurementClaim(ectMap.getCondition().get(1), "2.16.840.1.113741.1.15.4.201", DESIGN_VERSION);
    }

    @Test
    void parse_WithFirmwareVersionOnly_Success() throws Exception {
        AppraisalPolicy appraisalPolicies = prepareAppraisalPolicies("test_appraisal_policy_fw_only.txt");
        final var policies = appraisalPolicies.getPolicies();
        assertEquals(appraisalPolicies.getName(), "Appraisal policy template");
        assertEquals(policies.size(), 1);
        assertEquals(policies.get(0).getEnvironment().getClassId(), MeasurementType.FIRMWARE_VERSION.getOid());
        assertEquals(policies.get(0).getEnvironment().getVendor(), VENDOR);
        assertEquals(policies.get(0).getEnvironment().getLayer(), LAYER);
        assertEquals(policies.get(0).getElementList().size(), 1);
        assertEquals(policies.get(0).getElementList().get(0).getVersion(), FW_VERSION);
        assertEquals(policies.get(0).getElementList().get(0).getVersionScheme(), "3");
        assertEquals(policies.get(0).getAuthority(), trustedRootHash);
        assertEquals(policies.get(0).getCmtype(), ECTMap.CMType.ENDORSEMENTS.name().toUpperCase());

        final var policiesCbor = ofNullable(appraisalPolicies)
            .map(AppraisalPolicy::getPolicies)
            .stream()
            .flatMap(List::stream)
            .map(policy -> new TcbInfoMeasurement(policy))
            .toList();
        final var ectMap = ECTMap.createPolicyECTMap(policiesCbor, trustedRootHash, ECTMap.CMType.ENDORSEMENTS);

        verifyMeasurementClaim(ectMap.getCondition().get(0), MeasurementType.FIRMWARE_VERSION.getOid(), FW_VERSION);
    }

    @Test
    void serialize_parse_Success() throws Exception {
        AppraisalPolicy appraisalPolicy = new AppraisalPolicy("Appraisal policy template",
            List.of(new Policy(new Environment(MeasurementType.FIRMWARE_VERSION.getOid(), VENDOR, LAYER),
                               List.of(new Measurement(FW_VERSION, "3")),
                               trustedRootHash,
                               ECTMap.CMType.ENDORSEMENTS.name())));
        ObjectMapper mapper = new ObjectMapper();
        final var serializedData = mapper.writeValueAsString(appraisalPolicy);
        AppraisalPolicy parsedAppraisalPolicy = AppraisalPolicyParser.instance().parse(serializedData);
        assertEquals(parsedAppraisalPolicy.getPolicies().size(), 1);
    }

    private static String removeSlashPatterns(String jsonString) {
        // Regex matches: slash + spaces + non-slash chars + spaces + slash
        String pattern = "/\\s*[^/]+\\s*/";

        // Remove all occurrences of the pattern
        return jsonString.replaceAll(pattern, "");
    }

    private AppraisalPolicy prepareAppraisalPolicies(String policyTemplate) throws Exception {
        String jsonWithPattern = FileUtils.readFromResourcesAsString(TEST_FOLDER, policyTemplate);
        String cleanedJson = removeSlashPatterns(jsonWithPattern);
        return AppraisalPolicyParser.instance().parse(cleanedJson);
    }

    private void verifyMeasurementClaim(ECTMap condition, String classOid, String versionStr) {
        // Verify EnvironmentMap
        final var envCbor = ofNullable(condition)
            .map(ECTMap::getEnvironment)
            .map(env -> env.get(CBOR_CLASS_ID_KEY));
        envCbor.map(classMap -> classMap.get(CBOR_CLASS_ID_KEY))
            .map(val -> val.GetByteString())
            .ifPresent(data -> {
                try {
                    assertEquals(toHex(data), decimalToHexNotation(classOid));
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            });
        envCbor.map(classMap -> classMap.get(CBOR_VENDOR_KEY))
            .map(val -> val.AsString())
            .ifPresent(data -> assertEquals(data, VENDOR));
        envCbor.map(classMap -> classMap.get(CBOR_LAYER_KEY))
            .map(val -> val.AsInt32Value())
            .ifPresent(data -> assertEquals(data, LAYER));

        // Verify MeasurementMap
        final var meaCborContainsVer = ofNullable(condition)
            .map(ECTMap::getElementList)
            .map(elementMaps -> elementMaps.stream()
                .anyMatch(elementMap -> ofNullable(elementMap.getElementClaims())
                    .map(claim -> claim.get(MeasurementMap.CBOR_MEAS_VERSION_KEY))
                    .map(versionMap -> versionMap.get(MeasurementVersion.CBOR_VERSION_KEY))
                    .map(CBORObject::AsString)
                    .map(version -> version.equals(versionStr))
                    .orElse(false)))
            .orElse(false);
        assertTrue(meaCborContainsVer.booleanValue());
    }
}
