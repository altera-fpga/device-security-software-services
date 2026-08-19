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

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.junit.FuzzTest;
import com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfoMeasurement;
import com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfoMeasurementsAggregator;
import com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfoValue;
import com.intel.bkp.fpgacerts.ect.ECTMap;
import com.intel.bkp.fpgacerts.measurements.SpdmMeasurementResponseProvider;
import com.intel.bkp.fpgacerts.measurements.mapping.SpdmMeasurementResponseToTcbInfoMapper;
import com.intel.bkp.fpgacerts.verification.EvidenceVerifier;
import com.intel.bkp.fpgacerts.verification.VerificationResult;
import com.intel.bkp.protocol.spdm.model.SpdmMeasurementResponse;
import com.intel.bkp.protocol.spdm.model.SpdmMeasurementResponseBuilder;
import com.intel.bkp.verifier.service.measurements.RimHandlersProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.ArrayList;
import java.util.List;

import static com.intel.bkp.test.FileUtils.readFromResources;
import static com.intel.bkp.utils.HexConverter.toHex;
import static org.junit.jupiter.api.Assertions.assertEquals;

@ExtendWith(MockitoExtension.class)
public class EvidenceVerifierSpdmTestIT {

    private static final int MAX_FUZZ_STR_LEN = 1000;
    private static final String TEST_FOLDER_INTEGRATION = "integration/spdm/";
    private static final String FILENAME_AGILEX_RIM = "hps_fpga_signed_enc_test.rim";
    private static final String FILENAME_AGILEX_RIM_WITH_PR_REGION = "ghrd_agfd023r25a2e2vr0_pr.rim";
    private static final String FILENAME_AGILEX_RIM_FUZZ = "hps_fpga_signed_enc_test_fuzz.rim";
    private static final String FILENAME_AGILEX_RESPONSE = "measurements_hps_fpga_signed_enc_test.bin";
    private static final String FILENAME_AGILEX_RESPONSE_WITH_PR_REGION = "measurements_ghrd_agfd023r25a2e2vr0_pr.bin";
    private final List<String> trustedRootHash = List.of("A1B5D25D0C2F991EB5B3CBD408717B3A9296BE6E90D60997E29FEB3694F60D80",
        "9DB7D8D004D650B40ED993F2B665E19DA65BD065D7BBD35D6C1439C4B4201259");

    private static String refMeasurementsAgilex;
    private static String refMeasurementsAgilexWithPrRegion;
    private static String refMeasurementsAgilexFuzz;
    private static SpdmMeasurementResponseProvider responseAgilex;
    private static SpdmMeasurementResponseProvider responseAgilexWithPrRegion;

    private final SpdmMeasurementResponseToTcbInfoMapper measurementMapper =
        new SpdmMeasurementResponseToTcbInfoMapper();
    private final TcbInfoMeasurementsAggregator tcbInfoMeasurementsAggregator = new TcbInfoMeasurementsAggregator();
    private final List<ECTMap> acsECTMapList = new ArrayList<>();

    private final EvidenceVerifier sut = new EvidenceVerifier(new RimHandlersProvider());

    @BeforeAll
    static void init() throws Exception {
        refMeasurementsAgilex = readEvidence(FILENAME_AGILEX_RIM);
        refMeasurementsAgilexWithPrRegion = readEvidence(FILENAME_AGILEX_RIM_WITH_PR_REGION);
        refMeasurementsAgilexFuzz = readEvidence(FILENAME_AGILEX_RIM_FUZZ);

        responseAgilex =
            new SpdmMeasurementResponseProvider(readResponse(FILENAME_AGILEX_RESPONSE));
        responseAgilexWithPrRegion =
            new SpdmMeasurementResponseProvider(readResponse(FILENAME_AGILEX_RESPONSE_WITH_PR_REGION));
    }

    private static String readEvidence(String filename) throws Exception {
        return toHex(readFromResources(TEST_FOLDER_INTEGRATION, filename));
    }

    private static SpdmMeasurementResponse readResponse(String filename) throws Exception {
        final byte[] response = readFromResources(TEST_FOLDER_INTEGRATION, filename);
        return new SpdmMeasurementResponseBuilder()
            .parse(response)
            .build();
    }

    private static String getFuzzHex(FuzzedDataProvider data) {
        return toHex(data.consumeBytes(MAX_FUZZ_STR_LEN / 2));
    }

    private static void fuzzRandomTcbInfoMeasurement(FuzzedDataProvider data,
                                                     List<TcbInfoMeasurement> tcbInfosFromDevice) {
        final int elemToChange = data.consumeInt(0, tcbInfosFromDevice.size() - 1);
        System.out.println("Elem to change: " + elemToChange);

        final TcbInfoValue tcbInfoValue = tcbInfosFromDevice.get(elemToChange).getValue();
        System.out.println("Current tcbInfoValue: " + tcbInfoValue);

        tcbInfoValue.getFwid().ifPresent(fwIdField -> {
            final String newFieldValue = fuzzFieldValue(data, fwIdField.getDigest());
            fwIdField.setDigest(newFieldValue);
        });

        tcbInfoValue.getMaskedVendorInfo().ifPresent(maskedVendorInfo -> {
            final String newVendorInfo = fuzzFieldValue(data, maskedVendorInfo.getVendorInfo());
            maskedVendorInfo.setVendorInfo(newVendorInfo);
        });

        System.out.println("Updated tcbInfoValue: " + tcbInfoValue);
    }

    private static String fuzzFieldValue(FuzzedDataProvider data, String currentFieldValue) {
        String newFieldValue;
        do {
            newFieldValue = getFuzzHex(data);
        } while (currentFieldValue.equals(newFieldValue));
        return newFieldValue;
    }

    @Tag("Fuzz")
    @FuzzTest
    void verify_Spdm_Agilex_Fuzz(FuzzedDataProvider data) {
        // given
        final List<TcbInfoMeasurement> tcbInfosFromDevice = measurementMapper.map(responseAgilex);
        fuzzRandomTcbInfoMeasurement(data, tcbInfosFromDevice);
        acsECTMapList.addAll(ECTMap.createAeECTMap(tcbInfosFromDevice, trustedRootHash).getAddition());

        // when
        final var result = sut.verify(acsECTMapList, refMeasurementsAgilexFuzz);

        // then
        assertEquals(VerificationResult.FAILED, result);
    }

    @Test
    void verify_Spdm_Agilex() {
        // given
        acsECTMapList.addAll(ECTMap.createAeECTMap(measurementMapper.map(responseAgilex), trustedRootHash).getAddition());

        // when
        final var result = sut.verify(acsECTMapList, refMeasurementsAgilex);

        // then
        assertEquals(VerificationResult.PASSED, result);
    }

    @Test
    void verify_Spdm_AgilexWithPrRegion() {
        // given
        acsECTMapList.addAll(ECTMap.createAeECTMap(measurementMapper.map(responseAgilexWithPrRegion), trustedRootHash).getAddition());

        // when
        final var result =
            sut.verify(acsECTMapList, refMeasurementsAgilexWithPrRegion);

        // then
        assertEquals(VerificationResult.PASSED, result);
    }
}
