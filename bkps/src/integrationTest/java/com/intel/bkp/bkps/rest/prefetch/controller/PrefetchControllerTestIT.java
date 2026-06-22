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

package com.intel.bkp.bkps.rest.prefetch.controller;

import com.intel.bkp.bkps.BkpsApp;
import com.intel.bkp.bkps.domain.enumeration.FamilyExtended;
import com.intel.bkp.bkps.domain.enumeration.PrefetchStatus;
import com.intel.bkp.bkps.domain.enumeration.PrefetchType;
import com.intel.bkp.bkps.rest.RestUtil;
import com.intel.bkp.bkps.rest.onboarding.OnboardingResource;
import com.intel.bkp.bkps.rest.onboarding.model.PrefetchStatusRequestDTO;
import com.intel.bkp.bkps.rest.prefetching.PrefetchResource;
import com.intel.bkp.bkps.rest.prefetching.model.IndirectPrefetchRequestDTO;
import com.intel.bkp.bkps.testutils.IntegrationTestBase;
import com.intel.bkp.fpgacerts.model.Family;
import com.intel.bkp.fpgacerts.utils.DeviceIdUtil;
import com.intel.bkp.fpgacerts.utils.SkiHelper;
import com.intel.bkp.test.RandomUtils;
import com.intel.bkp.test.enumeration.ResourceDir;
import com.intel.bkp.utils.Base64Url;
import com.intel.bkp.utils.ByteBufferSafe;
import lombok.SneakyThrows;
import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.commons.lang3.tuple.Pair;
import org.hamcrest.Matcher;
import org.hamcrest.core.AnyOf;
import org.hamcrest.core.CombinableMatcher;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.autoconfigure.validation.ValidationAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultHandlers;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.net.URI;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

import static com.intel.bkp.fpgacerts.model.Family.AGILEX;
import static com.intel.bkp.fpgacerts.model.Family.AGILEX_B;
import static com.intel.bkp.fpgacerts.model.Family.EASIC_N5X;
import static com.intel.bkp.test.FileUtils.loadFile;
import static com.intel.bkp.utils.HexConverter.fromHex;
import static com.intel.bkp.utils.HexConverter.toHex;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.hasSize;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;


@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = {BkpsApp.class, ValidationAutoConfiguration.class})
@ActiveProfiles({"staticbouncycastle"})
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS)
public class PrefetchControllerTestIT extends IntegrationTestBase {

    private static final int MAX_RETRIES = 3;
    private static final String ENDPOINT = PrefetchResource.PREFETCH_DEVICES_NODE;
    private static final String STATUS_ENDPOINT = OnboardingResource.PREFETCH_STATUS;

    private static final String TEST_URL_BASE = "https://pre1-tsci.dev.altera.com/";

    private static final String DEVICEIDER_NAME = "deviceider_22d4ef4bd6a4d748";
    private static final int PDI_LENGTH = 48;


    @BeforeEach
    void setup() {
        mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext).build();
    }

    @Test
    void prefetch_WithSingleS10Device_Success() throws Exception {
        // given
        mockServerWithExpectedOrder();
        final var deviceId = "F63601AA73E7584C";
        mockS10RequestResponses();
        verifyStatusNotFound(Family.S10.getAsHex(), deviceId);

        // when-then
        mockMvc.perform(post(ENDPOINT)
                .contentType(RestUtil.APPLICATION_JSON_UTF8)
                .content(RestUtil.convertObjectToJsonBytes(prepareStatusPrefetchDto(null, deviceId))))
            //.andDo(MockMvcResultHandlers.print())
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.[*].label").value(hasSize(1)))
            .andExpect(jsonPath("$.[*].label").value(deviceId))
            .andExpect(jsonPath("$.[*].status").value(PrefetchStatus.PROGRESS.name()));

        mockServerDistributionPoint.verify(Duration.ofSeconds(15));
        verifyStatusDone(Family.S10.getAsHex(), deviceId);
    }

    @Test
    void prefetch_Indirect_WithListOfDevicesAndCerts_Success() throws Exception {
        // given
        mockServerIgnoreOrder();
        final Pair<String, String> diceEntryFileWithCorrespondingSki =
            new ImmutablePair<>(DEVICEIDER_NAME + ".pem", "e45ed6d808c4f17d2beb7196c85abcc82ac10096");
        final var dtoList = prepareIndirectPrefetchDto(diceEntryFileWithCorrespondingSki.getKey());
        mockZipResponses(dtoList, diceEntryFileWithCorrespondingSki.getValue());
        dtoList.forEach(dto -> verifyStatusNotFound(dto.getFamilyId(), dto.getUid()));

        // when-then
        final MockHttpServletRequestBuilder requestBuilder = MockMvcRequestBuilders
            .post(ENDPOINT)
            .contentType(RestUtil.APPLICATION_JSON_UTF8)
            .content(RestUtil.convertObjectToJsonBytes(dtoList));

        var resultAction = mockMvc.perform(requestBuilder)
            //.andDo(MockMvcResultHandlers.print())
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.[*].label").value(hasSize(dtoList.size())));

        for (int i = 0; i < dtoList.size(); i++) {
            resultAction.andExpect(jsonPath("$.[" + i + "].label").value(eitherOneOfUids(dtoList)))
                .andExpect(jsonPath("$.[" + i + "].status").value(PrefetchStatus.PROGRESS.name()));
        }
        mockServerDistributionPoint.verify(Duration.ofSeconds(15));
        dtoList.forEach(dto -> verifyStatusDone(dto.getFamilyId(), dto.getUid()));
    }

    private CombinableMatcher<String> eitherOneOfUids(List<IndirectPrefetchRequestDTO> dtoList) {
        final List<Matcher<? super String>> matchers = new ArrayList<>(dtoList.size());
        dtoList.stream().map(dto -> containsString(dto.getUid())).forEach(matchers::add);
        return new CombinableMatcher<>(new AnyOf<>(matchers));
    }

    private List<IndirectPrefetchRequestDTO> prepareIndirectPrefetchDto(String diceEntryFile) {
        var pem = loadFile(ResourceDir.ROOT, diceEntryFile);
        return List.of(
            generateDto(pem, AGILEX, false),
            generateDto(pem, EASIC_N5X, false),
            generateDto(null, AGILEX_B, true));
    }

    private List<PrefetchStatusRequestDTO> prepareStatusPrefetchDto(String family, String uid) {
        var list = new ArrayList<PrefetchStatusRequestDTO>();
        list.add(new PrefetchStatusRequestDTO(family, uid));
        return list;
    }

    private IndirectPrefetchRequestDTO generateDto(String pem, Family family, boolean isPdiRequired) {
        final var dto = new IndirectPrefetchRequestDTO();
        dto.setFamilyId(toHex(family.getFamilyId()));
        dto.setUid(RandomUtils.generateDeviceIdHex());
        if (isPdiRequired) {
            dto.setPdi(RandomUtils.generateRandomHex(PDI_LENGTH));
        }
        dto.setDeviceIdEr(pem);
        return dto;
    }

    private void mockS10RequestResponses() throws Exception {
        mockDpResponse(
            "/IPCS/certs/attestation_F63601AA73E7584C_00000002.cer",
            "/IPCS/certs/IPCS_stratix10.cer",
            "/DICE/certs/DICE_RootCA.cer",
            "/IPCS/crls/IPCS_stratix10.crl",
            "/DICE/crls/DICE.crl"
        );
    }

    private void mockZipResponses(List<IndirectPrefetchRequestDTO> dtos, String skiFromCert) {
        dtos.forEach(dto -> {
            final PrefetchType prefetchType = FamilyExtended.from(Family.from(dto.getFamilyId())).getPrefetchType();
            final String id = switch (prefetchType) {
                case ZIP_WITH_SKI -> getFormattedSki(skiFromCert);
                case ZIP_WITH_PDI -> SkiHelper.getPdiForUrlFrom(fromHex(dto.getPdi()));
                default -> throw new IllegalStateException("Method supports only mocking zip prefetching");
            };
            mockWithGivenZipNameParams(dto.getFamilyId(), dto.getUid(), id);
        });
    }

    @SneakyThrows
    private void mockWithGivenZipNameParams(String family, String uid, String skiOrPdi) {
        mockResponse(new URI(TEST_URL_BASE + String.format("content/IPCS/%s_%s_%s.zip",
                family, DeviceIdUtil.getReversed(uid).toLowerCase(Locale.ROOT), skiOrPdi)),
            RandomUtils.generateRandomBytes(1));
    }

    private String getFormattedSki(String skiFromCert) {
        byte[] shortenKeyIdentifier = new byte[20];
        ByteBufferSafe.wrap(fromHex(skiFromCert)).get(shortenKeyIdentifier);
        return Base64Url.encodeWithoutPadding(shortenKeyIdentifier);
    }

    private void mockServerWithExpectedOrder() {
        mockServerDistributionPoint = MockRestServiceServer.createServer(distributionPointRestTemplate);
    }

    private void mockServerIgnoreOrder() {
        mockServerDistributionPoint = MockRestServiceServer.bindTo(distributionPointRestTemplate)
            .ignoreExpectOrder(true)
            .bufferContent()
            .build();
    }

    @SneakyThrows
    private void verifyStatusDone(String family, String deviceId) {
        boolean success = false;
        int attempts = 0;

        while (attempts < MAX_RETRIES && !success) {
            try {
                mockMvc.perform(get(STATUS_ENDPOINT)
                        .contentType(RestUtil.APPLICATION_JSON_UTF8)
                        .param("familyId", family)
                        .param("uid", deviceId))
                    .andDo(MockMvcResultHandlers.print())
                    .andExpect(status().isOk())
                    .andExpect(content().string("{\"status\":\"DONE\"}"));
                success = true; // If no exception is thrown, mark as success
            } catch (AssertionError e) {
                attempts++;
                if (attempts >= MAX_RETRIES) {
                    throw e; // Rethrow the exception if max retries reached
                }
            }
        }
    }

    @SneakyThrows
    private void verifyStatusNotFound(String family, String deviceId) {
        mockMvc.perform(get(STATUS_ENDPOINT)
                        .contentType(RestUtil.APPLICATION_JSON_UTF8)
                        .param("familyId", family)
                        .param("uid", deviceId))
                .andDo(MockMvcResultHandlers.print())
                .andExpect(status().isOk())
                .andExpect(content().string("{\"status\":\"NOT_FOUND\"}"));
    }
}
