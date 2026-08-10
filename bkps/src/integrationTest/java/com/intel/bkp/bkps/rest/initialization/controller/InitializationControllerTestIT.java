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

package com.intel.bkp.bkps.rest.initialization.controller;

import com.intel.bkp.bkps.BkpsApp;
import com.intel.bkp.bkps.rest.errors.enums.ErrorCodeMap;
import com.intel.bkp.bkps.rest.initialization.InitializationResource;
import org.apache.commons.lang3.StringUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.validation.ValidationAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

import static com.intel.bkp.core.utils.ApplicationConstants.REQUEST_BODY_STRING_MAX_SIZE;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;


@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = {BkpsApp.class, ValidationAutoConfiguration.class})
@ActiveProfiles({"staticbouncycastle"})
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS)
public class InitializationControllerTestIT {

    private static final String SINGLE_ROOT_CHAIN = "singleRootChain";
    private static final String MULTI_ROOT_CHAIN = "multiRootChain";
    private static long SIGNING_KEY_ID = 1L;

    @Autowired
    protected WebApplicationContext webApplicationContext;

    private MockMvc mockMvc;

    @BeforeEach
    void setup() {
        this.mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext).build();
    }

    @Test
    void createRootSigningPublicKey_WithInvalidPublicKeySize_ReportsError() throws Exception {
        // given
        String testCertificate = StringUtils.repeat("*", REQUEST_BODY_STRING_MAX_SIZE + 1);
        String endpoint = InitializationResource.INIT_NODE + InitializationResource.ROOT_SIGNING_KEY;
        InputStream result = new ByteArrayInputStream(testCertificate.getBytes(StandardCharsets.UTF_8));
        MockMultipartFile file = new MockMultipartFile("file", "file", MediaType.TEXT_PLAIN_VALUE, result);

        // when
        final MockHttpServletRequestBuilder requestBuilder = MockMvcRequestBuilders
            .multipart(endpoint)
            .file(file)
            .contentType(MediaType.MULTIPART_FORM_DATA);

        mockMvc.perform(requestBuilder)
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.status.code").value(ErrorCodeMap.INVALID_FIELDS_IN_PAYLOAD.getCode()))
            .andExpect(jsonPath("$.status.message").value(ErrorCodeMap.INVALID_FIELDS_IN_PAYLOAD.getExternalMessage()));
    }

    @Test
    void uploadSigningKey_WithInvalidCertificateChainSize_ReportsError() throws Exception {
        // given
        String testCertificate = StringUtils.repeat("*", REQUEST_BODY_STRING_MAX_SIZE + 1);
        String endpoint = InitializationResource.INIT_NODE + InitializationResource.SIGNING_KEY_UPLOAD;
        InputStream result = new ByteArrayInputStream(testCertificate.getBytes(StandardCharsets.UTF_8));
        MockMultipartFile singleChainFile = mockSingleChain(result, SINGLE_ROOT_CHAIN);
        MockMultipartFile multiChainFile = mockSingleChain(result, MULTI_ROOT_CHAIN);

        // when
        final MockHttpServletRequestBuilder requestBuilder = MockMvcRequestBuilders
            .multipart(endpoint, SIGNING_KEY_ID)
            .file(singleChainFile)
            .file(multiChainFile)
            .contentType(MediaType.MULTIPART_FORM_DATA);

        mockMvc.perform(requestBuilder)
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.status.code").value(ErrorCodeMap.INVALID_FIELDS_IN_PAYLOAD.getCode()))
            .andExpect(jsonPath("$.status.message").value(ErrorCodeMap.INVALID_FIELDS_IN_PAYLOAD.getExternalMessage()));
    }

    private MockMultipartFile mockSingleChain(InputStream result, String singleRootChain) throws IOException {
        return new MockMultipartFile(singleRootChain, singleRootChain, MediaType.TEXT_PLAIN_VALUE, result);
    }


}
