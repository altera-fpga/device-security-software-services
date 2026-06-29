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


import com.intel.bkp.bkps.rest.initialization.InitializationResource;
import com.intel.bkp.bkps.rest.initialization.service.SigningKeyService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.verify;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@ExtendWith(MockitoExtension.class)
public class SigningKeyControllerTest {

    @Mock
    private SigningKeyService signingKeyService;

    @InjectMocks
    private SigningKeyController signingKeyController;

    private MockMvc mockMvc;

    private static final long SIGNING_KEY_ID = 1L;

    @BeforeEach
    void setup() {
        this.mockMvc = MockMvcBuilders.standaloneSetup(signingKeyController).build();
    }

    @Test
    void createRootSigningPublicKey_InvokesProperMethod() throws Exception {
        // given
        String testCertificate = "test";

        // when
        String endpoint = InitializationResource.INIT_NODE + InitializationResource.ROOT_SIGNING_KEY;
        InputStream result = new ByteArrayInputStream(testCertificate.getBytes(StandardCharsets.UTF_8));
        MockMultipartFile file = new MockMultipartFile("file", "file", MediaType.TEXT_PLAIN_VALUE, result);

        final MockHttpServletRequestBuilder requestBuilder = MockMvcRequestBuilders
            .multipart(endpoint)
            .file(file)
            .contentType(MediaType.MULTIPART_FORM_DATA);

        mockMvc.perform(requestBuilder)
            .andExpect(status().isOk());

        // then
        verify(signingKeyService).addRootSigningPublicKey(anyString());
    }

    @Test
    void createSigningKey_CallsCreateSigningKey() throws Exception {
        // when
        mockMvc.perform(post(InitializationResource.INIT_NODE + InitializationResource.SIGNING_KEY))
            .andExpect(status().isOk());

        // then
        verify(signingKeyService).createSigningKey();
    }

    @Test
    void getAllSigningKeys_CallsGetAllSigningKeys() throws Exception {
        // when
        mockMvc.perform(get(InitializationResource.INIT_NODE + InitializationResource.SIGNING_KEY_LIST))
            .andExpect(status().isOk());

        // then
        verify(signingKeyService).getAllSigningKeys();
    }

    @Test
    void getSigningKey_InvokesProperMethod() throws Exception {
        // when
        mockMvc.perform(
                get(InitializationResource.INIT_NODE + InitializationResource.SIGNING_KEY_PUB_KEY, SIGNING_KEY_ID))
            .andExpect(status().isOk());

        // then
        verify(signingKeyService).getSigningKeyPublicPart(SIGNING_KEY_ID);
    }

    @Test
    void activateSigningKey_InvokesProperMethod() throws Exception {
        // when
        mockMvc.perform(
                post(InitializationResource.INIT_NODE + InitializationResource.SIGNING_KEY_ACTIVATE, SIGNING_KEY_ID))
            .andExpect(status().isOk());
        // then
        verify(signingKeyService).activateSigningKey(SIGNING_KEY_ID);
    }

    @Test
    void uploadSigningKey_InvokesProperMethod() throws Exception {
        // given
        String testCertificate = "test";

        // when
        String endpoint = InitializationResource.INIT_NODE + InitializationResource.SIGNING_KEY_UPLOAD;
        InputStream result = new ByteArrayInputStream(testCertificate.getBytes(StandardCharsets.UTF_8));
        MockMultipartFile singleChainFile =
            new MockMultipartFile("singleRootChain", "singleRootChain", MediaType.TEXT_PLAIN_VALUE, result);
        MockMultipartFile multiChainFile =
            new MockMultipartFile("multiRootChain", "multiRootChain", MediaType.TEXT_PLAIN_VALUE, result);

        final MockHttpServletRequestBuilder requestBuilder = MockMvcRequestBuilders
            .multipart(endpoint, SIGNING_KEY_ID)
            .file(singleChainFile)
            .file(multiChainFile)
            .contentType(MediaType.MULTIPART_FORM_DATA);

        mockMvc.perform(requestBuilder)
            .andExpect(status().isOk());

        // then
        verify(signingKeyService).uploadSigningKeyChain(anyLong(), anyString(), anyString());
    }
}
