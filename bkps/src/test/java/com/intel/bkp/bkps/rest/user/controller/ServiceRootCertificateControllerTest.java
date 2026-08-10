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

package com.intel.bkp.bkps.rest.user.controller;

import com.intel.bkp.bkps.rest.RestUtil;
import com.intel.bkp.bkps.rest.user.UserResource;
import com.intel.bkp.bkps.rest.user.service.ServiceRootCertificateService;
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
import org.springframework.web.multipart.MultipartFile;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@ExtendWith(MockitoExtension.class)
public class ServiceRootCertificateControllerTest {

    @Mock
    private ServiceRootCertificateService serviceRootCertificateService;

    @InjectMocks
    private ServiceRootCertificateController sut;

    private MockMvc mockMvc;

    private static final String USER_TEST_ALIAS = "user_user_12345";

    @BeforeEach
    void setup() {
        this.mockMvc = MockMvcBuilders.standaloneSetup(sut).build();
    }

    @Test
    void importServiceRootCertificate_Success() throws Exception {
        // given
        String testCertificate = "test";
        InputStream result = new ByteArrayInputStream(testCertificate.getBytes(StandardCharsets.UTF_8));
        MockMultipartFile file = new MockMultipartFile("file", "file", MediaType.TEXT_PLAIN_VALUE, result);

        // when
        final MockHttpServletRequestBuilder requestBuilder = MockMvcRequestBuilders
            .multipart(UserResource.USER_NODE + UserResource.CERTIFICATE_MANAGE_NODE)
            .file(file)
            .contentType(MediaType.MULTIPART_FORM_DATA);

        mockMvc.perform(requestBuilder)
            .andExpect(status().isOk());

        // then
        verify(serviceRootCertificateService).rootCertificateImport(any(MultipartFile.class));
    }

    @Test
    void listServiceRootCertificates_Success() throws Exception {
        // when
        mockMvc.perform(get(UserResource.USER_NODE + UserResource.CERTIFICATE_MANAGE_NODE))
            .andExpect(status().isOk());

        // then
        verify(serviceRootCertificateService).getAll();
    }

    @Test
    void deleteServiceRootCertificate_Success() throws Exception {
        // when
        mockMvc.perform(delete(UserResource.USER_NODE + UserResource.CERTIFICATE_DELETE, USER_TEST_ALIAS)
                .accept(RestUtil.APPLICATION_JSON_UTF8))
            .andExpect(status().isOk());

        // then
        verify(serviceRootCertificateService).delete(USER_TEST_ALIAS);
    }
}
