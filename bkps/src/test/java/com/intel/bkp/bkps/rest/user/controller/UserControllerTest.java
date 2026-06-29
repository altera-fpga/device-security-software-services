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
import com.intel.bkp.bkps.rest.user.service.UserService;
import com.intel.bkp.bkps.security.AuthorityType;
import com.intel.bkp.core.helper.UserRoleManagementDTO;
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
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.Mockito.verify;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;


@ExtendWith(MockitoExtension.class)
public class UserControllerTest {

    @Mock
    private UserService userService;

    @InjectMocks
    private UserController userController;

    private MockMvc mockMvc;

    private static final Long USER_TEST_ID = 1L;

    @BeforeEach
    void setup() {
        this.mockMvc = MockMvcBuilders.standaloneSetup(userController).build();
    }

    @Test
    void createUser_Success() throws Exception {
        // given
        String testCertificate = "test";
        InputStream result = new ByteArrayInputStream(testCertificate.getBytes(StandardCharsets.UTF_8));
        MockMultipartFile file = new MockMultipartFile("file", "file", MediaType.TEXT_PLAIN_VALUE, result);

        // when
        final MockHttpServletRequestBuilder requestBuilder = MockMvcRequestBuilders
            .multipart(UserResource.USER_NODE + UserResource.MANAGE_NODE)
            .file(file)
            .contentType(MediaType.MULTIPART_FORM_DATA);

        mockMvc.perform(requestBuilder)
            .andExpect(status().isOk());

        // then
        verify(userService).save(any(MultipartFile.class), anyBoolean());
    }

    @Test
    void listUsers_Success() throws Exception {
        // when
        mockMvc.perform(get(UserResource.USER_NODE + UserResource.MANAGE_NODE))
            .andExpect(status().isOk());

        // then
        verify(userService).getAll();
    }

    @Test
    void setRoleUser_Success() throws Exception {
        // given
        UserRoleManagementDTO dto = new UserRoleManagementDTO();
        dto.setRole(AuthorityType.ROLE_SUPER_ADMIN.name());

        // when
        mockMvc.perform(post(UserResource.USER_NODE + UserResource.SET_ROLE, USER_TEST_ID)
            .contentType(RestUtil.APPLICATION_JSON_UTF8)
            .content(RestUtil.convertObjectToJsonBytes(dto)))
            .andExpect(status().isOk());

        // then
        verify(userService).roleSet(USER_TEST_ID, dto);
    }

    @Test
    void unsetRoleUser_Success() throws Exception {
        // given
        UserRoleManagementDTO dto = new UserRoleManagementDTO();
        dto.setRole(AuthorityType.ROLE_SUPER_ADMIN.name());

        // when
        mockMvc.perform(post(UserResource.USER_NODE + UserResource.UNSET_ROLE, USER_TEST_ID)
            .contentType(RestUtil.APPLICATION_JSON_UTF8)
            .content(RestUtil.convertObjectToJsonBytes(dto)))
            .andExpect(status().isOk());

        // then
        verify(userService).roleUnset(USER_TEST_ID, dto);
    }

    @Test
    void deleteUser_Success() throws Exception {
        // when
        mockMvc.perform(delete(UserResource.USER_NODE + UserResource.DELETE_USER, USER_TEST_ID)
            .accept(RestUtil.APPLICATION_JSON_UTF8))
            .andExpect(status().isOk());

        // then
        verify(userService).delete(USER_TEST_ID);
    }
}
