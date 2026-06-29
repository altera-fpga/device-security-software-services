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

package com.intel.bkp.bkps.config;

import com.intel.bkp.bkps.BkpsApp;
import com.intel.bkp.bkps.rest.initialization.InitializationResource;
import com.intel.bkp.bkps.rest.user.UserResource;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.validation.ValidationAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import static org.springframework.restdocs.mockmvc.RestDocumentationRequestBuilders.get;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = {BkpsApp.class, ValidationAutoConfiguration.class})
@ActiveProfiles({"staticbouncycastle"})
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS)
public class SecurityConfigurationTestIT {

    @Autowired
    protected WebApplicationContext webApplicationContext;

    private MockMvc mockMvc;

    public enum Role {
        ADMIN,
        SUPER_ADMIN,
        PROGRAMMER,
        NONEXISTENT
    }

    @Test
    void listSealingKeys_WithSuperAdmin_shouldSucceedWith200() throws Exception {
        setupRole(Role.SUPER_ADMIN.name());
        mockMvc.perform(get(InitializationResource.SEALING_KEY_BASE))
            .andExpect(status().isOk());
    }

    @Test
    void listSealingKeys_WithAdmin_shouldReturn403() throws Exception {
        setupRole(Role.ADMIN.name());
        mockMvc.perform(get(InitializationResource.SEALING_KEY_BASE))
            .andExpect(status().isForbidden());
    }

    @Test
    void listUsers_WithProgrammer_shouldReturn403() throws Exception {
        setupRole(Role.PROGRAMMER.name());
        mockMvc.perform(get(UserResource.USER_NODE + UserResource.MANAGE_NODE))
            .andExpect(status().isForbidden());
    }

    @Test
    void listUsers_WithAdmin_shouldShouldSucceedWith200() throws Exception {
        setupRole(Role.ADMIN.name());
        mockMvc.perform(get(UserResource.USER_NODE + UserResource.MANAGE_NODE))
            .andExpect(status().isOk());
    }

    private void setupRole(String role) {
        this.mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext)
            .defaultRequest(get("/")
                .with(user("user").password("password").roles(role)))
            .apply(springSecurity())
            .build();
    }
}
