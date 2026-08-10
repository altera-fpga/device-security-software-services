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


import com.intel.bkp.bkps.rest.RestUtil;
import com.intel.bkp.bkps.rest.initialization.InitializationResource;
import com.intel.bkp.bkps.rest.initialization.model.dto.EncryptedSealingKeyDTO;
import com.intel.bkp.bkps.rest.initialization.service.SealingKeyService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.util.Base64;

import static org.mockito.Mockito.verify;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@ExtendWith(MockitoExtension.class)
public class SealingKeyControllerTest {

    @Mock
    private SealingKeyService sealingKeyService;

    @InjectMocks
    private SealingKeyController sealingKeyController;

    private MockMvc mockMvc;

    @BeforeEach
    void setup() {
        this.mockMvc = MockMvcBuilders.standaloneSetup(sealingKeyController).build();
    }

    @Test
    void createSealingKey_CallsCreateSealingKey() throws Exception {
        //when
        mockMvc.perform(post(InitializationResource.SEALING_KEY_BASE))
            .andExpect(status().isOk());

        //then
        verify(sealingKeyService).createSealingKey();
    }

    @Test
    void rotateSealingKey_CallsRotateSealingKey() throws Exception {
        //when
        mockMvc.perform(
            post(InitializationResource.SEALING_KEY_BASE + InitializationResource.SEALING_KEY_ROTATE))
            .andExpect(status().isOk());

        //then
        verify(sealingKeyService).rotateSealingKey();
    }

    @Test
    void getAllSealingKeys_CallsGetAllSealingKeys() throws Exception {
        //when
        mockMvc.perform(get(InitializationResource.SEALING_KEY_BASE))
            .andExpect(status().isOk());

        //then
        verify(sealingKeyService).getAllSealingKeys();
    }

    @Test
    void backupConfigurations_Success() throws Exception {
        //given
        String rsaImportPubKey = "test";

        //when
        mockMvc.perform(
            post(InitializationResource.SEALING_KEY_BASE + InitializationResource.SEALING_KEY_BACKUP)
            .content(rsaImportPubKey))
            .andExpect(status().isOk());

        // then
        verify(sealingKeyService).backup(rsaImportPubKey);
    }

    @Test
    void backupConfigurations_WithMissingBody_Throws() throws Exception {
        //when
        mockMvc.perform(
            post(InitializationResource.SEALING_KEY_BASE + InitializationResource.SEALING_KEY_BACKUP))
            .andExpect(status().isBadRequest());
    }

    @Test
    void restoreConfigurations_Success() throws Exception {
        //given
        String encryptedSealingKey = Base64.getEncoder().encodeToString("test".getBytes());
        EncryptedSealingKeyDTO encryptedSealingKeyDTO = new EncryptedSealingKeyDTO(encryptedSealingKey);

        //when
        mockMvc.perform(
            post(InitializationResource.SEALING_KEY_BASE + InitializationResource.SEALING_KEY_RESTORE)
                .contentType(RestUtil.APPLICATION_JSON_UTF8)
                .content(RestUtil.convertObjectToJsonBytes(encryptedSealingKeyDTO)))
            .andExpect(status().isOk());

        // then
        verify(sealingKeyService).restore(encryptedSealingKey);
    }

    @Test
    void restoreConfigurations_WithMissingBody_Throws() throws Exception {
        //when
        mockMvc.perform(
            post(InitializationResource.SEALING_KEY_BASE + InitializationResource.SEALING_KEY_RESTORE))
            .andExpect(status().isBadRequest());
    }

}
