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

package com.intel.bkp.bkps.rest.configuration.controller;

import com.intel.bkp.bkps.BkpsApp;
import com.intel.bkp.bkps.attestation.mapping.CacheCborMapper;
import com.intel.bkp.bkps.attestation.mapping.CacheCertificateMapper;
import com.intel.bkp.bkps.attestation.mapping.CacheCrlMapper;
import com.intel.bkp.bkps.domain.PrefetchEntity;
import com.intel.bkp.bkps.domain.enumeration.PrefetchEntityType;
import com.intel.bkp.bkps.repository.PrefetchRepository;
import com.intel.bkp.bkps.rest.errors.ApplicationExceptionHandler;
import com.intel.bkp.test.FileUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.web.PageableHandlerMethodArgumentResolver;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.util.List;

import static com.intel.bkp.bkps.rest.RestUtil.createFormattingConversionService;
import static com.intel.bkp.bkps.rest.configuration.ConfigurationResource.ATTESTATION_FILE;
import static com.intel.bkp.bkps.rest.configuration.ConfigurationResource.CONFIG_NODE;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = BkpsApp.class)
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS)
public class AttestationFileControllerTestIT {

    @Autowired
    private MappingJackson2HttpMessageConverter jacksonMessageConverter;

    @Autowired
    private PageableHandlerMethodArgumentResolver pageableArgumentResolver;

    @Autowired
    private ApplicationExceptionHandler exceptionTranslator;

    @Autowired
    private PrefetchRepository prefetchRepository;

    private MockMvc restMockMvc;

    @BeforeEach
    void setup() {
        final AttestationFileController attestationFileResource =
            new AttestationFileController(prefetchRepository);
        this.restMockMvc = MockMvcBuilders.standaloneSetup(attestationFileResource)
            .setCustomArgumentResolvers(pageableArgumentResolver)
            .setControllerAdvice(exceptionTranslator)
            .setConversionService(createFormattingConversionService())
            .setMessageConverters(jacksonMessageConverter).build();
    }

    @Test
    @Transactional
    public void uploadCorimFile() throws Exception {
        var content = FileUtils.readFromResources("testfiles", "fw_rim_signed.corim");
        var path = "\"/testfiles/fw_rim_signed.corim\"";
        var pathWithoutQuote = path.replace("\"", "");
        int databaseSizeBeforeCreate = prefetchRepository.findAll().size();
        restMockMvc.perform(multipart(CONFIG_NODE + ATTESTATION_FILE)
            .file(new MockMultipartFile("file", "file", MediaType.APPLICATION_OCTET_STREAM_VALUE, content))
            .file(new MockMultipartFile("path", "", MediaType.APPLICATION_JSON_VALUE, path.getBytes(StandardCharsets.UTF_8))))
            .andExpect(status().isOk());
        List<PrefetchEntity> prefetchEntityList = prefetchRepository.findAll();
        assertEquals(databaseSizeBeforeCreate + 1, prefetchEntityList.size());
        var uploadedContent = prefetchRepository.findByPathAndType("file://" + pathWithoutQuote, PrefetchEntityType.CORIM)
            .map(PrefetchEntity::getContent);
        CacheCborMapper mapper = new CacheCborMapper();
        assertEquals(mapper.decode(uploadedContent.get()), mapper.parse(content).get());
    }

    @Test
    @Transactional
    public void uploadCertFile() throws Exception {
        var content = FileUtils.readFromResources("testfiles", "IPCS.cer");
        var path = "\"/testfiles/IPCS.cer\"";
        var pathWithoutQuote = path.replace("\"", "");
        int databaseSizeBeforeCreate = prefetchRepository.findAll().size();
        restMockMvc.perform(multipart(CONFIG_NODE + ATTESTATION_FILE)
            .file(new MockMultipartFile("file", "file", MediaType.APPLICATION_OCTET_STREAM_VALUE, content))
            .file(new MockMultipartFile("path", "", MediaType.APPLICATION_JSON_VALUE, path.getBytes(StandardCharsets.UTF_8))))
            .andExpect(status().isOk());
        List<PrefetchEntity> prefetchEntityList = prefetchRepository.findAll();
        assertEquals(databaseSizeBeforeCreate + 1, prefetchEntityList.size());
        var uploadedContent = prefetchRepository.findByPathAndType("file://" + pathWithoutQuote, PrefetchEntityType.CERT)
            .map(PrefetchEntity::getContent);
        CacheCertificateMapper mapper = new CacheCertificateMapper();
        assertEquals(mapper.decode(uploadedContent.get()), mapper.parse(content).get());
    }

    @Test
    @Transactional
    public void uploadCrlFile() throws Exception {
        var content = FileUtils.readFromResources("testfiles", "IPCS.crl");
        var path = "\"/testfiles/IPCS.crl\"";
        var pathWithoutQuote = path.replace("\"", "");
        int databaseSizeBeforeCreate = prefetchRepository.findAll().size();
        restMockMvc.perform(multipart(CONFIG_NODE + ATTESTATION_FILE)
            .file(new MockMultipartFile("file", "file", MediaType.APPLICATION_OCTET_STREAM_VALUE, content))
            .file(new MockMultipartFile("path", "", MediaType.APPLICATION_JSON_VALUE, path.getBytes(StandardCharsets.UTF_8))))
            .andExpect(status().isOk());
        List<PrefetchEntity> prefetchEntityList = prefetchRepository.findAll();
        assertEquals(databaseSizeBeforeCreate + 1, prefetchEntityList.size());
        var uploadedContent = prefetchRepository.findByPathAndType("file://" + pathWithoutQuote, PrefetchEntityType.CRL)
            .map(PrefetchEntity::getContent);
        CacheCrlMapper mapper = new CacheCrlMapper();
        assertEquals(mapper.decode(uploadedContent.get()), mapper.parse(content).get());
    }

    @Test
    @Transactional
    public void deleteCertFile() throws Exception {
        var content = FileUtils.readFromResources("testfiles", "IPCS.cer");
        var path = "\"/testfiles/IPCS.cer\"";
        var pathWithoutQuote = path.replace("\"", "");
        int databaseSizeBeforeCreate = prefetchRepository.findAll().size();
        restMockMvc.perform(multipart(CONFIG_NODE + ATTESTATION_FILE)
            .file(new MockMultipartFile("file", "file", MediaType.APPLICATION_OCTET_STREAM_VALUE, content))
            .file(new MockMultipartFile("path", "", MediaType.APPLICATION_JSON_VALUE, path.getBytes(StandardCharsets.UTF_8))))
            .andExpect(status().isOk());
        List<PrefetchEntity> prefetchEntityList = prefetchRepository.findAll();
        assertEquals(databaseSizeBeforeCreate + 1, prefetchEntityList.size());
        String pathToDelete = "file://" + pathWithoutQuote;
        assertTrue(prefetchRepository.existsByPathContainingIgnoreCaseAndType(pathToDelete, PrefetchEntityType.CERT));
        String pathToDeleteJson = "\"" + pathToDelete + "\"";
        restMockMvc.perform(multipart(HttpMethod.DELETE, CONFIG_NODE + ATTESTATION_FILE)
            .file(new MockMultipartFile("path", "", MediaType.APPLICATION_JSON_VALUE, pathToDeleteJson.getBytes(StandardCharsets.UTF_8))))
            .andExpect(status().isOk());
        prefetchEntityList = prefetchRepository.findAll();
        assertEquals(databaseSizeBeforeCreate, prefetchEntityList.size());
        assertFalse(prefetchRepository.existsByPathContainingIgnoreCaseAndType("file://" + pathWithoutQuote, PrefetchEntityType.CERT));
    }
}
