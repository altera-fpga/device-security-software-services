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

import com.fasterxml.jackson.databind.ObjectMapper;
import com.intel.bkp.bkps.BkpsApp;
import com.intel.bkp.bkps.domain.AppraisalPolicy;
import com.intel.bkp.bkps.domain.SealingKey;
import com.intel.bkp.bkps.domain.enumeration.SealingKeyStatus;
import com.intel.bkp.bkps.repository.AppraisalPolicyRepository;
import com.intel.bkp.bkps.repository.SealingKeyRepository;
import com.intel.bkp.bkps.rest.RestUtil;
import com.intel.bkp.bkps.rest.configuration.model.dto.AppraisalPolicyDTO;
import com.intel.bkp.bkps.rest.configuration.model.mapper.AppraisalPolicyMapper;
import com.intel.bkp.bkps.rest.configuration.service.AppraisalPolicyService;
import com.intel.bkp.bkps.rest.errors.ApplicationExceptionHandler;
import com.intel.bkp.bkps.rest.errors.enums.ErrorCodeMap;
import com.intel.bkp.bkps.testutils.TestHelper;
import com.intel.bkp.core.security.ISecurityProvider;
import com.intel.bkp.fpgacerts.appraisalpolicy.parser.AppraisalPolicyParser;
import com.intel.bkp.test.FileUtils;
import jakarta.persistence.EntityManager;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.web.PageableHandlerMethodArgumentResolver;
import org.springframework.http.MediaType;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.transaction.annotation.Transactional;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.List;

import static com.intel.bkp.bkps.rest.RestUtil.createFormattingConversionService;
import static com.intel.bkp.bkps.rest.configuration.ConfigurationResource.APPRAISAL_POLICY;
import static com.intel.bkp.bkps.rest.configuration.ConfigurationResource.APPRAISAL_POLICY_DETAIL;
import static com.intel.bkp.bkps.rest.configuration.ConfigurationResource.CONFIG_NODE;
import static com.intel.bkp.test.FileUtils.TEST_FOLDER;
import static com.intel.bkp.utils.HexConverter.fromHex;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.hasSize;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = BkpsApp.class)
@ActiveProfiles({"staticbouncycastle"})
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS)
public class AppraisalPolicyControllerTestIT {

    private static final String UPDATED_NAME = "BBBBBBBBBB";
    private static final String DEFAULT_NAME = "Appraisal Policy";
    private static final String SEALING_KEYNAME = "SealingKey";

    @Autowired
    private SealingKeyRepository sealingKeyRepository;

    @Autowired
    private AppraisalPolicyRepository appraisalPolicyRepository;

    @Autowired
    private AppraisalPolicyMapper appraisalPolicyMapper;

    @Autowired
    private AppraisalPolicyService appraisalPolicyService;

    @Autowired
    private MappingJackson2HttpMessageConverter jacksonMessageConverter;

    @Autowired
    private PageableHandlerMethodArgumentResolver pageableArgumentResolver;

    @Autowired
    private ApplicationExceptionHandler exceptionTranslator;

    @Autowired
    private EntityManager em;

    @Autowired
    private ISecurityProvider securityService;

    private MockMvc restMockMvc;

    private AppraisalPolicy appraisalPolicy;

    private AppraisalPolicy createNewPolicy() throws Exception {
        prepareSealingKey();
        int databaseSizeBeforeCreate = appraisalPolicyRepository.findAll().size();

        // Create the AppraisalPolicy
        AppraisalPolicyDTO appraisalPolicyDTO = appraisalPolicyMapper.toDto(appraisalPolicy);
        restMockMvc.perform(post(CONFIG_NODE + APPRAISAL_POLICY)
                .contentType(RestUtil.APPLICATION_JSON_UTF8)
                .content(RestUtil.convertObjectToJsonBytes(appraisalPolicyDTO)))
            .andExpect(status().isCreated());

        // Validate the AppraisalPolicy in the database
        List<AppraisalPolicy> appraisalPolicyList = appraisalPolicyRepository.findAll();
        assertEquals(databaseSizeBeforeCreate + 1, appraisalPolicyList.size());
        AppraisalPolicy testAppraisalPolicy = appraisalPolicyList.get(appraisalPolicyList.size() - 1);
        return testAppraisalPolicy;
    }

    @BeforeEach
    void setup() throws Exception {
        final AppraisalPolicyController appraisalPolicyResource =
            new AppraisalPolicyController(appraisalPolicyService);
        this.restMockMvc = MockMvcBuilders.standaloneSetup(appraisalPolicyResource)
            .setCustomArgumentResolvers(pageableArgumentResolver)
            .setControllerAdvice(exceptionTranslator)
            .setConversionService(createFormattingConversionService())
            .setMessageConverters(jacksonMessageConverter).build();

        appraisalPolicy = new AppraisalPolicy()
            .name(DEFAULT_NAME)
            .content(FileUtils.readFromResourcesAsString(TEST_FOLDER, "test_appraisal_policy.txt"));
    }

    @Test
    @Transactional
    public void createAppraisalPolicy() throws Exception {
        var testAppraisalPolicy = createNewPolicy();
        assertEquals(DEFAULT_NAME, testAppraisalPolicy.getName());
        var addedPolicy = AppraisalPolicyParser.instance().parse(appraisalPolicyService.findOneForDetails(testAppraisalPolicy.getId()).get());
        var expectedPolicy = AppraisalPolicyParser.instance().parse(appraisalPolicy.getContent());
        assertEquals(expectedPolicy, addedPolicy);

        var response = restMockMvc.perform(get(CONFIG_NODE + APPRAISAL_POLICY_DETAIL, testAppraisalPolicy.getId()))
            .andExpect(status().isOk())
            .andExpect(content().contentType(MediaType.APPLICATION_JSON_VALUE))
            .andReturn()
            .getResponse()
            .getContentAsString();

        ObjectMapper mapper = new ObjectMapper();
        String unescaped = mapper.readValue(response, String.class);
        assertEquals(unescaped, appraisalPolicy.getContent());
    }

    @Test
    @Transactional
    public void createAppraisalPolicyWithId() throws Exception {
        int databaseSizeBeforeCreate = appraisalPolicyRepository.findAll().size();

        // Create the AppraisalPolicy with ID
        appraisalPolicy.setId(1L);
        AppraisalPolicyDTO appraisalPolicyDTO = appraisalPolicyMapper.toDto(appraisalPolicy);

        // An entity with an ID cannot be created, so this API call must fail
        restMockMvc.perform(post(CONFIG_NODE + APPRAISAL_POLICY)
            .contentType(RestUtil.APPLICATION_JSON_UTF8)
            .content(RestUtil.convertObjectToJsonBytes(appraisalPolicyDTO)))
            .andExpect(status().isBadRequest());

        // Validate the AppraisalPolicy in the database
        List<AppraisalPolicy> appraisalPolicyList = appraisalPolicyRepository.findAll();
        assertEquals(databaseSizeBeforeCreate, appraisalPolicyList.size());
    }

    @Test
    @Transactional
    public void createAppraisalPolicyWithInvalidAppraisalPolicy() throws Exception {
        prepareSealingKey();
        int databaseSizeBeforeCreate = appraisalPolicyRepository.findAll().size();

        // Create the AppraisalPolicy with invalid Appraisal Policy
        appraisalPolicy = new AppraisalPolicy()
            .name(DEFAULT_NAME)
            .content(FileUtils.readFromResourcesAsString(TEST_FOLDER, "test_invalid_policy.txt"));
        AppraisalPolicyDTO appraisalPolicyDTO = appraisalPolicyMapper.toDto(appraisalPolicy);

        // An entity with invalid appraisal policy content cannot be created, so this API call must fail
        restMockMvc.perform(post(CONFIG_NODE + APPRAISAL_POLICY)
            .contentType(RestUtil.APPLICATION_JSON_UTF8)
            .content(RestUtil.convertObjectToJsonBytes(appraisalPolicyDTO)))
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.[*].message").value(ErrorCodeMap.CORRUPTED_APPRAISAL_POLICY.getExternalMessage()));

        // Validate the AppraisalPolicy in the database
        List<AppraisalPolicy> appraisalPolicyList = appraisalPolicyRepository.findAll();
        assertEquals(databaseSizeBeforeCreate, appraisalPolicyList.size());
    }

    @Test
    @Transactional
    public void checkNameIsRequired() throws Exception {
        prepareSealingKey();
        int databaseSizeBeforeTest = appraisalPolicyRepository.findAll().size();
        // set the field null
        appraisalPolicy.setName(null);

        // Create the AppraisalPolicy, which fails.
        AppraisalPolicyDTO appraisalPolicyDTO = appraisalPolicyMapper.toDto(appraisalPolicy);

        restMockMvc.perform(post(CONFIG_NODE + APPRAISAL_POLICY)
            .contentType(RestUtil.APPLICATION_JSON_UTF8)
            .content(RestUtil.convertObjectToJsonBytes(appraisalPolicyDTO)))
            .andExpect(status().isBadRequest());

        List<AppraisalPolicy> appraisalPolicyList = appraisalPolicyRepository.findAll();
        assertEquals(databaseSizeBeforeTest, appraisalPolicyList.size());
    }

    @Test
    @Transactional
    public void checkContentIsRequired() throws Exception {
        prepareSealingKey();
        int databaseSizeBeforeTest = appraisalPolicyRepository.findAll().size();// set the field null
        appraisalPolicy.setContent(null);

        // Create the AppraisalPolicy, which fails.
        AppraisalPolicyDTO appraisalPolicyDTO = appraisalPolicyMapper.toDto(appraisalPolicy);

        restMockMvc.perform(post(CONFIG_NODE + APPRAISAL_POLICY)
            .contentType(RestUtil.APPLICATION_JSON_UTF8)
            .content(RestUtil.convertObjectToJsonBytes(appraisalPolicyDTO)))
            .andExpect(status().isBadRequest());

        List<AppraisalPolicy> appraisalPolicyList = appraisalPolicyRepository.findAll();
        assertEquals(databaseSizeBeforeTest, appraisalPolicyList.size());
    }

    @Test
    @Transactional
    public void getAllAppraisalPolicies() throws Exception {
        // Initialize the database
        createNewPolicy();

        // Get all the appraisalPolicyList
        restMockMvc.perform(get(CONFIG_NODE + APPRAISAL_POLICY))
            .andExpect(status().isOk())
            .andExpect(content().contentType(MediaType.APPLICATION_JSON_VALUE))
            .andExpect(jsonPath("$.[*].id").value(hasSize(1)))
            .andExpect(jsonPath("$.[*].name").value(hasItem(DEFAULT_NAME)));
    }

    @Test
    @Transactional
    public void getNonExistingAppraisalPolicy() throws Exception {
        prepareSealingKey();
        // Get the appraisalPolicy
        restMockMvc.perform(get(CONFIG_NODE + APPRAISAL_POLICY_DETAIL, Long.MAX_VALUE))
            .andExpect(status().isNotFound())
            .andExpect(jsonPath("$.[*].message").value(ErrorCodeMap.APPRAISAL_POLICY_NOT_FOUND.getExternalMessage()));
    }

    @Test
    @Transactional
    public void updateAppraisalPolicy() throws Exception {
        // Initialize the database
        var policy = createNewPolicy();

        // Update the appraisalPolicy
        AppraisalPolicy updatedAppraisalPolicy = appraisalPolicyRepository
            .findById(policy.getId()).orElse(null);
        // Disconnect from session so that the updates on updatedAppraisalPolicy are not directly saved in db
        em.detach(updatedAppraisalPolicy);
        assert updatedAppraisalPolicy != null;
        updatedAppraisalPolicy.setName(UPDATED_NAME);
        updatedAppraisalPolicy.setContent(appraisalPolicy.getContent());
        AppraisalPolicyDTO appraisalPolicyDTO = appraisalPolicyMapper.toDto(updatedAppraisalPolicy);

        int databaseSizeBeforeUpdate = appraisalPolicyRepository.findAll().size();

        restMockMvc.perform(put(CONFIG_NODE + APPRAISAL_POLICY_DETAIL, updatedAppraisalPolicy.getId())
            .contentType(RestUtil.APPLICATION_JSON_UTF8)
            .content(RestUtil.convertObjectToJsonBytes(appraisalPolicyDTO))).andExpect(status().isOk());

        // Validate the AppraisalPolicy in the database
        List<AppraisalPolicy> appraisalPolicyList = appraisalPolicyRepository.findAll();
        assertEquals(databaseSizeBeforeUpdate, appraisalPolicyList.size());
        AppraisalPolicy testAppraisalPolicy = appraisalPolicyList.get(appraisalPolicyList.size() - 1);
        assertEquals(UPDATED_NAME, testAppraisalPolicy.getName());
        var addedPolicy = AppraisalPolicyParser.instance().parse(appraisalPolicyService.findOneForDetails(testAppraisalPolicy.getId()).get());
        var expectedPolicy = AppraisalPolicyParser.instance().parse(appraisalPolicy.getContent());
        assertEquals(expectedPolicy, addedPolicy);
    }

    @Test
    @Transactional
    public void updateNonExistingAppraisalPolicy() throws Exception {
        int databaseSizeBeforeUpdate = appraisalPolicyRepository.findAll().size();

        AppraisalPolicyDTO appraisalPolicyDTO = appraisalPolicyMapper.toDto(appraisalPolicy);

        restMockMvc.perform(put(CONFIG_NODE + APPRAISAL_POLICY_DETAIL, "100")
            .contentType(RestUtil.APPLICATION_JSON_UTF8)
            .content(RestUtil.convertObjectToJsonBytes(appraisalPolicyDTO)))
            .andExpect(status().isNotFound())
            .andExpect(jsonPath("$.[*].message").value(ErrorCodeMap.APPRAISAL_POLICY_NOT_FOUND.getExternalMessage()));

        List<AppraisalPolicy> appraisalPolicyList = appraisalPolicyRepository.findAll();
        assertEquals(databaseSizeBeforeUpdate, appraisalPolicyList.size());
    }

    @Test
    @Transactional
    public void deleteAppraisalPolicy() throws Exception {
        // Initialize the database
        var policy = createNewPolicy();

        int databaseSizeBeforeDelete = appraisalPolicyRepository.findAll().size();

        // Get the appraisalPolicy
        restMockMvc.perform(delete(CONFIG_NODE + APPRAISAL_POLICY_DETAIL, policy.getId())
            .accept(RestUtil.APPLICATION_JSON_UTF8))
            .andExpect(status().isOk());

        // Validate the database is empty
        List<AppraisalPolicy> appraisalPolicyList = appraisalPolicyRepository.findAll();
        assertEquals(databaseSizeBeforeDelete - 1, appraisalPolicyList.size());
    }

    private void prepareSealingKey() {
        SealingKey sealingKey = new SealingKey();
        sealingKey.setStatus(SealingKeyStatus.ENABLED);
        sealingKey.setGuid(SEALING_KEYNAME);

        if (sealingKeyRepository.findAll().isEmpty()) {
            sealingKeyRepository.save(sealingKey);
        }
        SecretKey key = new SecretKeySpec(fromHex(TestHelper.AES_ROOT_KEY), "AES/GCM/NoPadding");
        securityService.importSecretKey(SEALING_KEYNAME, key);

        assert securityService.existsSecurityObject(SEALING_KEYNAME);
    }
}
