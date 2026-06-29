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
import com.intel.bkp.bkps.crypto.aesgcm.AesGcmSealingKeyProviderImpl;
import com.intel.bkp.bkps.domain.AesKey;
import com.intel.bkp.bkps.domain.Qek;
import com.intel.bkp.bkps.domain.SealingKey;
import com.intel.bkp.bkps.domain.ServiceConfiguration;
import com.intel.bkp.bkps.domain.enumeration.ImportMode;
import com.intel.bkp.bkps.domain.enumeration.SealingKeyStatus;
import com.intel.bkp.bkps.repository.SealingKeyRepository;
import com.intel.bkp.bkps.repository.ServiceConfigurationRepository;
import com.intel.bkp.bkps.rest.RestUtil;
import com.intel.bkp.bkps.rest.configuration.model.dto.ServiceConfigurationDTO;
import com.intel.bkp.bkps.rest.configuration.model.mapper.ServiceConfigurationMapper;
import com.intel.bkp.bkps.rest.configuration.service.ServiceConfigurationService;
import com.intel.bkp.bkps.rest.errors.ApplicationExceptionHandler;
import com.intel.bkp.bkps.testutils.TestHelper;
import com.intel.bkp.core.manufacturing.model.PufType;
import com.intel.bkp.core.psgcertificate.enumerations.KeyWrappingType;
import com.intel.bkp.core.psgcertificate.enumerations.StorageType;
import com.intel.bkp.core.security.ISecurityProvider;
import com.intel.bkp.crypto.exceptions.EncryptionProviderException;
import com.intel.bkp.test.enumeration.ResourceDir;
import jakarta.persistence.EntityManager;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.data.web.PageableHandlerMethodArgumentResolver;
import org.springframework.http.MediaType;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

import static com.intel.bkp.bkps.rest.RestUtil.createFormattingConversionService;
import static com.intel.bkp.bkps.rest.configuration.ConfigurationResource.CONFIGURATION;
import static com.intel.bkp.bkps.rest.configuration.ConfigurationResource.CONFIGURATION_DETAIL;
import static com.intel.bkp.bkps.rest.configuration.ConfigurationResource.CONFIG_NODE;
import static com.intel.bkp.test.FileUtils.loadBinary;
import static com.intel.bkp.utils.HexConverter.toHex;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.hasSize;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;
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
public class ServiceConfigurationControllerTestIT {

    private static final String ENCRYPTED_DATA = "AQID";
    private static final String UPDATED_NAME = "BBBBBBBBBB";
    private static final Integer DEFAULT_OVERBUILD_MAX = 1;
    private static final PufType PUF_TYPE = PufType.IID;
    private static final KeyWrappingType KEY_WRAPPING_TYPE = KeyWrappingType.USER_IID_PUF;
    private static final PufType UPDATED_PUF_TYPE = PufType.IIDUSER;
    private static final StorageType STORAGE_TYPE = StorageType.PUFSS;

    @Autowired
    private SealingKeyRepository sealingKeyRepository;

    @Autowired
    private ServiceConfigurationRepository serviceConfigurationRepository;

    @Autowired
    private ServiceConfigurationMapper serviceConfigurationMapper;

    @Autowired
    private ServiceConfigurationService serviceConfigurationService;

    @Autowired
    private MappingJackson2HttpMessageConverter jacksonMessageConverter;

    @Autowired
    private PageableHandlerMethodArgumentResolver pageableArgumentResolver;

    @Autowired
    private ApplicationExceptionHandler exceptionTranslator;

    @Autowired
    private EntityManager em;

    @MockBean
    private ISecurityProvider securityService;

    @MockBean
    private AesGcmSealingKeyProviderImpl aesGcmSealingKeyProvider;

    private MockMvc restMockMvc;

    private ServiceConfiguration serviceConfiguration;

    @BeforeEach
    void setup() {
        final ServiceConfigurationController serviceConfigurationResource =
            new ServiceConfigurationController(serviceConfigurationService, serviceConfigurationMapper);
        this.restMockMvc = MockMvcBuilders.standaloneSetup(serviceConfigurationResource)
            .setCustomArgumentResolvers(pageableArgumentResolver)
            .setControllerAdvice(exceptionTranslator)
            .setConversionService(createFormattingConversionService())
            .setMessageConverters(jacksonMessageConverter).build();

        serviceConfiguration = TestHelper.createServiceConfigurationEntity(
            DEFAULT_OVERBUILD_MAX, STORAGE_TYPE, null, true, PUF_TYPE, KEY_WRAPPING_TYPE, null, null);
    }

    @Test
    @Transactional
    public void createServiceConfiguration() throws Exception {
        prepareSealingKey();
        int databaseSizeBeforeCreate = serviceConfigurationRepository.findAll().size();

        // Create the ServiceConfiguration
        ServiceConfigurationDTO serviceConfigurationDTO = serviceConfigurationMapper.toDto(serviceConfiguration);
        restMockMvc.perform(post(CONFIG_NODE + CONFIGURATION)
                .contentType(RestUtil.APPLICATION_JSON_UTF8)
                .content(RestUtil.convertObjectToJsonBytes(serviceConfigurationDTO)))
            .andExpect(status().isCreated());

        // Validate the ServiceConfiguration in the database
        List<ServiceConfiguration> serviceConfigurationList = serviceConfigurationRepository.findAll();
        assertEquals(databaseSizeBeforeCreate + 1, serviceConfigurationList.size());
        ServiceConfiguration testServiceConfiguration = serviceConfigurationList.get(
            serviceConfigurationList.size() - 1);
        assertEquals(TestHelper.DEFAULT_NAME, testServiceConfiguration.getName());
        assertEquals(PUF_TYPE, testServiceConfiguration.getPufType());
        assertEquals(DEFAULT_OVERBUILD_MAX, testServiceConfiguration.getOverbuildMax());

        final AesKey aesKey = testServiceConfiguration.getConfidentialData().getAesKey();
        assertEquals(STORAGE_TYPE, aesKey.getStorage());
        assertEquals(KEY_WRAPPING_TYPE, aesKey.getKeyWrappingType());
        assertEquals(Hex.toHexString(ENCRYPTED_DATA.getBytes()),
            aesKey.getValue());
    }

    @Test
    @Transactional
    public void createServiceConfigurationWithId() throws Exception {
        int databaseSizeBeforeCreate = serviceConfigurationRepository.findAll().size();

        // Create the ServiceConfiguration with ID
        serviceConfiguration.setId(1L);
        ServiceConfigurationDTO serviceConfigurationDTO = serviceConfigurationMapper.toDto(serviceConfiguration);

        // An entity with an ID cannot be created, so this API call must fail
        restMockMvc.perform(post(CONFIG_NODE + CONFIGURATION)
                .contentType(RestUtil.APPLICATION_JSON_UTF8)
                .content(RestUtil.convertObjectToJsonBytes(serviceConfigurationDTO)))
            .andExpect(status().isBadRequest());

        // Validate the ServiceConfiguration in the database
        List<ServiceConfiguration> serviceConfigurationList = serviceConfigurationRepository.findAll();
        assertEquals(databaseSizeBeforeCreate, serviceConfigurationList.size());
    }

    @Test
    @Transactional
    public void checkNameIsRequired() throws Exception {
        int databaseSizeBeforeTest = serviceConfigurationRepository.findAll().size();
        // set the field null
        serviceConfiguration.setName(null);

        // Create the ServiceConfiguration, which fails.
        ServiceConfigurationDTO serviceConfigurationDTO = serviceConfigurationMapper.toDto(serviceConfiguration);

        restMockMvc.perform(post(CONFIG_NODE + CONFIGURATION)
                .contentType(RestUtil.APPLICATION_JSON_UTF8)
                .content(RestUtil.convertObjectToJsonBytes(serviceConfigurationDTO)))
            .andExpect(status().isBadRequest());

        List<ServiceConfiguration> serviceConfigurationList = serviceConfigurationRepository.findAll();
        assertEquals(databaseSizeBeforeTest, serviceConfigurationList.size());
    }

    @Test
    @Transactional
    public void checkPufTypeIsRequired() throws Exception {
        int databaseSizeBeforeTest = serviceConfigurationRepository.findAll().size();
        // set the field null
        serviceConfiguration.setPufType(null);

        // Create the ServiceConfiguration, which fails.
        ServiceConfigurationDTO serviceConfigurationDTO = serviceConfigurationMapper.toDto(serviceConfiguration);

        restMockMvc.perform(post(CONFIG_NODE + CONFIGURATION)
                .contentType(RestUtil.APPLICATION_JSON_UTF8)
                .content(RestUtil.convertObjectToJsonBytes(serviceConfigurationDTO)))
            .andExpect(status().isBadRequest());

        List<ServiceConfiguration> serviceConfigurationList = serviceConfigurationRepository.findAll();
        assertEquals(databaseSizeBeforeTest, serviceConfigurationList.size());
    }

    @Test
    @Transactional
    public void checkQEKIsRequired() throws Exception {
        prepareSealingKey();
        int databaseSizeBeforeTest = serviceConfigurationRepository.findAll().size();
        // set the field null
        serviceConfiguration.getConfidentialData().setQek(null);

        // Create the ServiceConfiguration
        ServiceConfigurationDTO serviceConfigurationDTO = serviceConfigurationMapper.toDto(serviceConfiguration);

        restMockMvc.perform(post(CONFIG_NODE + CONFIGURATION)
                .contentType(RestUtil.APPLICATION_JSON_UTF8)
                .content(RestUtil.convertObjectToJsonBytes(serviceConfigurationDTO)))
            .andExpect(status().isCreated());

        // Validate the ServiceConfiguration in the database
        List<ServiceConfiguration> serviceConfigurationList = serviceConfigurationRepository.findAll();
        assertEquals(databaseSizeBeforeTest + 1, serviceConfigurationList.size());
        ServiceConfiguration testServiceConfiguration = serviceConfigurationList.get(
            serviceConfigurationList.size() - 1);
        assertNull(testServiceConfiguration.getConfidentialData().getQek());
    }

    @Test
    @Transactional
    public void checkQEKInfoIsRequiredSdm1_5() throws Exception {
        prepareSealingKey();
        // Cache QEK info
        Qek qek = new Qek();
        String qekData = toHex(loadBinary(ResourceDir.ROOT, "aes_testmode1.qek"));
        qek.setValue(qekData);
        qek.setKeyName(TestHelper.DEFAULT_KEY_NAME);
        serviceConfiguration.getConfidentialData().setQek(qek);

        // set the value null
        serviceConfiguration.getConfidentialData().getQek().setValue(null);

        // Create the ServiceConfiguration, which fails.
        ServiceConfigurationDTO serviceConfigurationDTO = serviceConfigurationMapper.toDto(serviceConfiguration);

        restMockMvc.perform(post(CONFIG_NODE + CONFIGURATION)
                .contentType(RestUtil.APPLICATION_JSON_UTF8)
                .content(RestUtil.convertObjectToJsonBytes(serviceConfigurationDTO)))
            .andExpect(status().isBadRequest());

        // set the keyName null
        serviceConfiguration.getConfidentialData().getQek().setValue(qekData);
        serviceConfiguration.getConfidentialData().getQek().setKeyName(null);

        // Create the ServiceConfiguration, which fails.
        serviceConfigurationDTO = serviceConfigurationMapper.toDto(serviceConfiguration);

        restMockMvc.perform(post(CONFIG_NODE + CONFIGURATION)
                .contentType(RestUtil.APPLICATION_JSON_UTF8)
                .content(RestUtil.convertObjectToJsonBytes(serviceConfigurationDTO)))
            .andExpect(status().isBadRequest());
    }

    @Test
    @Transactional
    public void getAllServiceConfigurations() throws Exception {
        // Initialize the database
        serviceConfigurationRepository.saveAndFlush(serviceConfiguration);

        // Get all the serviceConfigurationList
        restMockMvc.perform(get(CONFIG_NODE + CONFIGURATION))
            .andExpect(status().isOk())
            .andExpect(content().contentType(MediaType.APPLICATION_JSON_VALUE))
            .andExpect(jsonPath("$.[*].id").value(hasSize(1)))
            .andExpect(jsonPath("$.[*].name").value(hasItem(TestHelper.DEFAULT_NAME)));
    }

    @Test
    @Transactional
    public void getServiceConfiguration() throws Exception {
        // Initialize the database
        ServiceConfiguration config = serviceConfigurationRepository.saveAndFlush(this.serviceConfiguration);

        // Get the serviceConfiguration
        restMockMvc.perform(get(CONFIG_NODE + CONFIGURATION_DETAIL, this.serviceConfiguration.getId()))
            .andExpect(status().isOk())
            .andExpect(content().contentType(MediaType.APPLICATION_JSON_VALUE))
            .andExpect(jsonPath("$.id").value(config.getId()))
            .andExpect(jsonPath("$.name").value(config.getName()))
            .andExpect(jsonPath("$.pufType").value(PUF_TYPE.toString()))
            .andExpect(jsonPath("$.overbuild.max").value(1))
            .andExpect(jsonPath("$.overbuild.currentValue").value(2))
            .andExpect(jsonPath("$.confidentialData.importMode").value(ImportMode.PLAINTEXT.toString()))
            .andExpect(jsonPath("$.confidentialData.aesKey.storage").value(STORAGE_TYPE.toString()))
            .andExpect(jsonPath("$.confidentialData.aesKey.keyWrappingType").value(KEY_WRAPPING_TYPE.name()))
            .andExpect(jsonPath("$.attestationConfig.blackList.romVersions").isEmpty())
            .andExpect(jsonPath("$.attestationConfig.blackList.sdmBuildIdStrings").isEmpty())
            .andExpect(jsonPath("$.attestationConfig.blackList.sdmSvns").isEmpty())
            .andExpect(jsonPath("$.attestationConfig.efusesPublic.mask")
                .value(TestHelper.DEFAULT_EFUSES_PUB_MASK))
            .andExpect(jsonPath("$.attestationConfig.efusesPublic.value")
                .value(TestHelper.DEFAULT_EFUSES_PUB_VALUE));
    }

    @Test
    @Transactional
    public void getNonExistingServiceConfiguration() throws Exception {
        // Get the serviceConfiguration
        restMockMvc.perform(get(CONFIG_NODE + CONFIGURATION_DETAIL, Long.MAX_VALUE))
            .andExpect(status().isNotFound());
    }

    @Test
    @Transactional
    public void updateServiceConfiguration() throws Exception {
        prepareSealingKey();
        // Initialize the database
        serviceConfigurationRepository.saveAndFlush(serviceConfiguration);

        // Update the serviceConfiguration
        ServiceConfiguration updatedServiceConfiguration = serviceConfigurationRepository
            .findById(serviceConfiguration.getId()).orElse(null);
        // Disconnect from session so that the updates on updatedServiceConfiguration are not directly saved in db
        em.detach(updatedServiceConfiguration);
        assert updatedServiceConfiguration != null;
        updatedServiceConfiguration
            .name(UPDATED_NAME)
            .pufType(UPDATED_PUF_TYPE);
        ServiceConfigurationDTO serviceConfigurationDTO = serviceConfigurationMapper.toDto(updatedServiceConfiguration);

        int databaseSizeBeforeUpdate = serviceConfigurationRepository.findAll().size();

        restMockMvc.perform(put(CONFIG_NODE + CONFIGURATION_DETAIL,
            updatedServiceConfiguration.getId())
            .contentType(RestUtil.APPLICATION_JSON_UTF8)
            .content(RestUtil.convertObjectToJsonBytes(serviceConfigurationDTO))).andExpect(status().isOk());

        // Validate the ServiceConfiguration in the database
        List<ServiceConfiguration> serviceConfigurationList = serviceConfigurationRepository.findAll();
        assertEquals(databaseSizeBeforeUpdate, serviceConfigurationList.size());
        ServiceConfiguration testServiceConfiguration = serviceConfigurationList.get(
            serviceConfigurationList.size() - 1);
        assertEquals(UPDATED_NAME, testServiceConfiguration.getName());
        assertEquals(UPDATED_PUF_TYPE, testServiceConfiguration.getPufType());
    }

    @Test
    @Transactional
    public void updateNonExistingServiceConfiguration() throws Exception {
        int databaseSizeBeforeUpdate = serviceConfigurationRepository.findAll().size();

        ServiceConfigurationDTO serviceConfigurationDTO = serviceConfigurationMapper.toDto(serviceConfiguration);

        restMockMvc.perform(put(CONFIG_NODE + CONFIGURATION_DETAIL, "100")
                .contentType(RestUtil.APPLICATION_JSON_UTF8)
                .content(RestUtil.convertObjectToJsonBytes(serviceConfigurationDTO)))
            .andExpect(status().isNotFound());

        List<ServiceConfiguration> serviceConfigurationList = serviceConfigurationRepository.findAll();
        assertEquals(databaseSizeBeforeUpdate, serviceConfigurationList.size());
    }

    @Test
    @Transactional
    public void deleteServiceConfiguration() throws Exception {
        // Initialize the database
        serviceConfigurationRepository.saveAndFlush(serviceConfiguration);

        int databaseSizeBeforeDelete = serviceConfigurationRepository.findAll().size();

        // Get the serviceConfiguration
        restMockMvc.perform(delete(CONFIG_NODE + CONFIGURATION_DETAIL,
                serviceConfiguration.getId())
                .accept(RestUtil.APPLICATION_JSON_UTF8))
            .andExpect(status().isOk());

        // Validate the database is empty
        List<ServiceConfiguration> serviceConfigurationList = serviceConfigurationRepository.findAll();
        assertEquals(databaseSizeBeforeDelete - 1, serviceConfigurationList.size());
    }

    @Test
    @Transactional
    public void testEntityFromId() {
        assertEquals(42, serviceConfigurationMapper.fromId(42L).getId());
        assertNull(serviceConfigurationMapper.fromId(null));
    }

    private void prepareSealingKey() throws EncryptionProviderException {
        SealingKey sealingKey = new SealingKey();
        sealingKey.setStatus(SealingKeyStatus.ENABLED);
        sealingKey.setGuid("test");

        if (sealingKeyRepository.findAll().isEmpty()) {
            sealingKeyRepository.save(sealingKey);
        }

        when(securityService.existsSecurityObject(anyString())).thenReturn(true);
        when(aesGcmSealingKeyProvider.encrypt(any())).thenReturn(ENCRYPTED_DATA.getBytes());
    }
}
