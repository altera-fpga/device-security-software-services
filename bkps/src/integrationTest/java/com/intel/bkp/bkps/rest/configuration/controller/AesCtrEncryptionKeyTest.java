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

package com.intel.bkp.bkps.rest.configuration.controller;

import com.intel.bkp.bkps.BkpsApp;
import com.intel.bkp.bkps.crypto.aesctr.AesCtrEncryptionKeyProviderImpl;
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
import com.intel.bkp.crypto.aesctr.AesCtrQekIvProvider;
import com.intel.bkp.crypto.constants.SecurityKeyType;
import com.intel.bkp.test.enumeration.ResourceDir;
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
import java.util.Arrays;
import java.util.List;
import static com.intel.bkp.bkps.rest.RestUtil.createFormattingConversionService;
import static com.intel.bkp.bkps.rest.configuration.ConfigurationResource.CONFIGURATION;
import static com.intel.bkp.bkps.rest.configuration.ConfigurationResource.CONFIGURATION_DETAIL;
import static com.intel.bkp.bkps.rest.configuration.ConfigurationResource.CONFIG_NODE;
import static com.intel.bkp.test.FileUtils.loadBinary;
import static com.intel.bkp.test.FileUtils.loadFile;
import static com.intel.bkp.utils.HexConverter.fromHex;
import static com.intel.bkp.utils.HexConverter.toHex;
import static org.junit.jupiter.api.Assertions.assertEquals;
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
public class AesCtrEncryptionKeyTest {

    private static final Integer DEFAULT_OVERBUILD_MAX = 1;
    private static final PufType PUF_TYPE = PufType.INTEL;
    private static final KeyWrappingType KEY_WRAPPING_TYPE = KeyWrappingType.UDS_INTEL_PUF;
    private static final StorageType STORAGE_TYPE = StorageType.PUFSS;
    private static final String SEALING_KEYNAME = "SealingKey";
    private static String ENCRYPTION_KEY;

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
    private ISecurityProvider securityService;

    @Autowired
    private AesCtrEncryptionKeyProviderImpl aesCtrEncryptionKeyProvider;

    @Autowired
    private AesGcmSealingKeyProviderImpl aesGcmSealingKeyProvider;

    @Autowired
    private EntityManager em;

    private MockMvc restMockMvc;

    private ServiceConfiguration serviceConfiguration;

    private ServiceConfiguration serviceConfigurationVer1;

    private byte[] qekContent;

    private byte[] qekContentVer1;

    private byte[] aesKeyContent;

    private byte[] aesKeyContentVer1;

    @BeforeEach
    void setup() {
        final ServiceConfigurationController serviceConfigurationResource =
            new ServiceConfigurationController(serviceConfigurationService, serviceConfigurationMapper);
        this.restMockMvc = MockMvcBuilders.standaloneSetup(serviceConfigurationResource)
            .setCustomArgumentResolvers(pageableArgumentResolver)
            .setControllerAdvice(exceptionTranslator)
            .setConversionService(createFormattingConversionService())
            .setMessageConverters(jacksonMessageConverter).build();

        Qek qek = new Qek();
        qek.setKeyName(TestHelper.DEFAULT_KEY_NAME);
        qekContent = loadBinary(ResourceDir.ROOT, "aes_testmode1.qek");
        qek.setValue(toHex(qekContent));
        Qek qekVer1 = new Qek();
        qekVer1.setKeyName(TestHelper.DEFAULT_KEY_NAME);
        qekContentVer1 = loadBinary(ResourceDir.ROOT, "BKPSAESKey32.qek");
        qekVer1.setValue(toHex(qekContentVer1));
        byte[] encryptionKeyData = fromHex(loadFile(ResourceDir.ROOT, "aes_key_sdm1_5_ver2.txt"));
        ENCRYPTION_KEY = toHex(encryptionKeyData);
        aesKeyContent = loadBinary(ResourceDir.ROOT, "signed_UDS_intelpuf_wrapped_aes_testmode1.ccert");
        aesKeyContentVer1 = loadBinary(ResourceDir.ROOT, "signed_efuse_wrapped_aes_version_1.ccert");
        serviceConfiguration = TestHelper.createServiceConfigurationEntity(
            DEFAULT_OVERBUILD_MAX, STORAGE_TYPE, null, false, PUF_TYPE, KEY_WRAPPING_TYPE, qek, aesKeyContent);
        serviceConfigurationVer1 = TestHelper.createServiceConfigurationEntity(
            DEFAULT_OVERBUILD_MAX, STORAGE_TYPE, null, false, PufType.EFUSE, KeyWrappingType.INTERNAL, qekVer1, aesKeyContentVer1);
    }

    @Test
    @Transactional
    public void testAesCtr() throws Exception {
        prepareAesKey(SecurityKeyType.AES_CTR, TestHelper.DEFAULT_KEY_NAME, ENCRYPTION_KEY, "AES/CTR/NoPadding");
        byte[] ivBytes = fromHex(TestHelper.IV_DATA);
        AesCtrQekIvProvider ivProvider = new AesCtrQekIvProvider(ivBytes);
        aesCtrEncryptionKeyProvider.initialize(ivProvider, TestHelper.DEFAULT_KEY_NAME);
        byte[] cipherText = aesCtrEncryptionKeyProvider.encrypt(fromHex(TestHelper.AES_ROOT_KEY));
        byte[] decryptedText = aesCtrEncryptionKeyProvider.decrypt(cipherText);
        assert Arrays.equals(fromHex(TestHelper.AES_ROOT_KEY), decryptedText);
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
            .andExpect(jsonPath("$.confidentialData.qek.keyName").value(TestHelper.DEFAULT_KEY_NAME))
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
    public void createVersion1ServiceConfigurationWithTestProgramFlag() throws Exception {
        prepareSealingKey();
        prepareAesKey(SecurityKeyType.AES_CTR, TestHelper.DEFAULT_KEY_NAME, ENCRYPTION_KEY, "AES/CTR/NoPadding");
        int databaseSizeBeforeCreate = serviceConfigurationRepository.findAll().size();
        // Create the ServiceConfiguration
        ServiceConfigurationDTO serviceConfigurationDTO = serviceConfigurationMapper.toDto(serviceConfigurationVer1);
        serviceConfigurationDTO.getConfidentialData().getAesKey().setTestProgram(true);
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
        assertEquals(PufType.EFUSE, testServiceConfiguration.getPufType());
        assertEquals(DEFAULT_OVERBUILD_MAX, testServiceConfiguration.getOverbuildMax());

        final AesKey aesKey = testServiceConfiguration.getConfidentialData().getAesKey();
        assertEquals(StorageType.EFUSES, aesKey.getStorage());
        assertEquals(KeyWrappingType.INTERNAL, aesKey.getKeyWrappingType());
        aesGcmSealingKeyProvider.initialize(securityService.getKeyFromSecurityObject(SEALING_KEYNAME));
        final byte[] decryptedAesContent = aesGcmSealingKeyProvider.decrypt(fromHex(aesKey.getValue()));
        assert Arrays.equals(aesKeyContentVer1, decryptedAesContent);
        assertEquals(false, aesKey.getTestProgram());
        final Qek qek = testServiceConfiguration.getConfidentialData().getQek();
        assertEquals(TestHelper.DEFAULT_KEY_NAME, qek.getKeyName());
        final byte[] decryptedQekValue = aesGcmSealingKeyProvider.decrypt(fromHex(qek.getValue()));
        assert Arrays.equals(qekContentVer1, decryptedQekValue);
    }

    @Test
    @Transactional
    public void createServiceConfigurationWithTestProgramFlag() throws Exception {
        prepareSealingKey();
        prepareAesKey(SecurityKeyType.AES_CTR, TestHelper.DEFAULT_KEY_NAME, ENCRYPTION_KEY, "AES/CTR/NoPadding");
        int databaseSizeBeforeCreate = serviceConfigurationRepository.findAll().size();
        // Create the ServiceConfiguration
        ServiceConfigurationDTO serviceConfigurationDTO = serviceConfigurationMapper.toDto(serviceConfiguration);
        serviceConfigurationDTO.getConfidentialData().getAesKey().setTestProgram(true);
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
        aesGcmSealingKeyProvider.initialize(securityService.getKeyFromSecurityObject(SEALING_KEYNAME));
        final byte[] decryptedAesContent = aesGcmSealingKeyProvider.decrypt(fromHex(aesKey.getValue()));
        assert Arrays.equals(aesKeyContent, decryptedAesContent);
        assertEquals(false, aesKey.getTestProgram());
        final Qek qek = testServiceConfiguration.getConfidentialData().getQek();
        assertEquals(TestHelper.DEFAULT_KEY_NAME, qek.getKeyName());
        final byte[] decryptedQekValue = aesGcmSealingKeyProvider.decrypt(fromHex(qek.getValue()));
        assert Arrays.equals(qekContent, decryptedQekValue);
    }

    @Test
    @Transactional
    public void createServiceConfigurationWithoutTestProgramFlag() throws Exception {
        prepareSealingKey();
        prepareAesKey(SecurityKeyType.AES_CTR, TestHelper.DEFAULT_KEY_NAME, ENCRYPTION_KEY, "AES/CTR/NoPadding");
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
        aesGcmSealingKeyProvider.initialize(securityService.getKeyFromSecurityObject(SEALING_KEYNAME));
        final byte[] decryptedAesContent = aesGcmSealingKeyProvider.decrypt(fromHex(aesKey.getValue()));
        assert Arrays.equals(aesKeyContent, decryptedAesContent);
        assertEquals(false, aesKey.getTestProgram());
        final Qek qek = testServiceConfiguration.getConfidentialData().getQek();
        assertEquals(TestHelper.DEFAULT_KEY_NAME, qek.getKeyName());
        final byte[] decryptedQekValue = aesGcmSealingKeyProvider.decrypt(fromHex(qek.getValue()));
        assert Arrays.equals(qekContent, decryptedQekValue);
    }

    @Test
    @Transactional
    public void createServiceConfiguration_FailDecrypt() throws Exception {
        prepareSealingKey();
        prepareAesKey(SecurityKeyType.AES_CTR, TestHelper.DEFAULT_KEY_NAME, ENCRYPTION_KEY, "AES/CTR/NoPadding");
        int databaseSizeBeforeCreate = serviceConfigurationRepository.findAll().size();
        // Create the ServiceConfiguration
        String wrongKeyName = "Wrong key";
        serviceConfiguration.getConfidentialData().getQek().setKeyName(wrongKeyName);
        ServiceConfigurationDTO serviceConfigurationDTO = serviceConfigurationMapper.toDto(serviceConfiguration);
        var result = restMockMvc.perform(post(CONFIG_NODE + CONFIGURATION)
                    .contentType(RestUtil.APPLICATION_JSON_UTF8)
                    .content(RestUtil.convertObjectToJsonBytes(serviceConfigurationDTO)))
                    .andExpect(status().isInternalServerError())
                    .andReturn();
        assertEquals("QEK encryption key with key alias name (%s) does not exist in BKPS HSM".formatted(wrongKeyName), result.getResolvedException().getCause().getMessage());

        // Validate the ServiceConfiguration in the database
        List<ServiceConfiguration> serviceConfigurationList = serviceConfigurationRepository.findAll();
        assertEquals(databaseSizeBeforeCreate, serviceConfigurationList.size());
    }

    @Test
    @Transactional
    public void update_key_name_ServiceConfiguration() throws Exception {
        prepareSealingKey();
        prepareAesKey(SecurityKeyType.AES_CTR, TestHelper.DEFAULT_KEY_NAME, ENCRYPTION_KEY, "AES/CTR/NoPadding");
        // Initialize the database
        serviceConfigurationRepository.saveAndFlush(serviceConfiguration);

        // Update the serviceConfiguration
        ServiceConfiguration updatedServiceConfiguration = serviceConfigurationRepository
            .findById(serviceConfiguration.getId()).orElse(null);
        // Disconnect from session so that the updates on updatedServiceConfiguration are not directly saved in db
        em.detach(updatedServiceConfiguration);
        final String newKeyName = "Key2";
        prepareAesKey(SecurityKeyType.AES_CTR, newKeyName, ENCRYPTION_KEY, "AES/CTR/NoPadding");
        updatedServiceConfiguration.getConfidentialData().getQek().setKeyName(newKeyName);
        assert updatedServiceConfiguration != null;
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
        assertEquals(newKeyName, testServiceConfiguration.getConfidentialData().getQek().getKeyName());
    }

    private void prepareAesKey(SecurityKeyType keyType, String keyName, String keyData, String algo) {

        if (keyData != null && !keyData.isEmpty()) {
            SecretKeySpec key = new SecretKeySpec(fromHex(keyData), algo);
            securityService.importSecretKey(keyName, key);
        } else {
            securityService.createSecurityObject(keyType, keyName);
        }
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
