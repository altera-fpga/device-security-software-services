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

package com.intel.bkp.bkps.testutils;

import com.intel.bkp.bkps.crypto.contextkey.ContextKeyManager;
import com.intel.bkp.bkps.crypto.sealingkey.SealingKeyManager;
import com.intel.bkp.bkps.domain.AesKey;
import com.intel.bkp.bkps.domain.Qek;
import com.intel.bkp.bkps.domain.AttestationConfiguration;
import com.intel.bkp.bkps.domain.BlackList;
import com.intel.bkp.bkps.domain.ConfidentialData;
import com.intel.bkp.bkps.domain.EfusesPublic;
import com.intel.bkp.bkps.domain.ServiceConfiguration;
import com.intel.bkp.bkps.domain.SigningKeyCertificate;
import com.intel.bkp.bkps.domain.SigningKeyEntity;
import com.intel.bkp.bkps.domain.SigningKeyMultiCertificate;
import com.intel.bkp.bkps.domain.enumeration.ImportMode;
import com.intel.bkp.bkps.domain.enumeration.SigningKeyStatus;
import com.intel.bkp.bkps.repository.SigningKeyRepository;
import com.intel.bkp.bkps.rest.initialization.service.InitializationService;
import com.intel.bkp.bkps.rest.initialization.service.SealingKeyService;
import com.intel.bkp.bkps.rest.initialization.service.SigningKeyService;
import com.intel.bkp.core.manufacturing.model.PufType;
import com.intel.bkp.core.psgcertificate.PsgCertificateForBkpsAdapter;
import com.intel.bkp.core.psgcertificate.enumerations.KeyWrappingType;
import com.intel.bkp.core.psgcertificate.enumerations.StorageType;
import com.intel.bkp.core.security.ISecurityProvider;
import com.intel.bkp.crypto.CryptoUtils;
import com.intel.bkp.crypto.constants.SecurityKeyType;
import com.intel.bkp.crypto.exceptions.EncryptionProviderException;
import com.intel.bkp.test.enumeration.ResourceDir;
import com.intel.bkp.utils.ByteBufferSafe;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Optional;

import static com.intel.bkp.test.FileUtils.loadBinary;
import static com.intel.bkp.utils.HexConverter.toHex;
import static org.mockito.Mockito.when;

public class TestHelper {

    public static final String DEFAULT_NAME = "AAAAAAAAAA";
    public static final String DEFAULT_EFUSES_PUB_MASK =
        Hex.toHexString(ByteBuffer.allocate(256).putLong(151).putInt(8).array());
    public static final String DEFAULT_EFUSES_PUB_VALUE =
        Hex.toHexString(ByteBuffer.allocate(256).putLong(132).putInt(8).array());
    public static final String IV_DATA = "1234567890ABCDEF1234567890ABCDEF";
    public static final String AES_ROOT_KEY = "1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF";
    private static final String SIGNING_KEY_ROOT_SINGLE =
        "3690258998000000800000000000000000000000010000009b8b0b400000000060067058300000003000000048663254ffffffff"
            + "ffffffffdf512b36e90dee4237eef44d0ba104584c91274bd653a7525a6f2d41b7fdb4c7a3237a9d7bed8d794a6fbbe52a"
            + "5c8f4bcb17d16038edf33e5da4d58d381fd50e0fd596f4f76ee04e48faaa16c1b395fe45c8d574df54865445e7701393a3db06";
    private static final String SIGNING_KEY_ROOT_MULTI =
        "2436733698000000800000000000000000000000010000000a4a9a9e000000004366654000000000ffffffff48663254ffffffff"
            + "ffffffffdf512b36e90dee4237eef44d0ba104584c91274bd653a7525a6f2d41b7fdb4c7a3237a9d7bed8d794a6fbbe52a"
            + "5c8f4bcb17d16038edf33e5da4d58d381fd50e0fd596f4f76ee04e48faaa16c1b395fe45c8d574df54865445e7701393a3db06";

    private static final String SINGLE_CHAIN = SIGNING_KEY_ROOT_SINGLE
        + "1709549200010000780000007000000000000000000000006006705830000000300000004866325410000000000000000d8254"
        + "2c6f909faf634ed6592ff9442c2019b75df1f64241f1e38390385d606f1a042dce909844cfabce2fa5102386d133bde0456d8e"
        + "7583c1115648c59dd834437b7c57ae164713130c881dc7614b3d08376aade7d7eefd8b2a84dc1a4f1eb1201588743000000030"
        + "00000020885430aa33918e55c6c66d01eda913b5adbdc2aa7dd1b8d68e4596ae217b36970473566afeb64ec91bc98005df31c6"
        + "b66e601efa058b325ab520c33382562e74d8ebbca9f8f64c5189b2c166f073a7b9443a7c6ed038d43f00d2956fb8e85c1b8c541d";

    private static final String MULTI_CHAIN = SIGNING_KEY_ROOT_MULTI
        + "1709549200010000780000007000000000000000000000004366654000000000000000004866325410000000000000000d8254"
        + "2c6f909faf634ed6592ff9442c2019b75df1f64241f1e38390385d606f1a042dce909844cfabce2fa5102386d133bde0456d8e"
        + "7583c1115648c59dd834437b7c57ae164713130c881dc7614b3d08376aade7d7eefd8b2a84dc1a4f1eb1201588740000000000"
        + "0000002088543006ebd2e752a92a0e9aafccd87bc5c439166979fbcf2768b3bde7fe6fe34c7a42807e1fde3c35b174d64da79c"
        + "ef2b5efd4f431d2c19ba5e230e804c0c4bc53443ee5ad3049a903cd413368a64bf5c6de42822e1631d5c6fcbc14fa1c17fab46fb";

    public static final String DEFAULT_KEY_NAME = "Key123";

    public static ServiceConfiguration createServiceConfigurationEntity(Integer overbuildMax, StorageType storageType,
                                                                        SealingKeyManager sealingKeyManager,
                                                                        boolean requireIidUds,
                                                                        PufType pufType,
                                                                        KeyWrappingType keyWrappingType,
                                                                        Qek qek,
                                                                        byte[] aesCcertData) {
        return createServiceConfigurationEntity(overbuildMax, storageType,
            sealingKeyManager,
            requireIidUds,
            pufType,
            keyWrappingType,
            qek,
            aesCcertData,
            true,
            null);
    }

    public static ServiceConfiguration createServiceConfigurationEntity(Integer overbuildMax, StorageType storageType,
                                                                        SealingKeyManager sealingKeyManager,
                                                                        boolean requireIidUds,
                                                                        PufType pufType,
                                                                        KeyWrappingType keyWrappingType,
                                                                        Qek qek,
                                                                        byte[] aesCcertData,
                                                                        boolean autoFetchFirmwareCorim,
                                                                        Long appraisalPolicyId) {

        ConfidentialData confidentialData = new ConfidentialData();
        confidentialData.setImportMode(ImportMode.PLAINTEXT);

        AesKey aesKey = new AesKey();
        aesKey.setStorage(storageType);
        aesKey.setTestProgram(false);
        aesKey.setKeyWrappingType(keyWrappingType);

        if (aesCcertData == null) {
            aesCcertData = loadBinary(ResourceDir.ROOT, "signed_iid_aes.ccert");
        }
        final byte[] aesContent = aesCcertData;
        Optional.ofNullable(sealingKeyManager)
            .ifPresentOrElse(skm -> aesKey.setValue(getEncryptedAesKey(skm, aesContent)),
                () -> aesKey.setValue(toHex(aesContent))
            );

        confidentialData.setAesKey(aesKey);

        if (qek != null) {
            confidentialData.setQek(qek);
        }

        AttestationConfiguration attestationConfig = new AttestationConfiguration();
        EfusesPublic efusesPub = new EfusesPublic();
        efusesPub.setMask(DEFAULT_EFUSES_PUB_MASK);
        efusesPub.setValue(DEFAULT_EFUSES_PUB_VALUE);
        attestationConfig.setEfusesPublic(efusesPub);
        attestationConfig.setBlackList(new BlackList());

        return new ServiceConfiguration()
            .name(DEFAULT_NAME)
            .pufType(pufType)
            .requireIidUds(requireIidUds)
            .overbuildMax(overbuildMax)
            .overbuildCurrent(2)
            .confidentialData(confidentialData)
            .attestationConfig(attestationConfig)
            .autoFetchFirmwareCorim(autoFetchFirmwareCorim)
            .appraisalPolicyId(appraisalPolicyId);
    }

    private static String getEncryptedAesKey(SealingKeyManager sealingKeyManager, byte[] aesContent) {
        final TestAesGcmProviderImpl encryptionProvider = new TestAesGcmProviderImpl(sealingKeyManager.getActiveKey());
        try {
            return toHex(encryptionProvider.encrypt(aesContent));
        } catch (EncryptionProviderException e) {
            throw new RuntimeException("Failed to encrypt AES key.", e);
        }
    }

    private static void initializeKeys(InitializationService initializationService,
                                       SealingKeyService sealingKeyService, SigningKeyService signingKeyService) {
        initializationService.deleteServiceImportKey();
        initializationService.createServiceImportKeyPair();
        signingKeyService.createSigningKey();
        signingKeyService.addRootSigningPublicKey(SIGNING_KEY_ROOT_SINGLE);
        sealingKeyService.createSealingKey();
    }

    public static void setMockContextKey(ContextKeyManager contextKeyManager) {
        byte[] secret = new byte[32];
        new SecureRandom().nextBytes(secret);
        SecretKey originalKey = new SecretKeySpec(secret, 0, secret.length, "AES");
        when(contextKeyManager.get()).thenReturn(originalKey);
        when(contextKeyManager.getCipherType()).thenReturn("GCM");
        when(contextKeyManager.getProvider()).thenReturn(CryptoUtils.getBouncyCastleProvider());
    }

    public static void initializeBkps(SigningKeyRepository signingKeyRepository,
                                      InitializationService initializationService, SigningKeyService signingKeyService,
                                      ISecurityProvider securityService,
                                      SealingKeyService sealingKeyService) {

        initializeKeys(initializationService, sealingKeyService, signingKeyService);

        final SigningKeyEntity entity = new SigningKeyEntity();

        securityService.createSecurityObject(SecurityKeyType.EC, "TEST_KEY");
        entity.setName("TEST_KEY");
        entity.setStatus(SigningKeyStatus.ENABLED);

        PsgCertificateForBkpsAdapter.parse(SINGLE_CHAIN).forEach(entryHelper -> entity
            .getChain().add(new SigningKeyCertificate(entryHelper.getType(), entryHelper.getContent()))
        );
        PsgCertificateForBkpsAdapter.parse(MULTI_CHAIN).forEach(entryHelper -> entity
            .getMultiChain().add(new SigningKeyMultiCertificate(entryHelper.getType(), entryHelper.getContent()))
        );

        signingKeyRepository.save(entity);
    }

    public static int toInt(byte[] anInt) {
        final ByteBufferSafe wrap = ByteBufferSafe.wrap(anInt);
        wrap.rewind();
        return wrap.getInt();
    }

    public static byte[] toArray(int anInt) {
        return ByteBuffer.allocate(Integer.BYTES).putInt(anInt).array();
    }

}
