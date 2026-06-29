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

package com.intel.bkp.bkps.protocol.common;

import com.intel.bkp.bkps.command.CommandLayerService;
import com.intel.bkp.bkps.crypto.aesctr.AesCtrEncryptionKeyProviderImpl;
import com.intel.bkp.bkps.crypto.aesgcm.AesGcmSealingKeyProviderImpl;
import com.intel.bkp.bkps.crypto.sealingkey.SealingKeyManager;
import com.intel.bkp.bkps.domain.AesKey;
import com.intel.bkp.bkps.domain.AttestationConfiguration;
import com.intel.bkp.bkps.domain.ConfidentialData;
import com.intel.bkp.bkps.domain.EfusesPublic;
import com.intel.bkp.bkps.domain.Qek;
import com.intel.bkp.bkps.domain.ServiceConfiguration;
import com.intel.bkp.bkps.domain.enumeration.ImportMode;
import com.intel.bkp.bkps.exception.ProvisioningGenericException;
import com.intel.bkp.command.messages.common.Certificate;
import com.intel.bkp.command.model.CommandIdentifier;
import com.intel.bkp.core.endianness.EndiannessActor;
import com.intel.bkp.core.manufacturing.model.PufType;
import com.intel.bkp.core.psgcertificate.PsgAesKeyBuilderSDM12;
import com.intel.bkp.core.psgcertificate.PsgQekBuilderHSM;
import com.intel.bkp.core.psgcertificate.enumerations.StorageType;
import com.intel.bkp.crypto.exceptions.EncryptionProviderException;
import com.intel.bkp.test.FileUtils;
import com.intel.bkp.test.enumeration.ResourceDir;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import javax.crypto.SecretKey;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import static com.intel.bkp.test.FileUtils.loadBinary;
import static com.intel.bkp.utils.HexConverter.fromHex;
import static com.intel.bkp.utils.HexConverter.toHex;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
public class MessagesForSigmaEncPayloadTest {

    private static final String DEFAULT_NAME = "AAAAAAAAAA";
    private static final PufType DEFAULT_PUF_TYPE = PufType.EFUSE;
    private static final Integer DEFAULT_OVERBUILD_MAX = 1;
    private static final String DEFAULT_EFUSES_PUB_MASK =
        toHex(ByteBuffer.allocate(256).putLong(151).putInt(8).array());
    private static final String DEFAULT_EFUSES_PUB_VALUE =
        toHex(ByteBuffer.allocate(256).putLong(132).putInt(8).array());
    private static final String AES_CERT_FOLDER = "testdata/";
    private static final String ENCRYPTION_KEY = "ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890";

    private byte[] aesKeyBytes;
    private PsgAesKeyBuilderSDM12 aesKeyBuilder;

    @Mock
    private AesGcmSealingKeyProviderImpl aesGcmSealingKeyProvider;

    @Mock
    private AesCtrEncryptionKeyProviderImpl aesCtrEncryptionKeyProvider;

    @Mock
    private SealingKeyManager sealingKeyManager;

    @Mock
    SecretKey secretKey;

    @Mock
    private CommandLayerService commandLayer;

    @InjectMocks
    private MessagesForSigmaEncPayload sut;

    @BeforeEach
    void setUp() throws Exception {
        this.aesKeyBytes = FileUtils.readFromResources(AES_CERT_FOLDER, "signed_iid_aes.ccert");
        this.aesKeyBuilder = new PsgAesKeyBuilderSDM12()
            .withActor(EndiannessActor.FIRMWARE)
            .parse(this.aesKeyBytes);
    }

    @Test
    void prepareFrom_WithPufStorageTypeSdm15_Success() throws Exception {
        // given
        Qek qek = new Qek();
        qek.setKeyName("Key123");
        final byte[] encryptionKey = fromHex(ENCRYPTION_KEY);
        final byte[] qekContent = loadBinary(ResourceDir.ROOT, "aes_testmode1.qek");
        qek.setValue(toHex(qekContent));
        aesKeyBytes = loadBinary(ResourceDir.ROOT, "signed_UDS_intelpuf_wrapped_aes_testmode1.ccert");
        ServiceConfiguration serviceConfiguration = prepareServiceConfiguration(StorageType.PUFSS, false, qek);

        // when
        when(sut.decryptConfidentialData(serviceConfiguration.getConfidentialData().getAesKey())).thenReturn(aesKeyBytes); // Return unencrypted AES ccert
        when(sut.decryptConfidentialData(serviceConfiguration.getConfidentialData().getQek())).thenReturn(qekContent); // Return unencrypted QEK
        PsgQekBuilderHSM qekBuilderHSM = new PsgQekBuilderHSM();
        qekBuilderHSM.withActor(EndiannessActor.FIRMWARE).parse(qekContent);
        when(aesCtrEncryptionKeyProvider.decrypt(qekBuilderHSM.getEncryptedAESKey())).thenReturn(encryptionKey); // Return unencrypted QEK encryption key
        when(commandLayer.create(any(Certificate.class), eq(CommandIdentifier.USER_AES_ROOT_KEY_PROVISION))).thenAnswer(invocation -> {
            Certificate certificate = invocation.getArgument(0);
            return certificate.array();
        });

        // then
        final byte[] baseMessage = sut.prepareFrom(serviceConfiguration);
        ByteBuffer buffer = ByteBuffer.allocate(aesKeyBytes.length + encryptionKey.length);
        buffer.put(aesKeyBytes);
        buffer.put(encryptionKey);
        assertTrue(toHex(baseMessage).contains(toHex(buffer.array())));
    }

    @Test
    void prepareFrom_WithPufssStorageType_Success() throws Exception {
        // given
        ServiceConfiguration serviceConfiguration = prepareServiceConfigurationProduction(StorageType.PUFSS);
        mockBehavior();

        // when
        final byte[] baseMessage = sut.prepareFrom(serviceConfiguration);

        // then
        assertTrue(
            toHex(baseMessage).contains(toHex(aesKeyBuilder.build().array()))
        );
    }

    @Test
    void prepareFrom_WithBBRAMStorageType_Success() throws Exception {
        // given
        ServiceConfiguration serviceConfiguration = prepareServiceConfigurationProduction(StorageType.BBRAM);
        mockBehavior();

        // when
        final byte[] baseMessage = sut.prepareFrom(serviceConfiguration);

        // then
        assertTrue(
            toHex(baseMessage).contains(toHex(aesKeyBuilder.build().array()))
        );
    }

    @Test
    void prepareFrom_WithEFUSEStorageType_Success() throws Exception {
        // given
        ServiceConfiguration serviceConfiguration = prepareServiceConfigurationProduction(StorageType.EFUSES);
        mockBehavior();

        serviceConfiguration.getConfidentialData().getAesKey().setTestProgram(true);

        // when
        final byte[] baseMessage = sut.prepareFrom(serviceConfiguration);

        // then
        assertTrue(
            toHex(baseMessage).contains(toHex(aesKeyBuilder.build().array()))
        );
    }

    @Test
    void prepareFrom_WithEFUSEStorageTypeTestProgram_ReturnsCorrectMessage() throws Exception {
        // given
        final String expectedHexStringWhenTestProgramIsSet = "00000080";
        ServiceConfiguration serviceConfiguration = prepareServiceConfigurationWithTestProgram(StorageType.EFUSES);
        mockBehavior();

        // when
        final byte[] baseMessage = sut.prepareFrom(serviceConfiguration);

        // then
        assertTrue(toHex(baseMessage).startsWith(expectedHexStringWhenTestProgramIsSet));
    }

    @Test
    void prepareFrom_WithEFUSEStorageTypeAndAESDecryptException_ThrowsException() throws Exception {
        // given
        ServiceConfiguration serviceConfiguration = prepareServiceConfigurationProduction(StorageType.EFUSES);
        when(aesGcmSealingKeyProvider.decrypt(any()))
            .thenThrow(EncryptionProviderException.class);

        // when-then
        assertThrows(ProvisioningGenericException.class, () -> sut.prepareFrom(serviceConfiguration));
    }

    private ServiceConfiguration prepareServiceConfigurationWithTestProgram(StorageType aesKeyStorage) {
        return prepareServiceConfiguration(aesKeyStorage, true, null);
    }

    private ServiceConfiguration prepareServiceConfigurationProduction(StorageType aesKeyStorage) {
        return prepareServiceConfiguration(aesKeyStorage, false, null);
    }

    private ServiceConfiguration prepareServiceConfiguration(StorageType aesKeyStorage, boolean testProgram, Qek qek) {
        AesKey aesKey = new AesKey();
        aesKey.setStorage(aesKeyStorage);
        aesKey.setValue(toHex(aesKeyBytes));
        aesKey.setTestProgram(testProgram);

        ConfidentialData confidentialData = new ConfidentialData();
        confidentialData.setImportMode(ImportMode.PLAINTEXT);
        confidentialData.setAesKey(aesKey);
        if (qek != null) {
            confidentialData.setQek(qek);
        }

        EfusesPublic efusesPub = new EfusesPublic();
        efusesPub.setMask(DEFAULT_EFUSES_PUB_MASK);
        efusesPub.setValue(DEFAULT_EFUSES_PUB_VALUE);

        AttestationConfiguration attestationConfig = new AttestationConfiguration();
        attestationConfig.setEfusesPublic(efusesPub);

        return new ServiceConfiguration()
            .name(DEFAULT_NAME)
            .pufType(DEFAULT_PUF_TYPE)
            .overbuildMax(DEFAULT_OVERBUILD_MAX)
            .overbuildCurrent(2)
            .confidentialData(confidentialData)
            .attestationConfig(attestationConfig);
    }

    private void mockBehavior() throws EncryptionProviderException {
        when(sealingKeyManager.getActiveKey()).thenReturn(secretKey);
        when(aesGcmSealingKeyProvider.decrypt(any())).thenReturn(aesKeyBytes);
        when(commandLayer.create(any(Certificate.class), eq(CommandIdentifier.CERTIFICATE))).thenAnswer(invocation -> {
            Certificate certificate = invocation.getArgument(0);
            return certificate.array();
        });
    }
}
