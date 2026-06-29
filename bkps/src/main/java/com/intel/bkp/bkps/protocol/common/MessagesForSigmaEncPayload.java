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
import com.intel.bkp.bkps.domain.Qek;
import com.intel.bkp.bkps.domain.ServiceConfiguration;
import com.intel.bkp.bkps.exception.ProvisioningGenericException;
import com.intel.bkp.command.logger.CommandLogger;
import com.intel.bkp.command.messages.common.CertificateBuilder;
import com.intel.bkp.command.model.CommandIdentifier;
import com.intel.bkp.core.endianness.EndiannessActor;
import com.intel.bkp.core.endianness.StructureBuilder;
import com.intel.bkp.core.exceptions.ParseStructureException;
import com.intel.bkp.core.interfaces.IStructure;
import com.intel.bkp.core.psgcertificate.IPsgAesKeyBuilder;
import com.intel.bkp.core.psgcertificate.PsgAesKeyBuilderFactory;
import com.intel.bkp.core.psgcertificate.PsgQekBuilderHSM;
import com.intel.bkp.core.psgcertificate.model.PsgAesKeyType;
import com.intel.bkp.crypto.aesctr.AesCtrQekIvProvider;
import com.intel.bkp.crypto.exceptions.EncryptionProviderException;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import static com.intel.bkp.command.logger.CommandLoggerValues.CERTIFICATE_MESSAGE;
import static com.intel.bkp.utils.HexConverter.fromHex;

@Component
@RequiredArgsConstructor(access = AccessLevel.PACKAGE)
@Slf4j
public class MessagesForSigmaEncPayload {

    private final AesGcmSealingKeyProviderImpl aesGcmSealingKeyProvider;
    private final AesCtrEncryptionKeyProviderImpl aesCtrEncryptionKeyProvider;
    private final SealingKeyManager sealingKeyManager;
    private final CommandLayerService commandLayer;
    private final PsgAesKeyBuilderFactory psgAesKeyBuilderFactory = new PsgAesKeyBuilderFactory();
    private IPsgAesKeyBuilder<? extends StructureBuilder<?, ? extends IStructure>> aesKeyBuilder;

    public byte[] prepareFrom(ServiceConfiguration configuration) {
        final var confidentialData = configuration.getConfidentialData();
        final var aesKey = confidentialData.getAesKey();
        var aesKeyBytes = decryptConfidentialData(aesKey);
        verifyAesKeyCanBeParsed(aesKeyBytes);
        CommandIdentifier cmd = CommandIdentifier.CERTIFICATE;
        if (PsgAesKeyType.SDM_1_5.equals(aesKeyBuilder.getAesKeyType())) {
            cmd = CommandIdentifier.USER_AES_ROOT_KEY_PROVISION;
            aesKeyBytes = parseQekAppendCcert(confidentialData.getQek(), aesKeyBytes);
        }

        final var certificate = new CertificateBuilder(aesKeyBytes)
            .testProgram(aesKey.getTestProgram())
            .build();
        final byte[] certificateBytes = commandLayer.create(certificate, cmd);
        CommandLogger.log(certificate, CERTIFICATE_MESSAGE, this.getClass());

        return certificateBytes;
    }

    public byte[] decryptConfidentialData(AesKey aesKey) {
        return decryptConfidentialData(fromHex(aesKey.getValue()));
    }

    public byte[] decryptConfidentialData(Qek qek) {
        return decryptConfidentialData(fromHex(qek.getValue()));
    }

    private byte[] decryptConfidentialData(byte[] encryptedData) {
        aesGcmSealingKeyProvider.initialize(sealingKeyManager.getActiveKey());
        try {
            return aesGcmSealingKeyProvider.decrypt(encryptedData);
        } catch (EncryptionProviderException e) {
            throw new ProvisioningGenericException("Failed to decrypt sensitive data with sealing key.", e);
        }
    }

    private void verifyAesKeyCanBeParsed(byte[] aesKeyBytes) {
        try {
            aesKeyBuilder = psgAesKeyBuilderFactory
                            .withActor(EndiannessActor.FIRMWARE)
                            .getPsgAesKeyBuilder(aesKeyBytes);
            aesKeyBuilder
                .withActor(EndiannessActor.FIRMWARE)
                .parse(aesKeyBytes);
        } catch (ParseStructureException e) {
            throw new ProvisioningGenericException("Failed to get AES Key SDM version or parse Customer AES Key.", e);
        }
    }

    private byte[] parseQekAppendCcert(Qek qek, byte[] aesKey) {
        try {
            // Parse QEK content
            PsgQekBuilderHSM qekBuilder = new PsgQekBuilderHSM();
            final byte[] decryptedData = decryptConfidentialData(qek);
            qekBuilder.withActor(EndiannessActor.FIRMWARE).parse(decryptedData);
            // Append AES ccert with AES root key
            aesCtrEncryptionKeyProvider.initialize(new AesCtrQekIvProvider(qekBuilder.getIvData()), qek.getKeyName());
            final byte[] aesRootKey = aesCtrEncryptionKeyProvider.decrypt(qekBuilder.getEncryptedAESKey());
            ByteBuffer buffer = ByteBuffer.allocate(aesKey.length + aesRootKey.length);
            buffer.order(ByteOrder.LITTLE_ENDIAN).put(aesKey);
            buffer.put(aesRootKey);
            return buffer.array();
        } catch (EncryptionProviderException e) {
            throw new ProvisioningGenericException("Failed to decrypt encrypted AES root key from QEK content.", e);
        } catch (ParseStructureException e) {
            throw new ProvisioningGenericException("Failed to get encrypted AES root key from QEK content or parse QEK content.", e);
        }
    }
}
