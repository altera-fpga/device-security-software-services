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

package com.intel.bkp.bkps.protocol.sigma;

import com.intel.bkp.bkps.crypto.aesctr.AesCtrSigmaEncProviderImpl;
import com.intel.bkp.bkps.crypto.hmac.HMacSigmaEncProviderImpl;
import com.intel.bkp.bkps.programmer.model.dto.MessageDTO;
import com.intel.bkp.bkps.protocol.common.EncryptedPayload;
import com.intel.bkp.bkps.protocol.common.EncryptedPayloadProvider;
import com.intel.bkp.bkps.protocol.sigma.session.IMessageResponseCounterProvider;
import com.intel.bkp.bkps.protocol.sigma.session.SecureSessionIvProvider;
import com.intel.bkp.bkps.rest.provisioning.model.dto.ProvisioningResponseDTO;
import com.intel.bkp.bkps.testutils.MailboxResponseLayer;
import com.intel.bkp.bkps.testutils.TestHelper;
import com.intel.bkp.command.messages.sigma.SigmaEncMessage;
import com.intel.bkp.command.messages.sigma.SigmaEncMessageBuilder;
import com.intel.bkp.command.model.CertificateRequestType;
import com.intel.bkp.command.responses.common.CertificateResponse;
import com.intel.bkp.command.responses.common.CertificateResponseBuilder;
import com.intel.bkp.command.responses.common.GetCertificateResponse;
import com.intel.bkp.command.responses.common.GetCertificateResponseBuilder;
import com.intel.bkp.command.responses.common.GetChipIdResponse;
import com.intel.bkp.command.responses.common.GetChipIdResponseBuilder;
import com.intel.bkp.command.responses.sigma.SigmaEncResponse;
import com.intel.bkp.command.responses.sigma.SigmaEncResponseBuilder;
import com.intel.bkp.command.responses.sigma.SigmaM2Message;
import com.intel.bkp.command.responses.sigma.SigmaM2MessageBuilder;
import com.intel.bkp.command.responses.sigma.SigmaM3Response;
import com.intel.bkp.command.responses.sigma.SigmaM3ResponseBuilder;
import com.intel.bkp.command.responses.sigma.SigmaTeardownResponse;
import com.intel.bkp.command.responses.sigma.SigmaTeardownResponseBuilder;
import com.intel.bkp.core.endianness.EndiannessActor;
import com.intel.bkp.core.psgcertificate.PsgSignatureBuilder;
import com.intel.bkp.crypto.CryptoUtils;
import com.intel.bkp.crypto.constants.CryptoConstants;
import com.intel.bkp.crypto.ecdh.EcdhKeyPair;
import com.intel.bkp.crypto.sigma.HMacSigmaProviderImpl;
import com.intel.bkp.crypto.sigma.KdfProvider;
import com.intel.bkp.test.PsgSignatureUtils;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;

import java.util.Base64;

import static com.intel.bkp.bkps.testutils.TestHelper.toArray;
import static com.intel.bkp.bkps.testutils.TestHelper.toInt;
import static com.intel.bkp.command.responses.sigma.SigmaEncFlowType.WITH_ENCRYPTED_RESPONSE;
import static com.intel.bkp.test.RandomUtils.generateRandomBytes;
import static com.intel.bkp.utils.ByteSwap.getSwappedArray;
import static com.intel.bkp.utils.ByteSwap.getSwappedArrayByInt;
import static com.intel.bkp.utils.ByteSwapOrder.B2L;
import static com.intel.bkp.utils.ByteSwapOrder.L2B;
import static com.intel.bkp.utils.HexConverter.fromHex;

@AllArgsConstructor
@Slf4j
@Getter
public class SigmaTestUtils {

    private static final int STATUS_OK = 0;

    private final MailboxResponseLayer commandLayer;

    private final EcdhKeyPair bkpsDhKeyPair;
    private final EcdhKeyPair deviceDhKeyPair;
    private final EcdhKeyPair pakKeyPair;

    private byte[] protocolMacKey;
    private byte[] sessionEncryptionKey;
    private byte[] sessionMacKey;

    public SigmaTestUtils(MailboxResponseLayer commandLayer) throws Exception {
        this.commandLayer = commandLayer;
        this.bkpsDhKeyPair = EcdhKeyPair.generate();
        this.deviceDhKeyPair = EcdhKeyPair.generate();
        this.pakKeyPair = EcdhKeyPair.generate();
        deriveSessionKeys();
    }

    private void deriveSessionKeys() throws Exception {
        final byte[] ecdhSharedSecret = CryptoUtils.genEcdhSharedSecretBC(
            bkpsDhKeyPair.privateKey(), deviceDhKeyPair.publicKey());
        protocolMacKey = KdfProvider.derivePMK(ecdhSharedSecret);
        sessionEncryptionKey = KdfProvider.deriveSEK(ecdhSharedSecret);
        sessionMacKey = KdfProvider.deriveSMK(ecdhSharedSecret);
    }

    public SigmaEncMessage parseSigmaEncMessage(ProvisioningResponseDTO bkpsResponseDto) {
        final MessageDTO messageDTO = bkpsResponseDto.getJtagCommands().get(0);
        final byte[] decodedCommand = decodeCommandDto(messageDTO);

        return new SigmaEncMessageBuilder()
            .parse(commandLayer.retrieve(decodedCommand))
            .build();
    }

    public SigmaTeardownResponse getSigmaTeardownResponse() {
        return new SigmaTeardownResponseBuilder().build();
    }

    public GetChipIdResponse getChipIdResponse(String deviceId) {
        final GetChipIdResponseBuilder getChipIdResponseBuilder = new GetChipIdResponseBuilder();
        getChipIdResponseBuilder.setDeviceUniqueId(fromHex(deviceId));
        return getChipIdResponseBuilder.build();
    }

    public GetCertificateResponse getGetCertificateResponse() {
        return new GetCertificateResponseBuilder().build();
    }

    public GetCertificateResponse getGetCertificateResponse(byte[] certificate, CertificateRequestType type) {
        final GetCertificateResponseBuilder builder = new GetCertificateResponseBuilder();
        builder.setCertificateType(getSwappedArray(type.getType(), B2L));
        builder.setCertificateBlob(certificate);
        return builder.build();
    }

    public SigmaM3Response getSigmaM3Response() {
        return new SigmaM3ResponseBuilder().build();
    }

    public SigmaEncResponse getSigmaEncResponse(SigmaEncMessage sigmaEncMessage) throws Exception {
        return getSigmaEncResponse(sigmaEncMessage, new byte[0]);
    }

    public SigmaEncResponse getSigmaEncResponse(SigmaEncMessage sigmaEncMessage, byte[] certificateResponseData)
        throws Exception {
        return prepareSigmaEncResponseWithEncryptedPayload(
            STATUS_OK,
            toInt(getSwappedArrayByInt(sigmaEncMessage.getMessageResponseCounter(), L2B)) + 1,
            sigmaEncMessage.getMagic(),
            sigmaEncMessage.getInitialIv(),
            sigmaEncMessage.getSdmSessionId(),
            certificateResponseData
        );
    }

    private byte[] decodeCommandDto(MessageDTO messageDTO) {
        final String command = messageDTO.getValue();
        return Base64.getDecoder().decode(command);
    }

    private SigmaEncResponse prepareSigmaEncResponseWithEncryptedPayload(int status, int responseCounter,
                                                                         byte[] magic, byte[] initialIv,
                                                                         byte[] sdmSessionId,
                                                                         byte[] certificateResponseData)
        throws Exception {
        final CertificateResponse certificateResponse = prepareCertificateResponse(status, certificateResponseData);
        final EncryptedPayload payloadToBeEncrypted = EncryptedPayload.from(commandLayer.create(certificateResponse));

        final byte[] encryptedPayload = encryptPayload(responseCounter, initialIv, payloadToBeEncrypted);

        return prepareSigmaEncResponseInternal(responseCounter, magic, initialIv, sdmSessionId, payloadToBeEncrypted,
            encryptedPayload);
    }

    private SigmaEncResponse prepareSigmaEncResponseInternal(int responseCounter, byte[] magic, byte[] initialIv,
                                                             byte[] sdmSessionId, EncryptedPayload payloadToBeEncrypted,
                                                             byte[] encryptedPayload) throws Exception {

        final SigmaEncResponseBuilder encResponseBuilder = new SigmaEncResponseBuilder();
        encResponseBuilder.setFlowType(WITH_ENCRYPTED_RESPONSE);
        encResponseBuilder.withActor(EndiannessActor.FIRMWARE);
        encResponseBuilder.setMagic(magic);
        encResponseBuilder.setSdmSessionId(sdmSessionId);
        encResponseBuilder.setMessageResponseCounter(toArray(responseCounter));
        encResponseBuilder.setEncryptedPayload(encryptedPayload);
        encResponseBuilder.setPayloadLen(encryptedPayload.length);
        encResponseBuilder.setNumberOfPaddingBytes(payloadToBeEncrypted.getPaddingLength());
        encResponseBuilder.setInitialIv(initialIv);
        encResponseBuilder.mac(new HMacSigmaEncProviderImpl(sessionMacKey));
        return encResponseBuilder.build();
    }

    private byte[] encryptPayload(int responseCounter, byte[] initialIv, EncryptedPayload payloadToBeEncrypted) {
        return new EncryptedPayloadProvider(payloadToBeEncrypted.build(),
            new AesCtrSigmaEncProviderImpl(sessionEncryptionKey,
                new SecureSessionIvProvider(new IMessageResponseCounterProvider() {
                    @Override
                    public byte[] getInitialIv() {
                        return initialIv;
                    }

                    @Override
                    public byte[] getMessageResponseCounter() {
                        return toArray(responseCounter);
                    }
                })))
            .build();
    }

    private CertificateResponse prepareCertificateResponse(int status, byte[] certificateResponseData) {
        final CertificateResponseBuilder builder = new CertificateResponseBuilder();
        builder.setCertificateProcessStatus(getSwappedArray(status, B2L));
        builder.setResponseData(certificateResponseData);
        return builder.build();
    }

    public SigmaM2Message getSigmaM2(String deviceId) throws Exception {
        return getSigmaM2(true, deviceId);
    }

    public SigmaM2Message getSigmaM2(boolean validHmac, String deviceId) throws Exception {
        byte[] pmk = preparePmk(validHmac);

        final SigmaM2MessageBuilder builder = new SigmaM2MessageBuilder();
        builder.setMagic(generateRandomBytes(Integer.BYTES));
        builder.setSdmSessionId(generateRandomBytes(Integer.BYTES));
        builder.setDeviceUniqueId(fromHex(deviceId));
        builder.setRomVersionNum(generateRandomBytes(Integer.BYTES));
        builder.setSdmFwBuildId(generateRandomBytes(SigmaM2MessageBuilder.SDM_FW_BUILD_ID_LEN));
        builder.setSdmFwSecurityVersionNum(generateRandomBytes(Integer.BYTES));
        builder.setPublicEfuseValues(fromHex(TestHelper.DEFAULT_EFUSES_PUB_VALUE));
        builder.setDeviceDhPubKey(deviceDhKeyPair.getPublicKey());
        builder.setBkpsDhPubKey(bkpsDhKeyPair.getPublicKey());
        builder.setSignatureBuilder(prepareCorrectSignature(builder));
        builder.setMac(prepareCorrectMac(builder, pmk));

        return builder.withActor(EndiannessActor.FIRMWARE).build();
    }

    private byte[] preparePmk(boolean validHmac) {
        return validHmac
               ? protocolMacKey
               : generateRandomBytes(KdfProvider.PMK_OUTPUT_KEY_LEN);
    }

    private PsgSignatureBuilder prepareCorrectSignature(SigmaM2MessageBuilder builder) throws Exception {
        byte[] dataForSignature = builder.withActor(EndiannessActor.FIRMWARE).getDataForSignature();
        byte[] signatureInBkpsFormat = PsgSignatureUtils.signDataInPsgFormat(dataForSignature, pakKeyPair.privateKey(),
            CryptoConstants.SHA384_WITH_ECDSA);
        return new PsgSignatureBuilder().parse(signatureInBkpsFormat);
    }

    private byte[] prepareCorrectMac(SigmaM2MessageBuilder builder, byte[] protocolMacKey) throws Exception {
        final byte[] dataAndSignatureForMac = builder.withActor(EndiannessActor.FIRMWARE).getDataAndSignatureForMac();
        return new HMacSigmaProviderImpl(protocolMacKey).getHash(dataAndSignatureForMac);
    }
}
