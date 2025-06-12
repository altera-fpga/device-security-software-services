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


package com.intel.bkp.bkps.protocol.sigma.handler;


import com.intel.bkp.bkps.crypto.aesgcm.AesGcmContextProviderImpl;
import com.intel.bkp.bkps.domain.AttestationConfiguration;
import com.intel.bkp.bkps.domain.BlackList;
import com.intel.bkp.bkps.domain.EfusesPublic;
import com.intel.bkp.bkps.domain.ServiceConfiguration;
import com.intel.bkp.bkps.exception.ProvisioningConverterException;
import com.intel.bkp.bkps.exception.ProvisioningGenericException;
import com.intel.bkp.bkps.programmer.model.ProgrammerResponse;
import com.intel.bkp.bkps.programmer.model.ResponseStatus;
import com.intel.bkp.bkps.programmer.utils.ProgrammerResponseToDataAdapter;
import com.intel.bkp.bkps.protocol.common.handler.ProvHandlerTestUtil;
import com.intel.bkp.bkps.protocol.common.handler.ProvisioningHandler;
import com.intel.bkp.bkps.protocol.common.model.FlowStage;
import com.intel.bkp.bkps.protocol.common.service.SigningKeyManager;
import com.intel.bkp.bkps.protocol.sigma.model.ProvContext1;
import com.intel.bkp.bkps.rest.provisioning.chain.CertificateChainCreator;
import com.intel.bkp.bkps.rest.provisioning.chain.CertificateChainDTO;
import com.intel.bkp.bkps.rest.provisioning.chain.CertificateChainVerifier;
import com.intel.bkp.bkps.rest.provisioning.model.dto.ProvisioningRequestDTOReader;
import com.intel.bkp.bkps.rest.provisioning.model.dto.ProvisioningResponseDTO;
import com.intel.bkp.bkps.rest.provisioning.model.dto.ProvisioningTransferObject;
import com.intel.bkp.bkps.rest.provisioning.service.IServiceConfiguration;
import com.intel.bkp.command.model.CommandIdentifier;
import com.intel.bkp.command.model.CommandLayer;
import com.intel.bkp.command.responses.sigma.SigmaM2MessageBuilder;
import com.intel.bkp.core.endianness.EndiannessActor;
import com.intel.bkp.core.psgcertificate.PsgSignatureBuilder;
import com.intel.bkp.crypto.CryptoUtils;
import com.intel.bkp.crypto.asn1.Asn1ParsingUtils;
import com.intel.bkp.crypto.constants.CryptoConstants;
import com.intel.bkp.crypto.ecdh.EcdhKeyPair;
import com.intel.bkp.crypto.exceptions.EncryptionProviderException;
import com.intel.bkp.crypto.sigma.HMacSigmaProviderImpl;
import com.intel.bkp.crypto.sigma.KdfProvider;
import com.intel.bkp.test.PsgSignatureUtils;
import lombok.SneakyThrows;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.ThreadLocalRandom;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import static com.intel.bkp.bkps.protocol.sigma.SigmaM2TestUtil.getPublicKeyMatchingRealSigmaM2;
import static com.intel.bkp.bkps.protocol.sigma.SigmaM2TestUtil.getRealSigmaM2WithoutHeaderFm;
import static com.intel.bkp.bkps.protocol.sigma.SigmaM2TestUtil.getRealSigmaM2WithoutHeaderS10;
import static com.intel.bkp.bkps.rest.RestUtil.getProgrammerResponseFromArray;
import static com.intel.bkp.command.responses.sigma.DeviceFamilyFuseMap.FM568;
import static com.intel.bkp.command.responses.sigma.DeviceFamilyFuseMap.S10;
import static com.intel.bkp.test.RandomUtils.generateDeviceIdHex;
import static com.intel.bkp.test.RandomUtils.generateRandomBytes;
import static com.intel.bkp.utils.HexConverter.fromHex;
import static com.intel.bkp.utils.HexConverter.toHex;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
public class ProvAuthComponentTest {

    private static final EcdhKeyPair BKPS_DH_KEY_PAIR = new EcdhKeyPair(Hex.decode(
        "fed4231e2d0fe17b303a635bed18f1b9516b2aac94048cd613620ccbfb8087c746870c6c8127b80d30fd09bb59b9e01c460"
            + "5677840cc515ae64f031212bc92e7b22c6078716347ac05a12f185729e1fffe3cd4ff146bc9e794d352871e0d9a1f"),
        Hex.decode(
            "00fdb4a154a7320a686baf733fc1dabc5ac0ae39865d0168e8e1407e2e69c567cef"
                + "29e3545a9fea49f160d80a0a8507ec7"));
    private static final Long CFG_ID = ThreadLocalRandom.current().nextLong();
    private static final String DEVICE_ID = generateDeviceIdHex();
    private static final byte[] DEVICE_ID_ENROLLMENT_CERT_BYTES = new byte[]{1, 2, 3, 4};
    private static final String DEVICE_ID_ENROLLMENT_CERT_BYTES_HEX = toHex(DEVICE_ID_ENROLLMENT_CERT_BYTES);
    private static final int S10_EFUSES_PUBLIC_LEN = S10.getEfuseValuesFieldLen();
    private static final int FM_EFUSES_PUBLIC_LEN = FM568.getEfuseValuesFieldLen();

    private final EcdhKeyPair bkpsDhKeyPair = EcdhKeyPair.generate();
    private final EcdhKeyPair deviceDhKeyPair = EcdhKeyPair.generate();
    private final EcdhKeyPair pakKeyPair = EcdhKeyPair.generate();

    @Mock
    private IServiceConfiguration configurationCallback;
    @Mock
    private ProvisioningTransferObject transferObject;
    @Mock
    private ProvisioningRequestDTOReader dtoReader;
    @Mock
    private ProvisioningHandler successor;
    @Mock
    private ServiceConfiguration configuration;
    @Mock
    private AttestationConfiguration attestationConfiguration;
    @Mock
    private BlackList blackList;
    @Mock
    private EfusesPublic efusesPublic;
    @Mock
    private AesGcmContextProviderImpl contextEncryptionProvider;
    @Mock
    private SigningKeyManager signingKeyManager;
    @Mock
    private ProvContext1 context;
    @Mock
    private CommandLayer commandLayer;
    @Mock
    private CertificateChainCreator chainCreator;
    @Mock
    private CertificateChainVerifier chainVerifier;
    @Mock
    private CertificateChainDTO chainDTO;
    @Mock
    private LinkedList<X509Certificate> certs;
    @Mock
    private X509Certificate cert;
    @InjectMocks
    private ProvAuthComponent sut;

    ProvAuthComponentTest() throws Exception {
    }

    @BeforeEach
    void setUp() {
        sut.setSuccessor(successor);
    }

    @Test
    void handle_NotProperFlowStage_CallsSuccessor() {
        // given
        mockTransferObject(FlowStage.PROV_RESULT);

        // when
        sut.handle(transferObject);

        // then
        ProvHandlerTestUtil.verifySuccessorCalled(successor, transferObject);
    }

    @Test
    void handle_IncorrectNumberOfResponses_S10_Throws() {
        // given
        mockTransferObject(FlowStage.SIGMA_INIT_DATA);
        mockContext(DEVICE_ID, "");
        mockJtagResponses(3);

        // when-then
        assertThrows(ProvisioningGenericException.class,
            () -> sut.handle(transferObject)
        );
    }

    @Test
    void handle_IncorrectNumberOfResponses_Fm_Throws() {
        // given
        mockTransferObject(FlowStage.SIGMA_INIT_DATA);
        mockContext(DEVICE_ID, DEVICE_ID_ENROLLMENT_CERT_BYTES_HEX);
        mockJtagResponses(1);

        // when-then
        assertThrows(ProvisioningGenericException.class,
            () -> sut.handle(transferObject)
        );
    }

    @Test
    void perform_WithRealData_S10_Success() throws Exception {
        // given
        final String deviceId = "0B0A09080F0E0D0C";
        final PublicKey realKey = getPublicKeyMatchingRealSigmaM2();
        final byte[] realSigmaM2 = getRealSigmaM2WithoutHeaderS10();

        mockTransferObject(FlowStage.SIGMA_INIT_DATA);
        mockContext(deviceId, BKPS_DH_KEY_PAIR, "");
        mockJtagResponsesForS10(realSigmaM2);
        mockRetrieveFromCommandLayer(realSigmaM2);
        mockChainForS10(deviceId);
        mockPublicKeyOfLeafCert(realKey);
        mockSigningKeyManager();
        mockConfidentialData(S10_EFUSES_PUBLIC_LEN);
        mockCreatingJtagResponse();
        mockContextEncrypt();

        // when
        ProvisioningResponseDTO responseDTO = perform();

        // then
        assertEquals(1, responseDTO.getJtagCommands().size());
        verify(chainVerifier).verifyS10Chain(deviceId, chainDTO);
    }

    @Test
    void perform_WithRealData_Fm_Success() throws Exception {
        // given
        final boolean requireIidUds = false;
        final boolean testModeSecrets = false;
        final String deviceId = "7BCCC9AAA4E4B3CD";
        final PublicKey realKey = getPublicKeyMatchingRealSigmaM2();
        final byte[] realSigmaM2 = getRealSigmaM2WithoutHeaderFm();
        mockCreatingJtagResponse();
        mockContextEncrypt();

        mockTransferObject(FlowStage.SIGMA_INIT_DATA);
        mockContext(deviceId, BKPS_DH_KEY_PAIR, DEVICE_ID_ENROLLMENT_CERT_BYTES_HEX);
        mockJtagResponsesForFm(realSigmaM2);
        mockRetrieveFromCommandLayer(realSigmaM2);
        mockChainForFm(DEVICE_ID_ENROLLMENT_CERT_BYTES, requireIidUds, testModeSecrets);
        mockPublicKeyOfLeafCert(realKey);
        mockSigningKeyManager();
        mockConfidentialData(FM_EFUSES_PUBLIC_LEN);

        // when
        ProvisioningResponseDTO responseDTO = perform();

        // then
        assertEquals(1, responseDTO.getJtagCommands().size());
        verify(chainVerifier).verifyDiceChain(deviceId, chainDTO, requireIidUds, testModeSecrets);
    }

    @Test
    void perform_PerformsContextEncryption_Success() throws Exception {
        // given
        final byte[] sigmaM2 = generateSigmaM2();

        mockTransferObject(FlowStage.SIGMA_INIT_DATA);
        mockContextWithDefaultValuesForS10();
        mockJtagResponsesForS10(sigmaM2);
        mockRetrieveFromCommandLayer(sigmaM2);
        mockSigningKeyManager();
        mockConfidentialData(S10_EFUSES_PUBLIC_LEN);
        mockChainForS10(DEVICE_ID);
        mockPublicKeyOfLeafCert(pakKeyPair.publicKey());
        mockCreatingJtagResponse();
        mockContextEncrypt();

        // when
        perform();

        // then
        verify(contextEncryptionProvider).encrypt(any());
    }

    @Test
    void perform_ReturnsOneCommand() throws Exception {
        // given
        final byte[] sigmaM2 = generateSigmaM2();

        mockTransferObject(FlowStage.SIGMA_INIT_DATA);
        mockContextWithDefaultValuesForS10();
        mockJtagResponsesForS10(sigmaM2);
        mockRetrieveFromCommandLayer(sigmaM2);
        mockSigningKeyManager();
        mockConfidentialData(S10_EFUSES_PUBLIC_LEN);
        mockChainForS10(DEVICE_ID);
        mockPublicKeyOfLeafCert(pakKeyPair.publicKey());
        mockCreatingJtagResponse();
        mockContextEncrypt();

        // when
        ProvisioningResponseDTO responseDTO = perform();

        // then
        assertEquals(1, responseDTO.getJtagCommands().size());
    }

    @Test
    void perform_recoveryOfContextFailed_ThrowsException() {
        // given
        mockTransferObject(FlowStage.SIGMA_INIT_DATA);
        mockContextConversionThrows();

        // when-then
        assertThrows(ProvisioningGenericException.class,
            () -> sut.handle(transferObject)
        );
    }

    @Test
    void perform_WithWrongResponseEncryption_ThrowsException() throws Exception {
        // given
        final byte[] sigmaM2 = generateSigmaM2();

        mockTransferObject(FlowStage.SIGMA_INIT_DATA);
        mockContextWithDefaultValuesForS10();
        mockJtagResponsesForS10(sigmaM2);
        mockRetrieveFromCommandLayer(sigmaM2);
        mockSigningKeyManager();
        mockConfidentialData(S10_EFUSES_PUBLIC_LEN);
        mockChainForS10(DEVICE_ID);
        mockPublicKeyOfLeafCert(pakKeyPair.publicKey());

        mockContextEncryptionProviderThrows();

        // when-then
        assertThrows(ProvisioningGenericException.class, this::perform);
    }

    @Test
    void perform_WithWrongHmac_ThrowsException() throws Exception {
        // given
        final byte[] sigmaM2 = generateInvalidSigmaM2();

        mockTransferObject(FlowStage.SIGMA_INIT_DATA);
        mockContextWithDefaultValuesForS10();
        mockJtagResponsesForS10(sigmaM2);
        mockRetrieveFromCommandLayer(sigmaM2);
        mockChainForS10(DEVICE_ID);

        // when
        assertThrows(ProvisioningGenericException.class, () -> sut.handle(transferObject));
    }

    private ProvisioningResponseDTO perform() {
        ProvisioningResponseDTO responseDTO;
        try (var util = mockStatic(Asn1ParsingUtils.class)) {
            util.when(() -> Asn1ParsingUtils.extractR(any())).thenReturn(new byte[48]);
            util.when(() -> Asn1ParsingUtils.extractS(any())).thenReturn(new byte[48]);
            util.when(() -> Asn1ParsingUtils.convertToDerSignature(any(), any())).thenCallRealMethod();
            responseDTO = sut.handle(transferObject);
        }
        return responseDTO;
    }

    private void mockTransferObject(FlowStage flowStage) {
        when(transferObject.getDtoReader()).thenReturn(dtoReader);
        when(dtoReader.getFlowStage()).thenReturn(flowStage);
        if (FlowStage.SIGMA_INIT_DATA == flowStage) {
            when(transferObject.getConfigurationCallback()).thenReturn(configurationCallback);
        }
    }

    private void mockContextWithDefaultValuesForS10() {
        mockContext(DEVICE_ID, bkpsDhKeyPair, "");
    }

    private void mockContext(String deviceId, EcdhKeyPair ecdhKeyPair, String deviceIdEnrollmentCertBytesHex) {
        mockContext(deviceId, deviceIdEnrollmentCertBytesHex);
        when(context.getEcdhKeyPair()).thenReturn(ecdhKeyPair);
    }

    private void mockContext(String deviceId, String deviceIdEnrollmentCertBytesHex) {
        mockContextConversion();
        when(context.getCfgId()).thenReturn(CFG_ID);
        when(context.getChipId()).thenReturn(deviceId);
        when(context.getDeviceIdEnrollmentCert()).thenReturn(deviceIdEnrollmentCertBytesHex);
    }

    @SneakyThrows
    private void mockContextConversion() {
        when(dtoReader.read(ProvContext1.class)).thenReturn(context);
    }

    @SneakyThrows
    private void mockContextConversionThrows() {
        when(dtoReader.read(any())).thenThrow(new ProvisioningConverterException("test"));
    }

    private void mockJtagResponsesForS10(byte[] sigmaM2) {
        final var s10Responses = Collections.singletonList(new ProgrammerResponse(sigmaM2, ResponseStatus.ST_OK));
        mockJtagResponses(s10Responses);
    }

    private void mockJtagResponsesForFm(byte[] sigmaM2) {
        final var fmResponses = List.of(
            getProgrammerResponseFromArray(new byte[]{}),
            getProgrammerResponseFromArray(new byte[]{}),
            getProgrammerResponseFromArray(sigmaM2));
        mockJtagResponses(fmResponses);
    }

    private void mockJtagResponses(int responseCount) {
        final var responses = IntStream.range(0, responseCount)
            .mapToObj(i -> getProgrammerResponseFromArray(new byte[]{}))
            .collect(Collectors.toList());
        mockJtagResponses(responses);
    }

    private void mockJtagResponses(List<ProgrammerResponse> responses) {
        when(dtoReader.getJtagResponses()).thenReturn(responses);
    }

    private void mockChainForS10(String deviceId) {
        when(chainCreator.createS10Chain(deviceId)).thenReturn(chainDTO);
        mockChain();
    }

    private void mockChainForFm(byte[] deviceIdEnrollmentCertBytes, boolean isRequireIidUds, boolean testModeSecrets) {
        when(configuration.isRequireIidUds()).thenReturn(isRequireIidUds);
        when(configuration.isTestModeSecrets()).thenReturn(testModeSecrets);
        when(chainCreator.createDiceChain(any(), eq(deviceIdEnrollmentCertBytes), eq(isRequireIidUds)))
            .thenAnswer(invocation -> {
                ProgrammerResponseToDataAdapter adapter = invocation.getArgument(0);
                adapter.getNext();
                adapter.getNext();
                return chainDTO;
            });
        mockChain();
    }

    private void mockChain() {
        when(chainDTO.getCertificates()).thenReturn(certs);
        when(certs.getFirst()).thenReturn(cert);
    }

    private void mockPublicKeyOfLeafCert(PublicKey publicKey) {
        when(cert.getPublicKey()).thenReturn(publicKey);
    }

    private void mockRetrieveFromCommandLayer(byte[] sigmaM2) {
        when(commandLayer.retrieve(sigmaM2, CommandIdentifier.SIGMA_M1)).thenReturn(sigmaM2);
    }

    private void mockContextEncryptionProviderThrows() throws EncryptionProviderException {
        when(contextEncryptionProvider.encrypt(any()))
            .thenThrow(EncryptionProviderException.class);
    }

    private void mockConfidentialData(int efusesPublicLen) {
        when(configurationCallback.getConfiguration(CFG_ID)).thenReturn(configuration);
        when(configuration.getAttestationConfig()).thenReturn(attestationConfiguration);
        when(attestationConfiguration.getBlackList()).thenReturn(blackList);
        when(configuration.getAttestationConfig().getEfusesPublic()).thenReturn(efusesPublic);
        when(efusesPublic.getValue()).thenReturn(Hex.toHexString(new byte[efusesPublicLen]));
        when(efusesPublic.getMask()).thenReturn(Hex.toHexString(new byte[efusesPublicLen]));

        when(blackList.getRomVersions()).thenReturn(new HashSet<>());
        when(blackList.getSdmBuildIdStrings()).thenReturn(new HashSet<>());
        when(blackList.getSdmSvns()).thenReturn(new HashSet<>());
    }

    private byte[] generateSigmaM2() throws Exception {
        return prepareMockSigmaM2(true);
    }

    private byte[] generateInvalidSigmaM2() throws Exception {
        return prepareMockSigmaM2(false);
    }

    private byte[] prepareMockSigmaM2(boolean validHmac) throws Exception {
        final byte[] ecdhSharedSecret = CryptoUtils.genEcdhSharedSecretBC(
            bkpsDhKeyPair.privateKey(), deviceDhKeyPair.publicKey());

        byte[] pmk = validHmac
                     ? KdfProvider.derivePMK(ecdhSharedSecret)
                     : generateRandomBytes(SigmaM2MessageBuilder.DH_PUB_KEY_LEN);

        SigmaM2MessageBuilder sigmaM2MessageBuilder = new SigmaM2MessageBuilder();
        sigmaM2MessageBuilder.setDeviceDhPubKey(deviceDhKeyPair.getPublicKey());
        sigmaM2MessageBuilder.setDeviceUniqueId(fromHex(DEVICE_ID));
        sigmaM2MessageBuilder.setBkpsDhPubKey(bkpsDhKeyPair.getPublicKey());
        sigmaM2MessageBuilder.setSignatureBuilder(prepareCorrectSignature(sigmaM2MessageBuilder));
        sigmaM2MessageBuilder.setMac(prepareCorrectMac(sigmaM2MessageBuilder, pmk));
        return sigmaM2MessageBuilder.withActor(EndiannessActor.FIRMWARE).build().array();
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

    private void mockSigningKeyManager() {
        when(signingKeyManager.getSignature(any())).thenReturn(new byte[32]);
    }

    private void mockCreatingJtagResponse() {
        when(commandLayer.create(any(), any()))
            .thenReturn(new byte[]{4, 5, 6});
    }

    @SneakyThrows
    private void mockContextEncrypt() {
        when(contextEncryptionProvider.encrypt(any())).thenReturn(new byte[]{1, 2, 3});
    }
}

