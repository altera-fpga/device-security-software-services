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

import com.intel.bkp.bkps.crypto.aesgcm.AesGcmContextProviderImpl;
import com.intel.bkp.bkps.crypto.contextkey.ContextKeyManager;
import com.intel.bkp.bkps.crypto.sealingkey.SealingKeyManager;
import com.intel.bkp.bkps.domain.ServiceConfiguration;
import com.intel.bkp.bkps.exception.DeviceChainVerificationFailedException;
import com.intel.bkp.bkps.exception.ProvisioningGenericException;
import com.intel.bkp.bkps.programmer.model.CommunicationStatus;
import com.intel.bkp.bkps.programmer.model.dto.MessageDTO;
import com.intel.bkp.bkps.programmer.model.dto.ResponseDTO;
import com.intel.bkp.bkps.protocol.common.handler.ProvAdapterComponent;
import com.intel.bkp.bkps.protocol.common.handler.ProvisioningHandler;
import com.intel.bkp.bkps.protocol.common.model.FlowStage;
import com.intel.bkp.bkps.protocol.common.model.ProtocolType;
import com.intel.bkp.bkps.protocol.common.model.ProvContextWithFlow;
import com.intel.bkp.bkps.protocol.sigma.handler.ProvAuthComponent;
import com.intel.bkp.bkps.protocol.sigma.handler.ProvInitComponent;
import com.intel.bkp.bkps.protocol.sigma.handler.ProvSigmaProtocolService;
import com.intel.bkp.bkps.repository.ServiceConfigurationRepository;
import com.intel.bkp.bkps.repository.SigningKeyRepository;
import com.intel.bkp.bkps.rest.initialization.service.InitializationService;
import com.intel.bkp.bkps.rest.initialization.service.SealingKeyService;
import com.intel.bkp.bkps.rest.initialization.service.SigningKeyService;
import com.intel.bkp.bkps.rest.provisioning.model.dto.ContextDTO;
import com.intel.bkp.bkps.rest.provisioning.model.dto.ProvisioningResponseDTO;
import com.intel.bkp.bkps.rest.provisioning.model.dto.ProvisioningTransferObject;
import com.intel.bkp.bkps.rest.provisioning.service.ServiceConfigurationProvider;
import com.intel.bkp.bkps.rest.provisioning.utils.ProvisioningContextConverter;
import com.intel.bkp.bkps.testutils.IntegrationTestBase;
import com.intel.bkp.bkps.testutils.MailboxResponseLayer;
import com.intel.bkp.bkps.testutils.RequestUtils;
import com.intel.bkp.command.messages.sigma.SigmaEncMessage;
import com.intel.bkp.core.manufacturing.model.PufType;
import com.intel.bkp.core.psgcertificate.enumerations.KeyWrappingType;
import com.intel.bkp.core.psgcertificate.enumerations.StorageType;
import com.intel.bkp.core.security.ISecurityProvider;
import com.intel.bkp.test.enumeration.ResourceDir;
import com.intel.bkp.utils.interfaces.BytesConvertible;
import lombok.SneakyThrows;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.mock.mockito.SpyBean;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import static com.intel.bkp.bkps.programmer.model.MessageType.PUSH_WRAPPED_KEY;
import static com.intel.bkp.bkps.testutils.TestHelper.createServiceConfigurationEntity;
import static com.intel.bkp.bkps.testutils.TestHelper.initializeBkps;
import static com.intel.bkp.bkps.testutils.TestHelper.setMockContextKey;
import static com.intel.bkp.command.model.CertificateRequestType.DEVICE_ID_ENROLLMENT;
import static com.intel.bkp.command.model.CertificateRequestType.FIRMWARE;
import static com.intel.bkp.command.model.CertificateRequestType.UDS_EFUSE_BKP;
import static com.intel.bkp.command.model.CertificateRequestType.UDS_IID_PUF_BKP;
import static com.intel.bkp.test.DateTimeUtils.toInstant;
import static com.intel.bkp.test.FileUtils.loadBinary;
import static com.intel.bkp.test.RandomUtils.generateRandomBytes;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.CALLS_REAL_METHODS;
import static org.mockito.Mockito.doCallRealMethod;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;

@ExtendWith(SpringExtension.class)
@ActiveProfiles({"sigma"})
public class ProvisioningSigmaTestIT extends IntegrationTestBase {

    private static final Instant NOW_INSTANT = toInstant("2022-03-10T11:21:58");
    // these certificates where captured during real E2E session from Kibana logs
    private static final String DEVICE_ID_ENROLLMENT_CERT_FILENAME = "deviceider_22d4ef4bd6a4d748.cer";
    private static final String BKP_CERT_FILENAME = "bkp_22d4ef4bd6a4d748.cer";
    private static final String BKP_IID_CERT_FILENAME = "bkp_iid_22d4ef4bd6a4d748.cer";
    private static final String FIRMWARE_CERT_FILENAME = "firmware_22d4ef4bd6a4d748.cer";

    private static final byte[] WRAPPED_AES_KEY = generateRandomBytes(16);

    private static byte[] device_id_enrollment_cert;
    private static byte[] bkp_cert;
    private static byte[] bkp_iid_cert;
    private static byte[] firmware_cert;

    private static final String DEVICE_ID_S10 = "5ADF841DDEAD944E";
    private static final String DEVICE_ID_FM = "48D7A4D64BEFD422";

    private static MockedStatic<Instant> instantMockStatic;

    @BeforeAll
    static void init() {
        device_id_enrollment_cert = loadBinary(ResourceDir.ROOT, DEVICE_ID_ENROLLMENT_CERT_FILENAME);
        bkp_cert = loadBinary(ResourceDir.ROOT, BKP_CERT_FILENAME);
        firmware_cert = loadBinary(ResourceDir.ROOT, FIRMWARE_CERT_FILENAME);
        bkp_iid_cert = loadBinary(ResourceDir.ROOT, BKP_IID_CERT_FILENAME);
        instantMockStatic = mockStatic(Instant.class, CALLS_REAL_METHODS);
        when(Instant.now()).thenReturn(NOW_INSTANT);
    }

    @AfterAll
    static void closeStaticMock() {
        instantMockStatic.close();
    }

    @Autowired
    private ISecurityProvider securityService;

    @Autowired
    private SealingKeyService sealingKeyService;

    @Autowired
    private SealingKeyManager sealingKeyManager;

    @SpyBean
    private ProvInitComponent provInitComponentSpy;

    @SpyBean
    private ProvAuthComponent provAuthComponentSpy;

    @Autowired
    private SigningKeyRepository signingKeyRepository;

    @Autowired
    @InjectMocks
    private InitializationService initializationService;

    @Autowired
    private SigningKeyService signingKeyService;

    @Mock
    private ContextKeyManager contextKeyManager;

    @Autowired
    private ProvAdapterComponent provAdapterComponent;

    @Mock
    private ServiceConfigurationProvider serviceConfigurationProvider;

    @Autowired
    private ServiceConfigurationRepository serviceConfigurationRepository;

    @Autowired
    private AesGcmContextProviderImpl contextEncryptionProvider;

    @Autowired
    @InjectMocks
    private ProvSigmaProtocolService provisioningService;

    private final MailboxResponseLayer commandLayer = new MailboxResponseLayer();
    private final SigmaTestUtils sigmaTestUtils = new SigmaTestUtils(commandLayer);

    ProvisioningSigmaTestIT() throws Exception {
    }

    @BeforeEach
    void setup() {
        provAdapterComponent.setSuccessor(new ProvisioningHandler() {
            @Override
            public ProvisioningResponseDTO handle(ProvisioningTransferObject transferObject) {
                return provisioningService.run(transferObject);
            }
        });

        initializeBkps(signingKeyRepository, initializationService, signingKeyService, securityService,
            sealingKeyService);
        doReturn(sigmaTestUtils.getBkpsDhKeyPair()).when(provInitComponentSpy).generateEcdhKeyPair();

        // this is required because we don't have access to real private key
        doNothing().when(provAuthComponentSpy).verifyM2Signature(any(), any());

        setMockContextKey(contextKeyManager);

        this.mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext).build();
        initMockServers();
    }

    private Long createNewConfiguration(StorageType storageType, PufType pufType,
                                        KeyWrappingType keyWrappingType) {
        return createNewConfiguration(storageType, pufType, keyWrappingType, false);
    }

    private Long createNewConfiguration(StorageType storageType,
                                        PufType pufType, KeyWrappingType keyWrappingType,
                                        boolean requireIidUds) {
        final ServiceConfiguration serviceConfigurationEntity = createServiceConfigurationEntity(
            -1, storageType, sealingKeyManager, requireIidUds, pufType, keyWrappingType, null, null);

        final Long cfgId = serviceConfigurationRepository
            .save(serviceConfigurationEntity)
            .getId();

        when(serviceConfigurationProvider.getConfiguration(cfgId)).thenReturn(serviceConfigurationEntity);
        when(serviceConfigurationProvider.getConfigurationAndUpdate(cfgId)).thenReturn(1);

        return cfgId;
    }

    @Test
    void stratix10_ForEfuses_AllOk() throws Exception {
        stratix10MockResponse();
        final RequestUtils requester = getRequester(
            createNewConfiguration(StorageType.EFUSES, PufType.EFUSE, KeyWrappingType.INTERNAL));
        final ProvisioningResponseDTO initialDecisionResponse = getInitialDecisionResponse();
        final ProvisioningResponseDTO createResponse = runCreate(requester, initialDecisionResponse);
        final ProvisioningResponseDTO initResponse = runInitStratix10(requester, createResponse);
        final ProvisioningResponseDTO authResponse = runAuthStratix10(requester, initResponse);
        final ProvisioningResponseDTO encResponse = runSigmaEnc(requester, authResponse);
        final ProvisioningResponseDTO provResponse = runProv(requester, encResponse);
        runDone(requester, provResponse);
    }

    @SneakyThrows
    private ProvisioningResponseDTO getInitialDecisionResponse() {
        ProvContextWithFlow.ProvContextWithFlowBuilder provContextWithFlowBuilder = ProvContextWithFlow
            .builder()
            .flowStage(FlowStage.PROTOCOL_DECISION)
            .protocolType(ProtocolType.SIGMA);
        byte[] serializedWithFlow = ProvisioningContextConverter
            .serialize(provContextWithFlowBuilder.build());
        final byte[] encrypted = contextEncryptionProvider.encrypt(serializedWithFlow);
        final ContextDTO encoded = ContextDTO.from(encrypted);
        return new ProvisioningResponseDTO(encoded, CommunicationStatus.CONTINUE, List.of());
    }

    @Test
    void stratix10_ForBbram_AllOk() throws Exception {
        stratix10MockResponse();
        final RequestUtils requester = getRequester(
            createNewConfiguration(StorageType.BBRAM, PufType.EFUSE, KeyWrappingType.INTERNAL));
        final ProvisioningResponseDTO initialDecisionResponse = getInitialDecisionResponse();
        final ProvisioningResponseDTO createResponse = runCreate(requester, initialDecisionResponse);
        final ProvisioningResponseDTO initResponse = runInitStratix10(requester, createResponse);
        final ProvisioningResponseDTO authResponse = runAuthStratix10(requester, initResponse);
        final ProvisioningResponseDTO encEraseResponse = runSigmaEnc(requester, authResponse);
        final ProvisioningResponseDTO encResponse = runSigmaEncBbramSecond(requester, encEraseResponse);
        final ProvisioningResponseDTO provResponse = runProv(requester, encResponse);
        runDone(requester, provResponse);
    }

    @Test
    void stratix10_ForPufss_AllOk() throws Exception {
        stratix10MockResponse();
        final RequestUtils requester = getRequester(
            createNewConfiguration(StorageType.PUFSS, PufType.IID, KeyWrappingType.USER_IID_PUF));
        final ProvisioningResponseDTO initialDecisionResponse = getInitialDecisionResponse();
        final ProvisioningResponseDTO createResponse = runCreate(requester, initialDecisionResponse);
        final ProvisioningResponseDTO initResponse = runInitStratix10(requester, createResponse);
        final ProvisioningResponseDTO authResponse = runAuthStratix10(requester, initResponse);
        final ProvisioningResponseDTO encResponse = runSigmaEnc(requester, authResponse);

        final ProvisioningResponseDTO provResponse = runProvWithKeyWrapping(requester, encResponse);
        verifyPushWrappedKey(provResponse);

        runDone(requester, provResponse);
    }

    @Test
    void stratix10_withWrongHmac_ThrowException() throws Exception {
        stratix10MockResponse();
        final RequestUtils requester = getRequester(
            createNewConfiguration(StorageType.EFUSES, PufType.EFUSE, KeyWrappingType.INTERNAL));
        final ProvisioningResponseDTO initialDecisionResponse = getInitialDecisionResponse();
        final ProvisioningResponseDTO createResponse = runCreate(requester, initialDecisionResponse);
        final ProvisioningResponseDTO initResponse = runInitStratix10(requester, createResponse);

        final ProvisioningGenericException exception =
            assertThrows(ProvisioningGenericException.class, () -> requester.performGetNext(initResponse,
                0,
                getQuartusCommand(sigmaTestUtils.getSigmaM2(false, DEVICE_ID_S10))
            ));

        verifyExceptionMessage("HMAC verification failed.", exception.getCause());
    }

    @Test
    void stratix10_withWrongSignature_ThrowException() throws Exception {
        stratix10MockResponse();
        doCallRealMethod().when(provAuthComponentSpy).verifyM2Signature(any(), any());

        final RequestUtils requester = getRequester(
            createNewConfiguration(StorageType.EFUSES, PufType.EFUSE, KeyWrappingType.INTERNAL));
        final ProvisioningResponseDTO initialDecisionResponse = getInitialDecisionResponse();
        final ProvisioningResponseDTO createResponse = runCreate(requester, initialDecisionResponse);
        final ProvisioningResponseDTO initResponse = runInitStratix10(requester, createResponse);

        final ProvisioningGenericException exception =
            assertThrows(ProvisioningGenericException.class, () -> requester.performGetNext(initResponse,
                0,
                getQuartusCommand(sigmaTestUtils.getSigmaM2(DEVICE_ID_S10))
            ));

        verifyExceptionMessage("Sigma M2 signature verification failed.", exception);
    }

    @Test
    void agilex_NotRequireIidUds_ForEfuses_AllOk() throws Exception {
        final boolean requireIidUds = false;
        agilexMockBothChainsResponse();
        final RequestUtils requester = getRequester(
            createNewConfiguration(StorageType.EFUSES, PufType.EFUSE, KeyWrappingType.INTERNAL, requireIidUds));
        final ProvisioningResponseDTO initialDecisionResponse = getInitialDecisionResponse();
        final ProvisioningResponseDTO createResponse = runCreate(requester, initialDecisionResponse);
        final ProvisioningResponseDTO initResponse = runInitAgilex(requester, createResponse, requireIidUds);
        final ProvisioningResponseDTO authResponse = runAuthAgilex(requester, initResponse, requireIidUds);
        final ProvisioningResponseDTO encResponse = runSigmaEnc(requester, authResponse);
        final ProvisioningResponseDTO provResponse = runProv(requester, encResponse);
        runDone(requester, provResponse);
    }

    @Test
    void agilex_NotRequireIidUds_ForBbram_AllOk() throws Exception {
        final boolean requireIidUds = false;
        agilexMockBothChainsResponse();
        final RequestUtils requester = getRequester(
            createNewConfiguration(StorageType.BBRAM, PufType.EFUSE, KeyWrappingType.INTERNAL, requireIidUds));
        final ProvisioningResponseDTO initialDecisionResponse = getInitialDecisionResponse();
        final ProvisioningResponseDTO createResponse = runCreate(requester, initialDecisionResponse);
        final ProvisioningResponseDTO initResponse = runInitAgilex(requester, createResponse, requireIidUds);
        final ProvisioningResponseDTO authResponse = runAuthAgilex(requester, initResponse, requireIidUds);
        final ProvisioningResponseDTO encEraseResponse = runSigmaEnc(requester, authResponse);
        final ProvisioningResponseDTO encResponse = runSigmaEncBbramSecond(requester, encEraseResponse);
        final ProvisioningResponseDTO provResponse = runProv(requester, encResponse);
        runDone(requester, provResponse);
    }

    @Test
    void agilex_NotRequireIidUds_ForPufss_AllOk() throws Exception {
        final boolean requireIidUds = false;
        agilexMockBothChainsResponse();
        final RequestUtils requester = getRequester(
            createNewConfiguration(StorageType.PUFSS, PufType.IID, KeyWrappingType.USER_IID_PUF, requireIidUds));
        final ProvisioningResponseDTO initialDecisionResponse = getInitialDecisionResponse();
        final ProvisioningResponseDTO createResponse = runCreate(requester, initialDecisionResponse);
        final ProvisioningResponseDTO initResponse = runInitAgilex(requester, createResponse, requireIidUds);
        final ProvisioningResponseDTO authResponse = runAuthAgilex(requester, initResponse, requireIidUds);
        final ProvisioningResponseDTO encResponse = runSigmaEnc(requester, authResponse);

        final ProvisioningResponseDTO provResponse = runProvWithKeyWrapping(requester, encResponse);
        verifyPushWrappedKey(provResponse);

        runDone(requester, provResponse);
    }

    @Test
    void agilex_RequireIidUds_ForEfuses_AllOk() throws Exception {
        final boolean requireIidUds = true;
        agilexMockBothChainsResponse();
        final RequestUtils requester = getRequester(
            createNewConfiguration(StorageType.EFUSES, PufType.EFUSE, KeyWrappingType.INTERNAL, requireIidUds));
        final ProvisioningResponseDTO initialDecisionResponse = getInitialDecisionResponse();
        final ProvisioningResponseDTO createResponse = runCreate(requester, initialDecisionResponse);
        final ProvisioningResponseDTO initResponse = runInitAgilex(requester, createResponse, requireIidUds);
        final ProvisioningResponseDTO authResponse = runAuthAgilex(requester, initResponse, requireIidUds);
        final ProvisioningResponseDTO encResponse = runSigmaEnc(requester, authResponse);
        final ProvisioningResponseDTO provResponse = runProv(requester, encResponse);
        runDone(requester, provResponse);
    }

    @Test
    void agilex_BothEfuseAndIidChainNotExistOnDp_Throws() {
        final boolean requireIidUds = false;
        agilexMockNoChainsResponse();

        final RequestUtils requester = getRequester(
            createNewConfiguration(StorageType.EFUSES, PufType.EFUSE, KeyWrappingType.INTERNAL, requireIidUds));
        final ProvisioningResponseDTO initialDecisionResponse = getInitialDecisionResponse();
        final ProvisioningResponseDTO createResponse = runCreate(requester, initialDecisionResponse);

        final ProvisioningGenericException exception =
            assertThrows(ProvisioningGenericException.class, () -> runInitAgilex(requester, createResponse, false));

        verifyExceptionMessage("Failed to download at least one full chain (EFUSE or IID UDS).", exception.getCause());
    }

    @Test
    void agilex_OnlyIidChainExistsOnDp_Throws() throws Exception {
        final boolean requireIidUds = true;
        agilexMockOnlyIidChainResponse();
        final RequestUtils requester = getRequester(
            createNewConfiguration(StorageType.EFUSES, PufType.EFUSE, KeyWrappingType.INTERNAL, requireIidUds));
        final ProvisioningResponseDTO initialDecisionResponse = getInitialDecisionResponse();
        final ProvisioningResponseDTO createResponse = runCreate(requester, initialDecisionResponse);

        final ProvisioningResponseDTO initResponse = runInitAgilex(requester, createResponse, requireIidUds);

        final ProvisioningGenericException exception = assertThrows(DeviceChainVerificationFailedException.class,
            () -> runAuthAgilex(requester, initResponse, requireIidUds));

        verifyExceptionMessage("Required EFUSE UDS chain does not exist and cannot be verified.", exception);
    }

    @Test
    void agilex_withWrongHmac_ThrowException() throws Exception {
        final boolean requireIidUds = false;
        agilexMockBothChainsResponse();
        final RequestUtils requester = getRequester(
            createNewConfiguration(StorageType.EFUSES, PufType.EFUSE, KeyWrappingType.INTERNAL, requireIidUds));
        final ProvisioningResponseDTO initialDecisionResponse = getInitialDecisionResponse();
        final ProvisioningResponseDTO createResponse = runCreate(requester, initialDecisionResponse);
        final ProvisioningResponseDTO initResponse = runInitAgilex(requester, createResponse, requireIidUds);

        final ProvisioningGenericException exception =
            assertThrows(ProvisioningGenericException.class, () -> requester.performGetNext(initResponse,
                0,
                getQuartusCommand(sigmaTestUtils.getGetCertificateResponse(bkp_cert, UDS_EFUSE_BKP)),
                getQuartusCommand(sigmaTestUtils.getGetCertificateResponse(firmware_cert, FIRMWARE)),
                getQuartusCommand(sigmaTestUtils.getSigmaM2(false, DEVICE_ID_FM))
            ));

        verifyExceptionMessage("HMAC verification failed.", exception.getCause());
    }

    @Test
    void agilex_withWrongSignature_ThrowException() throws Exception {
        final boolean requireIidUds = false;
        agilexMockBothChainsResponse();
        doCallRealMethod().when(provAuthComponentSpy).verifyM2Signature(any(), any());

        final RequestUtils requester = getRequester(
            createNewConfiguration(StorageType.EFUSES, PufType.EFUSE, KeyWrappingType.INTERNAL, requireIidUds));
        final ProvisioningResponseDTO initialDecisionResponse = getInitialDecisionResponse();
        final ProvisioningResponseDTO createResponse = runCreate(requester, initialDecisionResponse);
        final ProvisioningResponseDTO initResponse = runInitAgilex(requester, createResponse, requireIidUds);

        final ProvisioningGenericException exception =
            assertThrows(ProvisioningGenericException.class, () -> requester.performGetNext(initResponse,
                0,
                getQuartusCommand(sigmaTestUtils.getGetCertificateResponse(bkp_cert, UDS_EFUSE_BKP)),
                getQuartusCommand(sigmaTestUtils.getGetCertificateResponse(firmware_cert, FIRMWARE)),
                getQuartusCommand(sigmaTestUtils.getSigmaM2(DEVICE_ID_FM))
            ));

        verifyExceptionMessage("Sigma M2 signature verification failed.", exception);
    }

    private void stratix10MockResponse() throws Exception {
        mockDpResponse("/IPCS/certs/attestation_5ADF841DDEAD944E_00000002.cer",
            "/IPCS/certs/IPCSSigningCA.cer",
            "/IPCS/certs/IPCS.cer",
            "/IPCS/crls/IPCSSigningCA.crl",
            "/IPCS/crls/IPCS.crl");
    }

    private void agilexMockBothChainsResponse() throws Exception {
        agilexMockDeviceIdResponse(true);
        agilexMockIntermediateAndRootResponse();
        agilexMockIidUdsResponse(true);
        agilexMockCrlsResponse();
    }

    private void agilexMockOnlyIidChainResponse() throws Exception {
        agilexMockDeviceIdResponse(false);
        agilexMockEnrollmentResponse(false);
        agilexMockIidUdsResponse(true);
        agilexMockIntermediateAndRootResponse();
        agilexMockCrlsResponse();
        // First time is during init, second time during auth (if not fetched during init)
        agilexMockDeviceIdResponse(false);
        agilexMockEnrollmentResponse(false);
    }

    private void agilexMockNoChainsResponse() {
        agilexMockDeviceIdResponse(false);
        agilexMockEnrollmentResponse(false);
        agilexMockIidUdsResponse(false);
    }

    private void agilexMockDeviceIdResponse(boolean exists) {
        mockDpResponse("/IPCS/certs/deviceid_22d4ef4bd6a4d748_5F7W2AjE8X0r63GWyFq8yCrBAJY.cer", exists);
    }

    private void agilexMockEnrollmentResponse(boolean exists) {
        mockDpResponse("/IPCS/certs/enrollment_22d4ef4bd6a4d748_00_4qn3XIBaW0e8pvKcZGG-zwhyxRk.cer", exists);
    }

    private void agilexMockIidUdsResponse(boolean exists) {
        mockDpResponse("/IPCS/certs/iiduds_22d4ef4bd6a4d748_4qn3XIBaW0e8pvKcZGG-zwhyxRk.cer", exists);
    }

    private void agilexMockIntermediateAndRootResponse() throws Exception {
        mockDpResponse("/IPCS/certs/IPCS_agilex.cer",
            "/DICE/certs/DICE_RootCA.cer");
    }

    private void agilexMockCrlsResponse() throws Exception {
        mockDpResponse("/IPCS/crls/IPCS_agilex.crl",
            "/DICE/crls/DICE.crl",
            "/IPCS/crls/IPCS_agilex_L1.crl");
    }

    @SneakyThrows
    private void mockDpResponse(String url, boolean exists) {
        if (exists) {
            mockDpResponse(url);
        } else {
            mockDpNotValidResponse(url);
        }
    }

    private ProvisioningResponseDTO runCreate(RequestUtils requester, ProvisioningResponseDTO initialDecisionResponse) {
        return requester.performGetNext(initialDecisionResponse, 3);
    }

    private ProvisioningResponseDTO runInitStratix10(RequestUtils requester, ProvisioningResponseDTO createResponse) {
        return requester.performGetNext(createResponse,
            1,  // M1
            getQuartusCommand(sigmaTestUtils.getChipIdResponse(DEVICE_ID_S10)),
            getQuartusCommand(sigmaTestUtils.getSigmaTeardownResponse()),
            getQuartusCommandUnknown(sigmaTestUtils.getGetCertificateResponse())
        );
    }

    private ProvisioningResponseDTO runInitAgilex(RequestUtils requester, ProvisioningResponseDTO createResponse,
                                                  boolean requireIidUds) {
        return requester.performGetNext(createResponse,
            requireIidUds ? 4 : 3, // GET_CERT(UDS_EFUSE_BKP), GET_CERT(FIRMWARE), [GET_CERT(UDS_IID_PUF_BKP)], M1
            getQuartusCommand(sigmaTestUtils.getChipIdResponse(DEVICE_ID_FM)),
            getQuartusCommand(sigmaTestUtils.getSigmaTeardownResponse()),
            getQuartusCommand(sigmaTestUtils.getGetCertificateResponse(device_id_enrollment_cert,
                DEVICE_ID_ENROLLMENT))
        );
    }

    private ProvisioningResponseDTO runAuthStratix10(RequestUtils requester,
                                                     ProvisioningResponseDTO initResponse) throws Exception {
        return requester.performGetNext(initResponse,
            1, // M3
            getQuartusCommand(sigmaTestUtils.getSigmaM2(DEVICE_ID_S10))
        );
    }

    private ProvisioningResponseDTO runAuthAgilex(RequestUtils requester,
                                                  ProvisioningResponseDTO initResponse,
                                                  boolean requireIidUds) throws Exception {
        final var quartusResponses = new ArrayList<ResponseDTO>();
        quartusResponses.add(getQuartusCommand(sigmaTestUtils.getGetCertificateResponse(bkp_cert, UDS_EFUSE_BKP)));
        quartusResponses.add(getQuartusCommand(sigmaTestUtils.getGetCertificateResponse(firmware_cert, FIRMWARE)));
        if (requireIidUds) {
            quartusResponses.add(
                getQuartusCommand(sigmaTestUtils.getGetCertificateResponse(bkp_iid_cert, UDS_IID_PUF_BKP)));
        }
        quartusResponses.add(getQuartusCommand(sigmaTestUtils.getSigmaM2(DEVICE_ID_FM)));

        return requester.performGetNext(initResponse,
            1,  // M3
            quartusResponses.toArray(ResponseDTO[]::new)
        );
    }

    private ProvisioningResponseDTO runSigmaEnc(RequestUtils requester, ProvisioningResponseDTO authResponse) {
        return requester.performGetNext(authResponse,
            1, // M_ENC(VOLATILE_AES_ERASE) for BBRAM or M_ENC(CERTIFICATE)
            getQuartusCommand(sigmaTestUtils.getSigmaM3Response())
        );
    }

    private ProvisioningResponseDTO runSigmaEncBbramSecond(RequestUtils requester,
                                                           ProvisioningResponseDTO encEraseResponse) throws Exception {
        final SigmaEncMessage sigmaEncEraseMessage = sigmaTestUtils.parseSigmaEncMessage(encEraseResponse);
        return requester.performGetNext(encEraseResponse,
            1, // M_ENC(CERTIFICATE)
            getQuartusCommand(sigmaTestUtils.getSigmaEncResponse(sigmaEncEraseMessage))
        );
    }

    private ProvisioningResponseDTO runProv(RequestUtils requester,
                                            ProvisioningResponseDTO encResponse) throws Exception {
        final SigmaEncMessage sigmaEncMessage = sigmaTestUtils.parseSigmaEncMessage(encResponse);
        return requester.performGetNext(encResponse,
            1, // PSGSIGMA_TEARDOWN
            getQuartusCommand(sigmaTestUtils.getSigmaEncResponse(sigmaEncMessage))
        );
    }

    private ProvisioningResponseDTO runProvWithKeyWrapping(RequestUtils requester,
                                                           ProvisioningResponseDTO encResponse) throws Exception {
        final SigmaEncMessage sigmaEncMessage = sigmaTestUtils.parseSigmaEncMessage(encResponse);
        return requester.performGetNext(encResponse,
            2, // PSGSIGMA_TEARDOWN, PUSH_WRAPPED_KEY
            getQuartusCommand(sigmaTestUtils.getSigmaEncResponse(sigmaEncMessage, WRAPPED_AES_KEY))
        );
    }

    private void runDone(RequestUtils requester, ProvisioningResponseDTO provResponse) {
        requester.performGetNextDone(provResponse,
            getQuartusCommand(sigmaTestUtils.getSigmaTeardownResponse())
        );
    }

    private RequestUtils getRequester(Long cfgId) {
        return new RequestUtils(serviceConfigurationProvider, provAdapterComponent, cfgId);
    }

    private ResponseDTO getQuartusCommand(BytesConvertible response) {
        return ResponseDTO.from(commandLayer.create(response));
    }

    private ResponseDTO getQuartusCommandUnknown(BytesConvertible response) {
        return ResponseDTO.from(commandLayer.createUnknown(response));
    }

    private void verifyExceptionMessage(String expectedMessage, Throwable exception) {
        assertTrue(exception.getMessage().contains(expectedMessage));
    }

    private void verifyPushWrappedKey(ProvisioningResponseDTO provResponse) {
        final MessageDTO messageDTO = provResponse.getJtagCommands().get(1);
        assertEquals(PUSH_WRAPPED_KEY.getValue(), messageDTO.getType());
        assertArrayEquals(WRAPPED_AES_KEY, Base64.getDecoder().decode(messageDTO.getValue()));
    }
}
