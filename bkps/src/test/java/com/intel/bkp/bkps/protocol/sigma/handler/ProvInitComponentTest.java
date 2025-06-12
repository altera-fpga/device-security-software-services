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

import com.intel.bkp.bkps.command.CommandLayerService;
import com.intel.bkp.bkps.crypto.aesgcm.AesGcmContextProviderImpl;
import com.intel.bkp.bkps.domain.ServiceConfiguration;
import com.intel.bkp.bkps.exception.ExceededOvebuildException;
import com.intel.bkp.bkps.exception.ProvisioningGenericException;
import com.intel.bkp.bkps.programmer.model.CommunicationStatus;
import com.intel.bkp.bkps.programmer.model.ProgrammerResponse;
import com.intel.bkp.bkps.programmer.model.ResponseStatus;
import com.intel.bkp.bkps.protocol.common.handler.ProvHandlerTestUtil;
import com.intel.bkp.bkps.protocol.common.handler.ProvisioningHandler;
import com.intel.bkp.bkps.protocol.common.model.FlowStage;
import com.intel.bkp.bkps.protocol.common.model.RootChainType;
import com.intel.bkp.bkps.protocol.common.service.BkpsDHCertBuilder;
import com.intel.bkp.bkps.protocol.common.service.BkpsDhEntryManager;
import com.intel.bkp.bkps.protocol.common.service.GetChipIdMessageSender;
import com.intel.bkp.bkps.rest.prefetching.service.ChainDataProvider;
import com.intel.bkp.bkps.rest.provisioning.model.dto.ProvisioningRequestDTOReader;
import com.intel.bkp.bkps.rest.provisioning.model.dto.ProvisioningResponseDTO;
import com.intel.bkp.bkps.rest.provisioning.model.dto.ProvisioningTransferObject;
import com.intel.bkp.bkps.rest.provisioning.service.IServiceConfiguration;
import com.intel.bkp.bkps.rest.provisioning.service.OverbuildCounterManager;
import com.intel.bkp.command.exception.JtagUnknownCommandResponseException;
import com.intel.bkp.command.model.CommandIdentifier;
import com.intel.bkp.command.responses.common.GetCertificateResponseBuilder;
import com.intel.bkp.command.responses.common.GetChipIdResponseBuilder;
import com.intel.bkp.command.responses.sigma.SigmaTeardownResponseBuilder;
import com.intel.bkp.core.manufacturing.model.PufType;
import com.intel.bkp.crypto.exceptions.EncryptionProviderException;
import com.intel.bkp.crypto.x509.parsing.X509CertificateParser;
import com.intel.bkp.utils.ByteSwap;
import com.intel.bkp.utils.ByteSwapOrder;
import lombok.SneakyThrows;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import static com.intel.bkp.command.model.CertificateRequestType.DEVICE_ID_ENROLLMENT;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
public class ProvInitComponentTest {

    private static final byte[] CERT_BLOB = new byte[]{1, 2};
    private static final byte[] MULTI_CHAIN_DATA = {5, 6};
    private static final byte[] SINGLE_CHAIN_DATA = {3, 4};

    private static final byte[] SIGMA_TEARDOWN = new SigmaTeardownResponseBuilder().build().array();
    private static final byte[] GET_CHIPID = new GetChipIdResponseBuilder().build().array();
    private static byte[] GET_ATTESTATION_CERTIFICATE;

    private static List<ProgrammerResponse> QUARTUS_RESPONSES;

    @BeforeAll
    static void init() {
        final GetCertificateResponseBuilder getCertificateResponseBuilder = new GetCertificateResponseBuilder();
        getCertificateResponseBuilder.setCertificateType(
            ByteSwap.getSwappedArray(DEVICE_ID_ENROLLMENT.getType(), ByteSwapOrder.B2L)
        );
        getCertificateResponseBuilder.setCertificateBlob(CERT_BLOB);
        GET_ATTESTATION_CERTIFICATE = getCertificateResponseBuilder.build().array();

        QUARTUS_RESPONSES = new ArrayList<>(List.of(
            new ProgrammerResponse(GET_CHIPID, ResponseStatus.ST_OK),
            new ProgrammerResponse(SIGMA_TEARDOWN, ResponseStatus.ST_OK),
            new ProgrammerResponse(GET_ATTESTATION_CERTIFICATE, ResponseStatus.ST_OK))
        );
    }

    @Mock
    private ProvisioningTransferObject transferObject;

    @Mock
    private ProvisioningRequestDTOReader dtoReader;

    @Mock
    private ProvisioningHandler successor;

    @Mock
    private BkpsDHCertBuilder bkpsDHCertBuilder;

    @Mock
    private BkpsDhEntryManager bkpsDhEntryManager;

    @Mock
    private AesGcmContextProviderImpl contextEncryptionProvider;

    @Mock
    private OverbuildCounterManager overbuildCounterManager;

    @Mock
    private ChainDataProvider chainDataProvider;

    @Mock
    private CommandLayerService commandLayer;

    @Mock
    private GetChipIdMessageSender getChipIdMessageSender;

    @Mock
    private ServiceConfiguration configuration;

    @InjectMocks
    private ProvInitComponent sut;

    private final IServiceConfiguration CONFIGURATION = new IServiceConfiguration() {
        @Override
        public ServiceConfiguration getConfiguration(Long cfgId) {
            return configuration;
        }

        @Override
        public int getConfigurationAndUpdate(Long cfgId) {
            return 0;
        }
    };

    @BeforeEach
    void setUp() {
        sut.setSuccessor(successor);
        when(transferObject.getDtoReader()).thenReturn(dtoReader);
        when(transferObject.getConfigurationCallback()).thenReturn(CONFIGURATION);
        when(dtoReader.getFlowStage()).thenReturn(FlowStage.SIGMA_CREATE_SESSION);
        when(dtoReader.getJtagResponses()).thenReturn(QUARTUS_RESPONSES);
        when(configuration.getPufType()).thenReturn(PufType.EFUSE);
        when(bkpsDhEntryManager.getDhEntry(any())).thenReturn(new byte[2]);
    }

    @Test
    void handle_S10_Success() {
        // given
        final int expectedNumberOfCommands = 1; // M1
        prepareResponses();
        mockContextEncrypt();
        mockCreatingJtagResponse();

        // when
        ProvisioningResponseDTO result = sut.handle(transferObject);

        // then
        assertNotNull(result.getContext());
        assertNotNull(result.getJtagCommands());
        assertEquals(expectedNumberOfCommands, result.getJtagCommands().size());
        assertEquals(CommunicationStatus.CONTINUE.getStatus(), result.getStatus());
        verify(chainDataProvider).fetchS10(any());
    }

    @Test
    void handle_Fm_Success() {
        // given
        final int expectedNumberOfCommands = 4; // M1, GET_ATTESTATION_CERTIFICATE x 3
        prepareResponses(true);
        final X509Certificate deviceIdEnrollmentCert = mock(X509Certificate.class);
        mockContextEncrypt();
        mockCreatingJtagResponse();
        when(configuration.isRequireIidUds()).thenReturn(true);

        final ProvisioningResponseDTO result;
        // when
        try (var parser = mockStatic(X509CertificateParser.class)) {
            parser.when(() -> X509CertificateParser.toX509Certificate(CERT_BLOB)).thenReturn(deviceIdEnrollmentCert);
            result = sut.handle(transferObject);
        }

        // then
        assertNotNull(result.getContext());
        assertNotNull(result.getJtagCommands());
        assertEquals(expectedNumberOfCommands, result.getJtagCommands().size());
        assertEquals(CommunicationStatus.CONTINUE.getStatus(), result.getStatus());
        verify(chainDataProvider).fetchDice(any(X509Certificate.class));
    }

    @Test
    void handle_WithVerifyOverbuildCounterReturn_Success() throws ExceededOvebuildException {
        // given
        prepareResponses();
        doNothing().when(overbuildCounterManager).verifyOverbuildCounter(any(), any());
        mockContextEncrypt();
        mockCreatingJtagResponse();

        // when
        ProvisioningResponseDTO result = sut.handle(transferObject);

        // then
        assertNotNull(result.getContext());
        assertNotNull(result.getJtagCommands());
        assertEquals(1, result.getJtagCommands().size());
        assertEquals(CommunicationStatus.CONTINUE.getStatus(), result.getStatus());
    }

    @Test
    void handle_WithVerifyOverbuildCounterThrows_Throws() throws ExceededOvebuildException {
        // given
        prepareResponses();
        doThrow(ProvisioningGenericException.class).when(overbuildCounterManager)
            .verifyOverbuildCounter(any(), any());

        // when-then
        ProvHandlerTestUtil.runAndVerifyException(sut, transferObject, ProvisioningGenericException.class);
    }

    @Test
    void handle_ResponsesVerificationFailed_Throws() {
        // given
        when(dtoReader.getJtagResponses()).thenReturn(List.of());

        // when-then
        ProvHandlerTestUtil.runAndVerifyException(sut, transferObject, ProvisioningGenericException.class);
    }

    @Test
    void handle_EncryptionProviderThrows() throws EncryptionProviderException {
        // given
        prepareResponses();
        when(contextEncryptionProvider.encrypt(any())).thenThrow(new EncryptionProviderException("test"));

        // when-then
        ProvHandlerTestUtil.runAndVerifyException(sut, transferObject, ProvisioningGenericException.class);
    }

    @Test
    void handle_NotProperFlowStage_CallsSuccessor() {
        // given
        when(dtoReader.getFlowStage()).thenReturn(FlowStage.PROV_RESULT);

        // when
        sut.handle(transferObject);

        // then
        ProvHandlerTestUtil.verifySuccessorCalled(successor, transferObject);
    }

    private void prepareResponses() {
        prepareResponses(false);
    }

    private void prepareResponses(boolean fm) {
        when(commandLayer.retrieve(SIGMA_TEARDOWN, CommandIdentifier.SIGMA_TEARDOWN))
            .thenReturn(SIGMA_TEARDOWN);
        when(getChipIdMessageSender.retrieve(GET_CHIPID)).thenReturn("0102030405060708");
        if (fm) {
            when(bkpsDHCertBuilder.getChain(RootChainType.MULTI)).thenReturn(MULTI_CHAIN_DATA);
            when(commandLayer.retrieve(GET_ATTESTATION_CERTIFICATE, CommandIdentifier.GET_ATTESTATION_CERTIFICATE))
                .thenReturn(GET_ATTESTATION_CERTIFICATE);
        } else {
            when(bkpsDHCertBuilder.getChain(RootChainType.SINGLE)).thenReturn(SINGLE_CHAIN_DATA);
            when(commandLayer.retrieve(GET_ATTESTATION_CERTIFICATE, CommandIdentifier.GET_ATTESTATION_CERTIFICATE))
                .thenThrow(new JtagUnknownCommandResponseException("TEST"));
        }
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
