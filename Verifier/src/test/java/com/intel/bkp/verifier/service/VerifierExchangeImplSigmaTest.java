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

package com.intel.bkp.verifier.service;

import com.intel.bkp.core.manufacturing.model.PufType;
import com.intel.bkp.protocol.spdm.service.SpdmGetVersionMessageSender;
import com.intel.bkp.verifier.exceptions.InitSessionFailedException;
import com.intel.bkp.verifier.exceptions.TransportLayerException;
import com.intel.bkp.verifier.model.VerifierExchangeResponse;
import com.intel.bkp.verifier.model.dto.VerifierExchangeResponseDTO;
import com.intel.bkp.verifier.protocol.sigma.service.GpS10AttestationComponent;
import com.intel.bkp.verifier.protocol.sigma.service.TeardownMessageSender;
import com.intel.bkp.verifier.service.certificate.AppContext;
import com.intel.bkp.verifier.transport.model.TransportLayer;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.*;
import org.mockito.junit.jupiter.MockitoExtension;

import static com.intel.bkp.utils.HexConverter.toHex;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class VerifierExchangeImplSigmaTest {

    private static final byte[] deviceId = new byte[]{0x01, 0x02};
    private static final String TRANSPORT_ID = "abcde";

    @Mock
    private AppContext appContext;

    @Mock
    private TransportLayer transportLayer;

    @Mock
    private SpdmGetVersionMessageSender spdmGetVersionMessageSender;

    @Mock
    private InitSessionComponent initSessionComponent;

    @Mock
    private CreateDeviceAttestationSubKeyComponent createSubKeyComponent;

    @Mock
    private GpS10AttestationComponent gpS10AttestationComponent;

    @Mock
    private TeardownMessageSender teardownMessageSender;

    @Mock
    private GetDeviceAttestationComponentSigma getAttestationComponentSigma;

    @InjectMocks
    private VerifierExchangeProtocolSigma verifierExchangeProtocolSigma;

    @InjectMocks
    private VerifierExchangeImpl verifierExchangeImpl;

    @BeforeEach
    void setUp() {
        this.verifierExchangeProtocolSigma = spy(new VerifierExchangeProtocolSigma(initSessionComponent, createSubKeyComponent, getAttestationComponentSigma));
        this.verifierExchangeImpl = spy(new VerifierExchangeImpl(null, verifierExchangeProtocolSigma, spdmGetVersionMessageSender));
    }

    @Test
    void createDeviceAttestationSubKey_ContextNotHex_ReturnsError() throws Exception {
        // given
        mockAppContext();
        String context = "not-a-valid-hex";
        try (MockedStatic<AppContext> app = mockStatic(AppContext.class)) {
            app.when(AppContext::instance).thenReturn(appContext);
            doReturn(false).when(verifierExchangeImpl).spdmSupported();
            // when
            int result = verifierExchangeImpl.createDeviceAttestationSubKey(TRANSPORT_ID, context, String.valueOf(PufType.EFUSE));

            // then
            app.verify(AppContext::instance, times(1));
            verify(transportLayer, times(1)).initialize(TRANSPORT_ID);
            assertEquals(VerifierExchangeResponse.ERROR.getCode(), result);
            verify(transportLayer, times(1)).disconnect();
        }
    }

    @Test
    void createDeviceAttestationSubKey_ExceptionThrown_ReturnsError() throws Exception {
        // given
        mockAppContext();
        String context = "01020304ABCDEF";
        when(initSessionComponent.initializeSessionForDeviceId())
                .thenThrow(InitSessionFailedException.class);

        try (MockedStatic<AppContext> app = mockStatic(AppContext.class)) {
            app.when(AppContext::instance).thenReturn(appContext);
            doReturn(false).when(verifierExchangeImpl).spdmSupported();
            // when
            int result = verifierExchangeImpl.createDeviceAttestationSubKey(TRANSPORT_ID, context, String.valueOf(PufType.EFUSE));

            // then
            app.verify(AppContext::instance, times(1));
            verify(transportLayer, times(1)).initialize(TRANSPORT_ID);
            assertEquals(VerifierExchangeResponse.ERROR.getCode(), result);
            verify(transportLayer, times(1)).disconnect();
        }
    }

    @Test
    void createDeviceAttestationSubKey_Succcess_ReturnsOk() throws Exception {
        // given
        mockAppContext();
        String context = "01020304ABCDEF";
        PufType pufType = PufType.EFUSE;
        mockInitSessionComponent();
        when(createSubKeyComponent.perform(context, pufType, deviceId))
                .thenReturn(VerifierExchangeResponse.OK);

        try (MockedStatic<AppContext> app = mockStatic(AppContext.class)) {
            app.when(AppContext::instance).thenReturn(appContext);
            doReturn(false).when(verifierExchangeImpl).spdmSupported();
            // when
            int result = verifierExchangeImpl.createDeviceAttestationSubKey(TRANSPORT_ID, context, String.valueOf(pufType));

            // then
            app.verify(AppContext::instance, times(1));
            verify(transportLayer, times(1)).initialize(TRANSPORT_ID);
            assertEquals(VerifierExchangeResponse.OK.getCode(), result);
            verify(transportLayer, times(1)).disconnect();
        }
    }

    @Test
    void createDeviceAttestationSubKey_CallsInitializeAndDisconect() throws Exception {
        // given
        mockAppContext();
        String context = "01020304ABCDEF";
        PufType pufType = PufType.EFUSE;
        mockInitSessionComponent();
        when(createSubKeyComponent.perform(context, pufType, deviceId))
                .thenReturn(VerifierExchangeResponse.OK);

        try (MockedStatic<AppContext> app = mockStatic(AppContext.class)) {
            app.when(AppContext::instance).thenReturn(appContext);
            doReturn(false).when(verifierExchangeImpl).spdmSupported();
            // when
            verifierExchangeImpl.createDeviceAttestationSubKey(TRANSPORT_ID, context, String.valueOf(pufType));

            // then
            app.verify(AppContext::instance, times(1));
            verify(transportLayer, times(1)).initialize(TRANSPORT_ID);
            verify(transportLayer, times(1)).disconnect();
        }
    }

    @Test
    void getDeviceAttestation_ExceptionThrown_ReturnsError() throws Exception {
        // given
        mockAppContext();
        String refMeasurement = "some reference measurements";
        mockInitSessionComponent();
        when(getAttestationComponentSigma.perform(refMeasurement, deviceId))
                .thenThrow(TransportLayerException.class);

        try (MockedStatic<AppContext> app = mockStatic(AppContext.class)) {
            app.when(AppContext::instance).thenReturn(appContext);
            doReturn(false).when(verifierExchangeImpl).spdmSupported();
            // when
            VerifierExchangeResponseDTO result = verifierExchangeImpl.getDeviceAttestation(TRANSPORT_ID, refMeasurement);

            // then
            app.verify(AppContext::instance, times(1));
            verify(transportLayer, times(1)).initialize(TRANSPORT_ID);
            assertEquals(VerifierExchangeResponse.ERROR.getCode(), result.getStatus());
            assertEquals(toHex(deviceId), result.getDeviceId());
            verify(transportLayer, times(1)).disconnect();
        }
    }

    @Test
    void getDeviceAttestation_Success_ReturnsOk() throws Exception {
        // given
        mockAppContext();
        String refMeasurement = "some referenece measurements";
        mockInitSessionComponent();
        when(getAttestationComponentSigma.perform(refMeasurement, deviceId))
                .thenReturn(VerifierExchangeResponse.OK);

        try (MockedStatic<AppContext> app = mockStatic(AppContext.class)) {
            app.when(AppContext::instance).thenReturn(appContext);
            doReturn(false).when(verifierExchangeImpl).spdmSupported();
            // when
            VerifierExchangeResponseDTO result = verifierExchangeImpl.getDeviceAttestation(TRANSPORT_ID, refMeasurement);

            // then
            app.verify(AppContext::instance, times(1));
            verify(transportLayer, times(1)).initialize(TRANSPORT_ID);
            assertEquals(VerifierExchangeResponse.OK.getCode(), result.getStatus());
            assertEquals(toHex(deviceId), result.getDeviceId());
            verify(transportLayer, times(1)).disconnect();
        }
    }

    @Test
    void getDeviceAttestation_CallsInitializeAndDisconnect() throws Exception {
        // given
        mockAppContext();
        String refMeasurement = "some reference measurements";
        mockInitSessionComponent();
        when(getAttestationComponentSigma.perform(refMeasurement, deviceId))
                .thenReturn(VerifierExchangeResponse.OK);

        try (MockedStatic<AppContext> app = mockStatic(AppContext.class)) {
            app.when(AppContext::instance).thenReturn(appContext);
            doReturn(false).when(verifierExchangeImpl).spdmSupported();
            // when
            verifierExchangeImpl.getDeviceAttestation(TRANSPORT_ID, refMeasurement);

            // then
            app.verify(AppContext::instance, times(1));
            verify(transportLayer, times(1)).initialize(TRANSPORT_ID);
            verify(transportLayer, times(1)).disconnect();
        }
    }

    @Test
    void healthCheck_ExceptionThrown_ReturnsError() {
        // given
        mockAppContext();
        when(transportLayer.sendCommand(any())).thenThrow(TransportLayerException.class);

        try (MockedStatic<AppContext> app = mockStatic(AppContext.class)) {
            app.when(AppContext::instance).thenReturn(appContext);
            doReturn(false).when(verifierExchangeImpl).spdmSupported();
            // when
            int result = verifierExchangeImpl.healthCheck(TRANSPORT_ID);

            // then
            app.verify(AppContext::instance, times(1));
            verify(transportLayer, times(1)).initialize(TRANSPORT_ID);
            assertEquals(VerifierExchangeResponse.ERROR.getCode(), result);
            verify(transportLayer, times(1)).disconnect();
        }
    }

    @Test
    void healthCheck_Succcess_ReturnsOk() {
        // given
        mockAppContext();
        when(transportLayer.sendCommand(any())).thenReturn(new byte[]{0x01, 0x02});

        try (MockedStatic<AppContext> app = mockStatic(AppContext.class)) {
            app.when(AppContext::instance).thenReturn(appContext);
            doReturn(false).when(verifierExchangeImpl).spdmSupported();
            // when
            int result = verifierExchangeImpl.healthCheck(TRANSPORT_ID);

            // then
            app.verify(AppContext::instance, times(1));
            verify(transportLayer, times(1)).initialize(TRANSPORT_ID);
            assertEquals(VerifierExchangeResponse.OK.getCode(), result);
            verify(transportLayer, times(1)).disconnect();
        }
    }

    @Test
    void healthCheck_EmptyResponse_ReturnsError() {
        // given
        mockAppContext();
        when(transportLayer.sendCommand(any())).thenReturn(new byte[0]);

        try (MockedStatic<AppContext> app = mockStatic(AppContext.class)) {
            app.when(AppContext::instance).thenReturn(appContext);
            doReturn(false).when(verifierExchangeImpl).spdmSupported();
            // when
            int result = verifierExchangeImpl.healthCheck(TRANSPORT_ID);

            // then
            app.verify(AppContext::instance, times(1));
            verify(transportLayer, times(1)).initialize(TRANSPORT_ID);
            assertEquals(VerifierExchangeResponse.ERROR.getCode(), result);
            verify(transportLayer, times(1)).disconnect();
        }
    }

    @Test
    void healthCheck_NullResponse_ReturnsError() {
        // given
        mockAppContext();
        when(transportLayer.sendCommand(any())).thenReturn(null);

        try (MockedStatic<AppContext> app = mockStatic(AppContext.class)) {
            app.when(AppContext::instance).thenReturn(appContext);
            doReturn(false).when(verifierExchangeImpl).spdmSupported();
            // when
            int result = verifierExchangeImpl.healthCheck(TRANSPORT_ID);

            // then
            app.verify(AppContext::instance, times(1));
            verify(transportLayer, times(1)).initialize(TRANSPORT_ID);
            assertEquals(VerifierExchangeResponse.ERROR.getCode(), result);
            verify(transportLayer, times(1)).disconnect();
        }
    }

    @Test
    void healthCheck_CallInitializeAndDisconnect() {
        // given
        mockAppContext();
        when(transportLayer.sendCommand(any())).thenReturn(new byte[0]);

        try (MockedStatic<AppContext> app = mockStatic(AppContext.class)) {
            app.when(AppContext::instance).thenReturn(appContext);
            doReturn(false).when(verifierExchangeImpl).spdmSupported();
            // when
            verifierExchangeImpl.healthCheck(TRANSPORT_ID);

            // then
            app.verify(AppContext::instance, times(1));
            verify(transportLayer, times(1)).initialize(TRANSPORT_ID);
            verify(transportLayer, times(1)).disconnect();
        }
    }

    private void mockAppContext() {
        when(appContext.getTransportLayer()).thenReturn(transportLayer);
    }

    private void mockInitSessionComponent() throws InitSessionFailedException {
        when(initSessionComponent.initializeSessionForDeviceId()).thenReturn(deviceId);
    }
}
