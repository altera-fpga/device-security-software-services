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

package com.intel.bkp.verifier.service;

import com.intel.bkp.command.model.CommandLayer;
import com.intel.bkp.fpgacerts.verification.VerificationResult;
import com.intel.bkp.protocol.spdm.exceptions.UnsupportedSpdmVersionException;
import com.intel.bkp.protocol.spdm.service.SpdmGetVersionMessageSender;
import com.intel.bkp.protocol.spdm.service.SpdmVcaMessageSender;
import com.intel.bkp.protocol.spdm.service.SpdmVersionVerifier;
import com.intel.bkp.verifier.exceptions.VerifierRuntimeException;
import com.intel.bkp.verifier.model.VerifierExchangeResponse;
import com.intel.bkp.verifier.protocol.spdm.service.SpdmDiceAttestationComponent;
import com.intel.bkp.verifier.service.certificate.AppContext;
import com.intel.bkp.verifier.transport.model.TransportLayer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class GetDeviceAttestationComponentSpdmTest {

    private static final String REF_MEASUREMENT = "abcd";
    private static final byte[] DEVICE_ID = new byte[8];
    private static final String SPDM_SUPPORTED_VERSION = "12";
    private static final String SPDM_NOT_SUPPORTED_VERSION = "10";

    @Mock
    private AppContext appContext;

    @Mock
    private CommandLayer commandLayer;

    @Mock
    private TransportLayer transportLayer;

    @Mock
    private SpdmGetVersionMessageSender spdmGetVersionMessageSender;

    @Mock
    private SpdmDiceAttestationComponent spdmDiceAttestationComponent;

    @Mock
    private SpdmVcaMessageSender spdmVcaMessageSender;

    @Mock
    private SpdmVersionVerifier spdmVersionVerifier;

    @InjectMocks
    private GetDeviceAttestationComponentSpdm sutSpdm;

    @Test
    void perform_SpdmAttestationInsufficientVersion_Throws() throws Exception {
        // given
        final String responderVersion = SPDM_NOT_SUPPORTED_VERSION;
        doReturn(responderVersion).when(spdmGetVersionMessageSender).send();
        doThrow(new UnsupportedSpdmVersionException(responderVersion, SPDM_SUPPORTED_VERSION))
            .when(spdmVersionVerifier).ensureVersionIsSupported(responderVersion);
        final String expectedExMessage =
            "SPDM is in unsupported version: Responder SPDM version: %s, supported version: %s"
                .formatted(responderVersion, SPDM_SUPPORTED_VERSION);

        // when
        final var ex = assertThrows(VerifierRuntimeException.class, () ->
            sutSpdm.perform(appContext, REF_MEASUREMENT, DEVICE_ID));

        // then
        assertEquals(expectedExMessage, ex.getMessage());
    }

    @Test
    void perform_SpdmVerificationFailsDueToVerifierException_Throws() throws Exception {
        // given
        final String expectedErrorMessage = "TEST";
        doThrow(new VerifierRuntimeException(expectedErrorMessage))
            .when(spdmGetVersionMessageSender).send();

        // when
        final VerifierRuntimeException ex =
            assertThrows(VerifierRuntimeException.class,
                () -> sutSpdm.perform(appContext, REF_MEASUREMENT, DEVICE_ID));

        // then
        assertEquals(expectedErrorMessage, ex.getMessage());
        verifyNoInteractions(spdmDiceAttestationComponent);
    }

    @Test
    void perform_SpdmVerificationFailsForOtherReason_Throws() throws Exception {
        // given
        final String expectedErrorMessage = "Failed to verify if SPDM is supported.";
        doThrow(new RuntimeException())
            .when(spdmGetVersionMessageSender).send();

        // when
        final VerifierRuntimeException ex =
            assertThrows(VerifierRuntimeException.class,
                () -> sutSpdm.perform(appContext, REF_MEASUREMENT, DEVICE_ID));

        // then
        assertEquals(expectedErrorMessage, ex.getMessage());
        verifyNoInteractions(spdmDiceAttestationComponent);
    }

    @Test
    void perform_SpdmAttestationSupported_CallsSpdmAttestation() throws Exception {
        // given
        final var attestationResult = VerificationResult.PASSED;
        final var expectedResult = VerifierExchangeResponse.OK;
        when(spdmGetVersionMessageSender.send()).thenReturn(SPDM_SUPPORTED_VERSION);
        when(spdmDiceAttestationComponent.perform(REF_MEASUREMENT, DEVICE_ID)).thenReturn(attestationResult);

        // when
        final var actualResult = sutSpdm.perform(appContext, REF_MEASUREMENT, DEVICE_ID);

        // then
        assertEquals(expectedResult, actualResult);
        verify(spdmDiceAttestationComponent).perform(REF_MEASUREMENT, DEVICE_ID);
    }
}
