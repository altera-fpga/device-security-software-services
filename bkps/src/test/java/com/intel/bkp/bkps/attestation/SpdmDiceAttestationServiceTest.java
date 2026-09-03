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

package com.intel.bkp.bkps.attestation;

import com.intel.bkp.fpgacerts.exceptions.SpdmAttestationException;
import com.intel.bkp.fpgacerts.spdm.SpdmAttestationResult;
import com.intel.bkp.fpgacerts.spdm.SpdmDiceAttestationComponentBase;
import com.intel.bkp.fpgacerts.verification.VerificationResult;
import com.intel.bkp.protocol.spdm.jna.model.SpdmProtocol;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.mockito.ArgumentMatchers;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Optional;
import java.util.function.Supplier;

import static com.intel.bkp.fpgacerts.verification.VerificationResult.PASSED;
import static com.intel.bkp.utils.HexConverter.fromHex;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.params.provider.EnumSource.Mode.EXCLUDE;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class SpdmDiceAttestationServiceTest {

    private static final String UID = "01030405060708";
    private static final String URL = "some/url.com";
    private static final AttestationParams ATTESTATION_PARAMS = new AttestationParams(true, true, URL);
    private static final Integer SLOT_ID = 3;

    @Mock
    private SpdmProtocol spdmProtocol;
    @Mock
    private SpdmDiceAttestationComponentBase component;
    @Mock
    private SpdmDiceAttestationComponentFactory componentFactory;
    @Mock
    private RimFetcher rimFetcher;

    @InjectMocks
    private SpdmDiceAttestationService sut;

    @Test
    void performAttestationAndGetSlotId_WhenVerificationPassed_ReturnsSlotId() {
        // given
        final var params = new AttestationParams(true, true, URL);
        when(componentFactory.get(spdmProtocol, params)).thenReturn(component);
        when(rimFetcher.fetchAsHex(URL)).thenReturn(Optional.of("rimContentInHex"));
        mockAttestation(PASSED);

        // when
        final var slotId = sut.performAttestationAndGetSlotId(spdmProtocol, UID, params);

        // then
        assertEquals(SLOT_ID, slotId);
    }

    @ParameterizedTest
    @EnumSource(value = VerificationResult.class, mode = EXCLUDE, names = {"PASSED"})
    void performAttestationAndGetSlotId_WhenVerificationResultDifferentThanPassed_Throws(VerificationResult result) {
        // given
        when(componentFactory.get(spdmProtocol, ATTESTATION_PARAMS)).thenReturn(component);
        when(rimFetcher.fetchAsHex(URL)).thenReturn(Optional.of("rimContentInHex"));
        mockAttestation(result);

        // when
        final var ex = assertThrows(SpdmAttestationException.class,
            () -> sut.performAttestationAndGetSlotId(spdmProtocol, UID, ATTESTATION_PARAMS));

        // then
        assertEquals("Attestation result: " + result, ex.getMessage());
    }

    @Test
    void performAttestationAndGetSlotId_WhenRimUrlMissing_Throws() {
        // given
        final var paramsWithEmptyUrl = new AttestationParams(true, true, null);
        when(componentFactory.get(spdmProtocol, paramsWithEmptyUrl)).thenReturn(component);
        // when
        final var ex = assertThrows(SpdmAttestationException.class,
            () -> sut.performAttestationAndGetSlotId(spdmProtocol, UID, paramsWithEmptyUrl));

        // then
        assertEquals("Missing RIM URL - required for attestation", ex.getMessage());
    }

    @Test
    void performAttestationAndGetSlotId_WhenRimNotFetched_Throws() {
        // given
        when(componentFactory.get(spdmProtocol, ATTESTATION_PARAMS)).thenReturn(component);
        when(rimFetcher.fetchAsHex(URL)).thenReturn(Optional.empty());
        mockAttestation(null);

        // when
        final var ex = assertThrows(SpdmAttestationException.class,
            () -> sut.performAttestationAndGetSlotId(spdmProtocol, UID, ATTESTATION_PARAMS));

        // then
        assertEquals("Failed to fetch RIM: " + URL, ex.getMessage());
    }

    private void mockAttestation(VerificationResult result) {
        doAnswer(invocation -> {
            Supplier<String> supplier = invocation.getArgument(0);
            supplier.get();
            return new SpdmAttestationResult(result, SLOT_ID);
        }).when(component).perform(ArgumentMatchers.<Supplier<String>>any(), eq(fromHex(UID)));
    }

}
