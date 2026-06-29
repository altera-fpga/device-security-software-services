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

package com.intel.bkp.bkps.rest.onboarding.handler;

import com.intel.bkp.bkps.exception.PrefetchingGenericException;
import com.intel.bkp.bkps.programmer.model.ProgrammerResponse;
import com.intel.bkp.bkps.protocol.common.service.GetAttestationCertificateMessageSender;
import com.intel.bkp.bkps.protocol.common.service.GetChipIdMessageSender;
import com.intel.bkp.bkps.protocol.common.service.GetDeviceIdentityMessageSender;
import com.intel.bkp.bkps.protocol.common.service.GetIdCodeMessageSender;
import com.intel.bkp.bkps.rest.onboarding.model.DeviceId;
import com.intel.bkp.bkps.rest.onboarding.model.DirectPrefetchRequestDTOReader;
import com.intel.bkp.bkps.rest.onboarding.model.DirectPrefetchTransferObject;
import com.intel.bkp.bkps.rest.onboarding.service.PrefetchService;
import com.intel.bkp.fpgacerts.model.Family;
import com.intel.bkp.test.CertificateUtils;
import com.intel.bkp.test.RandomUtils;
import lombok.SneakyThrows;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Optional;

import static com.intel.bkp.bkps.programmer.model.ResponseStatus.ST_OK;
import static com.intel.bkp.utils.HexConverter.toHex;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class DirectPrefetchFetchCertificateComponentTest {

    private static final byte[] DEVICE_ID = RandomUtils.generateDeviceId();
    private static final byte[] DEVICE_IDENTITY_RESP = RandomUtils.generateRandomBytes(4);
    private static final byte[] ID_CODE_RESP = RandomUtils.generateRandomBytes(4);
    private static final X509Certificate DEVICEID_ENROLLMENT_CERT = CertificateUtils.generateCertificate();
    private static final String UID = toHex(DEVICE_ID).toLowerCase(Locale.ROOT);

    private final byte[] getCertificateResponse = prepareGetCertificateResponse();

    @Mock
    private DirectPrefetchTransferObject transferObject;
    @Mock
    private DirectPrefetchHandler successor;
    @Mock
    private DirectPrefetchRequestDTOReader prefetchRequestDTOReader;
    @Mock
    private GetChipIdMessageSender getChipIdMessageSender;
    @Mock
    private GetIdCodeMessageSender getIdCodeMessageSender;
    @Mock
    private GetDeviceIdentityMessageSender getDeviceIdentityMessageSender;
    @Mock
    private GetAttestationCertificateMessageSender getAttestationCertificateMessageSender;

    @Mock
    private PrefetchService prefetchService;

    @InjectMocks
    private DirectPrefetchFetchCertificateComponent sut;

    @BeforeEach
    void setUp() {
        sut.setSuccessor(successor);
    }

    @Test
    @SneakyThrows
    void handle_WithFM_WithEnrollmentCertificateValidMessage_HandleDiceChainAndCallSuccessor() {
        // given
        mockJtagResponses(DEVICE_ID, ID_CODE_RESP, DEVICE_IDENTITY_RESP, getCertificateResponse);
        when(getChipIdMessageSender.retrieve(DEVICE_ID)).thenReturn(UID);
        when(getIdCodeMessageSender.retrieve(ID_CODE_RESP)).thenReturn(Family.AGILEX);
        when(getDeviceIdentityMessageSender.retrieve(DEVICE_IDENTITY_RESP)).thenReturn(
            toHex(DEVICE_IDENTITY_RESP));
        when(getAttestationCertificateMessageSender.retrieve(getCertificateResponse)).thenReturn(
            Optional.of(getCertificateResponse));

        // when
        sut.handle(transferObject);

        // then
        verify(successor).handle(transferObject);
        verifyChainHandledWithId(Family.AGILEX);
    }

    @Test
    @SneakyThrows
    void handle_WithSM_WithEnrollmentCertificateValidMessage_HandleDiceChainAndCallSuccessor() {
        // given
        mockJtagResponses(DEVICE_ID, ID_CODE_RESP, DEVICE_IDENTITY_RESP, getCertificateResponse);
        when(getChipIdMessageSender.retrieve(DEVICE_ID)).thenReturn(UID);
        when(getIdCodeMessageSender.retrieve(ID_CODE_RESP)).thenReturn(Family.AGILEX_B);
        when(getDeviceIdentityMessageSender.retrieve(DEVICE_IDENTITY_RESP)).thenReturn(
            toHex(DEVICE_IDENTITY_RESP));
        when(getAttestationCertificateMessageSender.retrieve(getCertificateResponse)).thenReturn(
            Optional.of(getCertificateResponse));

        // when
        sut.handle(transferObject);

        // then
        verify(successor).handle(transferObject);
        verifyChainHandledWithId(Family.AGILEX_B);
    }

    @Test
    void handle_WithS10_WithEnrollmentCertificateInvalidMessage_HandleS10ChainAndCallSuccessor() {
        // given
        mockJtagResponses(DEVICE_ID, ID_CODE_RESP, DEVICE_IDENTITY_RESP, getCertificateResponse);
        when(getChipIdMessageSender.retrieve(DEVICE_ID)).thenReturn(UID);
        when(getIdCodeMessageSender.retrieve(ID_CODE_RESP)).thenReturn(Family.S10);
        when(getDeviceIdentityMessageSender.retrieve(DEVICE_IDENTITY_RESP)).thenReturn(
            toHex(DEVICE_IDENTITY_RESP));
        when(getAttestationCertificateMessageSender.retrieve(getCertificateResponse))
            .thenReturn(Optional.empty());

        // when
        sut.handle(transferObject);

        // then
        verify(successor).handle(transferObject);
        verifyChainHandled(Family.S10);
    }

    @Test
    void handle_WithWrongNumberOfResponses_Throws() {
        // given
        mockJtagResponses(DEVICE_ID);

        // when-then
        assertThrows(PrefetchingGenericException.class, () -> sut.handle(transferObject));

        // then
        verifyNoInteractions(successor);
    }

    private void mockJtagResponses(byte[]... responses) {
        when(transferObject.getDtoReader()).thenReturn(prefetchRequestDTOReader);
        when(prefetchRequestDTOReader.getJtagResponses()).thenReturn(prepareResponses(responses));
    }

    private List<ProgrammerResponse> prepareResponses(byte[]... responses) {
        return Arrays.stream(responses)
            .map(response -> new ProgrammerResponse(response, ST_OK))
            .toList();
    }

    @SneakyThrows
    private static byte[] prepareGetCertificateResponse() {
        return DEVICEID_ENROLLMENT_CERT.getEncoded();
    }


    private void verifyChainHandled(Family family) {
        final DeviceId actualDeviceId = getDeviceIdFromCaptor(Optional.empty());
        assertEquals(family, actualDeviceId.getFamily());
        assertEquals(UID, actualDeviceId.getUid());
    }

    private void verifyChainHandledWithId(Family family) {
        final var actualDeviceId = getDeviceIdFromCaptor(Optional.of(getCertificateResponse));
        assertEquals(family, actualDeviceId.getFamily());
        assertEquals(UID, actualDeviceId.getUid());
        assertNotNull(actualDeviceId.getId());
    }

    private DeviceId getDeviceIdFromCaptor(Optional<byte[]> certificate) {
        final var deviceIdCaptor = ArgumentCaptor.forClass(DeviceId.class);
        verify(prefetchService).enqueue(deviceIdCaptor.capture(), eq(certificate));
        return deviceIdCaptor.getValue();
    }
}
