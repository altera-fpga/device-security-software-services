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

package com.intel.bkp.bkps.rest.prefetching.service;

import com.intel.bkp.bkps.exception.PrefetchingGenericException;
import com.intel.bkp.bkps.rest.onboarding.model.DeviceId;
import com.intel.bkp.bkps.rest.onboarding.service.PrefetchService;
import com.intel.bkp.bkps.rest.prefetching.model.IndirectPrefetchRequestDTO;
import com.intel.bkp.bkps.rest.prefetching.model.PrefetchStatusDTO;
import com.intel.bkp.crypto.pem.PemFormatEncoder;
import com.intel.bkp.crypto.pem.PemFormatHeader;
import com.intel.bkp.fpgacerts.model.Family;
import com.intel.bkp.test.CertificateUtils;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.cert.CertificateEncodingException;
import java.util.List;
import java.util.Optional;
import java.util.stream.IntStream;

import static com.intel.bkp.bkps.domain.enumeration.PrefetchStatus.ERROR;
import static com.intel.bkp.bkps.domain.enumeration.PrefetchStatus.PROGRESS;
import static com.intel.bkp.test.RandomUtils.generateDeviceIdHex;
import static com.intel.bkp.test.RandomUtils.generateRandomHex;
import static com.intel.bkp.test.RandomUtils.getRandomFamily;
import static org.apache.commons.collections4.CollectionUtils.isEqualCollection;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertIterableEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class IndirectPrefetchServiceTest {

    private static final int PDI_LENGTH = 48;

    @Mock
    private IndirectPrefetchRequestDTO indirectPrefetchRequestDTO;

    @Mock
    private PrefetchService prefetchService;

    @InjectMocks
    private IndirectPrefetchService sut;

    @Test
    void prefetchDevices_WithMultipleDevices_ReturnsProgressForEachDevice() {
        // given
        final List<IndirectPrefetchRequestDTO> devices = IntStream.range(0, 5)
            .mapToObj(inc -> generateDeviceIdHex())
            .map(this::getRequestDTO)
            .toList();

        final List<PrefetchStatusDTO> expectedResult = devices.stream()
            .map(dto -> new PrefetchStatusDTO(dto.getUid(), PROGRESS))
            .toList();

        // when
        final List<PrefetchStatusDTO> result = sut.prefetchDevices(devices);

        // then
        verifyDeviceIdMatch(devices);
        assertTrue(isEqualCollection(expectedResult, result));
    }

    @Test
    void prefetchDevices_ThrowException_ReturnsError() {
        // given
        final var dto = new IndirectPrefetchRequestDTO();
        dto.setUid(generateDeviceIdHex());
        dto.setFamilyId(getRandomFamily().getAsHex());
        dto.setPdi(generateRandomHex(PDI_LENGTH));
        dto.setDeviceIdEr(null);

        doThrow(PrefetchingGenericException.class)
            .when(prefetchService)
            .enqueue(getDeviceIdFromRequestDto(dto), Optional.empty());

        final var expectedResult = List.of(new PrefetchStatusDTO(dto.getUid(), ERROR));

        // when
        final List<PrefetchStatusDTO> result = sut.prefetchDevices(List.of(dto));

        // then
        assertIterableEquals(expectedResult, result);
    }

    @Test
    void getCertAsByteArray_WithNullCert_ReturnsEmptyOptional() {
        // given
        when(indirectPrefetchRequestDTO.getDeviceIdEr()).thenReturn(null);

        // when
        final var result = sut.getCertAsByteArray(indirectPrefetchRequestDTO);

        // then
        assertFalse(result.isPresent());
    }

    @Test
    void getCertAsByteArray_WithEmptyCert_ReturnsEmptyOptional() {
        // given
        when(indirectPrefetchRequestDTO.getDeviceIdEr()).thenReturn("");

        // when
        final var result = sut.getCertAsByteArray(indirectPrefetchRequestDTO);

        // then
        assertFalse(result.isPresent());
    }

    @Test
    void getCertAsByteArray_WithValidCert_Success() throws CertificateEncodingException {
        // given
        final var expected = CertificateUtils.generateCertificate().getEncoded();
        final var expectedAsString = PemFormatEncoder.encode(PemFormatHeader.CERTIFICATE, expected);
        when(indirectPrefetchRequestDTO.getDeviceIdEr()).thenReturn(expectedAsString);

        // when
        final var actual = sut.getCertAsByteArray(indirectPrefetchRequestDTO);

        // then
        assertArrayEquals(expected, actual.orElseThrow());
    }

    private IndirectPrefetchRequestDTO getRequestDTO(String uid) {
        final var prefetchDto = new IndirectPrefetchRequestDTO();
        prefetchDto.setUid(uid);
        return prefetchDto;
    }

    private DeviceId getDeviceIdFromRequestDto(IndirectPrefetchRequestDTO dto) {
        return DeviceId.instance(Family.from(dto.getFamilyId()), dto.getUid(), dto.getPdi());
    }

    private void verifyDeviceIdMatch(List<IndirectPrefetchRequestDTO> devices) {
        devices.stream()
            .map(this::getDeviceIdFromRequestDto)
            .forEach(deviceId ->
                verify(prefetchService).enqueue(deviceId, Optional.empty())
            );
    }
}
