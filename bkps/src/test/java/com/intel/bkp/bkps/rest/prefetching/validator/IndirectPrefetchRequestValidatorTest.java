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

package com.intel.bkp.bkps.rest.prefetching.validator;

import com.intel.bkp.bkps.domain.enumeration.FamilyExtended;
import com.intel.bkp.bkps.rest.prefetching.model.IndirectPrefetchRequestDTO;
import com.intel.bkp.fpgacerts.model.Family;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Optional;
import java.util.function.Predicate;
import java.util.stream.Stream;

import static com.intel.bkp.bkps.rest.prefetching.validator.IndirectPrefetchRequestValidator.PREFETCH_TYPE_REQUIRING_DEVICE_ID_ER;
import static com.intel.bkp.bkps.rest.prefetching.validator.IndirectPrefetchRequestValidator.PREFETCH_TYPE_REQUIRING_PDI;
import static com.intel.bkp.test.RandomUtils.generateDeviceIdHex;
import static com.intel.bkp.test.RandomUtils.generateRandomHex;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@ExtendWith(MockitoExtension.class)
class IndirectPrefetchRequestValidatorTest {

    private static final int PDI_LENGTH = 48;

    private final IndirectPrefetchRequestValidator sut = new IndirectPrefetchRequestValidator();

    private static Stream<Arguments> getFamiliesThatRequirePdi() {
        return getAllMatchingFamilies(
            f -> PREFETCH_TYPE_REQUIRING_PDI == f.getPrefetchType()
        );
    }

    private static Stream<Arguments> getFamiliesThatDoNotUsePdi() {
        return getAllMatchingFamilies(
            f -> PREFETCH_TYPE_REQUIRING_PDI != f.getPrefetchType()
        );
    }

    private static Stream<Arguments> getFamiliesThatRequireSki() {
        return getAllMatchingFamilies(
            f -> PREFETCH_TYPE_REQUIRING_DEVICE_ID_ER == f.getPrefetchType()
        );
    }

    private static Stream<Arguments> getFamiliesThatDoNotUseSki() {
        return getAllMatchingFamilies(
            f -> PREFETCH_TYPE_REQUIRING_DEVICE_ID_ER != f.getPrefetchType()
        );
    }

    private static Stream<Arguments> getAllMatchingFamilies(Predicate<FamilyExtended> predicate) {
        return FamilyExtended.getAllMatching(predicate)
            .stream()
            .map(Arguments::of);
    }

    @ParameterizedTest
    @MethodSource("getFamiliesThatRequirePdi")
    void isValid_WithPdi_WithFamilyThatRequiresPdi_ReturnsTrue(Family family) {
        // given
        final var dto = prepareDto(family);
        setPdi(dto);

        // when
        final var result = sut.isValid(dto, null);

        // then
        assertTrue(result);
    }

    @ParameterizedTest
    @MethodSource("getFamiliesThatDoNotUsePdi")
    void isValid_WithPdi_WithFamilyThatDoesNotUsePdi_ReturnsFalse(Family family) {
        // given
        final var dto = prepareDto(family);
        setPdi(dto);

        // when
        final var result = sut.isValid(dto, null);

        // then
        assertFalse(result);
    }

    @ParameterizedTest
    @MethodSource("getFamiliesThatRequireSki")
    void isValid_WithDeviceIdEr_WithFamilyThatRequiresSki_ReturnsTrue(Family family) {
        // given
        final var dto = prepareDto(family);
        setDeviceIdEr(dto);

        // when
        final var result = sut.isValid(dto, null);

        // then
        assertTrue(result);
    }

    @ParameterizedTest
    @MethodSource("getFamiliesThatDoNotUseSki")
    void isValid_WithDeviceIdEr_WithFamilyThatDoesNotUseSki_ReturnsFalse(Family family) {
        // given
        final var dto = prepareDto(family);
        setDeviceIdEr(dto);

        // when
        final var result = sut.isValid(dto, null);

        // then
        assertFalse(result);
    }

    private IndirectPrefetchRequestDTO prepareDto(Family family) {
        final var dto = new IndirectPrefetchRequestDTO();
        Optional.ofNullable(family).map(Family::getAsHex).ifPresent(dto::setFamilyId);
        dto.setUid(generateDeviceIdHex());
        return dto;
    }

    private void setPdi(IndirectPrefetchRequestDTO dto) {
        dto.setPdi(generateRandomHex(PDI_LENGTH));
    }

    private void setDeviceIdEr(IndirectPrefetchRequestDTO dto) {
        dto.setDeviceIdEr("dummy");
    }
}
