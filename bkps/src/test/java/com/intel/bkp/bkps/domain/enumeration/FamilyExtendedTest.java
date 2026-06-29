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

package com.intel.bkp.bkps.domain.enumeration;

import com.intel.bkp.fpgacerts.exceptions.UnknownFamilyIdException;
import com.intel.bkp.fpgacerts.model.Family;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class FamilyExtendedTest {

    @ParameterizedTest
    @EnumSource(value = FamilyExtended.class)
    void from_Success(FamilyExtended familyExtended) {
        // when
        final FamilyExtended result = FamilyExtended.from(familyExtended.getFamily());

        // then
        assertEquals(familyExtended, result);
    }

    @ParameterizedTest
    @EnumSource(value = FamilyExtended.class)
    void find_Success(FamilyExtended familyExtended) {
        // when
        final Optional<FamilyExtended> result = FamilyExtended.find(familyExtended.getFamily());

        // then
        assertEquals(Optional.of(familyExtended), result);
    }

    @ParameterizedTest
    @EnumSource(value = Family.class, mode = EnumSource.Mode.INCLUDE, names = {"MEV", "LKV", "CNV"})
    void from_UnknownFamily_Throws(Family family) {
        // when-then
        assertThrows(UnknownFamilyIdException.class, () -> FamilyExtended.from(family));
    }

    @ParameterizedTest
    @EnumSource(value = Family.class, mode = EnumSource.Mode.INCLUDE, names = {"MEV", "LKV", "CNV"})
    void find_UnknownFamily_ReturnsEmptyOptional(Family family) {
        // when
        final Optional<FamilyExtended> result = FamilyExtended.find(family);

        // then
        assertTrue(result.isEmpty());
    }
}
