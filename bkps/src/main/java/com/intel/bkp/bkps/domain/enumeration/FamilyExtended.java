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
import lombok.Getter;
import lombok.RequiredArgsConstructor;

import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Predicate;

import static com.intel.bkp.bkps.domain.enumeration.PrefetchType.NONE;
import static com.intel.bkp.bkps.domain.enumeration.PrefetchType.ZIP_WITH_PDI;
import static com.intel.bkp.bkps.domain.enumeration.PrefetchType.ZIP_WITH_SKI;

@RequiredArgsConstructor
@Getter
public enum FamilyExtended {

    S10(Family.S10, PrefetchType.S10, false, false),
    AGILEX(Family.AGILEX, ZIP_WITH_SKI, true, true),
    EASIC_N5X(Family.EASIC_N5X, ZIP_WITH_SKI, true, false),
    AGILEX_B(Family.AGILEX_B, ZIP_WITH_PDI, true, true);

    public static final List<Family> FAMILIES_WITH_PUF_SUPPORTED = getAllMatching((family) -> family.isPufSupported);

    public static final List<Family> FAMILIES_WITH_SET_AUTH_SUPPORTED =
        getAllMatching((family) -> family.isSetAuthSupported);

    public static final List<Family> FAMILIES_WITH_PREFETCH_SUPPORTED =
        getAllMatching((family) -> Objects.nonNull(family.prefetchType) && NONE != family.prefetchType);

    private final Family family;
    private final PrefetchType prefetchType;
    private final boolean isSetAuthSupported;
    private final boolean isPufSupported;

    public static FamilyExtended from(Family family) {
        return find(family)
            .orElseThrow(UnknownFamilyIdException::new);
    }

    public static Optional<FamilyExtended> find(Family family) {
        return Arrays.stream(values())
            .filter(familyExtended -> familyExtended.family == family)
            .findFirst();
    }

    public static List<Family> getAllMatching(Predicate<FamilyExtended> predicate) {
        return Arrays.stream(FamilyExtended.values())
            .filter(predicate)
            .map(FamilyExtended::getFamily)
            .toList();
    }
}
