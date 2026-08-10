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
import com.intel.bkp.bkps.domain.enumeration.PrefetchType;
import com.intel.bkp.bkps.rest.prefetching.model.IndirectPrefetchRequestDTO;
import com.intel.bkp.fpgacerts.model.Family;
import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import org.apache.commons.lang3.StringUtils;

import java.util.Objects;

import static com.intel.bkp.bkps.domain.enumeration.PrefetchType.ZIP_WITH_PDI;
import static com.intel.bkp.bkps.domain.enumeration.PrefetchType.ZIP_WITH_SKI;

public class IndirectPrefetchRequestValidator implements
    ConstraintValidator<IndirectPrefetchRequestValidation, IndirectPrefetchRequestDTO> {

    static final PrefetchType PREFETCH_TYPE_REQUIRING_PDI = ZIP_WITH_PDI;
    static final PrefetchType PREFETCH_TYPE_REQUIRING_DEVICE_ID_ER = ZIP_WITH_SKI;

    @Override
    public boolean isValid(IndirectPrefetchRequestDTO dto, ConstraintValidatorContext context) {
        final PrefetchType prefetchType = getPrefetchTypeBasedOnFamily(dto);
        return isValidPdi(dto.getPdi(), prefetchType)
            && isValidDeviceIdEr(dto.getDeviceIdEr(), prefetchType);
    }

    private static PrefetchType getPrefetchTypeBasedOnFamily(IndirectPrefetchRequestDTO dto) {
        return FamilyExtended.from(Family.from(dto.getFamilyId())).getPrefetchType();
    }

    private static boolean isValidPdi(String pdi, PrefetchType prefetchType) {
        return PREFETCH_TYPE_REQUIRING_PDI == prefetchType
               ? StringUtils.isNotBlank(pdi)
               : Objects.isNull(pdi);
    }

    private static boolean isValidDeviceIdEr(String deviceIdEr, PrefetchType prefetchType) {
        return PREFETCH_TYPE_REQUIRING_DEVICE_ID_ER == prefetchType
               ? StringUtils.isNotBlank(deviceIdEr)
               : Objects.isNull(deviceIdEr);
    }
}
