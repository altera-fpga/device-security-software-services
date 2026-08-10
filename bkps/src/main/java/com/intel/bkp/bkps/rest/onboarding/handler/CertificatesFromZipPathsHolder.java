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

import com.intel.bkp.bkps.exception.SetAuthorityGenericException;
import com.intel.bkp.core.manufacturing.model.PufType;
import com.intel.bkp.fpgacerts.model.Family;
import lombok.AccessLevel;
import lombok.Getter;

import java.util.Locale;

@Getter(AccessLevel.PACKAGE)
public class CertificatesFromZipPathsHolder {

    private static final String DICE_ROOT_CA_CER = "auth/DICE_RootCA.cer";
    private static final String IPCS_FAMILY_CER = "auth/IPCS_%s.cer";
    private static final String DEVICE_ID_CER = "%s/deviceid.cer";
    private static final String ENROLLMENT_DEVICE_ID_CER = "%s/enrollment_%s.cer";
    private static final String EFUSE_IIDUDS_CER = "%s/iiduds.cer";

    private final PufType pufType;
    private final String ipcsFamilyCer;
    private final String deviceIdCer;
    private final String enrollmentDeviceIdCer;
    private final String efuseIidudsCer;

    public CertificatesFromZipPathsHolder(PufType pufType, String svn, Family family) {
        this.pufType = pufType;
        this.ipcsFamilyCer = IPCS_FAMILY_CER.formatted(family.getFamilyName().toLowerCase(Locale.ROOT));
        this.deviceIdCer = DEVICE_ID_CER.formatted(pufTypeFolderName());
        this.enrollmentDeviceIdCer = ENROLLMENT_DEVICE_ID_CER.formatted(pufTypeFolderName(), svn);
        this.efuseIidudsCer = EFUSE_IIDUDS_CER.formatted(pufTypeFolderName());
    }

    String getDiceRootCaCer() {
        return DICE_ROOT_CA_CER;
    }

    String getEfuseIidudsCer() {
        return switch (pufType) {
            case IID -> efuseIidudsCer;
            default -> throw new SetAuthorityGenericException("IID certificate shall not be used for given Puf Type: %s"
                .formatted(pufType));
        };
    }

    private String pufTypeFolderName() {
        return switch (pufType) {
            case INTEL -> "puf";
            case EFUSE, IID -> "efuse";
            default -> throw new SetAuthorityGenericException("Not supported Puf Type: %s".formatted(pufType));
        };
    }
}
