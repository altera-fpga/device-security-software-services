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

package com.intel.bkp.bkps.rest.configuration.model.dto;

import com.intel.bkp.bkps.domain.enumeration.ImportMode;
import com.intel.bkp.bkps.rest.provisioning.model.dto.OverbuildDTO;
import com.intel.bkp.core.manufacturing.model.PufType;
import com.intel.bkp.core.psgcertificate.enumerations.StorageType;
import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validation;
import jakarta.validation.Validator;
import jakarta.validation.ValidatorFactory;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import java.nio.ByteBuffer;
import java.util.Set;

import static com.intel.bkp.test.RandomUtils.generateRandomString;
import static org.junit.jupiter.api.Assertions.assertEquals;

@ExtendWith(MockitoExtension.class)
class ServiceConfigurationDTOTest {

    private static final String AES_KEY_HEX = "3022e09098452ff5521674b193d0fb50d64d92d8977461f403161d86cedefe12";
    private Validator validator;

    @BeforeEach
    void setUp() {
        ValidatorFactory validatorFactory = Validation.buildDefaultValidatorFactory();
        validator = validatorFactory.getValidator();
    }

    @Test
    void validation_WithNotRequiredIid_ProperlyValidatesIidField() {
        //given
        ServiceConfigurationDTO sut = prepareServiceConfigurationDTO(PufType.EFUSE);

        //when
        Set<ConstraintViolation<ServiceConfigurationDTO>> violations = validator.validate(sut);

        //then
        assertEquals(0, violations.size());
    }

    @Test
    void validation_WithWrongOverbuildMax_ReturnsInvalidState() {
        //given
        ServiceConfigurationDTO sut = prepareServiceConfigurationDTO(PufType.EFUSE);
        sut.setOverbuild(new OverbuildDTO().maxValue(-4));

        //when
        Set<ConstraintViolation<ServiceConfigurationDTO>> violations = validator.validate(sut);

        //then
        assertEquals(1, violations.size());
    }

    @Test
    void validation_WithTooLongCorimUrl_ReturnsInvalidState() {
        //given
        ServiceConfigurationDTO sut = prepareServiceConfigurationDTO(PufType.EFUSE);
        sut.setCorimUrl(generateRandomString(256));

        //when
        Set<ConstraintViolation<ServiceConfigurationDTO>> violations = validator.validate(sut);

        //then
        assertEquals(1, violations.size());
    }

    private ServiceConfigurationDTO prepareServiceConfigurationDTO(PufType pufType) {
        ServiceConfigurationDTO form = new ServiceConfigurationDTO();
        form.setPufType(pufType);
        form.setName("TEST");
        form.setConfidentialData(getConfidentialDataDTO());
        form.setAttestationConfig(getAttestationConfigurationDTO());
        return form;
    }

    private AttestationConfigurationDTO getAttestationConfigurationDTO() {
        AttestationConfigurationDTO attestationConfig = new AttestationConfigurationDTO();
        byte[] mask = ByteBuffer.allocate(256).putLong(151).putInt(8).array();
        byte[] actual = ByteBuffer.allocate(256).putLong(172).putInt(15).array();
        attestationConfig.setEfusesPublic(new EfusesPublicDTO(Hex.toHexString(mask), Hex.toHexString(actual)));
        return attestationConfig;
    }

    private ConfidentialDataDTO getConfidentialDataDTO() {
        ConfidentialDataDTO confidentialData = new ConfidentialDataDTO();
        confidentialData.setImportMode(ImportMode.PLAINTEXT);
        confidentialData.setAesKey(new AesKeyDTO(StorageType.PUFSS, AES_KEY_HEX));
        return confidentialData;
    }
}
