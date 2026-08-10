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

package com.intel.bkp.bkps.config;

import com.intel.bkp.core.exceptions.JceSecurityProviderException;
import com.intel.bkp.core.security.SecurityProviderParams;
import com.intel.bkp.core.security.SecurityProviderParamsValidator;
import com.intel.bkp.core.security.params.KeyTypesProperties;
import com.intel.bkp.core.security.params.ProviderProperties;
import com.intel.bkp.core.security.params.SecurityProperties;
import com.intel.bkp.core.security.params.crypto.AesCtrProperties;
import com.intel.bkp.core.security.params.crypto.AesProperties;
import com.intel.bkp.core.security.params.crypto.EcProperties;
import com.intel.bkp.core.security.params.crypto.RsaProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static com.intel.bkp.test.RandomUtils.generateUuidString;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class SecurityProviderParamsValidatorTest {

    private static final String INVALID_VALUE = "Invalid values in security provider configuration:";
    private static final String NOT_NULL = "must not be null";

    private final SecurityProviderParams securityProviderParams = new SecurityProviderParams();

    @BeforeEach
    void setup() {
        prepareSecurityProviderParams();
    }

    @Test
    void nullSecurityProviderParams_throwException() {
        //given
        SecurityProviderParamsValidator sut = new SecurityProviderParamsValidator(null);

        //when-then
        assertThrows(IllegalArgumentException.class,
            sut::validateParams, "The object to be validated must not be null.");
    }

    @Test
    void securityProviderParams_nullKeyTypeProps_throwException() {
        //given
        KeyTypesProperties keyTypesProperties = new KeyTypesProperties();
        securityProviderParams.setKeyTypes(keyTypesProperties);
        SecurityProviderParamsValidator sut = new SecurityProviderParamsValidator(securityProviderParams);

        //when-then
        Exception ex = assertThrows(JceSecurityProviderException.class, sut::validateParams);
    }

    @Test
    void securityProviderParams_nullEC_throwException() {
        //given
        RsaProperties rsaProperties = setRsa();
        AesProperties aesProperties = setAes();
        AesCtrProperties aesCtrProperties = setAesCtr();
        EcProperties ecProperties = null;
        KeyTypesProperties keyTypesProperties = setKeyTypes(rsaProperties, aesProperties, aesCtrProperties, ecProperties);

        securityProviderParams.setKeyTypes(keyTypesProperties);
        SecurityProviderParamsValidator sut = new SecurityProviderParamsValidator(securityProviderParams);

        //when-then
        Exception ex = assertThrows(JceSecurityProviderException.class, sut::validateParams);

        assertEquals(INVALID_VALUE + " " + "keyTypes.ec " + NOT_NULL, ex.getMessage());
    }

    @Test
    void securityProviderParams_nullRSA_throwException() {
        //given
        RsaProperties rsaProperties = null;
        AesProperties aesProperties = setAes();
        AesCtrProperties aesCtrProperties = setAesCtr();
        EcProperties ecProperties = setEc();
        KeyTypesProperties keyTypesProperties = setKeyTypes(rsaProperties, aesProperties, aesCtrProperties, ecProperties);

        securityProviderParams.setKeyTypes(keyTypesProperties);
        SecurityProviderParamsValidator sut = new SecurityProviderParamsValidator(securityProviderParams);

        //when-then
        Exception ex = assertThrows(JceSecurityProviderException.class, sut::validateParams);

        assertEquals(INVALID_VALUE + " " + "keyTypes.rsa " + NOT_NULL, ex.getMessage());
    }

    @Test
    void securityProviderParams_nullAES_throwException() {
        //given
        RsaProperties rsaProperties = setRsa();
        AesProperties aesProperties = null;
        AesCtrProperties aesCtrProperties = setAesCtr();
        EcProperties ecProperties = setEc();
        KeyTypesProperties keyTypesProperties = setKeyTypes(rsaProperties, aesProperties, aesCtrProperties, ecProperties);

        securityProviderParams.setKeyTypes(keyTypesProperties);
        SecurityProviderParamsValidator sut = new SecurityProviderParamsValidator(securityProviderParams);

        //when-then
        Exception ex = assertThrows(JceSecurityProviderException.class, sut::validateParams);

        assertEquals(INVALID_VALUE + " " + "keyTypes.aes " + NOT_NULL, ex.getMessage());
    }

    @Test
    void securityProviderParams_nullAESCtr_throwException() {
        //given
        RsaProperties rsaProperties = setRsa();
        AesProperties aesProperties = setAes();
        AesCtrProperties aesCtrProperties = null;
        EcProperties ecProperties = setEc();
        KeyTypesProperties keyTypesProperties = setKeyTypes(rsaProperties, aesProperties, aesCtrProperties, ecProperties);

        securityProviderParams.setKeyTypes(keyTypesProperties);
        SecurityProviderParamsValidator sut = new SecurityProviderParamsValidator(securityProviderParams);

        //when-then
        Exception ex = assertThrows(JceSecurityProviderException.class, sut::validateParams);

        assertEquals(INVALID_VALUE + " " + "keyTypes.aesCtr " + NOT_NULL, ex.getMessage());
    }

    private void prepareSecurityProviderParams() {
        ProviderProperties providerProperties = new ProviderProperties();
        providerProperties.setName(generateUuidString());
        providerProperties.setFileBased(true);
        providerProperties.setClassName(generateUuidString());

        SecurityProperties securityProperties = new SecurityProperties();
        securityProperties.setKeyStoreName(generateUuidString());
        securityProperties.setPassword(generateUuidString());
        securityProperties.setInputStreamParam(generateUuidString());

        RsaProperties rsaProperties = setRsa();
        AesProperties aesProperties = setAes();
        AesCtrProperties aesCtrProperties = setAesCtr();
        EcProperties ecProperties = setEc();
        KeyTypesProperties keyTypesProperties = setKeyTypes(rsaProperties, aesProperties, aesCtrProperties, ecProperties);

        securityProviderParams.setProvider(providerProperties);
        securityProviderParams.setSecurity(securityProperties);
        securityProviderParams.setKeyTypes(keyTypesProperties);
    }

    private EcProperties setEc() {
        EcProperties ecProperties = new EcProperties();
        ecProperties.setKeyName(generateUuidString());
        ecProperties.setCurveSpec384(generateUuidString());
        ecProperties.setCurveSpec256(generateUuidString());
        ecProperties.setSignatureAlgorithm(generateUuidString());

        return ecProperties;
    }

    private RsaProperties setRsa() {
        RsaProperties rsaProperties = new RsaProperties();
        rsaProperties.setKeyName(generateUuidString());
        rsaProperties.setKeySize(1);
        rsaProperties.setCipherType(generateUuidString());
        rsaProperties.setSignatureAlgorithm(generateUuidString());

        return rsaProperties;
    }

    private AesProperties setAes() {
        AesProperties aesProperties = new AesProperties();
        aesProperties.setKeyName(generateUuidString());
        aesProperties.setKeySize(1);
        aesProperties.setCipherType(generateUuidString());

        return aesProperties;
    }

    private AesCtrProperties setAesCtr() {
        AesCtrProperties aesCtrProperties = new AesCtrProperties();
        aesCtrProperties.setKeyName(generateUuidString());
        aesCtrProperties.setKeySize(1);
        aesCtrProperties.setCipherType(generateUuidString());

        return aesCtrProperties;
    }

    private KeyTypesProperties setKeyTypes(RsaProperties rsaProperties, AesProperties aesProperties,
                                           AesCtrProperties aesCtrProperties, EcProperties ecProperties) {
        KeyTypesProperties keyTypesProperties = new KeyTypesProperties();
        keyTypesProperties.setRsa(rsaProperties);
        keyTypesProperties.setAes(aesProperties);
        keyTypesProperties.setAesCtr(aesCtrProperties);
        keyTypesProperties.setEc(ecProperties);

        return keyTypesProperties;
    }
}
