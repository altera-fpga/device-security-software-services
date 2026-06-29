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

package com.intel.bkp.bkps.rest.provisioning.chain;

import com.intel.bkp.bkps.config.ApplicationProperties;
import com.intel.bkp.bkps.exception.DeviceChainVerificationFailedException;
import com.intel.bkp.core.properties.DistributionPoint;
import com.intel.bkp.fpgacerts.dice.iidutils.IidFlowDetector;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class CertificateChainVerifierTest {

    private static final String DEVICE_ID_HEX = "010203";
    private static final byte[] DEVICE_ID = new byte[]{0x01, 0x02, 0x03};
    private static final String S10_ROOT_HASH = "s10RootHash";
    private static final String DICE_ROOT_HASH = "diceRootHash";
    private static final String[] TRUSTED_ROOT_HASH = new String[]{S10_ROOT_HASH, DICE_ROOT_HASH};
    private static final LinkedList<X509Certificate> certificates = new LinkedList<>();
    private static final LinkedList<X509Certificate> iidCertificates = new LinkedList<>();
    private static final Map<String, X509CRL> cachedCrls = new LinkedHashMap<>();
    private static final boolean TEST_MODE_SECRETS = true;

    private static CertificateChainDTO chainDTO;
    private static X509Certificate firstEfuseChainCert;

    @Mock
    private DiceBkpChainVerifier diceBkpChainVerifier;

    @Mock
    private S10BkpChainVerifier s10BkpChainVerifier;

    @Mock
    private DistributionPoint dp;

    @Mock
    private ApplicationProperties applicationProperties;

    @Mock
    private IidFlowDetector iidFlowDetector;

    @Spy
    @InjectMocks
    private CertificateChainVerifier sutSpy;

    @BeforeAll
    static void init() {
        chainDTO = new CertificateChainDTO(certificates, iidCertificates, cachedCrls);
        firstEfuseChainCert = mock(X509Certificate.class);
    }

    @Test
    void verifyDiceChain_WithEfuseChain_NoIidChain_requireIidUdsFalse_Success() {
        // given
        final boolean requireIidUds = false;
        final boolean isAgilex = true;
        mockTrustedRootHash();
        mockCreateDiceBkpChainVerifier();
        when(diceBkpChainVerifier.withDeviceId(DEVICE_ID)).thenReturn(diceBkpChainVerifier);
        mockEfuseChainExists();
        mockIsIidChainRequired(requireIidUds, isAgilex);
        mockIidChainDoesNotExist();

        // when
        sutSpy.verifyDiceChain(DEVICE_ID_HEX, chainDTO, requireIidUds, TEST_MODE_SECRETS);

        // then
        verify(diceBkpChainVerifier).verifyChain(certificates);
        verifyNoMoreInteractions(diceBkpChainVerifier);
    }

    @Test
    void verifyDiceChain_WithEfuseChain_NoIidChain_requireIidUdsTrue_Agilex_Throws() {
        // given
        final boolean requireIidUds = true;
        final boolean isAgilex = true;
        mockTrustedRootHash();
        mockCreateDiceBkpChainVerifier();
        when(diceBkpChainVerifier.withDeviceId(DEVICE_ID)).thenReturn(diceBkpChainVerifier);
        mockEfuseChainExists();
        mockIsIidChainRequired(requireIidUds, isAgilex);
        mockIidChainDoesNotExist();

        // when
        final var ex = assertThrows(DeviceChainVerificationFailedException.class,
            () -> sutSpy.verifyDiceChain(DEVICE_ID_HEX, chainDTO, requireIidUds, TEST_MODE_SECRETS));

        // then
        verify(diceBkpChainVerifier).verifyChain(certificates);
        assertTrue(ex.getMessage().contains("Required IID UDS chain does not exist and cannot be verified."));
    }

    @Test
    void verifyDiceChain_WithEfuseChain_NoIidChain_requireIidUdsTrue_NotAgilex_Success() {
        // given
        final boolean requireIidUds = true;
        final boolean isAgilex = false;
        mockTrustedRootHash();
        mockCreateDiceBkpChainVerifier();
        when(diceBkpChainVerifier.withDeviceId(DEVICE_ID)).thenReturn(diceBkpChainVerifier);
        mockEfuseChainExists();
        mockIsIidChainRequired(requireIidUds, isAgilex);
        mockIidChainDoesNotExist();

        // when
        sutSpy.verifyDiceChain(DEVICE_ID_HEX, chainDTO, requireIidUds, TEST_MODE_SECRETS);

        // then
        verify(diceBkpChainVerifier).verifyChain(certificates);
        verifyNoMoreInteractions(diceBkpChainVerifier);
    }

    @Test
    void verifyDiceChain_WithEfuseChain_WithIidChain_requireIidUdsTrue_Success() {
        // given
        final boolean requireIidUds = true;
        final boolean isAgilex = true;
        mockTrustedRootHash();
        mockCreateDiceBkpChainVerifier();
        when(diceBkpChainVerifier.withDeviceId(DEVICE_ID)).thenReturn(diceBkpChainVerifier);
        mockEfuseChainExists();
        mockIsIidChainRequired(requireIidUds, isAgilex);
        mockIidChainExists();

        // when
        sutSpy.verifyDiceChain(DEVICE_ID_HEX, chainDTO, requireIidUds, TEST_MODE_SECRETS);

        // then
        verify(diceBkpChainVerifier).verifyChain(certificates);
        verify(diceBkpChainVerifier).verifyChain(iidCertificates);
    }

    @Test
    void verifyDiceChain_WithEfuseChain_WithIidChain_requireIidUdsFalse_Success() {
        // given
        final boolean requireIidUds = false;
        final boolean isAgilex = true;
        mockTrustedRootHash();
        mockCreateDiceBkpChainVerifier();
        when(diceBkpChainVerifier.withDeviceId(DEVICE_ID)).thenReturn(diceBkpChainVerifier);
        mockEfuseChainExists();
        mockIsIidChainRequired(requireIidUds, isAgilex);
        mockIidChainExists();

        // when
        sutSpy.verifyDiceChain(DEVICE_ID_HEX, chainDTO, requireIidUds, TEST_MODE_SECRETS);

        // then
        verify(diceBkpChainVerifier).verifyChain(certificates);
        verifyNoMoreInteractions(diceBkpChainVerifier);
    }

    @Test
    void verifyDiceChain_NoEfuseChain_Throws() {
        // given
        final boolean requireIidUds = true;
        mockTrustedRootHash();
        mockCreateDiceBkpChainVerifier();
        when(diceBkpChainVerifier.withDeviceId(DEVICE_ID)).thenReturn(diceBkpChainVerifier);
        mockEfuseChainDoesNotExist();
        mockIidChainExists();

        // when
        final var ex = assertThrows(DeviceChainVerificationFailedException.class,
            () -> sutSpy.verifyDiceChain(DEVICE_ID_HEX, chainDTO, requireIidUds, TEST_MODE_SECRETS));

        // then
        verifyNoMoreInteractions(diceBkpChainVerifier);
        assertTrue(ex.getMessage().contains("Required EFUSE UDS chain does not exist and cannot be verified."));
    }

    @Test
    void verifyS10Chain_Success() {
        // given
        mockTrustedRootHash();
        mockCreateS10BkpChainVerifier();
        when(s10BkpChainVerifier.withDeviceId(DEVICE_ID)).thenReturn(s10BkpChainVerifier);

        // when
        sutSpy.verifyS10Chain(DEVICE_ID_HEX, chainDTO);

        // then
        verify(s10BkpChainVerifier).verifyChain(certificates);
        verifyNoMoreInteractions(s10BkpChainVerifier);
    }

    private void mockTrustedRootHash() {
        when(applicationProperties.getDistributionPoint()).thenReturn(dp);
        when(dp.getTrustedRootHash()).thenReturn(TRUSTED_ROOT_HASH);
    }

    private void mockCreateDiceBkpChainVerifier() {
        when(sutSpy.createDiceBkpChainVerifier(cachedCrls, new String[]{S10_ROOT_HASH, DICE_ROOT_HASH},
            TEST_MODE_SECRETS))
            .thenReturn(diceBkpChainVerifier);
    }

    private void mockCreateS10BkpChainVerifier() {
        when(sutSpy.createS10BkpChainVerifier(cachedCrls, new String[]{S10_ROOT_HASH, DICE_ROOT_HASH}))
            .thenReturn(s10BkpChainVerifier);
    }

    private void mockIsIidChainRequired(boolean requireIidUds, boolean isAgilex) {
        when(iidFlowDetector.withRequireIidUds(requireIidUds)).thenReturn(iidFlowDetector);
        when(iidFlowDetector.isIidFlow(firstEfuseChainCert)).thenReturn(requireIidUds && isAgilex);
    }

    private void mockEfuseChainExists() {
        certificates.add(firstEfuseChainCert);
        certificates.add(mock(X509Certificate.class));
    }

    private void mockEfuseChainDoesNotExist() {
        certificates.clear();
    }

    private void mockIidChainExists() {
        iidCertificates.add(mock(X509Certificate.class));
    }

    private void mockIidChainDoesNotExist() {
        iidCertificates.clear();
    }
}
