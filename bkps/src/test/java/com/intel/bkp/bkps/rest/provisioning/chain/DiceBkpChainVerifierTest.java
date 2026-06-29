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

import com.intel.bkp.bkps.exception.DeviceChainVerificationFailedException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.cert.X509CRL;
import java.util.Map;

import static com.intel.bkp.fpgacerts.model.Oid.KEY_PURPOSE_ATTEST_INIT;
import static com.intel.bkp.fpgacerts.model.Oid.KEY_PURPOSE_BKP;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
class DiceBkpChainVerifierTest {

    @Mock
    private Map<String, X509CRL> cachedCrls;
    private DiceBkpChainVerifier sutSpy;

    @BeforeEach
    void init() {
        sutSpy = spy(new DiceBkpChainVerifier(cachedCrls, new String[]{"diceRootHash"}, false));
    }

    @Test
    void getExpectedLeafCertKeyPurposes_ReturnsPurposeForBkpCertificate() {
        // given
        final String[] bkpCertificateKeyPurposes = new String[]{KEY_PURPOSE_BKP.getOid(),
            KEY_PURPOSE_ATTEST_INIT.getOid()};

        // when
        final String[] result = sutSpy.getExpectedLeafCertKeyPurposes();

        // then
        assertArrayEquals(bkpCertificateKeyPurposes, result);
    }

    @Test
    void withDeviceId_SetsDeviceIdInBaseClass() {
        // given
        final byte[] deviceId = new byte[]{0x01, 0x02};

        // when
        sutSpy.withDeviceId(deviceId);

        // then
        verify(sutSpy).setDeviceId(deviceId);
    }

    @Test
    void handleVerificationFailure_throwsDeviceChainVerificationFailedException() {
        // given
        final String failureDetails = "some details about why validation failed.";

        // when-then
        DeviceChainVerificationFailedException ex =
            assertThrows(DeviceChainVerificationFailedException.class,
                () -> sutSpy.handleVerificationFailure(failureDetails));

        // then
        assertTrue(ex.getMessage().contains(failureDetails));
    }
}
