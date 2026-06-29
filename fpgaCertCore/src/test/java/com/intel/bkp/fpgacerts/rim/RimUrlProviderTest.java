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

package com.intel.bkp.fpgacerts.rim;

import com.intel.bkp.fpgacerts.dice.DiceChainMeasurementsCollector;
import com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfoKey;
import com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfoMeasurement;
import com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfoValue;
import com.intel.bkp.fpgacerts.url.DistributionPointAddressProvider;
import com.intel.bkp.test.ChainPreparationUtils;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;

import static java.util.stream.Collectors.toMap;
import static org.junit.jupiter.api.Assertions.assertEquals;

@ExtendWith(MockitoExtension.class)
class RimUrlProviderTest {

    private static final String IPCS_PATH = "ipcs/path/";
    private static final List<X509Certificate> REAL_CHAIN = ChainPreparationUtils.prepareEfuseChain();
    private static final Map<TcbInfoKey, TcbInfoValue> REAL_MEASUREMENTS = getMeasurements(REAL_CHAIN);
    private static final String CORIM_NAME = "agilex_L1_pKSlyFjsvCxayf-OxfvEtK6nyNGZ.corim"; // based on firmware cert

    private static Map<TcbInfoKey, TcbInfoValue> getMeasurements(List<X509Certificate> realChain) {
        return new DiceChainMeasurementsCollector().getMeasurementsFromCertChain(realChain)
            .stream().collect(toMap(TcbInfoMeasurement::getKey, TcbInfoMeasurement::getValue));
    }

    private final RimUrlProvider sut = new RimUrlProvider(new DistributionPointAddressProvider(IPCS_PATH));

    @Test
    void getRimUrl_Success() {
        // when
        final String result = sut.getRimUrl(REAL_CHAIN, REAL_MEASUREMENTS);

        // then
        assertEquals(IPCS_PATH + CORIM_NAME, result);
    }

}
