/*
 * This project is licensed as below.
 *
 * **************************************************************************
 *
 * Copyright 2020-2025 Altera Corporation. All Rights Reserved.
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

package com.intel.bkp.bkps.protocol.sigma;

import com.intel.bkp.crypto.ecdh.EcdhKeyPair;
import com.intel.bkp.test.FileUtils;
import com.intel.bkp.utils.ByteBufferSafe;
import lombok.SneakyThrows;

import java.security.PublicKey;

import static com.intel.bkp.utils.HexConverter.fromHex;

public class SigmaM2TestUtil {

    private static final int COMMAND_HEADER_LEN = 4;

    /*
    This method uses SigmaM2 generated during real (test environment) provisioning
    If command format and protocol changes at any time this test will probably fail
    If so, sigmaM2MessageTest.bin will have to be regenerated:
    1. Hardcode ECDH key in M1 generation based on the below EcdhKeyPair
    2. Add code that saves the received M2 message to bin file
    3. Uncomment mock-fw-data section in manifestfiller application.yml -> this will case to generate identical
        PUF Manifest with mocked data and private keys for S10 (PufAttestationKey) and FM (BKP key)
    4. Run all services and wait for synchronization to iPCS
    5. Run Quartus provisioning with options:
        --mockEcdhPub 9df974acd8969a0ab370e8b121079c404c542564eff9b56169d4d860a89ee5d0d9d797ebcddb78dcdfce561e35d50b43 \
        73498c8871a1a8b354ea6b0e534df9ea23b09fabbc54f69f9910bf68de30781531c8d8f474628bd4fc9b861ca4a2fad4
        --mockEcdhPriv 3fd79ca675ada68a885d1d8aa0cbb6d06365f9dbbf7ab646abaac03d6a1d177983fd0c0234d2d5d1f79b11b2f9e4b22f
    6. When Provisioning completes copy ~/BlackKeyProvisioning/SigmaM2Message.bin to test/resources/sigma
     */

    private static byte[] getRealSigmaM2S10() throws Exception {
        return loadFile("sigmaM2MessageTest_S10.bin");
    }

    private static byte[] getRealSigmaM2Fm() throws Exception {
        return loadFile("sigmaM2MessageTest_FM.bin");
    }

    private static byte[] loadFile(String filename) throws Exception {
        return FileUtils.readFromResources("sigma/", filename);
    }

    private static byte[] getRealSigmaM2WithoutHeader(byte[] realSigmaM2) {
        return ByteBufferSafe.wrap(realSigmaM2).skip(COMMAND_HEADER_LEN).getRemaining();
    }

    public static byte[] getRealSigmaM2WithoutHeaderS10() throws Exception {
        return getRealSigmaM2WithoutHeader(getRealSigmaM2S10());
    }

    public static byte[] getRealSigmaM2WithoutHeaderFm() throws Exception {
        return getRealSigmaM2WithoutHeader(getRealSigmaM2Fm());
    }

    @SneakyThrows
    public static PublicKey getPublicKeyMatchingRealSigmaM2() {
        final EcdhKeyPair keyPair = new EcdhKeyPair(
            fromHex("d10e6277bf7497a9e6c37437139847cc0d44bc900eb304a3cc7c441b38b39efc40f18368bf0ad0b987a51d9726586805"
                + "60f257ecf786b2ad4001a8a3ab174bd31bebeede556c06dfed0b1da97a80ac9d0ad040a8c4a6f919356df68eb3442d76"),
            fromHex("20e4002abcb67c4f528dba4148dd1b731b47e879397b8ff31cd30faaca8df1f0ecd1197b4370509f2b686b70c9cd0fec")
        );
        return keyPair.publicKey();
    }
}
