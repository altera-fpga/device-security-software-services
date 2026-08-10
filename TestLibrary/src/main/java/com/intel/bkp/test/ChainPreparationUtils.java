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

package com.intel.bkp.test;

import java.nio.ByteBuffer;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.List;

import static com.intel.bkp.test.FileUtils.loadCertificate;

public class ChainPreparationUtils {

    private static final String EFUSE_CHAIN_FOLDER = "dice/aliasEfuseSpdmChain/";
    private static final String IIDUDS_CHAIN_FOLDER = "dice/iidudsSpdmChain/";
    public static final String COMMON_PRE_FOLDER = "dice/common/pre/";
    private static final String FAMILY_CERT = "IPCS_agilex.cer";
    public static final String ROOT_CERT = "DICE_RootCA.cer";

    public static byte[] prepareEfuseChainAsBytes() {
        return prepareChainAsBytes(prepareEfuseChain());
    }

    public static List<X509Certificate> prepareEfuseChain() {
        final String folder = EFUSE_CHAIN_FOLDER;
        final X509Certificate aliasCert = loadCertificate(folder + "alias_01458210996be470_spdm.cer");
        final X509Certificate firmwareCert = loadCertificate(folder + "firmware_01458210996be470_spdm.cer");
        final X509Certificate deviceIdCert = loadCertificate(folder + "deviceId_01458210996be470_spdm.cer");
        final X509Certificate productFamilyCert = loadCertificate(COMMON_PRE_FOLDER + FAMILY_CERT);
        final X509Certificate rootCert = loadCertificate(COMMON_PRE_FOLDER + ROOT_CERT);
        return List.of(aliasCert, firmwareCert, deviceIdCert, productFamilyCert, rootCert);
    }

    public static byte[] prepareIidChainAsBytes() {
        return prepareChainAsBytes(prepareIidChain());
    }

    private static List<X509Certificate> prepareIidChain() {
        final String folder = IIDUDS_CHAIN_FOLDER;
        final X509Certificate aliasCert = loadCertificate(folder + "iiduds_alias_simulator.der");
        final X509Certificate ipcsIidudsCert = loadCertificate(folder + "ipcs_iiduds_simulator.der");
        final X509Certificate productFamilyCert = loadCertificate(COMMON_PRE_FOLDER + FAMILY_CERT);
        final X509Certificate rootCert = loadCertificate(COMMON_PRE_FOLDER + ROOT_CERT);
        return List.of(aliasCert, ipcsIidudsCert, productFamilyCert, rootCert);
    }


    private static byte[] prepareChainAsBytes(List<X509Certificate> chain) {
        return addAll(chain.stream().map(ChainPreparationUtils::getBytes).toList());
    }

    private static byte[] getBytes(X509Certificate cert) {
        try {
            return cert.getEncoded();
        } catch (CertificateEncodingException e) {
            throw new RuntimeException(e);
        }
    }

    private static byte[] addAll(List<byte[]> arrays) {
        final ByteBuffer buffer = ByteBuffer.allocate(arrays.stream().mapToInt(a -> a.length).sum());
        for (byte[] array : arrays) {
            buffer.put(array);
        }
        return buffer.array();
    }
}
