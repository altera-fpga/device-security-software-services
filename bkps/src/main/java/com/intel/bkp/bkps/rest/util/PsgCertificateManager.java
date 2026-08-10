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

package com.intel.bkp.bkps.rest.util;

import com.intel.bkp.bkps.exception.InitializationServiceException;
import com.intel.bkp.bkps.exception.PsgCertificateInvalidPermissionsException;
import com.intel.bkp.bkps.rest.errors.enums.ErrorCodeMap;
import com.intel.bkp.core.exceptions.BKPBadRequestException;
import com.intel.bkp.core.exceptions.PublicKeyHelperException;
import com.intel.bkp.core.psgcertificate.PsgCertificateEntryBuilder;
import com.intel.bkp.core.psgcertificate.PsgCertificateHelper;
import com.intel.bkp.core.psgcertificate.PsgPublicKeyHelper;
import com.intel.bkp.core.psgcertificate.exceptions.PsgCertificateChainWrongSizeException;
import com.intel.bkp.core.psgcertificate.exceptions.PsgInvalidLeafCertificateException;
import com.intel.bkp.core.psgcertificate.exceptions.PsgInvalidRootCertificateException;
import com.intel.bkp.core.psgcertificate.exceptions.PsgInvalidSignatureException;
import com.intel.bkp.core.psgcertificate.model.CertificateEntryWrapper;
import com.intel.bkp.core.psgcertificate.model.PsgPermissions;
import com.intel.bkp.core.utils.ModifyBitsBuilder;
import com.intel.bkp.utils.MaskHelper;

import java.security.interfaces.ECPublicKey;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;

import static com.intel.bkp.utils.ByteConverter.toBytes;

public class PsgCertificateManager extends PsgCertificateHelper {

    public void verifyChainListSize(List<CertificateEntryWrapper> certificateChainList) {
        try {
            verifyChainListSizeInternal(certificateChainList);
        } catch (PsgCertificateChainWrongSizeException e) {
            throw new InitializationServiceException(ErrorCodeMap.CERTIFICATE_CHAIN_WRONG_SIZE);
        }
    }

    public void verifyRootCertificate(List<CertificateEntryWrapper> certificateChainList, byte[] rootCertificate) {
        try {
            verifyRootCertificateInternal(certificateChainList, rootCertificate);
        } catch (PsgCertificateChainWrongSizeException e) {
            throw new InitializationServiceException(ErrorCodeMap.CERTIFICATE_CHAIN_WRONG_SIZE);
        } catch (PsgInvalidRootCertificateException e) {
            throw new InitializationServiceException(ErrorCodeMap.ROOT_CERTIFICATE_IS_INCORRECT);
        } catch (PublicKeyHelperException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public void verifyParentsInChainByPubKey(List<CertificateEntryWrapper> certificateChainList) {
        Iterator<CertificateEntryWrapper> certificateChainIterator = certificateChainList.iterator();
        if (certificateChainIterator.hasNext()) {
            try {
                if (!verifyParentsByPubKeyRecursive(certificateChainIterator.next(), certificateChainIterator)) {
                    throw new InitializationServiceException(ErrorCodeMap.PARENT_CERTIFICATES_DO_NOT_MATCH);
                }
            } catch (PsgInvalidSignatureException e) {
                throw new BKPBadRequestException(ErrorCodeMap.PSG_CERTIFICATE_EXCEPTION, e);
            }
        }
    }

    public void verifyLeafCertificatePermissions(List<CertificateEntryWrapper> chainList) {
        final PsgCertificateEntryBuilder leafCertificateInChain = getLeafCert(chainList);
        verifyPermissionsMask(leafCertificateInChain.getPsgPublicKeyBuilder().getPublicKeyPermissions());
    }

    public void verifyLeafCertificateMatchesSigningKeyPub(List<CertificateEntryWrapper> chainList, ECPublicKey pubKey) throws PublicKeyHelperException {
        final PsgCertificateEntryBuilder leafCertificateInChain = getLeafCert(chainList);

        if (!PsgPublicKeyHelper.from(leafCertificateInChain.getPsgPublicKeyBuilder()).areEqual(pubKey)) {
            throw new InitializationServiceException(ErrorCodeMap.PUBLIC_KEY_IN_CERTIFICATE_DOES_NOT_MATCH);
        }
    }

    private PsgCertificateEntryBuilder getLeafCert(List<CertificateEntryWrapper> chainList) {
        final PsgCertificateEntryBuilder leafCertificateInChain;
        try {
            leafCertificateInChain = findLeafCertificateInChain(chainList);
        } catch (PsgCertificateChainWrongSizeException e) {
            throw new InitializationServiceException(ErrorCodeMap.CERTIFICATE_CHAIN_WRONG_SIZE);
        } catch (PsgInvalidLeafCertificateException e) {
            throw new InitializationServiceException(ErrorCodeMap.LEAF_CERTIFICATE_IS_INCORRECT);
        }
        return leafCertificateInChain;
    }

    private void verifyPermissionsMask(int permissions) {
        final byte[] mask = toBytes(
            ModifyBitsBuilder.fromNone().set(PsgPermissions.SIGN_BKP_DH.getBitPosition()).build()
        );

        final byte[] maskedValue;
        try {
            maskedValue = MaskHelper.applyMask(toBytes(permissions), mask);
        } catch (MaskHelper.MismatchedMaskLengthException invalidMaskLengthException) {
            throw new PsgCertificateInvalidPermissionsException();
        }

        if (!Arrays.equals(maskedValue, mask)) {
            throw new PsgCertificateInvalidPermissionsException();
        }
    }
}
