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

package com.intel.bkp.bkps.rest.util;

import com.intel.bkp.bkps.exception.InitializationServiceException;
import com.intel.bkp.bkps.rest.errors.enums.ErrorCodeMap;
import com.intel.bkp.core.exceptions.BKPBadRequestException;
import com.intel.bkp.core.exceptions.PublicKeyHelperException;
import com.intel.bkp.core.psgcertificate.PsgCertificateEntry;
import com.intel.bkp.core.psgcertificate.PsgCertificateEntryBuilder;
import com.intel.bkp.core.psgcertificate.PsgCertificateHelper;
import com.intel.bkp.core.psgcertificate.PsgCertificateRootEntryBuilder;
import com.intel.bkp.core.psgcertificate.PsgPublicKeyBuilder;
import com.intel.bkp.core.psgcertificate.PsgSignatureBuilder;
import com.intel.bkp.core.psgcertificate.exceptions.PsgCertificateChainWrongSizeException;
import com.intel.bkp.core.psgcertificate.exceptions.PsgInvalidRootCertificateException;
import com.intel.bkp.core.psgcertificate.exceptions.PsgInvalidSignatureException;
import com.intel.bkp.core.psgcertificate.model.CertificateEntryWrapper;
import com.intel.bkp.core.psgcertificate.model.PsgCertificateType;
import com.intel.bkp.core.psgcertificate.model.PsgCurveType;
import com.intel.bkp.core.psgcertificate.model.PsgPermissions;
import com.intel.bkp.core.psgcertificate.model.PsgPublicKeyMagic;
import com.intel.bkp.core.psgcertificate.model.PsgSignatureCurveType;
import com.intel.bkp.core.utils.ModifyBitsBuilder;
import com.intel.bkp.crypto.CryptoUtils;
import com.intel.bkp.crypto.constants.CryptoConstants;
import com.intel.bkp.crypto.exceptions.KeystoreGenericException;
import com.intel.bkp.test.KeyGenUtils;
import com.intel.bkp.test.SigningUtils;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.KeyPair;
import java.security.interfaces.ECPublicKey;
import java.util.LinkedList;
import java.util.List;

import static com.intel.bkp.core.psgcertificate.model.PsgSignatureCurveType.SECP384R1;
import static com.intel.bkp.test.AssertionUtils.verifyExpectedErrorCode;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.spy;

@ExtendWith(MockitoExtension.class)
public class PsgCertificateManagerTest {

    private final PsgCertificateManager sut = new PsgCertificateManager();

    @Test
    void prepareCertChain_MatchesSigKey_Success() throws KeystoreGenericException {
        // given
        final KeyPair bkpsSigningKey = preparePublicKey();
        List<CertificateEntryWrapper> certificateChainList = prepareCertChain(bkpsSigningKey);

        // when-then
        assertDoesNotThrow(
            () -> sut.verifyLeafCertificateMatchesSigningKeyPub(certificateChainList,
                (ECPublicKey) bkpsSigningKey.getPublic())
        );
    }

    @Test
    void prepareCertChain_DoesNotMatchSigKey_ThrowsException() throws KeystoreGenericException {
        // given
        final KeyPair bkpsSigningKey = preparePublicKey();
        final KeyPair differentSigningKey = preparePublicKey();
        List<CertificateEntryWrapper> certificateChainList = prepareCertChain(bkpsSigningKey);

        // when-then
        final InitializationServiceException exception = assertThrows(InitializationServiceException.class,
            () -> sut.verifyLeafCertificateMatchesSigningKeyPub(certificateChainList,
                (ECPublicKey) differentSigningKey.getPublic())
        );

        // then
        verifyExpectedErrorCode(exception, ErrorCodeMap.PUBLIC_KEY_IN_CERTIFICATE_DOES_NOT_MATCH);
    }

    @Test
    void verifyChainListSize_withOneCertificate_throwsException() {
        // given
        List<CertificateEntryWrapper> certificateChainList = new LinkedList<>();
        certificateChainList.add(new CertificateEntryWrapper(PsgCertificateType.ROOT, new byte[4]));

        // when-then
        final InitializationServiceException exception = assertThrows(InitializationServiceException.class,
            () -> sut.verifyChainListSize(certificateChainList)
        );

        // then
        verifyExpectedErrorCode(exception, ErrorCodeMap.CERTIFICATE_CHAIN_WRONG_SIZE);
    }

    @Test
    void verifyChainListSize_withFourCertificates_throwsException() {
        // given
        List<CertificateEntryWrapper> certificateChainList = new LinkedList<>();
        certificateChainList.add(new CertificateEntryWrapper(PsgCertificateType.LEAF, new byte[4]));
        certificateChainList.add(new CertificateEntryWrapper(PsgCertificateType.LEAF, new byte[4]));
        certificateChainList.add(new CertificateEntryWrapper(PsgCertificateType.LEAF, new byte[4]));
        certificateChainList.add(new CertificateEntryWrapper(PsgCertificateType.ROOT, new byte[4]));

        // when-then
        final InitializationServiceException exception = assertThrows(InitializationServiceException.class,
            () -> sut.verifyChainListSize(certificateChainList)
        );

        // then
        verifyExpectedErrorCode(exception, ErrorCodeMap.CERTIFICATE_CHAIN_WRONG_SIZE);
    }

    @Test
    void verifyChainListSize_withThreeCertificatesAndTwoRootCerts_throwsException() {
        // given
        List<CertificateEntryWrapper> certificateChainList = new LinkedList<>();
        certificateChainList.add(new CertificateEntryWrapper(PsgCertificateType.LEAF, new byte[4]));
        certificateChainList.add(new CertificateEntryWrapper(PsgCertificateType.ROOT, new byte[4]));
        certificateChainList.add(new CertificateEntryWrapper(PsgCertificateType.ROOT, new byte[4]));

        // when-then
        final InitializationServiceException exception = assertThrows(InitializationServiceException.class,
            () -> sut.verifyChainListSize(certificateChainList)
        );

        // then
        verifyExpectedErrorCode(exception, ErrorCodeMap.CERTIFICATE_CHAIN_WRONG_SIZE);
    }

    @Test
    void verifyChainListSize_notThrowsAnything() {
        // given
        List<CertificateEntryWrapper> certificateChainList = new LinkedList<>();
        certificateChainList.add(new CertificateEntryWrapper(PsgCertificateType.LEAF, new byte[4]));
        certificateChainList.add(new CertificateEntryWrapper(PsgCertificateType.ROOT, new byte[4]));

        // when
        assertDoesNotThrow(() -> sut.verifyChainListSize(certificateChainList));
    }

    @Test
    void verifyRootCertificate_notThrowsAnything() {
        // given
        KeyPair rootKeyPair = KeyGenUtils.genEc384();
        assert rootKeyPair != null;
        List<CertificateEntryWrapper> certificateChainList = new LinkedList<>();
        byte[] rootContent = new PsgCertificateRootEntryBuilder()
            .publicKey(getPsgPublicKeyBuilder(rootKeyPair, PsgCurveType.SECP384R1))
            .build()
            .array();
        certificateChainList.add(new CertificateEntryWrapper(PsgCertificateType.LEAF, new byte[4]));
        certificateChainList.add(new CertificateEntryWrapper(PsgCertificateType.ROOT, rootContent));

        // when
        assertDoesNotThrow(() -> sut.verifyChainListSize(certificateChainList));
    }

    @Test
    void verifyRootCertificate_withNoRootCert_throwsException() {
        // given
        List<CertificateEntryWrapper> certificateChainList = new LinkedList<>();
        certificateChainList.add(new CertificateEntryWrapper(PsgCertificateType.LEAF, new byte[4]));

        // when-then
        final InitializationServiceException exception = assertThrows(InitializationServiceException.class,
            () -> sut.verifyRootCertificate(certificateChainList, new byte[4])
        );

        // then
        verifyExpectedErrorCode(exception, ErrorCodeMap.CERTIFICATE_CHAIN_WRONG_SIZE);
    }

    @Test
    void verifyRootCertificate_withInvalidCert_throwsException()
        throws PsgCertificateChainWrongSizeException, PsgInvalidRootCertificateException, PublicKeyHelperException {
        // given
        List<CertificateEntryWrapper> certificateChainList = new LinkedList<>();
        certificateChainList.add(new CertificateEntryWrapper(PsgCertificateType.LEAF, new byte[4]));
        PsgCertificateManager spy = spy(sut);
        doThrow(PsgInvalidRootCertificateException.class).when(spy).verifyRootCertificateInternal(any(), any());

        // when-then
        final BKPBadRequestException exception = assertThrows(BKPBadRequestException.class,
            () -> spy.verifyRootCertificate(certificateChainList, new byte[4])
        );

        // then
        verifyExpectedErrorCode(exception, ErrorCodeMap.ROOT_CERTIFICATE_IS_INCORRECT);
    }

    @Test
    void verifyRootCertificate_withIncorrectCert_throwsException() {
        // given
        KeyPair rootKeyPair = KeyGenUtils.genEc384();
        KeyPair leafKeyPair = KeyGenUtils.genEc384();
        assert rootKeyPair != null;
        assert leafKeyPair != null;
        List<CertificateEntryWrapper> certificateChainList = new LinkedList<>();
        byte[] rootContent = new PsgCertificateRootEntryBuilder()
            .publicKey(getPsgPublicKeyBuilder(rootKeyPair, PsgCurveType.SECP384R1))
            .build()
            .array();
        certificateChainList.add(new CertificateEntryWrapper(PsgCertificateType.ROOT, rootContent));
        byte[] wrongRootContent = new PsgCertificateRootEntryBuilder()
            .publicKey(getPsgPublicKeyBuilder(leafKeyPair, PsgCurveType.SECP384R1))
            .build()
            .array();

        // when-then
        final InitializationServiceException exception = assertThrows(InitializationServiceException.class,
            () -> sut.verifyRootCertificate(certificateChainList, wrongRootContent)
        );

        // then
        verifyExpectedErrorCode(exception, ErrorCodeMap.ROOT_CERTIFICATE_IS_INCORRECT);

    }

    @Test
    void verifyParentsInChainByPubKey_succeedsIfNoError() {
        // given
        KeyPair rootKeyPair = KeyGenUtils.genEc384();
        KeyPair leafKeyPair = KeyGenUtils.genEc384();
        KeyPair leafSecondKeyPair = KeyGenUtils.genEc384();

        assert rootKeyPair != null;
        assert leafKeyPair != null;
        assert leafSecondKeyPair != null;

        List<CertificateEntryWrapper> certificateChainList = new LinkedList<>();

        byte[] rootContent = new PsgCertificateRootEntryBuilder()
            .publicKey(getPsgPublicKeyBuilder(rootKeyPair, PsgCurveType.SECP384R1))
            .build()
            .array();
        certificateChainList.add(new CertificateEntryWrapper(PsgCertificateType.ROOT, rootContent));

        byte[] leafContent = new PsgCertificateEntryBuilder()
            .withSignature(getPsgSignatureBuilder(SECP384R1))
            .publicKey(getPsgPublicKeyBuilder(leafKeyPair, PsgCurveType.SECP384R1))
            .signData(dataToSign -> SigningUtils.signEcData(
                    dataToSign, rootKeyPair.getPrivate(), CryptoConstants.SHA384_WITH_ECDSA),
                SECP384R1
            )
            .build()
            .array();
        certificateChainList.add(new CertificateEntryWrapper(PsgCertificateType.LEAF, leafContent));

        byte[] leafSecondContent = new PsgCertificateEntryBuilder()
            .withSignature(getPsgSignatureBuilder(SECP384R1))
            .publicKey(getPsgPublicKeyBuilder(leafSecondKeyPair, PsgCurveType.SECP384R1))
            .signData(dataToSign -> SigningUtils.signEcData(
                    dataToSign, leafKeyPair.getPrivate(), CryptoConstants.SHA384_WITH_ECDSA),
                SECP384R1
            )
            .build()
            .array();
        certificateChainList.add(new CertificateEntryWrapper(PsgCertificateType.LEAF, leafSecondContent));

        // when
        sut.verifyParentsInChainByPubKey(certificateChainList);
    }

    @Test
    void verifyParentsInChainByPubKey_withInvalidParent_throwException() {
        // given
        KeyPair rootKeyPair = KeyGenUtils.genEc384();
        KeyPair leafKeyPair = KeyGenUtils.genEc384();
        assert rootKeyPair != null;
        assert leafKeyPair != null;

        List<CertificateEntryWrapper> certificateChainList = new LinkedList<>();
        byte[] leafContent = new PsgCertificateEntryBuilder()
            .withSignature(getPsgSignatureBuilder(SECP384R1))
            .publicKey(getPsgPublicKeyBuilder(leafKeyPair, PsgCurveType.SECP384R1))
            .signData(dataToSign -> SigningUtils.signEcData(
                    dataToSign, leafKeyPair.getPrivate(), CryptoConstants.SHA384_WITH_ECDSA),
                SECP384R1
            )
            .build()
            .array();
        certificateChainList.add(new CertificateEntryWrapper(PsgCertificateType.LEAF, leafContent));

        byte[] rootContent = new PsgCertificateRootEntryBuilder()
            .publicKey(getPsgPublicKeyBuilder(rootKeyPair, PsgCurveType.SECP384R1))
            .build()
            .array();
        certificateChainList.add(new CertificateEntryWrapper(PsgCertificateType.ROOT, rootContent));

        // when-then
        final InitializationServiceException exception = assertThrows(InitializationServiceException.class,
            () -> sut.verifyParentsInChainByPubKey(certificateChainList)
        );

        // then
        verifyExpectedErrorCode(exception, ErrorCodeMap.PARENT_CERTIFICATES_DO_NOT_MATCH);
    }

    @Test
    void verifyParentsInChainByPubKey_withWrongSignature_throwException()
        throws PsgInvalidSignatureException {
        // given
        PsgCertificateHelper spy = spy(sut);
        doThrow(new PsgInvalidSignatureException("test", new Exception())).when(spy).sigVerify(any(), any());
        KeyPair rootKeyPair = KeyGenUtils.genEc384();
        KeyPair leafKeyPair = KeyGenUtils.genEc384();

        assert rootKeyPair != null;
        assert leafKeyPair != null;
        List<CertificateEntryWrapper> certificateChainList = new LinkedList<>();
        byte[] leafContent = new PsgCertificateEntryBuilder()
            .withSignature(getPsgSignatureBuilder(SECP384R1))
            .publicKey(getPsgPublicKeyBuilder(leafKeyPair, PsgCurveType.SECP384R1))
            .signData(dataToSign -> SigningUtils.signEcData(
                    dataToSign, leafKeyPair.getPrivate(), CryptoConstants.SHA384_WITH_ECDSA),
                SECP384R1
            )
            .build()
            .array();
        certificateChainList.add(new CertificateEntryWrapper(PsgCertificateType.LEAF, leafContent));

        byte[] rootContent = new PsgCertificateRootEntryBuilder()
            .publicKey(getPsgPublicKeyBuilder(rootKeyPair, PsgCurveType.SECP384R1))
            .build()
            .array();
        certificateChainList.add(new CertificateEntryWrapper(PsgCertificateType.ROOT, rootContent));

        // when-then
        final BKPBadRequestException exception = assertThrows(BKPBadRequestException.class,
            () -> spy.verifyParentsInChainByPubKey(certificateChainList)
        );

        // then
        verifyExpectedErrorCode(exception, ErrorCodeMap.PSG_CERTIFICATE_EXCEPTION);
    }

    @Test
    void verifyParentsInChainByPubKey_withInvalidCert_throwsException()
        throws PsgInvalidSignatureException {
        // given
        List<CertificateEntryWrapper> certificateChainList = new LinkedList<>();
        certificateChainList.add(new CertificateEntryWrapper(PsgCertificateType.LEAF, new byte[4]));
        PsgCertificateManager spy = spy(sut);
        doThrow(new PsgInvalidSignatureException("test")).when(spy).verifyParentsByPubKeyRecursive(any(), any());

        // when-then
        final BKPBadRequestException exception = assertThrows(BKPBadRequestException.class,
            () -> spy.verifyParentsInChainByPubKey(certificateChainList)
        );

        // then
        verifyExpectedErrorCode(exception, ErrorCodeMap.PSG_CERTIFICATE_EXCEPTION);
    }

    @Test
    void verifyLeafCertificatePermissions_Success() {
        // given
        KeyPair leafKeyPair = KeyGenUtils.genEc384();
        assert leafKeyPair != null;
        byte[] leafContent = new PsgCertificateEntryBuilder()
            .publicKey(getPsgPublicKeyBuilder(leafKeyPair, PsgCurveType.SECP384R1))
            .withBkpPermissions()
            .withNoCancellationId()
            .withSignature(getPsgSignatureBuilder(SECP384R1))
            .signData(dataToSign -> SigningUtils.signEcData(
                    dataToSign, leafKeyPair.getPrivate(), CryptoConstants.SHA384_WITH_ECDSA),
                SECP384R1
            )
            .build()
            .array();
        List<CertificateEntryWrapper> certificateChainList = new LinkedList<>();
        certificateChainList.add(new CertificateEntryWrapper(PsgCertificateType.LEAF, leafContent));

        // when
        sut.verifyLeafCertificatePermissions(certificateChainList);
    }

    @Test
    void verifyLeafCertificatePermissions_WithNotExclusiveBkpsPermission_Success() {
        // given
        KeyPair leafKeyPair = KeyGenUtils.genEc384();
        assert leafKeyPair != null;
        byte[] leafContent = new PsgCertificateEntryBuilder()
            .publicKey(getPsgPublicKeyBuilder(leafKeyPair, PsgCurveType.SECP384R1))
            .withPermissions(
                getPermissions(ModifyBitsBuilder.fromNone().set(PsgPermissions.SIGN_BKP_DH.getBitPosition()))
            )
            .withNoCancellationId()
            .withSignature(getPsgSignatureBuilder(SECP384R1))
            .signData(dataToSign -> SigningUtils.signEcData(
                    dataToSign, leafKeyPair.getPrivate(), CryptoConstants.SHA384_WITH_ECDSA),
                SECP384R1
            )
            .build()
            .array();
        List<CertificateEntryWrapper> certificateChainList = new LinkedList<>();
        certificateChainList.add(new CertificateEntryWrapper(PsgCertificateType.LEAF, leafContent));

        // when
        sut.verifyLeafCertificatePermissions(certificateChainList);
    }

    @Test
    void verifyLeafCertificatePermissions_WithNonBkpsPermission_Success() {
        // given
        KeyPair leafKeyPair = KeyGenUtils.genEc384();
        assert leafKeyPair != null;
        byte[] leafContent = new PsgCertificateEntryBuilder()
            .publicKey(getPsgPublicKeyBuilder(leafKeyPair, PsgCurveType.SECP384R1))
            .withPermissions(getPermissions(ModifyBitsBuilder.fromNone()))
            .withNoCancellationId()
            .withSignature(getPsgSignatureBuilder(SECP384R1))
            .signData(dataToSign -> SigningUtils.signEcData(
                    dataToSign, leafKeyPair.getPrivate(), CryptoConstants.SHA384_WITH_ECDSA),
                SECP384R1
            )
            .build()
            .array();
        List<CertificateEntryWrapper> certificateChainList = new LinkedList<>();
        certificateChainList.add(new CertificateEntryWrapper(PsgCertificateType.LEAF, leafContent));

        // when-then
        final BKPBadRequestException exception = assertThrows(BKPBadRequestException.class,
            () -> sut.verifyLeafCertificatePermissions(certificateChainList)
        );

        // then
        verifyExpectedErrorCode(exception, ErrorCodeMap.PSG_CERTIFICATE_INVALID_PERMISSIONS);
    }

    @Test
    void verifyLeafCertificatePermissions_WithWrongPermissions_ThrowsException() {
        // given
        KeyPair leafKeyPair = KeyGenUtils.genEc384();
        assert leafKeyPair != null;
        byte[] leafContent = new PsgCertificateEntryBuilder()
            .withSignature(getPsgSignatureBuilder(SECP384R1))
            .publicKey(getPsgPublicKeyBuilder(leafKeyPair, PsgCurveType.SECP384R1))
            .signData(dataToSign -> SigningUtils.signEcData(
                    dataToSign, leafKeyPair.getPrivate(), CryptoConstants.SHA384_WITH_ECDSA),
                SECP384R1
            )
            .build()
            .array();
        List<CertificateEntryWrapper> certificateChainList = new LinkedList<>();
        certificateChainList.add(new CertificateEntryWrapper(PsgCertificateType.LEAF, leafContent));

        // when-then
        final BKPBadRequestException exception = assertThrows(BKPBadRequestException.class,
            () -> sut.verifyLeafCertificatePermissions(certificateChainList)
        );

        // then
        verifyExpectedErrorCode(exception, ErrorCodeMap.PSG_CERTIFICATE_INVALID_PERMISSIONS);
    }

    @Test
    void verifyLeafCertificatePermissions_WithNoLeaf_ThrowsException() {
        // given
        List<CertificateEntryWrapper> certificateChainList = new LinkedList<>();

        // when-then
        final BKPBadRequestException exception = assertThrows(BKPBadRequestException.class,
            () -> sut.verifyLeafCertificatePermissions(certificateChainList)
        );

        // then
        verifyExpectedErrorCode(exception, ErrorCodeMap.CERTIFICATE_CHAIN_WRONG_SIZE);
    }

    @Test
    void verifyLeafCertificatePermissions_WithInvalidLeaf_ThrowsException() {
        // given
        List<CertificateEntryWrapper> certificateChainList = new LinkedList<>();
        certificateChainList.add(new CertificateEntryWrapper(PsgCertificateType.LEAF, new byte[4]));

        // when-then
        final BKPBadRequestException exception = assertThrows(BKPBadRequestException.class,
            () -> sut.verifyLeafCertificatePermissions(certificateChainList)
        );

        // then
        verifyExpectedErrorCode(exception, ErrorCodeMap.LEAF_CERTIFICATE_IS_INCORRECT);
    }

    private KeyPair preparePublicKey() throws KeystoreGenericException {
        return CryptoUtils.genEcdsaBC();
    }

    private List<CertificateEntryWrapper> prepareCertChain(
        KeyPair bkpsSigningKey) {

        final PsgPublicKeyBuilder pubKeyBuilder = getPsgPublicKeyBuilder(bkpsSigningKey, PsgCurveType.SECP384R1);
        final PsgCertificateEntry bkpsLeafCert = prepareLeafCertWith(pubKeyBuilder);

        List<CertificateEntryWrapper> certificateChainList = new LinkedList<>();
        certificateChainList.add(new CertificateEntryWrapper(PsgCertificateType.LEAF, bkpsLeafCert.array()));
        return certificateChainList;
    }

    private PsgCertificateEntry prepareLeafCertWith(PsgPublicKeyBuilder psgPublicKeyBuilder) {
        return new PsgCertificateEntryBuilder().publicKey(psgPublicKeyBuilder).build();
    }

    private PsgPublicKeyBuilder getPsgPublicKeyBuilder(KeyPair keyPair, PsgCurveType psgCurveType) {
        return new PsgPublicKeyBuilder()
            .magic(PsgPublicKeyMagic.M1_MAGIC)
            .publicKey(keyPair.getPublic(), psgCurveType);
    }

    private PsgSignatureBuilder getPsgSignatureBuilder(PsgSignatureCurveType psgSignatureCurveType) {
        return PsgSignatureBuilder.empty(psgSignatureCurveType);
    }

    private int getPermissions(ModifyBitsBuilder set) {
        return set
            .set(PsgPermissions.SIGN_CERT.getBitPosition())
            .build();
    }
}
