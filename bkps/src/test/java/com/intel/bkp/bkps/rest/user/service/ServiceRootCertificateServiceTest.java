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

package com.intel.bkp.bkps.rest.user.service;

import com.intel.bkp.bkps.domain.AppUser;
import com.intel.bkp.bkps.domain.Authority;
import com.intel.bkp.bkps.domain.DynamicCertificate;
import com.intel.bkp.bkps.exception.CertificateWrongFormat;
import com.intel.bkp.bkps.exception.X509TrustManagerException;
import com.intel.bkp.bkps.repository.DynamicCertificateRepository;
import com.intel.bkp.bkps.repository.UserRepository;
import com.intel.bkp.bkps.rest.errors.enums.ErrorCodeMap;
import com.intel.bkp.bkps.rest.user.model.dto.DynamicCertificateDTO;
import com.intel.bkp.bkps.rest.user.model.mapper.DynamicCertificateMapper;
import com.intel.bkp.bkps.security.AuthorityType;
import com.intel.bkp.bkps.security.X509TrustManagerManager;
import com.intel.bkp.bkps.utils.DateMapper;
import com.intel.bkp.core.exceptions.BKPBadRequestException;
import com.intel.bkp.core.exceptions.BKPInternalServerException;
import com.intel.bkp.core.exceptions.BKPNotFoundException;
import com.intel.bkp.core.helper.DynamicCertificateType;
import com.intel.bkp.core.helper.TruststoreCertificateEntryData;
import com.intel.bkp.core.utils.ApplicationConstants;
import com.intel.bkp.crypto.CryptoUtils;
import com.intel.bkp.crypto.constants.CryptoConstants;
import com.intel.bkp.crypto.pem.PemFormatEncoder;
import com.intel.bkp.crypto.pem.PemFormatHeader;
import com.intel.bkp.test.CertificateUtils;
import com.intel.bkp.test.KeyGenUtils;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentMatchers;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.security.KeyPair;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import static com.intel.bkp.crypto.x509.utils.X509CertificateUtils.toPem;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
public class ServiceRootCertificateServiceTest {

    private static final String TEST_ALIAS = "user_service_12345";

    @Mock
    private X509TrustManagerManager x509TrustManagerFactory;

    @Mock
    private DynamicCertificateRepository dynamicCertificateRepository;

    @Mock
    private DynamicCertificateMapper dynamicCertificateMapper;

    @Mock
    private DynamicCertificate dynamicCertificate;

    @Mock
    private UserRepository userRepository;

    @Mock
    private AppUser appUser;

    @Mock
    private DateMapper dateMapper;

    @Mock
    private MultipartFile uploadedFile;

    @InjectMocks
    private ServiceRootCertificateService sut;

    @Test
    void rootCertificateImport_Success() throws Exception {
        // given
        mockUploadedKeyCert(true);

        // when
        sut.rootCertificateImport(uploadedFile);

        // then
        verify(dynamicCertificateRepository).save(any());
    }

    @Test
    void rootCertificateImport_WithIOException_ThrowsException() throws Exception {
        // given
        when(uploadedFile.getBytes()).thenThrow(IOException.class);

        // when-then
        final BKPBadRequestException exception = assertThrows(BKPBadRequestException.class,
            () -> sut.rootCertificateImport(uploadedFile)
        );

        // then
        assertEquals(ErrorCodeMap.USER_INVALID_FILE_UPLOADED.getExternalMessage(), exception.getMessage());
    }

    @Test
    void rootCertificateImport_WithFailedToAddEntryToTruststore_ThrowsException() throws Exception {
        // given
        mockUploadedKeyCert(true);
        doThrow(X509TrustManagerException.class).when(x509TrustManagerFactory)
            .addEntry(any(), anyString());

        // when-then
        final BKPInternalServerException exception = assertThrows(BKPInternalServerException.class,
            () -> sut.rootCertificateImport(uploadedFile)
        );

        // then
        assertEquals(ErrorCodeMap.SAVE_CERTIFICATE_IN_TRUSTSTORE_FAILED.getExternalMessage(), exception.getMessage());
    }

    @Test
    void rootCertificateImport_WithExistingFingerprint_ThrowsException() throws Exception {
        // given
        mockUploadedKeyCert(true);
        when(dynamicCertificateRepository.existsByFingerprint(anyString())).thenReturn(true);

        // when-then
        final BKPBadRequestException exception = assertThrows(BKPBadRequestException.class,
            () -> sut.rootCertificateImport(uploadedFile)
        );

        // then
        assertEquals(ErrorCodeMap.USER_DUPLICATED_FINGERPRINT.getExternalMessage(), exception.getMessage());
    }

    @Test
    void rootCertificateImport_WithPubKeyNotCert_ThrowsException() throws Exception {
        // given
        mockUploadedKeyCert(false);

        // when-then
        final CertificateWrongFormat exception = assertThrows(CertificateWrongFormat.class,
            () -> sut.rootCertificateImport(uploadedFile)
        );

        // then
        assertEquals(ErrorCodeMap.CERTIFICATE_WRONG_FORMAT.getExternalMessage(), exception.getMessage());
    }

    @Test
    void getAll_WithEmptyValidUntilInDatabase_Success() throws Exception {
        // given
        mockBehavior(false, false);

        // when
        final List<DynamicCertificateDTO> list = sut.getAll();

        // then
        assertEquals(2, list.size());
    }

    @Test
    void getAll_WithNotEmptyValidUntilInDatabase_Success() throws Exception {
        // given
        mockBehavior(true, false);

        // when
        final List<DynamicCertificateDTO> list = sut.getAll();

        // then
        assertEquals(2, list.size());
    }

    @Test
    void getAll_WithSameFingerprints_Success() throws Exception {
        // given
        mockBehavior(true, true);

        // when
        final List<DynamicCertificateDTO> list = sut.getAll();

        // then
        assertEquals(1, list.size());
    }

    @Test
    void delete_Success() throws Exception {
        // given
        mockDeleteBehavior(true);

        // when
        sut.delete(TEST_ALIAS);

        // then
        verify(dynamicCertificateRepository).findByAlias(TEST_ALIAS);
        verify(dynamicCertificateRepository).delete(dynamicCertificate);
        verify(x509TrustManagerFactory).removeEntry(TEST_ALIAS);
    }

    @Test
    void delete_WithCertificateNotExists_ThrowsException() throws Exception {
        // given
        mockDeleteBehavior(false);

        // when-then
        final BKPNotFoundException exception = assertThrows(BKPNotFoundException.class,
            () -> sut.delete(TEST_ALIAS)
        );

        // then
        final String exceptionMessage = String.format(ErrorCodeMap.CERTIFICATE_FAILED_TO_REMOVE.getExternalMessage(), TEST_ALIAS);
        assertEquals(exceptionMessage, exception.getMessage());
        verify(dynamicCertificateRepository).findByAlias(TEST_ALIAS);
    }

    @Test
    void delete_WithErrorOnRemovingEntry_LogsException() throws Exception {
        // given
        mockDeleteBehavior(true);
        doThrow(X509TrustManagerException.class).when(x509TrustManagerFactory).removeEntry(TEST_ALIAS);

        // when
        sut.delete(TEST_ALIAS);

        // then
        verify(dynamicCertificateRepository).findByAlias(TEST_ALIAS);
        verify(dynamicCertificateRepository).delete(dynamicCertificate);
        verify(x509TrustManagerFactory).removeEntry(TEST_ALIAS);
    }

    @Test
    void isAnyCertificateCloseToExpire_Success() {
        // given
        int daysThreshold = 7;
        when(dynamicCertificateRepository.count(ArgumentMatchers.<Specification<DynamicCertificate>>any()))
            .thenReturn(2L);

        // when
        final boolean result = sut.isAnyCertificateCloseToExpire(daysThreshold);

        // then
        assertTrue(result);
    }

    @Test
    void getCloseToExpireCertificates_Success() throws Exception {
        // given
        int daysThreshold = 7;
        final String testAlias = "testAlias";
        final ArrayList<DynamicCertificate> dynamicCertificates = getDynamicCertificates();
        when(dynamicCertificateRepository.findAll(ArgumentMatchers.<Specification<DynamicCertificate>>any()))
            .thenReturn(dynamicCertificates);
        final DynamicCertificateDTO expected = new DynamicCertificateDTO();
        expected.setAlias(testAlias);
        expected.setFingerprint(dynamicCertificate.getFingerprint());
        when(dynamicCertificateMapper.toDto(any(DynamicCertificate.class)))
            .thenReturn(expected);

        // when
        final List<DynamicCertificateDTO> result = sut.getCloseToExpireCertificates(daysThreshold);

        // then
        assertFalse(result.isEmpty());
        verify(dynamicCertificateMapper).toDto(any(DynamicCertificate.class));
    }

    @Test
    void isAnyNotExpired_Success() throws Exception {
        // given
        List<DynamicCertificate> dynamicCertificates = getDynamicCertificates();
        when(dynamicCertificateRepository.findAllByFingerprintInAndRemovedDateIsNull(anyList()))
            .thenReturn(dynamicCertificates);
        List<String> userFingerprints = new ArrayList<>();

        // when
        final boolean result = sut.isAnyNotExpired(userFingerprints);

        // then
        assertTrue(result);
    }

    @Test
    void isAnyNotExpired_WithSelfSigned_Success() throws Exception {
        // given
        List<DynamicCertificate> dynamicCertificates = getDynamicCertificates();
        when(dynamicCertificateRepository.findAllByFingerprintInAndRemovedDateIsNull(anyList()))
            .thenReturn(dynamicCertificates);
        List<String> userFingerprints = dynamicCertificates
            .stream()
            .map(DynamicCertificate::getFingerprint).collect(Collectors.toList());

        // when
        final boolean result = sut.isAnyNotExpired(userFingerprints);

        // then
        assertTrue(result);
    }

    @Test
    void isAnyNotExpired_WithFailToParseCertificate_Success() throws Exception {
        // given
        List<DynamicCertificate> dynamicCertificates = getDynamicCertificates();
        dynamicCertificates.get(0).setCertificate("notValidCertificate");
        when(dynamicCertificateRepository.findAllByFingerprintInAndRemovedDateIsNull(anyList()))
            .thenReturn(dynamicCertificates);
        List<String> userFingerprints = new ArrayList<>();

        // when
        final boolean result = sut.isAnyNotExpired(userFingerprints);

        // then
        assertTrue(result);
    }

    private ArrayList<DynamicCertificate> getDynamicCertificates() throws CertificateEncodingException {
        final ArrayList<DynamicCertificate> dynamicCertificates = new ArrayList<>();
        final X509Certificate certificate = CertificateUtils.generateCertificate();
        dynamicCertificates.add(
            DynamicCertificate.createServerCert(CryptoUtils.generateFingerprint(certificate.getEncoded()),
                certificate.getNotAfter().toInstant(), toPem(certificate)));
        return dynamicCertificates;
    }

    private void mockDeleteBehavior(boolean aliasExists) throws Exception {
        when(dynamicCertificateRepository.findByAlias(TEST_ALIAS))
            .thenReturn(aliasExists ? Optional.of(dynamicCertificate) : Optional.empty());

        if (aliasExists) {
            when(dynamicCertificate.getAlias()).thenReturn(TEST_ALIAS);
            when(x509TrustManagerFactory.exists(TEST_ALIAS)).thenReturn(true);
        }
    }

    private void mockUploadedKeyCert(boolean isCert) throws IOException, CertificateEncodingException {
        final KeyPair keyPair = KeyGenUtils.genEc256();

        final byte[] data;
        if (isCert) {
            String hashAlg = CryptoConstants.SHA384_WITH_ECDSA;
            data = toPem(CertificateUtils.generateCertificate(keyPair, hashAlg)).getBytes();
        } else {
            data = PemFormatEncoder.encode(PemFormatHeader.PUBLIC_KEY, keyPair.getPublic().getEncoded()).getBytes();
        }

        when(uploadedFile.getBytes()).thenReturn(data);
    }

    private void mockBehavior(boolean isValidUntilSet, boolean sameFingerprint) throws Exception {
        final X509Certificate certificate = CertificateUtils.generateCertificate();
        String fingerprint = CryptoUtils.generateFingerprint(certificate.getEncoded());
        when(dynamicCertificate.getCertificate()).thenReturn(toPem(certificate));
        if (isValidUntilSet) {
            when(dynamicCertificate.getValidUntil()).thenReturn(Instant.now());
        }
        DynamicCertificateDTO dto = new DynamicCertificateDTO();
        dto.setFingerprint(fingerprint);
        dto.setCertificateType(DynamicCertificateType.SERVER);

        when(dateMapper.asStringFormat(anyString(), any()))
            .thenReturn(new SimpleDateFormat(ApplicationConstants.DATE_FORMAT).format(Instant.now().toEpochMilli()));
        when(dynamicCertificateRepository.findAll())
            .thenReturn(Collections.singletonList(dynamicCertificate));
        when(dynamicCertificateMapper.toDto(dynamicCertificate)).thenReturn(dto);

        mockCertificateInfoList(sameFingerprint ? fingerprint : "otherFingerprint");
    }

    private void mockCertificateInfoList(String fingerprint) throws Exception {
        TruststoreCertificateEntryData dto = new TruststoreCertificateEntryData("testAlias", fingerprint);
        when(x509TrustManagerFactory.getCertificateInfoList())
            .thenReturn(Collections.singletonList(dto));

        mockUserRepository();
    }

    private void mockUserRepository() {
        Set<Authority> authorities = new HashSet<>();
        authorities.add(Authority.from(AuthorityType.ROLE_SUPER_ADMIN.name()));
        authorities.add(Authority.from(AuthorityType.ROLE_ADMIN.name()));
        when(appUser.getAuthorities()).thenReturn(authorities);
        when(userRepository.findOneWithAuthoritiesByFingerprint(anyString())).thenReturn(Optional.of(appUser));
    }
}
