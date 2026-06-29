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

package com.intel.bkp.bkps.async.service;

import com.intel.bkp.bkps.BkpsApp;
import com.intel.bkp.bkps.domain.DynamicCertificate;
import com.intel.bkp.bkps.exception.X509TrustManagerException;
import com.intel.bkp.bkps.repository.DynamicCertificateRepository;
import com.intel.bkp.bkps.security.X509TrustManagerManager;
import com.intel.bkp.core.exceptions.BKPInternalServerException;
import com.intel.bkp.core.helper.TruststoreCertificateEntryData;
import com.intel.bkp.crypto.CryptoUtils;
import com.intel.bkp.test.CertificateUtils;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.boot.ApplicationArguments;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.test.util.ReflectionTestUtils;

import java.security.KeyStoreException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;

import static com.intel.bkp.crypto.x509.utils.X509CertificateUtils.toPem;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyCollection;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
public class VerifyTruststoreAsyncServiceTest {

    private final Specification<DynamicCertificate> dynamicCertificateSpec =
            (root, query, criteriaBuilder) -> null;

    @Mock
    private DynamicCertificateRepository dynamicCertificateRepository;

    @Mock
    private X509TrustManagerManager trustManagerFactory;

    @Mock
    private ConfigurableApplicationContext context;

    @Mock
    private ApplicationArguments applicationArguments;

    @InjectMocks
    private VerifyTruststoreAsyncService sut;

    @Test
    void synchronize_WithEmptyDatabaseAndTruststore_DoNothing() throws Exception {
        // given
        mockDbAndTruststore(false, false, false);

        // when
        sut.synchronize();

        // then
        verify(trustManagerFactory, times(0)).addEntry(any(), any());
    }

    @Test
    void synchronize_WithNotEmptyDatabaseAndEmptyTruststore_RestartsApp() throws Exception {
        // given
        mockDbAndTruststore(true, false, false);
        mockAppRestart();

        // when
        sut.synchronize();

        // then
        verify(trustManagerFactory, times(1)).addEntry(any(), any());
    }

    @Test
    void synchronize_WithEmptyDatabaseAndNotEmptyTruststore_DoNothing() throws Exception {
        // given
        mockDbAndTruststore(false, true, false);

        // when
        sut.synchronize();

        // then
        verify(trustManagerFactory, times(0)).addEntry(any(), any());
    }

    @Test
    void synchronize_WithDeletedCertificate_Success() throws Exception {
        // given
        mockDbAndTruststoreRemovedEntry();
        mockAppRestart();

        // when
        sut.synchronize();

        // then
        verify(trustManagerFactory, times(1)).removeEntry(any());
    }

    @Test
    void synchronize_WithDeletedCertificate_LogsException() throws Exception {
        // given
        mockDbAndTruststoreRemovedEntry();
        doThrow(new X509TrustManagerException("")).when(trustManagerFactory)
            .removeEntry(any());

        // when
        sut.synchronize();

        // then
        verify(trustManagerFactory, times(1)).removeEntry(any());
    }

    @Test
    void synchronize_WithExistingEntryInTruststore_DoNothing() throws Exception {
        // given
        mockDbAndTruststore(true, true, true);

        // when
        sut.synchronize();

        // then
        verify(trustManagerFactory, times(0))
            .addEntry(any(), any());
    }

    @Test
    void synchronize_WithNotExistingEntryInTruststore_RestartsApp() throws Exception {
        // given
        mockDbAndTruststore(true, true, false);
        mockAppRestart();

        // when
        sut.synchronize();

        // then
        verify(trustManagerFactory, times(1)).addEntry(any(), any());
    }

    @Test
    void synchronize_WithNotExistingEntryInTruststore_LogsError() throws Exception {
        // given
        mockDbAndTruststore(true, true, false);
        doThrow(new X509TrustManagerException("")).when(trustManagerFactory)
            .addEntry(any(), anyString());

        // when
        sut.synchronize();

        // then
        verify(trustManagerFactory, times(1)).addEntry(any(), any());
    }

    @Test()
    void synchronize_WithGetCertificatesException_LogsError() throws Exception {
        // given
        mockDbAndTruststore(true, true, false);
        when(trustManagerFactory.getCertificateInfoList()).thenThrow(KeyStoreException.class);

        // then
        assertThrows(BKPInternalServerException.class, () -> {
            // when
            sut.synchronize();
        });
    }

    @Test
    void cleanRemovedCertificates_Success() {
        // given
        ReflectionTestUtils.setField(sut, "cleanRemovedAfterDays", 7);
        when(dynamicCertificateRepository.getRemovedByDate(any()))
            .thenReturn(dynamicCertificateSpec);
        when(dynamicCertificateRepository.findAll(dynamicCertificateSpec))
            .thenReturn(new ArrayList<>());

        // when
        sut.cleanRemovedCertificates();

        // then
        verify(dynamicCertificateRepository).findAll(dynamicCertificateSpec);
        verify(dynamicCertificateRepository).deleteAll(anyCollection());

    }

    private void mockDbAndTruststore(boolean nonEmptyDb, boolean nonEmptyTruststore, boolean sameEntry)
        throws Exception {
        final ArrayList<DynamicCertificate> dynamicCertificates = new ArrayList<>();
        final ArrayList<TruststoreCertificateEntryData> infoModels = new ArrayList<>();

        String dbAlias = "sameCertAlias";
        String truststoreAlias = sameEntry ? dbAlias : "otherCertAlias";

        String fingerprint = "randomFingerprint";
        if (nonEmptyDb) {
            final X509Certificate certificate = CertificateUtils.generateCertificate();
            fingerprint = CryptoUtils.generateFingerprint(certificate.getPublicKey().getEncoded());
            final DynamicCertificate dynamicCertificate = DynamicCertificate.createServerCert(
                fingerprint, certificate.getNotAfter().toInstant(), toPem(certificate)
            );
            dynamicCertificate.setAlias(dbAlias);
            dynamicCertificates.add(dynamicCertificate);
        }

        if (!sameEntry) {
            fingerprint = "randomFingerprint";
        }

        if (nonEmptyTruststore) {
            infoModels.add(new TruststoreCertificateEntryData(truststoreAlias, fingerprint));
        }

        when(dynamicCertificateRepository.findAll()).thenReturn(dynamicCertificates);
        when(trustManagerFactory.getCertificateInfoList()).thenReturn(infoModels);
    }

    private void mockDbAndTruststoreRemovedEntry()
        throws Exception {
        final ArrayList<DynamicCertificate> dynamicCertificates = new ArrayList<>();
        final ArrayList<TruststoreCertificateEntryData> infoModels = new ArrayList<>();

        String dbAlias = "sameCertAlias";
        String truststoreAlias = "otherCertAlias";

        final X509Certificate certificate = CertificateUtils.generateCertificate();
        String fingerprint = CryptoUtils.generateFingerprint(certificate.getPublicKey().getEncoded());
        final DynamicCertificate dynamicCertificate = DynamicCertificate.createServerCert(
            fingerprint, certificate.getNotAfter().toInstant(), toPem(certificate)
        );
        dynamicCertificate.setAlias(dbAlias);
        dynamicCertificate.remove();
        dynamicCertificates.add(dynamicCertificate);

        infoModels.add(new TruststoreCertificateEntryData(truststoreAlias, fingerprint));

        when(dynamicCertificateRepository.findAll()).thenReturn(dynamicCertificates);
        when(trustManagerFactory.getCertificateInfoList()).thenReturn(infoModels);
    }

    private void mockAppRestart() {
        BkpsApp.setContext(context);
        when(context.getBean(ApplicationArguments.class)).thenReturn(applicationArguments);
        lenient().when(applicationArguments.getSourceArgs()).thenReturn(new String[]{});
    }
}
