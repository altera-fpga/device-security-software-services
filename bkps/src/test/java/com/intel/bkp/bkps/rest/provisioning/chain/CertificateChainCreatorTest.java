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

import com.intel.bkp.bkps.exception.CertificateRequestTypeMismatchException;
import com.intel.bkp.bkps.exception.ProvisioningGenericException;
import com.intel.bkp.bkps.programmer.model.ProgrammerResponse;
import com.intel.bkp.bkps.programmer.utils.ProgrammerResponseToDataAdapter;
import com.intel.bkp.bkps.rest.errors.enums.ErrorCodeMap;
import com.intel.bkp.bkps.rest.prefetching.model.PrefetchChainDataDTO;
import com.intel.bkp.bkps.rest.prefetching.service.ChainDataProvider;
import com.intel.bkp.command.model.CertificateRequestType;
import com.intel.bkp.command.model.CommandLayer;
import com.intel.bkp.crypto.exceptions.X509CertificateParsingException;
import com.intel.bkp.crypto.x509.parsing.X509CertificateParser;
import com.intel.bkp.crypto.x509.utils.KeyIdentifierUtils;
import com.intel.bkp.fpgacerts.chain.DistributionPointCertificate;
import com.intel.bkp.fpgacerts.chain.DistributionPointCrl;
import com.intel.bkp.test.RandomUtils;
import lombok.SneakyThrows;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static com.intel.bkp.bkps.rest.RestUtil.getProgrammerResponseFromArray;
import static com.intel.bkp.command.model.CertificateRequestType.FIRMWARE;
import static com.intel.bkp.command.model.CertificateRequestType.UDS_EFUSE_BKP;
import static com.intel.bkp.command.model.CertificateRequestType.UDS_IID_PUF_BKP;
import static com.intel.bkp.command.model.CommandIdentifier.GET_ATTESTATION_CERTIFICATE;
import static com.intel.bkp.fpgacerts.chain.DistributionPointCertificate.getX509Certificates;
import static com.intel.bkp.utils.HexConverter.toHex;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertIterableEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class CertificateChainCreatorTest {

    private static final String DEVICE_ID = "0102030405060708";
    private static final String CRL_URL = "https://some.domain/crl.crl";
    private static final byte[] deviceIdEnrollmentBytes = new byte[]{0x01, 0x02};

    private static MockedStatic<X509CertificateParser> x509CertificateParserMockStatic;
    private static MockedStatic<KeyIdentifierUtils> keyIdentifierUtilsMockStatic;

    @Mock
    private X509CRL crl;

    @Mock
    private X509Certificate bkpCert;

    @Mock
    private X509Certificate iidBkpCert;

    @Mock
    private X509Certificate fwCert;

    @Mock
    private X509Certificate deviceIdEnrollmentCert;

    @Mock
    private X509Certificate deviceIdCert;

    @Mock
    private X509Certificate enrollmentCert;

    @Mock
    private X509Certificate iidUdsCert;

    @Mock
    private X509Certificate familyCert;

    @Mock
    private X509Certificate rootCert;

    @Mock
    private PrefetchChainDataDTO chainDataDTO;

    @Mock
    private ChainDataProvider chainDataProvider;

    @Mock
    private CommandLayer commandLayer;

    @InjectMocks
    private CertificateChainCreator sut;

    @BeforeAll
    static void prepareStaticMock() {
        x509CertificateParserMockStatic = mockStatic(X509CertificateParser.class);
        keyIdentifierUtilsMockStatic = mockStatic(KeyIdentifierUtils.class);
    }

    @AfterAll
    static void closeStaticMock() {
        x509CertificateParserMockStatic.close();
        keyIdentifierUtilsMockStatic.close();
    }

    @Test
    void createS10Chain_Success() {
        // given
        final var certs = prepareDpCerts(bkpCert, familyCert, rootCert); // it doesn't matter which certs are used
        mockFetchS10(certs);

        // when
        final var result = sut.createS10Chain(DEVICE_ID);

        // then
        assertIterableEquals(getX509Certificates(certs), result.getCertificates());
        assertTrue(result.getCertificatesIID().isEmpty());
        assertEquals(getExpectedCrlMap(), result.getCachedCrls());
    }

    @Test
    void createDiceChain_WithoutIid_Success() {
        // given
        final boolean requireIidUds = false;
        final boolean isEnrollmentFlow = false;
        final boolean efuseChainFetched = true;
        final boolean iidChainFetched = true;
        final var adapter = prepareQuartusAdapterWithMockedResponses(requireIidUds);
        mockFetchDice(efuseChainFetched, iidChainFetched, isEnrollmentFlow);

        // when
        final var result = sut.createDiceChain(adapter, deviceIdEnrollmentBytes, requireIidUds);

        // then
        assertIterableEquals(getExpectedEfuseChain(isEnrollmentFlow), result.getCertificates());
        assertTrue(result.getCertificatesIID().isEmpty());
        assertEquals(getExpectedCrlMap(), result.getCachedCrls());
    }

    @Test
    void createDiceChain_WithIid_Success() {
        // given
        final boolean requireIidUds = true;
        final boolean isEnrollmentFlow = false;
        final boolean efuseChainFetched = true;
        final boolean iidChainFetched = true;
        final var adapter = prepareQuartusAdapterWithMockedResponses(requireIidUds);
        mockFetchDice(efuseChainFetched, iidChainFetched, isEnrollmentFlow);

        // when
        final var result = sut.createDiceChain(adapter, deviceIdEnrollmentBytes, requireIidUds);

        // then
        assertIterableEquals(getExpectedEfuseChain(isEnrollmentFlow), result.getCertificates());
        assertIterableEquals(getExpectedIidChain(), result.getCertificatesIID());
        assertEquals(getExpectedCrlMap(), result.getCachedCrls());
    }

    @Test
    void createDiceChain_EnrollmentFlow_WithIid_Success() {
        // given
        final boolean requireIidUds = true;
        final boolean isEnrollmentFlow = true;
        final boolean efuseChainFetched = true;
        final boolean iidChainFetched = true;
        final var adapter = prepareQuartusAdapterWithMockedResponses(requireIidUds);
        mockFetchDice(efuseChainFetched, iidChainFetched, isEnrollmentFlow);

        // when
        final var result = sut.createDiceChain(adapter, deviceIdEnrollmentBytes, requireIidUds);

        // then
        assertIterableEquals(getExpectedEfuseChain(isEnrollmentFlow), result.getCertificates());
        assertIterableEquals(getExpectedIidChain(), result.getCertificatesIID());
        assertEquals(getExpectedCrlMap(), result.getCachedCrls());
    }

    @Test
    void createDiceChain_NoEfuseChainFetched_WithIid_Success() {
        // given
        final boolean requireIidUds = true;
        final boolean isEnrollmentFlow = false;
        final boolean efuseChainFetched = false;
        final boolean iidChainFetched = true;
        final var adapter = prepareQuartusAdapterWithMockedResponses(requireIidUds);
        mockFetchDice(efuseChainFetched, iidChainFetched, isEnrollmentFlow);

        // when
        final var result = sut.createDiceChain(adapter, deviceIdEnrollmentBytes, requireIidUds);

        // then
        assertTrue(result.getCertificates().isEmpty());
        assertIterableEquals(getExpectedIidChain(), result.getCertificatesIID());
        assertEquals(getExpectedCrlMap(), result.getCachedCrls());
    }

    @Test
    void createDiceChain_WithIid_NoIidChainFetched_Success() {
        // given
        final boolean requireIidUds = true;
        final boolean isEnrollmentFlow = false;
        final boolean efuseChainFetched = true;
        final boolean iidChainFetched = false;
        final var adapter = prepareQuartusAdapterWithMockedResponses(requireIidUds);
        mockFetchDice(efuseChainFetched, iidChainFetched, isEnrollmentFlow);

        // when
        final var result = sut.createDiceChain(adapter, deviceIdEnrollmentBytes, requireIidUds);

        // then
        assertIterableEquals(getExpectedEfuseChain(isEnrollmentFlow), result.getCertificates());
        assertTrue(result.getCertificatesIID().isEmpty());
        assertEquals(getExpectedCrlMap(), result.getCachedCrls());
    }

    @Test
    void createDiceChain_FailsToParseCertificate_Throws() {
        // given
        mockCertificateParsingThrows(deviceIdEnrollmentBytes);

        // when-then
        final var ex = assertThrows(ProvisioningGenericException.class,
            () -> sut.createDiceChain(null, deviceIdEnrollmentBytes, false));

        // then
        assertEquals(ErrorCodeMap.FAILED_TO_PARSE_CERTIFICATE_FROM_DEVICE, ex.getErrorCode());
    }

    @Test
    void createDiceChain_IncorrectQuartusResponseOrder_Throws() {
        // given
        mockCertificateParsing(deviceIdEnrollmentBytes, deviceIdEnrollmentCert);
        final var adapter = prepareQuartusAdapterWithMockedResponsesInWrongOrder();

        // when-then
        final var ex = assertThrows(CertificateRequestTypeMismatchException.class,
            () -> sut.createDiceChain(adapter, deviceIdEnrollmentBytes, false));

        // then
        assertEquals(ErrorCodeMap.PROVISIONING_GENERIC_EXCEPTION, ex.getErrorCode());
    }

    private void mockFetchS10(List<DistributionPointCertificate> certificates) {
        when(chainDataProvider.fetchS10(DEVICE_ID)).thenReturn(chainDataDTO);
        when(chainDataDTO.getCertificates()).thenReturn(certificates);
        when(chainDataDTO.getCrls()).thenReturn(prepareDpCrls());
    }

    private void mockFetchDice(boolean efuseChainFetched, boolean iidChainFetched, boolean isEnrollmentFlow) {
        mockCertificateParsing(deviceIdEnrollmentBytes, deviceIdEnrollmentCert);
        when(chainDataProvider.fetchDice(deviceIdEnrollmentCert)).thenReturn(chainDataDTO);
        mockFetchedCertificatesAndCrls(efuseChainFetched, iidChainFetched, isEnrollmentFlow);
    }

    private void mockFetchedCertificatesAndCrls(boolean efuseChainFetched, boolean iidChainFetched,
                                                boolean isEnrollmentFlow) {
        when(chainDataDTO.getCrls()).thenReturn(prepareDpCrls());

        if (efuseChainFetched) {
            final var efuseCerts = mockEfuseCerts(isEnrollmentFlow);
            when(chainDataDTO.getCertificates()).thenReturn(efuseCerts);
        }

        if (iidChainFetched) {
            final var iidCerts = mockIidCerts();
            when(chainDataDTO.getCertificatesIID()).thenReturn(iidCerts);
        }
    }

    private ProgrammerResponseToDataAdapter prepareQuartusAdapterWithMockedResponsesInWrongOrder() {
        final var secondResponse = prepareQuartusResponse(FIRMWARE, RandomUtils.generateDeviceId());

        when(commandLayer.retrieve(secondResponse.getValue(), GET_ATTESTATION_CERTIFICATE)).thenReturn(secondResponse.getValue());

        return new ProgrammerResponseToDataAdapter(List.of(secondResponse));
    }

    private ProgrammerResponseToDataAdapter prepareQuartusAdapterWithMockedResponses(boolean requireIidUds) {
        final var responses = new ArrayList<ProgrammerResponse>();

        responses.add(mockGetCertificateFromResponse(UDS_EFUSE_BKP, bkpCert));
        responses.add(mockGetCertificateFromResponse(FIRMWARE, fwCert));

        if (requireIidUds) {
            responses.add(mockGetCertificateFromResponse(UDS_IID_PUF_BKP, iidBkpCert));
        }

        return new ProgrammerResponseToDataAdapter(responses);
    }

    private ProgrammerResponse mockGetCertificateFromResponse(CertificateRequestType certificateRequestType,
                                                              X509Certificate certificate) {
        final var certBytes = RandomUtils.generateDeviceId();
        final var response = prepareQuartusResponse(certificateRequestType, certBytes);

        when(commandLayer.retrieve(response.getValue(), GET_ATTESTATION_CERTIFICATE)).thenReturn(response.getValue());
        mockCertificateParsing(certBytes, certificate);

        return response;
    }

    private ProgrammerResponse prepareQuartusResponse(CertificateRequestType certificateRequestType, byte[] certBytes) {
        final byte[] response = ByteBuffer.allocate(Integer.BYTES + certBytes.length)
            .order(ByteOrder.LITTLE_ENDIAN)
            .putInt(certificateRequestType.getType())
            .order(ByteOrder.BIG_ENDIAN)
            .put(certBytes)
            .array();

        return getProgrammerResponseFromArray(response);
    }

    @SneakyThrows
    private void mockCertificateParsing(byte[] certBytes, X509Certificate resultCert) {
        x509CertificateParserMockStatic.when(() -> X509CertificateParser.toX509Certificate(certBytes))
            .thenReturn(resultCert);
    }

    @SneakyThrows
    private void mockCertificateParsingThrows(byte[] certBytes) {
        x509CertificateParserMockStatic.when(() -> X509CertificateParser.toX509Certificate(certBytes))
            .thenThrow(new X509CertificateParsingException("test", null));
    }

    private List<X509Certificate> getExpectedEfuseChain(boolean isEnrollmentFlow) {
        return isEnrollmentFlow
               ? List.of(bkpCert, fwCert, deviceIdEnrollmentCert, enrollmentCert, familyCert, rootCert)
               : List.of(bkpCert, fwCert, deviceIdCert, familyCert, rootCert);
    }

    private List<X509Certificate> getExpectedIidChain() {
        return List.of(iidBkpCert, iidUdsCert, familyCert, rootCert);
    }

    private Map<String, X509CRL> getExpectedCrlMap() {
        return Map.of(CRL_URL, crl);
    }

    private List<DistributionPointCertificate> mockEfuseCerts(boolean isEnrollmentFlow) {
        final byte[] fwAki = RandomUtils.generateDeviceId();
        when(KeyIdentifierUtils.getAuthorityKeyIdentifier(fwCert)).thenReturn(fwAki);
        if (isEnrollmentFlow) {
            when(KeyIdentifierUtils.getSubjectKeyIdentifier(enrollmentCert)).thenReturn(RandomUtils.generateDeviceId());
            return prepareDpCerts(enrollmentCert, familyCert, rootCert);
        } else {
            when(KeyIdentifierUtils.getSubjectKeyIdentifier(deviceIdCert)).thenReturn(fwAki);
            return prepareDpCerts(deviceIdCert, familyCert, rootCert);
        }
    }

    private List<DistributionPointCertificate> mockIidCerts() {
        return prepareDpCerts(iidUdsCert, familyCert, rootCert);
    }

    private List<DistributionPointCertificate> prepareDpCerts(X509Certificate... certs) {
        final String randomDeviceId = toHex(RandomUtils.generateDeviceId());
        return Arrays.stream(certs)
            .map(cert -> new DistributionPointCertificate(randomDeviceId, cert))
            .collect(Collectors.toList());
    }

    private List<DistributionPointCrl> prepareDpCrls() {
        return List.of(new DistributionPointCrl(CRL_URL, crl));
    }
}
