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

package com.intel.bkp.fpgacerts.cbor.service;

import com.intel.bkp.fpgacerts.cbor.CborBroker;
import com.intel.bkp.fpgacerts.cbor.CborConverter;
import com.intel.bkp.fpgacerts.cbor.CborObjectParser;
import com.intel.bkp.fpgacerts.cbor.LocatorType;
import com.intel.bkp.fpgacerts.cbor.exception.RimVerificationException;
import com.intel.bkp.fpgacerts.cbor.rim.Comid;
import com.intel.bkp.fpgacerts.cbor.rim.RimUnsigned;
import com.intel.bkp.fpgacerts.cbor.rim.comid.LinkedTag;
import com.intel.bkp.fpgacerts.cbor.rim.comid.mapping.ReferenceTripleToTcbInfoMeasurementMapper;
import com.intel.bkp.fpgacerts.cbor.rim.parser.RimSignedParser;
import com.intel.bkp.fpgacerts.cbor.rim.parser.RimUnsignedParser;
import com.intel.bkp.fpgacerts.cbor.signer.CborSignatureVerifier;
import com.intel.bkp.fpgacerts.cbor.utils.ProfileValidator;
import com.intel.bkp.fpgacerts.cbor.utils.SignatureTimeValidator;
import com.intel.bkp.fpgacerts.cbor.xrim.XrimService;
import com.intel.bkp.fpgacerts.dice.tcbinfo.MeasurementHolder;
import com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfoMeasurement;
import com.intel.bkp.fpgacerts.dp.IDistributionPointConnector;
import com.intel.bkp.fpgacerts.ect.ECTMap;
import com.intel.bkp.fpgacerts.ect.IECTMapStorage;
import com.intel.bkp.fpgacerts.rim.IRimHandler;
import com.intel.bkp.fpgacerts.url.FetchDataSchemeBroker;
import com.intel.bkp.fpgacerts.utils.VerificationStatusLogger;
import com.upokecenter.cbor.CBORObject;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.Collection;

import static com.intel.bkp.utils.HexConverter.fromHex;

@RequiredArgsConstructor(access = AccessLevel.PACKAGE)
@Getter
@Slf4j
public class CoRimHandler implements IRimHandler<CBORObject> {

    public static final int FIRST_COM_ID = 0;
    protected static final int MAX_NESTED_LOCATORS_DEPTH = 16;

    private final ReferenceTripleToTcbInfoMeasurementMapper measurementMapper;
    private final RimSigningChainService chainService;
    private final CborSignatureVerifier cborSignatureVerifier;
    private final XrimService xrimService;
    private final boolean acceptUnsignedCorim;
    private final IDistributionPointConnector dpConnector;
    private final Set<String> linkedTags = new HashSet<>();
    private int counter = 0;
    private final List<String> trustedRootHash;

    public CoRimHandler(IDistributionPointConnector dpConnector) {
        this(dpConnector, null, false);
    }

    public CoRimHandler(IDistributionPointConnector dpConnector, String[] trustedRootHash,
                        boolean acceptUnsignedCorim) {
        this(new ReferenceTripleToTcbInfoMeasurementMapper(),
            new RimSigningChainService(dpConnector, trustedRootHash),
            new CborSignatureVerifier(),
            new XrimService(dpConnector, new CborSignatureVerifier()),
            acceptUnsignedCorim,
            dpConnector,
            Optional.ofNullable(trustedRootHash).map(Arrays::asList).orElse(List.of())
        );
    }

    @Override
    public String getFormatName() {
        return "CBOR CoRIM";
    }

    @Override
    public CBORObject parse(String hex) {
        return CborObjectParser.instance().parse(fromHex(hex));
    }

    @Override
    public MeasurementHolder getMeasurements(CBORObject rimCbor) {
        final List<CBORObject> cborList = new ArrayList<>();
        cborList.add(rimCbor);
        final var measurements = fetchMeasurements(cborList, new MeasurementHolder());
        logMeasurements(measurements);
        return measurements;
    }

    private List<IECTMapStorage> getReferenceMeasurements(RimUnsigned unsignedRim) {
        List<TcbInfoMeasurement> refTcbInfoMeasurements = unsignedRim
                                                            .getComIds()
                                                            .get(FIRST_COM_ID)
                                                            .getClaims()
                                                            .getReferenceTriples()
                                                            .stream()
                                                            .map(measurementMapper::map)
                                                            .collect(Collectors.toList());
        return ECTMap.createRvECTMap(refTcbInfoMeasurements, trustedRootHash);
    }

    private IECTMapStorage getConditionalEndorsedMeasurements(RimUnsigned unsignedRim) {

        List<TcbInfoMeasurement> conditionMeasurements = Optional.ofNullable(unsignedRim
                                                            .getComIds()
                                                            .get(FIRST_COM_ID)
                                                            .getClaims())
                                                            .map(claim -> Optional.ofNullable(claim.getConditionalEndorsedTriples())
                                                                .map(e -> e.getConditions().stream()
                                                                    .map(measurementMapper::map)
                                                                    .toList())
                                                                .or(() -> {
                                                                    if (claim.getEndorsedTriples() != null) {
                                                                        return Optional.ofNullable(claim.getReferenceTriples())
                                                                            .map(e -> e.stream()
                                                                                .map(measurementMapper::map)
                                                                                .toList());
                                                                    }
                                                                    return Optional.empty();
                                                                })
                                                                .orElse(List.of()))
                                                            .orElse(List.of());

        List<TcbInfoMeasurement> endorseMeasurements = Optional.ofNullable(unsignedRim
                                                            .getComIds()
                                                            .get(FIRST_COM_ID)
                                                            .getClaims())
                                                            .flatMap(c -> Optional.ofNullable(c.getConditionalEndorsedTriples())
                                                                .map(e -> e.getEndorsements())
                                                                .or(() -> Optional.ofNullable(c.getEndorsedTriples())))
                                                            .stream()
                                                            .flatMap(Collection::stream)
                                                            .map(measurementMapper::map)
                                                            .toList();

        return ECTMap.createEvECTMap(conditionMeasurements,
                                     endorseMeasurements,
                                     trustedRootHash);
    }

    private MeasurementHolder fetchMeasurements(List<CBORObject> cborList, MeasurementHolder measurements) {
        log.debug("Level of nested locators: " + counter);
        final List<CoRimHelperDTO> currentLevelDtos = cborList.stream()
            .map(object -> handleCoRim(object, measurements))
            .toList();
        final List<CBORObject> nestedLevelCborObjects = currentLevelDtos.stream()
            .map(dto -> getListOfNestedCbors(dto.rim()))
            .flatMap(List::stream)
            .toList();

        if (nestedLevelCborObjects.isEmpty() || counter >= MAX_NESTED_LOCATORS_DEPTH) {
            log.debug("Stop parsing nested locators at level: " + counter);
            return measurements;
        }
        counter++;

        return fetchMeasurements(nestedLevelCborObjects, measurements);
    }

    private CoRimHelperDTO handleCoRim(CBORObject rimCbor, MeasurementHolder measurements) {
        final var cborParser = CborBroker.detectCborType(rimCbor);
        final var helperDTO = switch (cborParser) {
            case RIM_SIGNED -> handleSigned(cborParser, rimCbor);
            case RIM_UNSIGNED -> handleUnsigned(cborParser, rimCbor);
            default -> throw new RimVerificationException("not a CoRIM object.");
        };

        verifyXCoRim(helperDTO);

        if (!linkedTags.isEmpty() && !helperDTO.rim.isDesign()) {
            final String corimId = helperDTO.rim.getManifestId();
            if (!linkedTags.contains(corimId)) {
                throw new RimVerificationException("Detected unexpected linked item: %s, expected one of: [%s]"
                    .formatted(corimId, String.join(",", linkedTags)
                    ));
            }
        }

        measurements.getReferenceMeasurements().addAll(getReferenceMeasurements(helperDTO.rim()));
        var conditionalEndorsedECTMapStorage = getConditionalEndorsedMeasurements(helperDTO.rim());
        if (!conditionalEndorsedECTMapStorage.getCondition().isEmpty()
            && !conditionalEndorsedECTMapStorage.getAddition().isEmpty()) {
            measurements.getConditionalEndorsedMeasurements().add(conditionalEndorsedECTMapStorage);
        }

        return helperDTO;
    }

    private List<CBORObject> getListOfNestedCbors(RimUnsigned rimUnsigned) {
        return rimUnsigned.getLocatorLinks(LocatorType.CORIM)
            .stream()
            .map(this::downloadNestedData)
            .toList();
    }

    private void verifyXCoRim(CoRimHelperDTO helperDTO) {
        xrimService.verifyXRimAndEnsureRimIsNotRevoked(helperDTO.rim(), helperDTO.rimSigPubKey(), acceptUnsignedCorim);
    }

    private CoRimHelperDTO handleUnsigned(CborConverter converter, CBORObject rimCbor) {
        log.info("Verifying unsigned CoRIM with accept unsigned flag set to: {}", acceptUnsignedCorim);
        if (!acceptUnsignedCorim) {
            throw new RimVerificationException("CoRIM not signed. Signature cannot be verified.");
        }
        final var rim = ((RimUnsignedParser) converter.getParser()).parse(rimCbor);
        ProfileValidator.verify(rim.getProfile());

        appendLinkedTags(rim);

        final var rimSigPubKey = rim.getLocatorLink(LocatorType.CER)
            .map(chainService::verifyRimSigningChainAndGetRimSigningKey)
            .orElse(null);
        return new CoRimHelperDTO(rim, rimSigPubKey);
    }

    private CoRimHelperDTO handleSigned(CborConverter converter, CBORObject rimCbor) {
        final var signed = ((RimSignedParser) converter.getParser()).parse(rimCbor);
        final var rim = signed.getPayload();
        SignatureTimeValidator.verify(signed);
        if (!rim.getProfile().isEmpty()) {
            ProfileValidator.verify(rim.getProfile());
        }

        appendLinkedTags(rim);

        final var rimSigPubKey = rim.getLocatorLink(LocatorType.CER)
            .map(chainService::verifyRimSigningChainAndGetRimSigningKey)
            .orElseThrow(() -> new RimVerificationException("trusted Anchor is not implemented."));
        log.info(VerificationStatusLogger.success("Verified CoRIM Signing Certificate chain."));
        verifyRimSignature(rimCbor, rimSigPubKey);
        return new CoRimHelperDTO(rim, rimSigPubKey);
    }

    private void appendLinkedTags(RimUnsigned rim) {
        rim.getComIds().stream()
            .map(Comid::getLinkedTags)
            .filter(Objects::nonNull)
            .flatMap(List::stream)
            .map(LinkedTag::getLinkedTagId)
            .forEach(linkedTags::add);
    }

    private void verifyRimSignature(CBORObject signedRim, PublicKey rimSigPubkey) {
        if (!cborSignatureVerifier.verify(rimSigPubkey, signedRim)) {
            throw new RimVerificationException("invalid signature.");
        }
        log.info(VerificationStatusLogger.success("CoRIM signature verification"));
    }

    private CBORObject downloadNestedData(String url) {
        log.info("Downloading nested CoRIM data from: {}", url);
        return FetchDataSchemeBroker.fetchData(url, dpConnector)
            .map(content -> CborObjectParser.instance().parse(content))
            .orElseThrow(() -> new RimVerificationException("failed to download data from path: %s".formatted(url)));
    }

    private void logMeasurements(MeasurementHolder measurements) {
        var rvList = measurements.getReferenceMeasurements();
        if (!rvList.isEmpty()) {
            log.debug("reference-values ECT: {}",
                Optional.ofNullable(measurements.getReferenceMeasurements())
                    .map(list -> list.stream()
                        .map(e -> e.toString())
                        .collect(Collectors.joining(",\n\t", "\n[\n\t", "\n]\n")))
                    .orElse("null"));
        }

        var evList = measurements.getConditionalEndorsedMeasurements();
        if (!evList.isEmpty()) {
            log.debug("endorsements ECT: {}", Optional.ofNullable(measurements.getConditionalEndorsedMeasurements())
                                              .map(list -> list.stream()
                                                    .map(e -> e.toString())
                                                    .collect(Collectors.joining(",\n\t", "\n[\n\t", "\n]\n")))
                                              .orElse("null"));
        }
    }

    private record CoRimHelperDTO(RimUnsigned rim, PublicKey rimSigPubKey) {

    }
}
