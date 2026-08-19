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

package com.intel.bkp.fpgacerts.cbor.rim.builder;

import com.intel.bkp.crypto.CryptoUtils;
import com.intel.bkp.crypto.constants.CryptoConstants;
import com.intel.bkp.crypto.impl.EcUtils;
import com.intel.bkp.fpgacerts.cbor.exception.CborParserException;
import com.intel.bkp.fpgacerts.cbor.rim.parser.RimUnsignedParser;
import com.intel.bkp.fpgacerts.cbor.signer.cose.CborKeyPair;
import com.intel.bkp.test.FileUtils;
import com.intel.bkp.test.rim.RimGenerator;
import com.upokecenter.cbor.CBORObject;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import static com.intel.bkp.utils.HexConverter.fromHex;
import static com.intel.bkp.utils.HexConverter.toHex;
import static org.junit.jupiter.api.Assertions.assertEquals;

class RimUnsignedBuilderTest {

    private final RimUnsignedBuilder sut = RimUnsignedBuilder.instance().standalone();
    private static final String digest0 = "E5D8D432075437126D1A06E54B3FB71D3059716245084419A0CF227E571AA26F5F47B943D2D7DC7082B0459A806E33B9";
    private static final String digest1 = "C574AB3419977535175D4353C64702544FDB54834F2E03FA33C74D2769501000DC2D70BE80876BE53BFB0D73C01CC669";
    private static final String digest2 = "16DA52155780DC488AE41B2122C59ABD6A65DA10DD1015345BB2178DC144FF1A64AE2E27ECF17C022A30DCA951F4CA77";
    private static final String layer0Digest = "26B15D3C904B4FA7EB51D9CA40C06D6228B30E37C11BED342F62BEE3CAC0D7C059E33F0BDB21F930AB84F2BDB4F587C1";
    private static final String layer1Digest = "F2C9F87762366BF2E36ABDAFAD03A6BAECF2E2BF3C20BF00DB24106C6289475AA85B8B1A1197577B96CAE7CDE55FA88C";
    private static byte[] generateUnsignedRim(boolean designRim,
                                              boolean newCorimFormat,
                                              boolean includeProfile) throws Exception {
        String privateKey = "008B3C43AC7741D04C6CE68B8B9DB555A5CBAF9DE4F8D9B73C0779396D748069AA7621100A7F34EA4C779FC8A306E94491";
        String publicKey = "9CC1A8B89D5F8BBCF8A81B5E352CA7EA41F4D90FCD6DAE3634DD2EDAEF7AD63B1B153D853112EEE9B532E3E84A8" +
            "CB11DE3F93D7BEDF37CB2DC44E3851428483BC31A04935E497C5D29AA5F0A7160000CDBAE5AB7B0DCE2070D0466B25EE27247";
        var priv = EcUtils.toPrivate(fromHex(privateKey), CryptoConstants.EC_KEY,
            CryptoConstants.EC_CURVE_SPEC_384, CryptoUtils.getBouncyCastleProvider());
        var pub = EcUtils.toPublic(fromHex(publicKey), CryptoConstants.EC_KEY,
            CryptoConstants.EC_CURVE_SPEC_384, CryptoUtils.getBouncyCastleProvider());
        var signingKey = CborKeyPair.fromKeyPair(pub, priv);
        final byte[] unsigned = RimGenerator.instance()
            .signed(false)
            .design(designRim)
            .publicKey(signingKey.getPublicKey())
            .newCorimFormat(newCorimFormat)
            .expectedDigest0(digest0)
            .expectedDigest1(digest1)
            .expectedDigest2(digest2)
            .layer0Digest(layer0Digest)
            .layer1Digest(layer1Digest)
            .includeProfile(includeProfile)
            .generate();
        return unsigned;
    }

    public CBORObject parse(byte[] cborData) {
        try (InputStream stream = new ByteArrayInputStream(cborData)) {
            final var cbor = CBORObject.Read(stream);
            if (cbor == null) {
                throw new CborParserException("No data to parse");
            }
            return cbor;
        } catch (Exception e) {
            throw new CborParserException("Failed to parse cbor binary data", e);
        }
    }

    @Test
    void build_WithFwCoRim_WithNewCoRimFormat_Success() throws Exception {
        // given
        final byte[] expectedCorim = FileUtils.readFromResources(FileUtils.TEST_FOLDER, "new_fw_rim_unsigned.rim");

        // when
        final byte[] corim = generateUnsignedRim(false, true, false);
        final var entity = RimUnsignedParser.instance().parse(corim);
        final byte[] buildFromParsed = sut.designRim(false).build(entity);

        // then
        assertEquals(toHex(expectedCorim), toHex(buildFromParsed));
        assertEquals(toHex(expectedCorim), toHex(corim));
    }

    @Test
    void build_WithDesignCoRim_WithNewCoRimFormat_Success() throws Exception {
        // given
        final byte[] expectedCorim = FileUtils.readFromResources(FileUtils.TEST_FOLDER, "new_design_rim_unsigned.rim");

        // when
        final byte[] corim = generateUnsignedRim(true, true, false);
        final var entity = RimUnsignedParser.instance().parse(corim);
        final byte[] buildFromParsed = sut.designRim(true).build(entity);

        // then
        assertEquals(toHex(expectedCorim), toHex(buildFromParsed));
        assertEquals(toHex(expectedCorim), toHex(corim));
    }

    @Test
    void build_WithFwCoRim_WithOldCoRimFormat_Success() throws Exception {
        // given
        final byte[] expectedCorim = FileUtils.readFromResources(FileUtils.TEST_FOLDER, "fw_rim_unsigned.rim");

        // when
        final byte[] corim = generateUnsignedRim(false, false, true);
        final var entity = RimUnsignedParser.instance().parse(corim);
        final byte[] buildFromParsed = sut.designRim(false).build(entity);

        // then
        assertEquals(toHex(expectedCorim), toHex(buildFromParsed));
        assertEquals(toHex(expectedCorim), toHex(corim));
    }

    @Test
    void build_WithDesignCoRim_WithOldCoRimFormat_Success() throws Exception {
        // given
        final byte[] expectedCorim = FileUtils.readFromResources(FileUtils.TEST_FOLDER, "design_rim_unsigned.rim");

        // when
        final byte[] corim = generateUnsignedRim(true, false, true);
        final var entity = RimUnsignedParser.instance().parse(corim);
        final byte[] buildFromParsed = sut.designRim(true).build(entity);

        // then
        assertEquals(toHex(expectedCorim), toHex(buildFromParsed));
        assertEquals(toHex(expectedCorim), toHex(corim));
    }
}
