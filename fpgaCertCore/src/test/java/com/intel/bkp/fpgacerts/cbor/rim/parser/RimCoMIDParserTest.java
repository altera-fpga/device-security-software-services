/*
 * This project is licensed as below.
 *
 * **************************************************************************
 *
 * Copyright 2020-2024 Intel Corporation. All Rights Reserved.
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

package com.intel.bkp.fpgacerts.cbor.rim.parser;

import com.intel.bkp.fpgacerts.cbor.rim.Comid;
import com.intel.bkp.test.FileUtils;
import com.intel.bkp.utils.HexConverter;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static com.intel.bkp.test.FileUtils.TEST_FOLDER;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

class RimCoMIDParserTest {

    private byte[] cborData;

    private final RimCoMIDParser sut = RimCoMIDParser.instance();

    @BeforeEach
    void setUp() throws Exception {
        cborData = FileUtils.readFromResources(TEST_FOLDER, "rim_unsigned_comid.cbor");
    }

    @Test
    void parse_Success() {
        // when
        final Comid entity = sut.parse(cborData);

        // then
        assertEquals("51F505F82911480B9F44B8A614FF2B18", entity.getId().getValue());
    }

    @Test
    void parse_WithLinkedTags_Success() {
        // given
        final var data = "A401A10050E7D0DBB1A8764C7F9B71A6E8391DE7220281A3006D44657369676E20417574686F7201D82060028100"
            + "0381A200502F77CE7A5808487C9D1CA49CEA86B993010004A1008482A100A300D86F4B6086480186F84D010F04010169696E746"
            + "56C2E636F6D030281A101A204D902304800000000020000000548FFFFFFFF000000FF82A100A300D86F4B6086480186F84D010F"
            + "04020169696E74656C2E636F6D030281A101A1028182075830846646A488583DC83352FF1603371D309C787E45547044165AC97"
            + "F99FA3D25C429732D634D5EA2403DDC912DFDB2BACE82A100A300D86F4B6086480186F84D010F04030169696E74656C2E636F6D"
            + "030281A101A102818207583044C1FC50DAF21239465EE9022887C92F10B266EF0DA12A60914F9650BD7777D23545445EF17EF70"
            + "31C87F1C045A3159F82A100A300D86F4C6086480186F84D010F0481480169696E74656C2E636F6D030181A101A100A2006D5369"
            + "676E2D32332E34666D2D360103";

        // when
        final Comid parse = sut.parse(HexConverter.fromHex(data));

        // then
        assertFalse(parse.getLinkedTags().isEmpty());
        assertEquals("2F77CE7A5808487C9D1CA49CEA86B993", parse.getLinkedTags().get(0).getLinkedTagId());
        assertEquals(0, parse.getLinkedTags().get(0).getTagRel());
    }
}
