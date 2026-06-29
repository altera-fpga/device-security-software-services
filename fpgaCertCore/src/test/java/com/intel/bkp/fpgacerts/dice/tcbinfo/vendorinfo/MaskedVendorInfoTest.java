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

package com.intel.bkp.fpgacerts.dice.tcbinfo.vendorinfo;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MaskedVendorInfoTest {

    private static final String VENDOR_INFO = "0011001100001111";
    private static final String VENDOR_INFO_MASK = "FFFFFFFF000000FF";
    private static final String VENDOR_INFO_RESPONSE_VALID = "0011001111111111";
    private static final String VENDOR_INFO_RESPONSE_INVALID = "0011001111111100";

    private final MaskedVendorInfo other = new MaskedVendorInfo(VENDOR_INFO, VENDOR_INFO_MASK);
    private final MaskedVendorInfo otherInvalidInfo = new MaskedVendorInfo("AAAA", VENDOR_INFO_MASK);
    private final MaskedVendorInfo otherInvalidMask = new MaskedVendorInfo(VENDOR_INFO, "AAAA");

    private final MaskedVendorInfo sut = new MaskedVendorInfo(VENDOR_INFO, VENDOR_INFO_MASK);

    @Test
    void setMaskBasedOnVendorInfo_VendorInfoSet_SetsMask() {
        // given
        final var vendorInfo = "111111";
        final String expectedMask = "FFFFFF";
        final var sut = new MaskedVendorInfo(vendorInfo);

        // when
        sut.setMaskBasedOnVendorInfo();

        // then
        assertEquals(expectedMask, sut.getVendorInfoMask());
    }

    @Test
    void setMaskBasedOnVendorInfo_VendorInfoNotSet_DoesNothing() {
        // given
        final var sut = new MaskedVendorInfo(null);

        // when
        sut.setMaskBasedOnVendorInfo();

        // then
        assertNull(sut.getVendorInfoMask());
    }

    @Test
    void hasMask_MaskSetInConstructor_ReturnsTrue() {
        // given
        final var sut = new MaskedVendorInfo(VENDOR_INFO, VENDOR_INFO_MASK);

        // when-then
        assertTrue(sut.hasMask());
    }

    @Test
    void hasMask_MaskSetBasedOnVendorInfo_ReturnsTrue() {
        // given
        final var sut = new MaskedVendorInfo(VENDOR_INFO);
        sut.setMaskBasedOnVendorInfo();

        // when-then
        assertTrue(sut.hasMask());
    }

    @Test
    void hasMask_MaskNotSet_ReturnsFalse() {
        // given
        final var sut = new MaskedVendorInfo(VENDOR_INFO);

        // when-then
        assertFalse(sut.hasMask());
    }

    @Test
    void equals_Basics() {
        // then
        assertNotEquals(null, sut);
        assertEquals(sut, sut);
        assertNotEquals("ABC", sut);
    }

    @Test
    void equals_WithOtherNullVendorInfo_ReturnsFalse() {
        // then
        assertNotEquals(sut, new MaskedVendorInfo(null));
        assertNotEquals(new MaskedVendorInfo(null), sut);
    }

    @Test
    void equals_WithOtherBothSetGood_ReturnsTrue() {
        // then
        assertEquals(sut, other);
        assertEquals(other, sut);
    }

    @Test
    void equals_WithOtherBothSetInvalidInfo_ReturnsFalse() {
        // then
        assertNotEquals(sut, otherInvalidInfo);
        assertNotEquals(otherInvalidInfo, sut);
    }

    @Test
    void equals_WithOtherBothSetInvalidMask_ReturnsFalse() {
        // then
        assertNotEquals(sut, otherInvalidMask);
        assertNotEquals(otherInvalidMask, sut);
    }

    @Test
    void equals_WithOtherBothSetNullMask_ReturnsTrue() {
        // then
        final MaskedVendorInfo left = new MaskedVendorInfo(VENDOR_INFO, null);
        final MaskedVendorInfo right = new MaskedVendorInfo(VENDOR_INFO, null);
        assertEquals(left, right);
        assertEquals(right, left);
    }

    @Test
    void equals_WithOtherBothSetNullInfo_ReturnsTrue() {
        // then
        final MaskedVendorInfo left = new MaskedVendorInfo(null, VENDOR_INFO_MASK);
        final MaskedVendorInfo right = new MaskedVendorInfo(null, VENDOR_INFO_MASK);
        assertEquals(left, right);
        assertEquals(right, left);
    }

    @Test
    void equals_FromResponse_ValidResponse_ReturnsTrue() {
        // then
        assertEquals(sut, new MaskedVendorInfo(VENDOR_INFO_RESPONSE_VALID));
        assertEquals(new MaskedVendorInfo(VENDOR_INFO_RESPONSE_VALID), sut);
    }

    @Test
    void equals_FromResponse_InvalidResponse_ReturnsFalse() {
        // then
        assertNotEquals(sut, new MaskedVendorInfo(VENDOR_INFO_RESPONSE_INVALID));
        assertNotEquals(new MaskedVendorInfo(VENDOR_INFO_RESPONSE_INVALID), sut);
    }

    @Test
    void toString_ReturnsValidString() {
        // given
        String expected = "MaskedVendorInfo( vendorInfo=0011001100001111 vendorInfoMask=FFFFFFFF000000FF )";

        // when
        final String result = sut.toString();

        // then
        assertEquals(expected, result);
    }
}
