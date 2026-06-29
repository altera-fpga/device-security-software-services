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

package com.intel.bkp.protocol.spdm.service;

import com.intel.bkp.protocol.spdm.exceptions.InvalidSpdmVersionException;
import com.intel.bkp.protocol.spdm.exceptions.UnsupportedSpdmVersionException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class SpdmVersionVerifierTest {

    private static final String SUPPORTED_VERSION = "12";
    private static final String VALID_UNSUPPORTED_VERSION = "10";
    private static final String VALID_UNSUPPORTED_VERSION_2 = "13";
    private static final String INVALID_VERSION = "notHex";

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {INVALID_VERSION})
    void constructor_WithInvalidVersion_Throws(String invalidVersion) {
        // when-then
        final var ex = assertThrows(InvalidSpdmVersionException.class,
            () -> new SpdmVersionVerifier(invalidVersion));

        // then
        assertEquals("Invalid SPDM version: " + invalidVersion, ex.getMessage());
    }

    @Test
    void ensureVersionIsSupported_WithSupportedVersion_DoesNotThrow() {
        // given
        final var sut = new SpdmVersionVerifier(SUPPORTED_VERSION);
        // when-then
        assertDoesNotThrow(() -> sut.ensureVersionIsSupported(SUPPORTED_VERSION));
    }

    @ParameterizedTest
    @ValueSource(strings = {VALID_UNSUPPORTED_VERSION, VALID_UNSUPPORTED_VERSION_2})
    void ensureVersionIsSupported_WithValidButUnsupportedVersion_Throws(String unsupportedVersion) {
        // given
        final var sut = new SpdmVersionVerifier(SUPPORTED_VERSION);
        final String expectedExMessage =
            "Responder SPDM version: %s, supported version: %s".formatted(unsupportedVersion, SUPPORTED_VERSION);

        // when-then
        final var ex = assertThrows(UnsupportedSpdmVersionException.class,
            () -> sut.ensureVersionIsSupported(unsupportedVersion));

        // then
        assertEquals(expectedExMessage, ex.getMessage());
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {INVALID_VERSION})
    void ensureVersionIsSupported_WithInvalidVersion_Throws(String invalidVersion) {
        // given
        final var sut = new SpdmVersionVerifier(SUPPORTED_VERSION);

        // when-then
        final var ex = assertThrows(InvalidSpdmVersionException.class,
            () -> sut.ensureVersionIsSupported(invalidVersion));

        // then
        assertEquals("Invalid SPDM version: " + invalidVersion, ex.getMessage());
    }
}
