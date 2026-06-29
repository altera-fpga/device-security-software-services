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

package com.intel.bkp.bkps.rest.provisioning.utils;

import com.intel.bkp.test.FileUtils;
import lombok.SneakyThrows;
import org.apache.commons.codec.digest.DigestUtils;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@ExtendWith(MockitoExtension.class)
class ZipUtilTest {

    private static final String TEST_PATH = "zip";
    private static final String ZIP_AGILEX_DEV_PATH = "DEV_34_0029842e27ca682f_vEmoW9hRWHY-tu9ni4AmAwd_sA0.zip";

    private static final byte[] ZIP_AGILEX_DEV = prepareAgilexZipFile();
    private static final int VERY_BIG_FILE_SIZE = 10240;
    private static final String PUF_PUFHELPER_NAME = "puf/pufhelper.puf";
    private static final String DEVICEID_NAME = "efuse/deviceid.cer";
    private static final String FILE_NOT_PRESENT = "file_not_present";

    @SneakyThrows
    private static byte[] prepareAgilexZipFile() {
        return FileUtils.readFromResources(TEST_PATH, ZIP_AGILEX_DEV_PATH);
    }

    @Test
    void listZipContentFilenames_Success() {
        // given
        final int expectedFileCount = 6;

        // when
        final List<String> result = ZipUtil.listZipContentFilenames(ZIP_AGILEX_DEV);

        // then
        assertEquals(expectedFileCount, result.size());
        assertTrue(result.stream().anyMatch(file -> file.endsWith(PUF_PUFHELPER_NAME)));
    }

    @Test
    void extractFileFromZip_PufHelperData_Success() {
        // given
        final String expectedHash = "F8180AA8B0E6D3C8913F914537C23C76DCB236073D1DFFA583585025D60CA647";

        // when
        final Optional<byte[]> result = ZipUtil.extractFileFromZip(ZIP_AGILEX_DEV, PUF_PUFHELPER_NAME);

        // then
        assertTrue(result.isPresent());
        assertEquals(expectedHash, calculateResultHash(result.orElseThrow()));
    }

    @Test
    void extractFileFromZip_EfuseDeviceId_Success() {
        // given
        final String expectedHash = "9A543F09ED7306884BB1B28ACED0DCEC615BD1D6B169F61192DD1759F0263D67";

        // when
        final Optional<byte[]> result = ZipUtil.extractFileFromZip(ZIP_AGILEX_DEV, DEVICEID_NAME);

        // then
        assertEquals(expectedHash, calculateResultHash(result.orElseThrow()));
    }

    @Test
    void extractFilesFromZip_Success() {
        // given
        final int expectedCerFileCount = 4;

        // when
        final Map<String, byte[]> result = ZipUtil.extractFilesFromZip(ZIP_AGILEX_DEV, ".cer");

        // then
        assertEquals(expectedCerFileCount, result.size());

        final Set<String> keys = result.keySet();
        assertTrue(keys.stream().anyMatch(s -> s.endsWith("DICE_RootCA.cer")));
        assertTrue(keys.stream().anyMatch(s -> s.endsWith("IPCS_agilex.cer")));
        assertTrue(keys.stream().anyMatch(s -> s.endsWith("deviceid.cer")));
        assertTrue(keys.stream().anyMatch(s -> s.endsWith("iiduds.cer")));
    }

    @Test
    void extractFileFromZip_FileNotFound_Throws() {
        // when
        final Optional<byte[]> result = ZipUtil.extractFileFromZip(ZIP_AGILEX_DEV, FILE_NOT_PRESENT);

        // then
        assertTrue(result.isEmpty());
    }

    @Test
    void extractFileFromZip_FileTooBig_ReturnsMaxSize() throws IOException {
        // given
        final String fileName = "very_big_file";
        final byte[] veryBigZip = createZipFileWithContent(fileName, VERY_BIG_FILE_SIZE);

        // when-then
        final Optional<byte[]> result = ZipUtil.extractFileFromZip(veryBigZip, fileName);

        assertEquals(ZipUtil.MAX_BUFFER_SIZE_BYTES, result.orElseThrow().length);
    }

    private static String calculateResultHash(byte[] result) {
        return DigestUtils.sha256Hex(result).toUpperCase(Locale.ROOT);
    }

    private static byte[] createZipFileWithContent(String filename, int fileSize) throws IOException {
        try (ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
             ZipOutputStream zipOutputStream = new ZipOutputStream(outputStream)) {

            final ZipEntry entry = new ZipEntry(filename);
            zipOutputStream.putNextEntry(entry);

            final byte[] zeros = new byte[fileSize];
            zipOutputStream.write(zeros);

            zipOutputStream.closeEntry();
            zipOutputStream.close();

            return outputStream.toByteArray();
        }
    }
}
