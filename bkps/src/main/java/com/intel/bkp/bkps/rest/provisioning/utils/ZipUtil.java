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

import lombok.extern.slf4j.Slf4j;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

@Slf4j
public class ZipUtil {

    public static final int MAX_BUFFER_SIZE_BYTES = 8192;
    private static final int CHUNK_SIZE = 1024;

    public static List<String> listZipContentFilenames(byte[] zipBytes) {
        final List<String> files = new ArrayList<>();

        try (ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(zipBytes);
             ZipInputStream zipInputStream = new ZipInputStream(byteArrayInputStream)) {

            ZipEntry entry;
            while ((entry = zipInputStream.getNextEntry()) != null) {
                if (!entry.isDirectory()) {
                    files.add(entry.getName());
                }
            }
        } catch (IOException e) {
            log.error("Error during parsing ZIP file: {}", e.getMessage());
            log.debug("Stacktrace: ", e);
        }

        return files;
    }

    public static Optional<byte[]> extractFileFromZip(byte[] zipBytes, String fileSuffix) {
        final Map<String, byte[]> files = extractFilesFromZip(zipBytes, fileSuffix);
        return files.values().stream().findFirst();
    }

    public static Map<String, byte[]> extractFilesFromZip(byte[] zipBytes, String fileSuffix) {
        log.debug("Extracting files from zip by pattern: {}", fileSuffix);
        final Map<String, byte[]> extractedFiles = new HashMap<>();

        try (ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(zipBytes);
             ZipInputStream zipInputStream = new ZipInputStream(byteArrayInputStream);
             ByteArrayOutputStream outputStream = new ByteArrayOutputStream()) {

            ZipEntry entry;
            while ((entry = zipInputStream.getNextEntry()) != null) {
                final String entryName = entry.getName();

                if (entryName.endsWith(fileSuffix)) {
                    log.trace("Parsing next ZIP entry. Entry name: {}", entryName);

                    final int entrySize = getEntrySize(entry);
                    if (entrySize > MAX_BUFFER_SIZE_BYTES) {
                        log.error("ZIP entry contains too much data. "
                                + "Entry size: {} bytes, Max allowed: {}. Entry name: {}",
                            entrySize, MAX_BUFFER_SIZE_BYTES, entryName);
                        continue;
                    }

                    int bytesRead;
                    int totalBytesRead = 0;
                    final byte[] chunk = new byte[CHUNK_SIZE];
                    while ((bytesRead = zipInputStream.read(chunk)) != -1
                        && totalBytesRead + bytesRead <= entrySize) {

                        log.trace("ZIP entry read {} bytes chunk. Entry name: {}", bytesRead, entryName);
                        outputStream.write(chunk, 0, bytesRead);
                        totalBytesRead += bytesRead;
                    }

                    log.debug("ZIP entry total read {} bytes. Entry name: {}", totalBytesRead, entryName);
                    extractedFiles.put(entryName, outputStream.toByteArray());
                } else {
                    log.trace("Skipping next ZIP entry. Entry name: {}", entryName);
                }
            }

        } catch (IOException e) {
            log.error("Failed to extract file from zip. Exception: {}", e.getMessage());
            log.debug("Stacktrace: ", e);
        }

        return extractedFiles;
    }

    private static int getEntrySize(ZipEntry entry) throws IllegalArgumentException {
        final long entrySize = entry.getSize();
        log.trace("ZIP entry size: {} bytes", entrySize);

        if (entrySize < 0) {
            return MAX_BUFFER_SIZE_BYTES;
        }

        return (int) entrySize;
    }
}
