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

package com.intel.bkp.bkps.config;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.scheduling.concurrent.ConcurrentTaskExecutor;

import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

@ExtendWith(MockitoExtension.class)
public class ExceptionHandlingAsyncTaskExecutorTest {

    private ExceptionHandlingAsyncTaskExecutor sut;

    @BeforeEach
    void setUp() {
        sut = new ExceptionHandlingAsyncTaskExecutor(new ConcurrentTaskExecutor(Executors.newSingleThreadExecutor()));
    }

    @Test
    void execute_Success() {
        // given
        int[] counter = {10};

        // when
        sut.execute(() -> {
            counter[0]++;
            assertEquals(11, counter[0]);
        });
    }

    @Test
    void submit_Success() {
        // given
        int[] counter = {10};

        // when
        sut.submit(() -> {
            counter[0]++;
            assertEquals(11, counter[0]);
        });
    }

    @Test
    void execute_WithTimeout_Success() {
        // given
        int[] counter = {10};

        // when
        sut.execute(() -> {
            counter[0]++;
            assertEquals(11, counter[0]);
        }, 15);
    }

    @Test
    void execute_LogsError() {
        // when
        assertDoesNotThrow(() -> sut.execute(() -> {
            throw new RuntimeException("test");
        }));
    }

    @Test
    void submit_WithCallable_RunsTask() throws ExecutionException, InterruptedException {
        // when
        Future<Integer> future = sut.submit(() -> 1);
        Integer result = future.get();

        // than
        assertEquals((Integer) 1, result);
    }

    @Test
    void submit_WithCallable_ThrowsException() {
        // when
        Future<Integer> future = sut.submit(() -> {
            throw new RuntimeException("test");
        });

        // than
        assertThrows(ExecutionException.class, () -> {
            Integer result = future.get();
            assertEquals((Integer) 1, result);
        });
    }
}

