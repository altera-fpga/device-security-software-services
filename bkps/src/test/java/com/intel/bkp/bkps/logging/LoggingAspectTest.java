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

package com.intel.bkp.bkps.logging;

import lombok.extern.slf4j.Slf4j;
import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.Signature;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.core.env.Environment;
import org.springframework.core.env.Profiles;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.mockito.internal.verification.VerificationModeFactory.times;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
@Slf4j
public class LoggingAspectTest {

    @Mock
    private JoinPoint joinPoint;

    @Mock
    private ProceedingJoinPoint proceedingJoinPoint;

    @Mock
    private Throwable throwable;

    @Mock
    private Signature signature;

    @Mock
    private Environment environment;

    private LoggingAspect sut;

    @BeforeEach
    void setUp() {
        sut = new LoggingAspect(environment);
    }

    @Test
    void logAfterThrowing_WithDevelopmentProfile_LogsMessages() {
        // given
        when(environment.acceptsProfiles(any(Profiles.class))).thenReturn(true);
        when(joinPoint.getSignature()).thenReturn(signature);
        when(signature.getDeclaringTypeName()).thenReturn("test");
        when(signature.getName()).thenReturn("test");

        // when
        sut.logAfterThrowing(joinPoint, throwable);

        // then
        verify(joinPoint, times(1)).getSignature();
        verify(signature, times(1)).getDeclaringTypeName();
        verify(signature, times(1)).getName();
    }

    @Test
    void logAfterThrowing_WithoutDevelopmentProfile_LogsMessages() {
        // given
        when(joinPoint.getSignature()).thenReturn(signature);
        when(signature.getDeclaringTypeName()).thenReturn("test");
        when(signature.getName()).thenReturn("test");

        // when
        sut.logAfterThrowing(joinPoint, throwable);

        // then
        verify(throwable, times(0)).getMessage();
        verify(throwable, times(1)).getCause();
    }

    @Test
    void logAround_Success() throws Throwable {
        // given
        when(proceedingJoinPoint.getArgs()).thenReturn(new String[]{});
        when(proceedingJoinPoint.getSignature()).thenReturn(signature);
        when(proceedingJoinPoint.proceed()).thenReturn("proceedObj");
        when(signature.getDeclaringTypeName()).thenReturn("test");
        when(signature.getName()).thenReturn("test");

        // when
        Object resultObject = sut.logAround(proceedingJoinPoint);

        // then
        verify(proceedingJoinPoint, times(1)).proceed();
        assertEquals("proceedObj", resultObject);
    }

    @Test
    void logAround_ThrowsIllegalArgumentException() throws Throwable {
        // given
        when(proceedingJoinPoint.getArgs()).thenReturn(new String[]{});
        when(proceedingJoinPoint.getSignature()).thenReturn(signature);
        when(proceedingJoinPoint.proceed()).thenThrow(new IllegalArgumentException());
        when(signature.getDeclaringTypeName()).thenReturn("test");
        when(signature.getName()).thenReturn("test");

        // when
        assertThrows(IllegalArgumentException.class, () -> sut.logAround(proceedingJoinPoint));
    }

    @Test
    void dummyCheckEmptyMethodsTest() {
        assertDoesNotThrow(sut::springBeanPointcut);
        assertDoesNotThrow(sut::applicationPackagePointcut);
        assertDoesNotThrow(sut::notHealthPointcut);
    }
}
