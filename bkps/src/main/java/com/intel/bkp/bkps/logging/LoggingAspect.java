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

import com.intel.bkp.core.exceptions.BKPRuntimeException;
import com.intel.bkp.core.utils.ProfileConstants;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.Signature;
import org.aspectj.lang.annotation.AfterThrowing;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Pointcut;
import org.springframework.core.env.Environment;
import org.springframework.core.env.Profiles;

import java.util.Arrays;

import static lombok.AccessLevel.PUBLIC;

/**
 * Aspect for logging execution of service and repository Spring components.
 * By default, it only runs with the "dev" profile.
 */
@Aspect
@Slf4j
@AllArgsConstructor(access = PUBLIC)
public class LoggingAspect {

    private final Environment env;

    /**
     * Pointcut that matches all repositories, services and Web REST endpoints.
     */
    @Pointcut("within(@org.springframework.stereotype.Repository *)"
        + " || within(@org.springframework.stereotype.Service *)"
        + " || within(@org.springframework.web.bind.annotation.RestController *)")
    public void springBeanPointcut() {
        // Method is empty as this is just a Pointcut, the implementations are in the advices.
    }

    /**
     * Pointcut that matches all Spring beans in the application's main packages.
     */
    @Pointcut("within(com.intel.bkp.bkps.repository..*)"
        + " || within(com.intel.bkp.bkps.service..*)"
        + " || within(com.intel.bkp.bkps.rest.*.service..*)"
        + " || within(com.intel.bkp.bkps.rest.*.verification..*)")
    public void applicationPackagePointcut() {
        // Method is empty as this is just a Pointcut, the implementations are in the advices.
    }

    @Pointcut("!within(com.intel.bkp.bkps.rest.health..*) || within(com.intel.bkp.bkps.rest.health.checker..*)")
    public void notHealthPointcut() {
        // Method is empty as this is just a Pointcut, the implementations are in the advices.
    }

    /**
     * Advice that logs methods throwing exception.
     *
     * @param joinPoint join point for advice
     * @param e         exception
     */
    @AfterThrowing(pointcut = "applicationPackagePointcut() && springBeanPointcut()", throwing = "e")
    public void logAfterThrowing(JoinPoint joinPoint, Throwable e) {
        if (env.acceptsProfiles(Profiles.of(ProfileConstants.SPRING_PROFILE_DEVELOPMENT))) {
            log.error("Exception in {} with cause = '{}' and exception = '{}'",
                getFullMethodName(joinPoint.getSignature()), e.getCause() != null ? e.getCause() : "NULL",
                e.getMessage(), e);
        } else if (e instanceof final BKPRuntimeException bkpEx) {
            String additionalMsg = "";
            if (e.getCause() != null) {
                additionalMsg = " | " + e.getCause();
            } else if (e.getMessage() != null && !bkpEx.getErrorCode().getExternalMessage().equals(e.getMessage())) {
                additionalMsg = " | " + e.getMessage();
            }
            log.error("Exception in {} with error: {} | [{}] {}{}",
                getFullMethodName(joinPoint.getSignature()), e.getClass().getSimpleName(),
                bkpEx.getErrorCode().getCode(), bkpEx.getErrorCode().getExternalMessage(), additionalMsg);
        } else {
            log.error("Exception in {} with cause = {}", getFullMethodName(joinPoint.getSignature()),
                e.getCause() != null ? e.getCause() : "NULL");
        }
    }

    /**
     * Advice that logs when a method is entered and exited.
     *
     * @param joinPoint join point for advice
     * @return result
     * @throws Throwable throws IllegalArgumentException
     */
    @Around("applicationPackagePointcut() && springBeanPointcut() && notHealthPointcut()")
    public Object logAround(ProceedingJoinPoint joinPoint) throws Throwable {
        if (log.isDebugEnabled()) {
            log.debug("Enter: {} with argument[s] = {}", getFullMethodName(joinPoint.getSignature()),
                Arrays.toString(joinPoint.getArgs()));
        }
        try {
            Object result = joinPoint.proceed();
            if (log.isDebugEnabled()) {
                log.debug("Exit: {} with result = {}", getFullMethodName(joinPoint.getSignature()), result);
            }
            return result;
        } catch (IllegalArgumentException e) {
            log.error("Illegal argument: {} in {}", Arrays.toString(joinPoint.getArgs()),
                getFullMethodName(joinPoint.getSignature()));

            throw e;
        }
    }

    private String getFullMethodName(Signature signature) {
        return String.format("%s.%s()", signature.getDeclaringTypeName(), signature.getName());
    }
}
