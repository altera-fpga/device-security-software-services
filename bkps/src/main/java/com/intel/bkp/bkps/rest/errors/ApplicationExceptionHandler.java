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

package com.intel.bkp.bkps.rest.errors;

import com.intel.bkp.bkps.rest.errors.enums.ErrorCodeMap;
import com.intel.bkp.bkps.utils.MdcHelper;
import com.intel.bkp.core.exceptions.ApplicationError;
import com.intel.bkp.core.exceptions.BKPBadRequestException;
import com.intel.bkp.core.exceptions.BKPInternalServerException;
import com.intel.bkp.core.exceptions.BKPNotFoundException;
import com.intel.bkp.core.exceptions.JceSecurityProviderException;
import com.intel.bkp.core.interfaces.IErrorCode;
import com.intel.bkp.core.utils.SecurityLogType;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.ConstraintViolationException;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.annotation.AnnotationUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.validation.BindingResult;
import org.springframework.validation.ObjectError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

import java.util.List;

import static com.intel.bkp.bkps.rest.errors.TransactionIdHelper.getTransactionId;

/**
 * Controller advice to translate the server side exception to client-friendly json structures.
 */

@RestControllerAdvice
@Slf4j
public class ApplicationExceptionHandler extends ResponseEntityExceptionHandler {

    @ExceptionHandler(Exception.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    public ApplicationError defaultErrorHandler(Exception e) throws Exception {
        // If the exception is annotated with @ResponseStatus rethrow it and let the framework handle it
        if (AnnotationUtils.findAnnotation(e.getClass(), ResponseStatus.class) != null) {
            throw e;
        }

        log.error(e.getMessage(), e);
        return new ApplicationError(ErrorCodeMap.UNKNOWN_ERROR, getTransactionId());
    }

    @ExceptionHandler({MethodArgumentTypeMismatchException.class})
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ApplicationError handleMethodArgumentTypeMismatch(MethodArgumentTypeMismatchException ex) {
        return handleInvalidPayload(ex);
    }

    @ExceptionHandler(ConstraintViolationException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ApplicationError handleConstraintViolationExceptions(ConstraintViolationException ex) {
        return handleInvalidPayload(ex);
    }

    @ExceptionHandler(AuthenticationException.class)
    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    public ApplicationError handleUnauthorizedExceptions(AuthenticationException e, HttpServletRequest request) {
        MdcHelper.addSecurityTag(SecurityLogType.SECURITY_AUTH);
        log.error(String.format("Unauthorized access to resource [%s] '%s': %s",
            request.getMethod(), request.getRequestURI(), e.getMessage()));
        return new ApplicationError(ErrorCodeMap.AUTHORIZATION_REQUIRED, getTransactionId());
    }

    @ExceptionHandler(AccessDeniedException.class)
    @ResponseStatus(HttpStatus.FORBIDDEN)
    public ApplicationError handleForbiddenExceptions(AccessDeniedException e, HttpServletRequest request) {
        MdcHelper.addSecurityTag(SecurityLogType.SECURITY_AUTH);
        log.error(String.format("Forbidden access to resource [%s] '%s': %s",
            request.getMethod(), request.getRequestURI(), e.getMessage()));
        return new ApplicationError(ErrorCodeMap.ACCESS_DENIED, getTransactionId());
    }

    @ExceptionHandler(BKPBadRequestException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ApplicationError handleBadRequestExceptions(BKPBadRequestException exception) {
        IErrorCode errorCode = exception.getErrorCode();
        return new ApplicationError(errorCode, getTransactionId());
    }

    @ExceptionHandler({JceSecurityProviderException.class})
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    public ApplicationError handleJceSecurityProviderException(JceSecurityProviderException e) {
        log.error(e.getMessage(), e);
        return new ApplicationError(ErrorCodeMap.SECURITY_PROVIDER_ERROR, getTransactionId());
    }

    @ExceptionHandler({BKPInternalServerException.class})
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    public ApplicationError handleInternalServerExceptions(BKPInternalServerException exception) {
        IErrorCode errorCode = exception.getErrorCode();
        return new ApplicationError(errorCode, getTransactionId());
    }

    @ExceptionHandler(BKPNotFoundException.class)
    @ResponseStatus(HttpStatus.NOT_FOUND)
    public ApplicationError handleNotFoundExceptions(BKPNotFoundException exception) {
        IErrorCode errorCode = exception.getErrorCode();
        return new ApplicationError(errorCode, getTransactionId());
    }

    @Override
    protected ResponseEntity<Object> handleMethodArgumentNotValid(@NonNull MethodArgumentNotValidException ex,
                                                                  @NonNull HttpHeaders headers,
                                                                  @NonNull HttpStatusCode status,
                                                                  @NonNull WebRequest request) {
        BindingResult result = ex.getBindingResult();
        IErrorCode errorCode = ErrorCodeMap.INVALID_FIELDS_IN_PAYLOAD;
        List<ObjectError> allErrors = result.getAllErrors();
        if (allErrors.stream().anyMatch(
            objectError -> "com.intel.bkp.bkps.errors.testprogram.required".equals(objectError.getDefaultMessage()))) {
            errorCode = ErrorCodeMap.MISSING_FLAG_TEST_PROGRAM;
        }
        log.error("Invalid request data: {}", ex.getMessage());
        return ResponseEntity.badRequest().body(new ApplicationError(errorCode, getTransactionId()));
    }

    @Override
    protected ResponseEntity<Object> handleHttpMessageNotReadable(@NonNull HttpMessageNotReadableException ex,
                                                                  @NonNull HttpHeaders headers,
                                                                  @NonNull HttpStatusCode status,
                                                                  @NonNull WebRequest request) {
        return ResponseEntity.badRequest().body(handleInvalidPayload(ex));
    }

    @Override
    protected ResponseEntity<Object> handleMissingServletRequestParameter(
            @NonNull MissingServletRequestParameterException ex, @NonNull HttpHeaders headers,
            @NonNull HttpStatusCode status,
            @NonNull WebRequest request) {
        return ResponseEntity.badRequest().body(handleInvalidPayload(ex));
    }

    private ApplicationError handleInvalidPayload(Exception ex) {
        MdcHelper.addSecurityTag(SecurityLogType.SECURITY_VALIDATION);
        log.error("Invalid request data: {}", ex.getMessage());
        return new ApplicationError(ErrorCodeMap.INVALID_FIELDS_IN_PAYLOAD, getTransactionId());
    }
}
