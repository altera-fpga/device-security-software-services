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

package com.intel.bkp.bkps.rest.errors.enums;

import com.intel.bkp.core.interfaces.IErrorCode;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.ToString;

@Getter
@ToString
@AllArgsConstructor
public enum ErrorCodeMap implements IErrorCode {

    /* =========== Unknown =========== */
    UNKNOWN_ERROR(2000, "Unknown Error occurred."),

    /* =========== Connectivity =========== */
    FAILED_TO_FETCH_INFORMATION(2020, "Failed to fetch information from internal resource."),

    /* =========== Authorization =========== */
    AUTHORIZATION_REQUIRED(2050, "Need authorization for this resource."),
    ACCESS_DENIED(2051, "Access denied for this resource."),
    USER_ALREADY_INITIALIZED(2052,
        "Access denied for this resource. Initial user has been successfully created."),
    USER_NOT_FOUND(2053, "User with provided id does not exist."),
    USER_ROLE_NOT_VALID(2054, "Provided user role is not valid."),
    USER_DUPLICATED_FINGERPRINT(2055, "Failed to create user - provided certificate already exists."),
    USER_INVALID_CERT_UPLOADED(2056, "Invalid x509 certificate uploaded."),
    USER_INVALID_FILE_UPLOADED(2057, "Invalid public key/certificate file uploaded."),
    USER_ROLE_RESTRICTED(2058, "Provided user role is restricted. Use SUPER_ADMIN account to set this role."),
    USER_CERTIFICATE_EXPIRED(2059, "Failed to authorize - expired user certificate."),
    USER_INVALID_TEMP_TOKEN(2060, "Failed to authorize - temporary token is invalid."),
    USER_ROLE_NOT_EMPTY(2061, "User has already been assigned a role: %s"),

    /* =========== Security Provider =========== */
    SECURITY_PROVIDER_ERROR(2080, "Connection to secure enclave failed."),

    /* =========== Payload =========== */
    INVALID_FIELDS_IN_PAYLOAD(2950, "Request contains invalid fields. Please check your request."),

    /* =========== Common =========== */
    CONFIGURATION_NOT_FOUND(2150, "Configuration not found."),
    IMPORT_KEY_DOES_NOT_EXIST(2151, "Service Import Key Pair does not exist."),
    SEALING_KEY_DOES_NOT_EXIST(2152, "Sealing Key does not exist."),
    SEALING_KEY_EXISTS_IN_DB_BUT_NOT_ENCLAVE(2153,
        "Sealing Key does not exist in security enclave but exists in database."),
    PROVISIONING_GENERIC_EXCEPTION(2154, "Provisioning failed."),
    SIGNING_KEY_DOES_NOT_EXIST(2155, "Signing Key does not exist."),
    UNABLE_TO_RETRIEVE_PUBLIC_KEY(2156, "Unable to retrieve public key."),
    CERTIFICATE_CHAIN_WRONG_SIZE(2157, "Invalid number of certificates in chain."),
    ROOT_CERTIFICATE_IS_INCORRECT(2158, "Product Owner Root Certificate verification failed."),
    PARENT_CERTIFICATES_DO_NOT_MATCH(2159, "Verify that uploaded certificate chain has correct format."),
    PSG_CERTIFICATE_EXCEPTION(2160, "Invalid PSG certificate provided."),
    MISSING_ROOT_CERTIFICATE(2161, "Could not get root certificate from chain."),
    MISSING_LEAF_CERTIFICATE(2162, "Could not get leaf certificate from chain."),
    CERTIFICATE_CHAIN_VALIDATION_FAILED(2163, "Certificate chain validation failed."),
    CERTIFICATE_WRONG_FORMAT(2164, "Verify that uploaded certificate chain has correct format."),
    CONTEXT_KEY_ERROR(2165, "Failed to initialize provisioning context."),
    WRAPPING_KEY_ERROR(2166, "Failed to create wrapping key. Please rotate the key manually."),
    LEAF_CERTIFICATE_IS_INCORRECT(2167, "BKP Service Leaf Certificate has incorrect format."),
    COMMAND_NOT_SUPPORTED(2169, "Programmer does not support command for requested operation."),
    CONFIGURATION_IS_INVALID(2170, "Configuration of id %d is invalid."),
    FAILED_TO_PARSE_CERTIFICATE(2171, "Failed to parse certificate."),
    FAILED_TO_CREATE_CERT_FINGERPRINT(2172, "Exception occurred - failed to generate Certificate fingerprint."),
    CERTIFICATE_FINGERPRINT_EXISTS(2173, "Exception occurred - certificate fingerprint already exists."),
    SAVE_CERTIFICATE_IN_TRUSTSTORE_FAILED(2174, "Failed to save uploaded certificate in truststore."),
    CERTIFICATE_IN_TRUSTSTORE_CHECK_FAILED(2175, "Failed to check if certificate is saved in truststore."),
    CERTIFICATE_FAILED_TO_REMOVE(2176, "Failed to remove certificate: specified alias '%s' not found"),
    SPDM_PROCESS_RUNNING(2177, "SPDM Process is still running. Please try again in a few seconds."),
    MALFORMED_URL_PATH(2178, "URL path \"%s\" to be fetched is malformed."),

    /* =========== Onboarding =========== */
    PREFETCHING_GENERIC_EXCEPTION(2300, "Prefetching failed."),
    PREFETCHING_STATUS_FAILED_INVALID_PARAMS(2301, "Both familyID and uid must be provided or none."),
    PREFETCHING_STATUS_FAILED_INVALID_FAMILY(2302, "Not supported family id."),
    PUF_ACTIVATION_GENERIC_EXCEPTION(2303, "Puf Activation failed."),
    SET_AUTHORITY_GENERIC_EXCEPTION(2304, "Set Authority failed."),
    PUF_HELPER_DATA_NOT_FOUND_IN_CACHE(2305, "PUF Helper Data not found in cache. Run Prefetching first."),
    PUF_TYPE_NOT_SUPPORTED_FOR_PUF_ACTIVATION(2306, "PufType other than %s are not supported for Puf Activation."),
    PUF_TYPE_NOT_SUPPORTED_FOR_SET_AUTHORITY(2307, "PufType other than %s are not supported for Set Authority."),
    FAMILY_NOT_SUPPORTED_FOR_PUF_ACTIVATION(2308, "Family other than %s are not supported for Puf Activation."),
    FAMILY_NOT_SUPPORTED_FOR_SET_AUTHORITY(2309, "Family other than %s are not supported for Set Authority."),
    GET_ATTESTATION_CERT_FAILED(2310, "Get Attestation Certificate command failed: %s"),

    /* =========== Initialization Endpoint Group =========== */
    FAILED_TO_SAVE_SEALING_KEY_IN_SECURITY_ENCLAVE(2350, "Failed to save Sealing Key in security enclave."),
    ACTIVE_SEALING_KEY_ALREADY_EXISTS(2351, "Active (enabled) Sealing Key already exists."),
    FAILED_TO_PARSE_ROOT_PUBLIC_KEY(2352, "Failed to parse Product Owner/Customer Root Signing Public Key."),
    SIGNING_KEY_ALREADY_ACTIVATED(2353, "Signing Key is already activated."),
    SIGNING_KEY_IS_NOT_CONFIGURED_MISSING_CHAIN(2354, "Signing Key is not configured - missing certificate chain."),
    ROOT_SIGNING_KEY_DOES_NOT_EXIST(2355, "Root Signing Key does not exist."),
    ROOT_SIGNING_KEY_ALREADY_EXISTS(2356, "Root Signing Key already exists."),
    SIGNING_KEY_CHAIN_ALREADY_EXISTS(2357, "Signing key chain already exists."),
    PSG_CERTIFICATE_INVALID_PERMISSIONS(2358, "Permissions for leaf certificate are incorrect."),
    SIGNING_KEY_CHAIN_DOES_NOT_EXIST(2359, "Signing key chain does not exist."),
    IMPORT_KEY_ALREADY_EXISTS(2360, "Import Key already exists. Delete the key first to "
        + "create a new one."),
    FAILED_TO_SAVE_IMPORT_KEY_IN_SECURITY_ENCLAVE(2361, "Failed to save Import Key in security enclave."),
    SEALING_KEY_ROTATION_PENDING(2362, "Sealing Key rotation is in progress."),
    SEALING_KEY_ROTATION_FAILED(2363, "Sealing Key rotation failed."),
    ACTIVE_SEALING_KEY_DOES_NOT_EXIST(2364, "Active (enabled) Sealing Key does not exists."),
    SEALING_KEY_BACKUP_FAILED(2365, "Sealing Key backup failed."),
    SEALING_KEY_RESTORE_FAILED(2366, "Sealing Key restore failed."),
    SEALING_KEY_BACKUP_HASH_DOES_NOT_MATCH(2367, "Incorrect Backup Sealing Key."),
    SEALING_KEY_BACKUP_HASH_DOES_NOT_EXIST(2368, "Sealing Key restore failed - "
        + "call Backup API first."),
    PUBLIC_KEY_IN_CERTIFICATE_DOES_NOT_MATCH(2369, "Public Key in certificate does not match "
        + "the created Signing Public Key."),

    /* =========== Configuration Endpoint Group =========== */
    CREATE_ID_EXISTS_RESTRICTION(2400, "New configuration cannot have ID."),
    FAILED_TO_ENCRYPT_SENSITIVE_DATA_WITH_SEALING_KEY(2401, "Failed to encrypt sensitive data with sealing key."),
    MISSING_FLAG_TEST_PROGRAM(2402, "Field confidentialData.aesKey.testProgram is required for "
        + "SDM 1.2 devices with storage type EFUSES."),
    FAILED_TO_DECRYPT_UPLOADED_SENSITIVE_DATA(2403,
        "Failed to decrypt uploaded sensitive data in Configuration."),
    MISSING_ENCRYPTED_AES_KEY(2404, "Field 'encryptedAesKey' is required for ENCRYPTED import mode."),
    CORRUPTED_AES_KEY(2405, "Failed to parse confidentialData.aesKey.value."),
    UNSUPPORTED_PROVISIONING_OPERATION_FOR_PUFSS(2406, "Off-chip provisioning not supported."),
    DIFFERENT_AES_KEY_VALUE(2407, "Detected different AES Key test flag value: %s."),
    CORRUPTED_QEK(2408, "Failed to parse confidentialData.qek.value."),
    MISSING_ENCRYPTED_QEK(2409, "Field 'encryptedQek' is required for ENCRYPTED import mode."),
    CREATE_ID_EXISTS_RESTRICTION_POLICY(2410, "ID assignment is not permitted for new appraisal policies."),
    PARSE_ERROR_WHEN_UPLOADING(2411, "Failed to upload the target file due to invalid syntax or format."),
    PATH_NOT_EXIST_IN_PREFETCH(2412, "The target path does not exist in the BKPS prefetch table."),
    UNSUPPORTED_FILETYPE_IN_PREFETCH(2413, "The file type %s is not supported by the BKPS prefetch."),
    CORRUPTED_APPRAISAL_POLICY(2414, "Failed to parse the appraisal policy. Check for syntax errors or unsupported fields in the appraisal policy and try again."),

    /* =========== Provisioning Init Group =========== */
    OTHER_TRANSACTION_IN_PROGRESS(2500, "Provisioning failed - another transaction in progress."),

    /* =========== Provisioning Auth Group =========== */
    CRL_NOT_FOUND(2600, "Failed to find required CRL in previously cached CRLs or on distribution point."),
    FAILED_TO_PARSE_CERTIFICATE_FROM_DEVICE(2601, "Failed to parse certificate from device.");

    /* =========== Provisioning Provision Group =========== */
    // 2700

    private final int code;

    private final String externalMessage;
}
