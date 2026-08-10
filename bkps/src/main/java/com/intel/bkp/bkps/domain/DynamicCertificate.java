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

package com.intel.bkp.bkps.domain;

import com.intel.bkp.core.helper.DynamicCertificateType;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.PrePersist;
import jakarta.persistence.Table;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;

import java.time.Instant;

@Getter
@Setter
@Entity
@Table(name = "dynamic_certificate")
@ToString
@NoArgsConstructor
public class DynamicCertificate {

    @Id
    @NotNull
    @Column(nullable = false)
    private String fingerprint;

    @NotNull
    @Size(max = 8192)
    @Column(nullable = false, length = 8192)
    private String certificate;

    @Column
    private String alias;

    @Column
    private Instant createdDate;

    @Column
    private Instant validUntil;

    @Column
    @Enumerated(EnumType.STRING)
    private DynamicCertificateType certificateType;

    @Column
    private Instant removedDate;

    @PrePersist
    public void onCreate() {
        this.createdDate = Instant.now();
    }

    public static DynamicCertificate createServerCert(String fingerprint, Instant validUntil, String certificate) {
        final DynamicCertificate entity = new DynamicCertificate();
        entity.setAlias("server_" + Instant.now().toEpochMilli());
        entity.setFingerprint(fingerprint);
        entity.setValidUntil(validUntil);
        entity.setCertificate(certificate);
        entity.setCertificateType(DynamicCertificateType.SERVER);
        return entity;
    }

    public static DynamicCertificate createUserCert(String alias, String fingerprint, Instant validUntil,
                                                    String certificate) {
        final DynamicCertificate entity = new DynamicCertificate();
        entity.setAlias(alias);
        entity.setFingerprint(fingerprint);
        entity.setValidUntil(validUntil);
        entity.setCertificate(certificate);
        entity.setCertificateType(DynamicCertificateType.USER);
        return entity;
    }

    public void remove() {
        this.removedDate = Instant.now();
    }

    public boolean isRemoved() {
        return this.removedDate != null;
    }

    public boolean isNotRemoved() {
        return this.removedDate == null;
    }
}
