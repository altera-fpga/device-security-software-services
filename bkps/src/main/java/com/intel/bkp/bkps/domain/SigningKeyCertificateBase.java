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

import com.intel.bkp.core.psgcertificate.model.PsgCertificateType;
import com.intel.bkp.utils.HexConverter;
import jakarta.persistence.Column;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.MappedSuperclass;
import jakarta.persistence.PrePersist;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.AccessLevel;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;

import java.time.Instant;
import java.util.Optional;

@Getter
@Setter
@ToString
@NoArgsConstructor
@EqualsAndHashCode
@MappedSuperclass
public abstract class SigningKeyCertificateBase {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "created_at")
    private Instant createdAt;

    @NotNull
    @Enumerated(EnumType.STRING)
    @Column(name = "cert_type", nullable = false)
    private PsgCertificateType certificateType;

    @Getter(AccessLevel.NONE)
    @Setter(AccessLevel.NONE)
    @Size(max = 8192)
    @Column(length = 8192)
    private String certificate;

    @ManyToOne
    @ToString.Exclude
    @EqualsAndHashCode.Exclude
    private SigningKeyEntity signingKey;

    @PrePersist
    protected void onCreate() {
        createdAt = Instant.now();
    }

    public byte[] getCertificate() {
        return Optional.ofNullable(certificate).map(HexConverter::fromHex).orElse(null);
    }

    public void setCertificate(byte[] certificateArray) {
        this.certificate = Optional.ofNullable(certificateArray)
            .map(HexConverter::toLowerCaseHex)
            .orElse(null);
    }
}
