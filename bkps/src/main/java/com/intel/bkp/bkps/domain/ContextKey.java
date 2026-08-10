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

import com.intel.bkp.bkps.domain.enumeration.ContextKeyType;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.Id;
import jakarta.persistence.OneToOne;
import jakarta.persistence.PrePersist;
import jakarta.persistence.PreUpdate;
import jakarta.persistence.Table;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.AccessLevel;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.io.Serializable;
import java.time.Instant;
import java.util.Base64;

@Entity
@Table(name = "context_key")
@Getter
@EqualsAndHashCode(of = {"keyType", "value", "modifiedDate"})
@NoArgsConstructor
public class ContextKey implements Serializable {

    @Id
    @Column
    private String keyType;

    @NotNull
    @Setter(AccessLevel.PACKAGE)
    @Size(max = 1024)
    @Column(name = "jhi_value", nullable = false, length = 1024)
    private String value;

    @NotNull
    @Column(nullable = false)
    private Instant modifiedDate;

    @OneToOne(optional = false, fetch = FetchType.EAGER)
    private WrappingKey wrappingKey;

    private ContextKey(String wrappedContextKey, WrappingKey wrappingKey) {
        this.value = wrappedContextKey;
        this.keyType = ContextKeyType.ACTUAL.name();
        this.wrappingKey = wrappingKey;
    }

    @PrePersist
    @PreUpdate
    protected void onSave() {
        modifiedDate = Instant.now();
    }

    public static ContextKey from(byte[] secretKeyBytes, WrappingKey wrappingKey) {
        return new ContextKey(Base64.getEncoder().encodeToString(secretKeyBytes), wrappingKey);
    }

    public byte[] decoded() {
        return Base64.getDecoder().decode(value);
    }

}
