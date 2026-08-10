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

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.intel.bkp.bkps.security.AuthoritiesConstants;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.JoinTable;
import jakarta.persistence.ManyToMany;
import jakarta.persistence.SequenceGenerator;
import jakarta.persistence.Table;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import org.hibernate.annotations.BatchSize;

import java.io.Serializable;
import java.time.Instant;
import java.util.HashSet;
import java.util.Set;

@Getter
@Setter
@Entity
@Table(name = "app_user")
@ToString
public class AppUser implements Serializable {

    @Id
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "sequenceGenerator")
    @SequenceGenerator(name = "sequenceGenerator")
    private Long id;

    @NotNull
    @Pattern(regexp = "^[_.@A-Za-z0-9-]*$")
    @Size(min = 1, max = 50)
    @Column(length = 50, unique = true, nullable = false)
    private String login;

    @JsonIgnore
    @NotNull
    @Column(nullable = false)
    private String fingerprint;

    @JsonIgnore
    @ManyToMany
    @JoinTable(
        name = "app_user_authority",
        joinColumns = {@JoinColumn(name = "user_id", referencedColumnName = "id")},
        inverseJoinColumns = {@JoinColumn(name = "authority_name", referencedColumnName = "name")})
    @BatchSize(size = 20)
    private Set<Authority> authorities = new HashSet<>();

    public AppUser generateLogin() {
        this.login = ("user_" + Instant.now().toEpochMilli()).toLowerCase();
        return this;
    }

    public AppUser fingerprint(String fingerprint) {
        this.fingerprint = fingerprint;
        return this;
    }

    public AppUser assignDefaultRole(boolean isInitial) {
        if (isInitial) {
            assignDefaultSuperAdminRole();
        }
        return this;
    }

    private void assignDefaultSuperAdminRole() {
        final HashSet<Authority> authoritiesSet = new HashSet<>();
        authoritiesSet.add(Authority.from(AuthoritiesConstants.SUPER_ADMIN));
        this.authorities = authoritiesSet;
    }
}
