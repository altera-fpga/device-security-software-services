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

import com.intel.bkp.core.manufacturing.model.PufType;
import jakarta.persistence.CascadeType;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.OneToOne;
import jakarta.persistence.SequenceGenerator;
import jakarta.persistence.Table;
import jakarta.validation.constraints.Size;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

import java.io.Serializable;

/**
 * A ServiceConfiguration.
 */
@Entity
@Table(name = "service_configuration")
@Getter
@Setter
@EqualsAndHashCode(of = {"id", "name", "pufType"})
@ToString
public class ServiceConfiguration implements Serializable {

    public static final int OVERBUILD_MAX_INFINITE = -1;

    @Id
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "sequenceGenerator")
    @SequenceGenerator(name = "sequenceGenerator")
    private Long id;

    @Size(max = 255)
    @Column(nullable = false)
    private String name;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private PufType pufType;

    @Column
    private int overbuildMax;

    @Column
    private int overbuildCurrent;

    @Column
    private boolean requireIidUds = true;

    @Column
    private boolean testModeSecrets = false;

    @Size
    @Column
    private String corimUrl;

    @Column
    private boolean autoFetchFirmwareCorim = true;

    @Column
    private Long appraisalPolicyId = 0L;

    @OneToOne(cascade = CascadeType.ALL, orphanRemoval = true)
    @JoinColumn(unique = true)
    private AttestationConfiguration attestationConfig;

    @OneToOne(cascade = CascadeType.ALL, orphanRemoval = true, optional = false)
    @JoinColumn(unique = true)
    private ConfidentialData confidentialData;

    public ServiceConfiguration name(String name) {
        this.name = name;
        return this;
    }

    public ServiceConfiguration pufType(PufType pufType) {
        this.pufType = pufType;
        return this;
    }

    public ServiceConfiguration overbuildMax(Integer overbuildMax) {
        this.overbuildMax = overbuildMax;
        return this;
    }

    public ServiceConfiguration overbuildCurrent(Integer overbuildCurrent) {
        this.overbuildCurrent = overbuildCurrent;
        return this;
    }

    public ServiceConfiguration requireIidUds(boolean requireIidUds) {
        this.requireIidUds = requireIidUds;
        return this;
    }

    public ServiceConfiguration attestationConfig(AttestationConfiguration attestationConfiguration) {
        this.attestationConfig = attestationConfiguration;
        return this;
    }

    public ServiceConfiguration confidentialData(ConfidentialData confidentialData) {
        this.confidentialData = confidentialData;
        return this;
    }

    public ServiceConfiguration autoFetchFirmwareCorim(boolean autoFetchFirmwareCorim) {
        this.autoFetchFirmwareCorim = autoFetchFirmwareCorim;
        return this;
    }

    public ServiceConfiguration appraisalPolicyId(Long id) {
        if (id != null) {
            this.appraisalPolicyId = id;
        }
        return this;
    }
}
