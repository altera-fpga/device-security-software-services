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

package com.intel.bkp.bkps.rest.onboarding.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.intel.bkp.bkps.domain.enumeration.FamilyExtended;
import com.intel.bkp.fpgacerts.model.Family;
import com.intel.bkp.fpgacerts.utils.DeviceIdUtil;
import com.intel.bkp.fpgacerts.utils.SkiHelper;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.apache.commons.lang3.StringUtils;

import java.io.Serializable;
import java.util.Optional;

import static com.intel.bkp.fpgacerts.utils.ToStringUtils.includeIfNonNull;
import static com.intel.bkp.utils.HexConverter.fromHex;

@NoArgsConstructor
@EqualsAndHashCode
@Getter
public class DeviceId implements Serializable {

    private Family family;
    private String uid;
    private String dpUid;
    private String deviceIdentity;
    private String id;

    private DeviceId(Family family, String uid, String dpUid, String deviceIdentity) {
        this.family = family;
        this.uid = uid;
        this.dpUid = dpUid;
        this.deviceIdentity = deviceIdentity;
    }

    private DeviceId(Family family, String uid, String dpUid) {
        this.family = family;
        this.uid = uid;
        this.dpUid = dpUid;
    }

    public static DeviceId instance(Family family, String uid, String deviceIdentity) {
        return new DeviceId(family, uid, getDpUid(family, uid), deviceIdentity);
    }

    public static DeviceId instance(Family family, String uid) {
        return new DeviceId(family, uid, getDpUid(family, uid));
    }

    private static String getDpUid(Family family, String uid) {
        return Family.S10 == family ? uid : DeviceIdUtil.getReversed(uid);
    }

    private static String getPdiForUrl(String deviceIdentity) {
        return SkiHelper.getPdiForUrlFrom(fromHex(deviceIdentity));
    }

    public void setExplicitId(String id) {
        this.id = id;
    }

    public String getId() {
        if (StringUtils.isNotBlank(id)) {
            return id;
        }

        if (StringUtils.isNotBlank(deviceIdentity)) {
            return getPdiForUrl(deviceIdentity);
        }

        return "NO_ID";
    }

    @JsonIgnore
    public Optional<FamilyExtended> getFamilyExtended() {
        return Optional.ofNullable(family)
            .flatMap(FamilyExtended::find);
    }

    @Override
    public String toString() {
        return "DeviceId{"
            + includeIfNonNull("family", family)
            + includeIfNonNull("uid", uid)
            + includeIfNonNull("dpUid", dpUid)
            + includeIfNonNull("deviceIdentity", deviceIdentity)
            + includeIfNonNull("id", id)
            + " }";
    }
}
