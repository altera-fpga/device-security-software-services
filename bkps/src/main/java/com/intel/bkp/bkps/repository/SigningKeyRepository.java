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

package com.intel.bkp.bkps.repository;

import com.intel.bkp.bkps.domain.SigningKeyEntity;
import com.intel.bkp.bkps.domain.SigningKeyEntity_;
import com.intel.bkp.bkps.domain.enumeration.SigningKeyStatus;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.List;

@Repository
public interface SigningKeyRepository extends JpaRepository<SigningKeyEntity, Long>,
    JpaSpecificationExecutor<SigningKeyEntity> {

    default Specification<SigningKeyEntity> getEnabled() {
        return (root, query, cb) -> cb.equal(root.get(SigningKeyEntity_.status), SigningKeyStatus.ENABLED);
    }

    default Specification<SigningKeyEntity> findAllNotEnabled() {
        return (root, query, cb) -> cb.notEqual(root.get(SigningKeyEntity_.status), SigningKeyStatus.ENABLED);
    }

    default Specification<SigningKeyEntity> getOlderOrEqualToTime(Instant createdDate) {
        return (root, query, cb) -> cb.lessThanOrEqualTo(root.get(SigningKeyEntity_.createdAt), createdDate);
    }

    default Specification<SigningKeyEntity> notIn(List<Long> ids) {
        return (root, query, cb) -> root.get(SigningKeyEntity_.id).in(ids).not();
    }
}
