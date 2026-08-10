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

import com.intel.bkp.bkps.domain.AppUser;
import com.intel.bkp.bkps.domain.Authority;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

/**
 * Spring Data JPA repository for the AppUser entity.
 */
@Repository
public interface UserRepository extends JpaRepository<AppUser, Long> {

    @EntityGraph(attributePaths = "authorities")
    Optional<AppUser> findOneWithAuthoritiesByFingerprint(String fingerprint);

    @EntityGraph(attributePaths = "authorities")
    Optional<AppUser> findOneWithAuthoritiesById(Long id);

    @Query("SELECT DISTINCT entity FROM AppUser entity LEFT JOIN FETCH entity.authorities ORDER BY entity.id DESC")
    List<AppUser> getAllWithAuthorities();

    boolean existsByAuthoritiesContainingAndIdNot(Authority authority, Long userId);

    boolean existsByFingerprint(String fingerprint);

    List<AppUser> getAllByAuthoritiesContaining(Authority authority);
}
