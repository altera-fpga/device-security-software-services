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

package com.intel.bkp.bkps.config;

import com.intel.bkp.bkps.rest.configuration.ConfigurationResource;
import com.intel.bkp.bkps.rest.errors.SecurityProblemHandler;
import com.intel.bkp.bkps.rest.health.HealthResource;
import com.intel.bkp.bkps.rest.initialization.InitializationResource;
import com.intel.bkp.bkps.rest.onboarding.OnboardingResource;
import com.intel.bkp.bkps.rest.prefetching.PrefetchResource;
import com.intel.bkp.bkps.rest.provisioning.ProvisioningResource;
import com.intel.bkp.bkps.rest.user.UserResource;
import com.intel.bkp.bkps.security.AuthoritiesConstants;
import com.intel.bkp.bkps.utils.CertificateManager;
import com.intel.bkp.crypto.CryptoUtils;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.preauth.x509.X509AuthenticationFilter;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;

import static org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher.withDefaults;

@Configuration
@Import(SecurityProblemHandler.class)
@EnableWebSecurity
@EnableMethodSecurity(securedEnabled = true)
@AllArgsConstructor(access = AccessLevel.PACKAGE)
public class SecurityConfiguration {

    private static final PathPatternRequestMatcher.Builder PATH = withDefaults();

    private final UserDetailsService userDetailsService;
    private final SecurityProblemHandler problemHandler;
    private final PasswordEncoder passwordEncoder;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        final AuthenticationManager authenticationManager = getAuthenticationManager(http);
        // @formatter:off
        http
            .cors(Customizer.withDefaults())
            .csrf(csrf -> csrf.ignoringRequestMatchers("/h2-console/**").disable())
            .exceptionHandling(cfg -> cfg.accessDeniedHandler(problemHandler).authenticationEntryPoint(problemHandler))
            .headers(cfg -> cfg.frameOptions(HeadersConfigurer.FrameOptionsConfig::disable))
            .sessionManagement(cfg -> cfg.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authenticationManager(authenticationManager)
            .authorizeHttpRequests(authz ->
                authz
                .requestMatchers(PATH.matcher("/*.ico"))
                    .permitAll()
                .requestMatchers(PATH.matcher("/"))
                    .permitAll()
                .requestMatchers(PATH.matcher("/index.html"))
                    .permitAll()
                .requestMatchers(PATH.matcher("/h2-console/**"))
                    .permitAll()
                .requestMatchers(PATH.matcher("/api-docs.yaml"))
                    .permitAll()
                .requestMatchers(PATH.matcher(HealthResource.HEALTH))
                    .permitAll()
                .requestMatchers(PATH.matcher(HealthResource.SLA_HEALTH))
                    .permitAll()
                .requestMatchers(PATH.matcher(HealthResource.STATUS_HEALTH))
                    .permitAll()
                .requestMatchers(PATH.matcher(UserResource.CREATE_USER))
                    .permitAll()
                .requestMatchers(PATH.matcher(InitializationResource.INIT_NODE + "/**"))
                    .hasAuthority(AuthoritiesConstants.SUPER_ADMIN)
                .requestMatchers(PATH.matcher(ConfigurationResource.CONFIG_NODE + "/**"))
                    .hasAnyAuthority(AuthoritiesConstants.ADMIN, AuthoritiesConstants.SUPER_ADMIN)
                .requestMatchers(PATH.matcher(UserResource.USER_NODE + UserResource.CERTIFICATE_NODE + "/**"))
                    .hasAnyAuthority(AuthoritiesConstants.ADMIN, AuthoritiesConstants.SUPER_ADMIN)
                .requestMatchers(PATH.matcher(UserResource.USER_NODE + UserResource.SET_ROLE))
                    .hasAnyAuthority(AuthoritiesConstants.ADMIN, AuthoritiesConstants.SUPER_ADMIN)
                .requestMatchers(PATH.matcher(HttpMethod.POST, UserResource.USER_NODE + UserResource.MANAGE_NODE))
                    .hasAnyAuthority(AuthoritiesConstants.ADMIN, AuthoritiesConstants.SUPER_ADMIN)
                .requestMatchers(PATH.matcher(HttpMethod.GET, UserResource.USER_NODE + UserResource.MANAGE_NODE))
                    .hasAnyAuthority(AuthoritiesConstants.ADMIN, AuthoritiesConstants.SUPER_ADMIN)
                .requestMatchers(PATH.matcher(UserResource.USER_NODE + "/**"))
                    .hasAuthority(AuthoritiesConstants.SUPER_ADMIN)
                .requestMatchers(PATH.matcher(HttpMethod.POST, OnboardingResource.PREFETCH_NEXT))
                    .hasAuthority(AuthoritiesConstants.PROGRAMMER)
                .requestMatchers(PATH.matcher(HttpMethod.POST, PrefetchResource.PREFETCH_NODE
                    + PrefetchResource.PREFETCH_DEVICES))
                    .hasAnyAuthority(AuthoritiesConstants.ADMIN, AuthoritiesConstants.SUPER_ADMIN)
                .requestMatchers(PATH.matcher(HttpMethod.GET, OnboardingResource.PREFETCH_STATUS))
                    .hasAnyAuthority(AuthoritiesConstants.ADMIN, AuthoritiesConstants.SUPER_ADMIN,
                        AuthoritiesConstants.PROGRAMMER)
                .requestMatchers(PATH.matcher(HttpMethod.POST, OnboardingResource.SET_AUTHORITY))
                    .hasAuthority(AuthoritiesConstants.PROGRAMMER)
                .requestMatchers(PATH.matcher(HttpMethod.POST, OnboardingResource.PUF_ACTIVATE))
                    .hasAuthority(AuthoritiesConstants.PROGRAMMER)
                .requestMatchers(PATH.matcher(HttpMethod.POST, ProvisioningResource.PROVISIONING_NODE + "/**"))
                    .hasAuthority(AuthoritiesConstants.PROGRAMMER))
            .x509(cfg -> cfg.x509AuthenticationFilter(x509AuthenticationFilter(authenticationManager)))
            .authorizeHttpRequests(cfg -> cfg.anyRequest().denyAll());
        return http.build();
        // @formatter:on
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration)
        throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    private AuthenticationManager getAuthenticationManager(HttpSecurity http) throws Exception {
        final AuthenticationManagerBuilder builder = http.getSharedObject(AuthenticationManagerBuilder.class);
        builder.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder);
        return builder.build();
    }

    private X509AuthenticationFilter x509AuthenticationFilter(AuthenticationManager authenticationManager) {
        final X509AuthenticationFilter filter = new X509AuthenticationFilter();
        filter.setAuthenticationManager(authenticationManager);
        filter.setPrincipalExtractor(
            cert -> CryptoUtils.generateFingerprint(CertificateManager.getCertificateContent(cert))
        );
        return filter;
    }
}
