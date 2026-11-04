package com.simpath.app.config;

import com.simpath.app.token.token.JwtAuthFilter;
import com.simpath.app.security.RateLimitFilter;
import com.simpath.app.security.RateLimitService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final JwtAuthFilter jwtAuthFilter;
    private final RateLimitService rateLimits;

    public SecurityConfig(JwtAuthFilter jwtAuthFilter, RateLimitService rateLimits) {
        this.jwtAuthFilter = jwtAuthFilter;
        this.rateLimits = rateLimits;
    }

    @Bean
    SecurityFilterChain filterChain(HttpSecurity http, com.simpath.app.security.ClientAddressResolver addresses, com.simpath.app.common.ApiErrorWriter errors) throws Exception {
        return http
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(
                                "/v3/api-docs/**",
                                "/swagger-ui/**",
                                "/swagger-ui.html",
                                "/auth/**",
                                "/actuator/health"
                        ).permitAll()
                        .anyRequest().authenticated()
                )
                .exceptionHandling(exceptions -> exceptions
                        .authenticationEntryPoint((request, response, ex) ->
                                errors.write(request, response, 401, "UNAUTHORIZED", "Authentication required."))
                        .accessDeniedHandler((request, response, ex) ->
                                errors.write(request, response, 403, "FORBIDDEN", "Access denied.")))
                .httpBasic(AbstractHttpConfigurer::disable)
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class)
                .addFilterBefore(new RateLimitFilter(rateLimits, addresses, errors), JwtAuthFilter.class)
                .build();
    }
}



