package com.simpath.app.auth.controller;

import com.simpath.app.auth.dto.*;
import com.simpath.app.auth.service.AuthService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final AuthService auth;

    public AuthController(AuthService auth) {
        this.auth = auth;
    }

    @PostMapping("/register")
    public void register(@Valid @RequestBody RegisterRequest req) {
        auth.register(req);
    }

    @PostMapping("/login")
    public AuthResponse login(@Valid @RequestBody LoginRequest req, HttpServletRequest http) {
        return auth.login(req, http.getHeader("User-Agent"), http.getRemoteAddr());
    }

    @PostMapping("/refresh")
    public AuthResponse refresh(@Valid @RequestBody RefreshRequest req, HttpServletRequest http) {
        return auth.refresh(req, http.getHeader("User-Agent"), http.getRemoteAddr());
    }

    @PostMapping("/logout")
    public void logout(@Valid @RequestBody LogoutRequest req, HttpServletRequest http) {
        auth.logout(req, http.getHeader("User-Agent"), http.getRemoteAddr());
    }

    @PostMapping("/logout-all")
    public void logoutAll(@Valid @RequestBody LogoutRequest req, HttpServletRequest http) {
        auth.logoutAll(req, http.getHeader("User-Agent"), http.getRemoteAddr());
    }

}