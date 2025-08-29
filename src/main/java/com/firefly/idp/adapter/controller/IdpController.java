package com.firefly.idp.adapter.controller;

import com.firefly.idp.adapter.IdpAdapter;
import com.firefly.idp.dtos.*;
import lombok.extern.java.Log;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

import java.util.List;

@RestController
@RequestMapping("/idp")
@Slf4j
public class IdpController {

    private final IdpAdapter idpAdapter;

    @Autowired
    public IdpController(IdpAdapter idpAdapter) {
        this.idpAdapter = idpAdapter;
    }

    private String mask(String token) {
        if (token == null) return "null";
        int len = token.length();
        int show = Math.min(6, len);
        return token.substring(0, show) + "***" + "(len=" + len + ")";
    }

    // User endpoints
    @PostMapping("/login")
    public Mono<ResponseEntity<TokenResponse>> login(@RequestBody LoginRequest request) {
        log.info("POST /idp/login - username={}", request.getUsername());
        return idpAdapter.login(request);
    }

    @PostMapping("/refresh")
    public Mono<ResponseEntity<TokenResponse>> refresh(@RequestBody RefreshRequest request) {
        log.info("POST /idp/refresh - refreshToken={}", mask(request.getRefreshToken()));
        return idpAdapter.refresh(request);
    }

    @PostMapping("/logout")
    public Mono<Void> logout(@RequestBody LogoutRequest request) {
        log.info("POST /idp/logout - refreshToken={}", mask(request.getRefreshToken()));
        return idpAdapter.logout(request);
    }

    @GetMapping("/introspect")
    public Mono<ResponseEntity<IntrospectionResponse>> introspect(@RequestHeader("Authorization") String accessToken) {
        log.info("GET /idp/introspect - accessToken={}", mask(accessToken));
        return idpAdapter.introspect(accessToken);
    }

    @GetMapping("/userinfo")
    public Mono<ResponseEntity<UserInfoResponse>> getUserInfo(@RequestHeader("Authorization") String accessToken) {
        log.info("GET /idp/userinfo - accessToken={}", mask(accessToken));
        return idpAdapter.getUserInfo(accessToken);
    }

    @PostMapping("/revoke-refresh-token")
    public Mono<Void> revokeRefreshToken(@RequestParam("refreshToken") String refreshToken) {
        log.info("POST /idp/revoke-refresh-token - refreshToken={}", mask(refreshToken));
        return idpAdapter.revokeRefreshToken(refreshToken);
    }

    // Admin endpoints (simple testing endpoints)
    @PostMapping("/admin/users")
    public Mono<ResponseEntity<CreateUserResponse>> createUser(@RequestBody CreateUserRequest request) {
        log.info("POST /idp/admin/users - username={}, email={}", request.getUsername(), request.getEmail());
        return idpAdapter.createUser(request);
    }

    @PostMapping("/admin/password")
    public Mono<Void> changePassword(@RequestBody ChangePasswordRequest request) {
        log.info("POST /idp/admin/password - userId={}", request.getUserId());
        return idpAdapter.changePassword(request);
    }

    @PostMapping("/admin/password/reset")
    public Mono<Void> resetPassword(@RequestParam("username") String username) {
        log.info("POST /idp/admin/password/reset - username={}", username);
        return idpAdapter.resetPassword(username);
    }

    @PostMapping("/admin/mfa/challenge")
    public Mono<ResponseEntity<MfaChallengeResponse>> mfaChallenge(@RequestParam("username") String username) {
        log.info("POST /idp/admin/mfa/challenge - username={}", username);
        return idpAdapter.mfaChallenge(username);
    }

    @PostMapping("/admin/mfa/verify")
    public Mono<Void> mfaVerify(@RequestBody MfaVerifyRequest request) {
        log.info("POST /idp/admin/mfa/verify - userId={}", request.getUserId());
        return idpAdapter.mfaVerify(request);
    }

    @GetMapping("/admin/users/{userId}/sessions")
    public Mono<ResponseEntity<List<SessionInfo>>> listSessions(@PathVariable("userId") String userId) {
        log.info("GET /idp/admin/users/{}/sessions", userId);
        return idpAdapter.listSessions(userId);
    }

    @DeleteMapping("/admin/sessions/{sessionId}")
    public Mono<Void> revokeSession(@PathVariable("sessionId") String sessionId) {
        log.info("DELETE /idp/admin/sessions/{}", sessionId);
        return idpAdapter.revokeSession(sessionId);
    }

    @GetMapping("/admin/users/{userId}/roles")
    public Mono<ResponseEntity<List<String>>> getRoles(@PathVariable("userId") String userId) {
        log.info("GET /idp/admin/users/{}/roles", userId);
        return idpAdapter.getRoles(userId);
    }

    @DeleteMapping("/admin/users/{userId}")
    public Mono<Void> deleteUser(@PathVariable("userId") String userId) {
        log.info("DELETE /idp/admin/users/{}", userId);
        return idpAdapter.deleteUser(userId);
    }

    @PutMapping("/admin/users")
    public Mono<ResponseEntity<UpdateUserResponse>> updateUser(@RequestBody UpdateUserRequest request) {
        log.info("PUT /idp/admin/users - userId={}", request.getUserId());
        return idpAdapter.updateUser(request);
    }

    @PostMapping("/admin/roles")
    public Mono<ResponseEntity<CreateRolesResponse>> createRoles(@RequestBody CreateRolesRequest request) {
        log.info("POST /idp/admin/roles - count={}", request.getRoleNames() == null ? 0 : request.getRoleNames().size());
        return idpAdapter.createRoles(request);
    }

    @PostMapping("/admin/scopes")
    public Mono<ResponseEntity<CreateScopeResponse>> createScope(@RequestBody CreateScopeRequest request) {
        log.info("POST /idp/admin/scopes - name={}", request.getName());
        return idpAdapter.createScope(request);
    }

    @PostMapping("/admin/users/roles/assign")
    public Mono<Void> assignRolesToUser(@RequestBody AssignRolesRequest request) {
        log.info("POST /idp/admin/users/roles/assign - userId={}, count={}", request.getUserId(), request.getRoleNames() == null ? 0 : request.getRoleNames().size());
        return idpAdapter.assignRolesToUser(request);
    }

    @PostMapping("/admin/users/roles/remove")
    public Mono<Void> removeRolesFromUser(@RequestBody AssignRolesRequest request) {
        log.info("POST /idp/admin/users/roles/remove - userId={}, count={}", request.getUserId(), request.getRoleNames() == null ? 0 : request.getRoleNames().size());
        return idpAdapter.removeRolesFromUser(request);
    }
}
