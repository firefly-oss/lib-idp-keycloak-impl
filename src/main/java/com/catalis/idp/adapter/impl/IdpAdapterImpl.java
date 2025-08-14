package com.catalis.idp.adapter.impl;

import com.catalis.idp.adapter.IdpAdapter;
import com.catalis.idp.adapter.service.IdpAdminService;
import com.catalis.idp.adapter.service.IdpUserService;
import com.catalis.idp.dtos.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.util.List;

@Service
public class IdpAdapterImpl implements IdpAdapter {

    private final IdpUserService userService;
    private final IdpAdminService adminService;

    @Autowired
    public IdpAdapterImpl(IdpUserService userService, IdpAdminService adminService) {
        this.userService = userService;
        this.adminService = adminService;
    }

    @Override
    public Mono<ResponseEntity<TokenResponse>> login(LoginRequest request) {
        return userService.login(request);
    }

    @Override
    public Mono<ResponseEntity<TokenResponse>> refresh(RefreshRequest request) {
        return userService.refresh(request);
    }

    @Override
    public Mono<Void> logout(String accessToken) {
        return userService.logout(accessToken);
    }

    @Override
    public Mono<ResponseEntity<IntrospectionResponse>> introspect(String accessToken) {
        return userService.introspect(accessToken);
    }

    @Override
    public Mono<ResponseEntity<UserInfoResponse>> getUserInfo(String accessToken) {
        return userService.getUserInfo(accessToken);
    }

    @Override
    public Mono<ResponseEntity<CreateUserResponse>> createUser(CreateUserRequest request) {
        return adminService.createUser(request);
    }

    @Override
    public Mono<Void> changePassword(ChangePasswordRequest request) {
        return adminService.changePassword(request);
    }

    @Override
    public Mono<Void> resetPassword(String username) {
        return adminService.resetPassword(username);
    }

    @Override
    public Mono<ResponseEntity<MfaChallengeResponse>> mfaChallenge(String username) {
        return adminService.mfaChallenge(username);
    }

    @Override
    public Mono<Void> mfaVerify(MfaVerifyRequest request) {
        return adminService.mfaVerify(request);
    }

    @Override
    public Mono<Void> revokeRefreshToken(String refreshToken) {
        return userService.revokeRefreshToken(refreshToken);
    }

    @Override
    public Mono<ResponseEntity<List<SessionInfo>>> listSessions(String userId) {
        return adminService.listSessions(userId);
    }

    @Override
    public Mono<Void> revokeSession(String sessionId) {
        return adminService.revokeSession(sessionId);
    }

    @Override
    public Mono<ResponseEntity<List<String>>> getRoles(String userId) {
        return adminService.getRoles(userId);
    }

    @Override
    public Mono<Void> deleteUser(String userId) {
        return adminService.deleteUser(userId);
    }

    @Override
    public Mono<ResponseEntity<UpdateUserResponse>> updateUser(UpdateUserRequest request) {
        return adminService.updateUser(request);
    }

    @Override
    public Mono<ResponseEntity<CreateRolesResponse>> createRoles(CreateRolesRequest request) {
        return adminService.createRoles(request);
    }

    @Override
    public Mono<ResponseEntity<CreateScopeResponse>> createScope(CreateScopeRequest request) {
        return adminService.createScope(request);
    }

    @Override
    public Mono<Void> assignRolesToUser(AssignRolesRequest request) {
        return adminService.assignRolesToUser(request);
    }

    @Override
    public Mono<Void> removeRolesFromUser(AssignRolesRequest request) {
        return adminService.removeRolesFromUser(request);
    }
}
