package com.catalis.idp.adapter.impl;

import com.catalis.idp.adapter.IdpAdapter;
import com.catalis.idp.dtos.*;
import org.springframework.http.ResponseEntity;
import reactor.core.publisher.Mono;

import java.util.List;

public class IdpAdapterImpl implements IdpAdapter {

    @Override
    public Mono<ResponseEntity<TokenResponse>> login(LoginRequest request) {
        return null;
    }

    @Override
    public Mono<ResponseEntity<TokenResponse>> refresh(RefreshRequest request) {
        return null;
    }

    @Override
    public void logout(String accessToken) {

    }

    @Override
    public Mono<ResponseEntity<IntrospectionResponse>> introspect(String accessToken) {
        return null;
    }

    @Override
    public Mono<ResponseEntity<UserInfoResponse>> getUserInfo(String accessToken) {
        return null;
    }

    @Override
    public Mono<ResponseEntity<CreateUserResponse>> createUser(CreateUserRequest request) {
        return null;
    }

    @Override
    public void changePassword(ChangePasswordRequest request) {

    }

    @Override
    public void resetPassword(String username) {

    }

    @Override
    public Mono<ResponseEntity<MfaChallengeResponse>> mfaChallenge(String username) {
        return null;
    }

    @Override
    public void mfaVerify(MfaVerifyRequest request) {

    }

    @Override
    public void revokeRefreshToken(String refreshToken) {

    }

    @Override
    public Mono<ResponseEntity<List<SessionInfo>>> listSessions(String userId) {
        return null;
    }

    @Override
    public void revokeSession(String sessionId) {

    }

    @Override
    public Mono<ResponseEntity<List<String>>> getRoles(String userId) {
        return null;
    }
}
