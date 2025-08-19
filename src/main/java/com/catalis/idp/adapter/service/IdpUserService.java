package com.catalis.idp.adapter.service;

import com.catalis.idp.dtos.*;
import org.springframework.http.ResponseEntity;
import reactor.core.publisher.Mono;

public interface IdpUserService {

    Mono<ResponseEntity<TokenResponse>> login(LoginRequest request);

    Mono<ResponseEntity<TokenResponse>> refresh(RefreshRequest request);

    Mono<Void> logout(LogoutRequest request);

    Mono<ResponseEntity<IntrospectionResponse>> introspect(String accessToken);

    Mono<ResponseEntity<UserInfoResponse>> getUserInfo(String accessToken);

    Mono<Void> revokeRefreshToken(String refreshToken);
}
