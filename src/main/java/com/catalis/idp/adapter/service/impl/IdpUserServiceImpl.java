package com.catalis.idp.adapter.service.impl;

import com.catalis.idp.adapter.exception.KeycloakExceptionHandler;
import com.catalis.idp.adapter.keycloak.KeycloakAPIFactory;
import com.catalis.idp.adapter.service.IdpUserService;
import com.catalis.idp.dtos.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.BodyInserters;
import reactor.core.publisher.Mono;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.Map;

@Service
@Slf4j
public class IdpUserServiceImpl implements IdpUserService {

    private final KeycloakAPIFactory keycloakAPIFactory;

    public IdpUserServiceImpl(KeycloakAPIFactory keycloakAPIFactory) {
        this.keycloakAPIFactory = keycloakAPIFactory;
    }

    @Override
    public Mono<ResponseEntity<TokenResponse>> login(LoginRequest request) {
        return keycloakAPIFactory.tokenWebClient()
                .post()
                .uri("/token")
                .header("Content-Type", "application/x-www-form-urlencoded")
                .body(BodyInserters.fromFormData(keycloakAPIFactory.passwordGrantBody(request)))
                .retrieve()
                .bodyToMono(TokenResponse.class)
                .map(ResponseEntity::ok)
                .onErrorResume(throwable -> Mono.just(KeycloakExceptionHandler.handleException(throwable)));
    }

    @Override
    public Mono<ResponseEntity<TokenResponse>> refresh(RefreshRequest request) {
        return keycloakAPIFactory.tokenWebClient()
                .post()
                .uri("/token")
                .header("Content-Type", "application/x-www-form-urlencoded")
                .body(BodyInserters.fromFormData(keycloakAPIFactory.refreshTokenBody(request.getRefreshToken())))
                .retrieve()
                .bodyToMono(TokenResponse.class)
                .map(ResponseEntity::ok)
                .onErrorResume(throwable -> Mono.just(KeycloakExceptionHandler.handleException(throwable)));
    }

    @Override
    public Mono<Void> logout(String accessToken) {
        return keycloakAPIFactory.tokenWebClient()
                .post()
                .uri("/logout")
                .header("Authorization", accessToken)
                .header("Content-Type", "application/x-www-form-urlencoded")
                .body(BodyInserters.fromFormData(keycloakAPIFactory.logoutBody()))
                .retrieve()
                .toBodilessEntity()
                .then()
                .onErrorResume(throwable -> {
                    log.warn("Error calling logout endpoint", throwable);
                    return Mono.empty();
                });

    }

    @Override
    public Mono<ResponseEntity<IntrospectionResponse>> introspect(String accessToken) {
        // Extract raw token in case the header value includes the "Bearer " prefix
        String rawToken = accessToken;
        if (rawToken != null && rawToken.toLowerCase().startsWith("bearer ")) {
            rawToken = rawToken.substring(7).trim();
        }

        return keycloakAPIFactory.tokenWebClient()
                .post()
                .uri("/token/introspect")
                .header("Content-Type", "application/x-www-form-urlencoded")
                .body(BodyInserters.fromFormData(keycloakAPIFactory.introspectionBody(rawToken)))
                .retrieve()
                .bodyToMono(IntrospectionResponse.class)
                .map(ResponseEntity::ok)
                .onErrorResume(throwable -> Mono.just(KeycloakExceptionHandler.handleException(throwable)));
    }

    @Override
    public Mono<ResponseEntity<UserInfoResponse>> getUserInfo(String accessToken) {
        return keycloakAPIFactory.tokenWebClient()
                .get()
                .uri("/userinfo")
                .header("Authorization", accessToken)
                .retrieve()
                .bodyToMono(UserInfoResponse.class)
                .map(ResponseEntity::ok)
                .onErrorResume(throwable -> Mono.just(KeycloakExceptionHandler.handleException(throwable)));
    }

    @Override
    public Mono<Void> revokeRefreshToken(String refreshToken) {
        return keycloakAPIFactory.tokenWebClient()
                .post()
                .uri("/token/revocation")
                .header("Content-Type", "application/x-www-form-urlencoded")
                .body(BodyInserters.fromFormData(keycloakAPIFactory.revocationBody(refreshToken)))
                .retrieve()
                .toBodilessEntity()
                .then()
                .onErrorResume(throwable -> {
                    log.warn("Error calling token revocation endpoint", throwable);
                    return Mono.empty();
                });

    }

}
