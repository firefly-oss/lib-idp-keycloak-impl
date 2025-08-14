package com.catalis.idp.adapter.service.impl;

import com.catalis.idp.adapter.dtos.ExtendedTokenResponse;
import com.catalis.idp.adapter.keycloak.KeycloakClientFactory;
import com.catalis.idp.adapter.service.IdpUserService;
import com.catalis.idp.dtos.*;
import jakarta.ws.rs.WebApplicationException;
import org.keycloak.TokenVerifier;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.AccessTokenResponse;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Service
public class IdpUserServiceImpl implements IdpUserService {

    private final KeycloakClientFactory keycloakFactory;

    public IdpUserServiceImpl(KeycloakClientFactory keycloakFactory) {
        this.keycloakFactory = keycloakFactory;
    }

    @Override
    public Mono<ResponseEntity<TokenResponse>> login(LoginRequest request) {
        return Mono.fromCallable(() -> doLogin(request))
                .map(ResponseEntity::ok)
                .onErrorResume(throwable -> {
                    if (throwable instanceof WebApplicationException wae && wae.getResponse() != null) {
                        int status = wae.getResponse().getStatus();
                        return Mono.just(ResponseEntity.status(status).build());
                    }
                    return Mono.just(ResponseEntity.internalServerError().build());
                });
    }

    @Override
    public Mono<ResponseEntity<TokenResponse>> refresh(RefreshRequest request) {
        return Mono.fromCallable(this::doRefresh)
                .map(ResponseEntity::ok)
                .onErrorResume(throwable -> {
                    if (throwable instanceof WebApplicationException wae && wae.getResponse() != null) {
                        int status = wae.getResponse().getStatus();
                        return Mono.just(ResponseEntity.status(status).build());
                    }
                    return Mono.just(ResponseEntity.internalServerError().build());
                });
    }

    @Override
    public Mono<Void> logout(String accessToken) {
        return Mono.fromRunnable(() -> {
            try {
                AccessToken token = TokenVerifier.create(accessToken, AccessToken.class).getToken();
                String sessionId = token.getSessionId();
                String userId = token.getSubject();

                try (Keycloak keycloak = keycloakFactory.baseClient()) {
                    String realm = keycloakFactory.getRealm();
                    if (sessionId != null && !sessionId.isBlank()) {
                        keycloak.realm(realm).deleteSession(sessionId, false);
                    } else if (userId != null && !userId.isBlank()) {
                        keycloak.realm(realm).users().get(userId).logout();
                    }
                }
            } catch (WebApplicationException wae) {
                throw wae;
            } catch (Throwable ex) {
                throw new WebApplicationException(ex.getMessage(), ex);
            }
        });
    }

    @Override
    public Mono<ResponseEntity<IntrospectionResponse>> introspect(String accessToken) {
        // Not implemented yet in original code
        return null;
    }

    @Override
    public Mono<ResponseEntity<UserInfoResponse>> getUserInfo(String accessToken) {
        return Mono.fromCallable(() -> {
            org.keycloak.representations.idm.UserRepresentation user;
            try (Keycloak keycloak = keycloakFactory.baseClient()) {
                AccessToken token = TokenVerifier.create(accessToken, AccessToken.class).getToken();
                String userId = token.getSubject();
                user = keycloak.realm(keycloakFactory.getRealm()).users().get(userId).toRepresentation();
            }

            if (user == null) {
                return ResponseEntity.notFound().build();
            }

            UserInfoResponse userInfo = new UserInfoResponse(
                    user.getId(),
                    user.getEmail(),
                    user.isEmailVerified(),
                    user.getFirstName() + " " + user.getLastName(),
                    user.getUsername(),
                    user.getFirstName(),
                    user.getLastName()
            );

            return ResponseEntity.ok(userInfo);
        });
    }

    @Override
    public Mono<Void> revokeRefreshToken(String refreshToken) {
        return Mono.fromRunnable(() -> {
            try {
                // Decode the refresh token
                AccessToken token = TokenVerifier.create(refreshToken, AccessToken.class).getToken();
                String sessionId = token.getSessionId();
                String userId = token.getSubject();

                try (Keycloak keycloak = keycloakFactory.baseClient()) {
                    String realm = keycloakFactory.getRealm();

                    if (sessionId != null && !sessionId.isBlank()) {
                        // Revoke the specific session
                        keycloak.realm(realm).deleteSession(sessionId, false);
                    } else if (userId != null && !userId.isBlank()) {
                        // If there is no sessionId, perform a full user logout
                        keycloak.realm(realm).users().get(userId).logout();
                    }
                }
            } catch (WebApplicationException wae) {
                throw wae;
            } catch (Throwable ex) {
                throw new WebApplicationException("Error revoking refresh token", ex);
            }
        });
    }

    private TokenResponse doLogin(LoginRequest request) {
        AccessTokenResponse kc;
        try (Keycloak keycloak = keycloakFactory.passwordClient(request.getUsername(), request.getPassword())) {
            kc = keycloak.tokenManager().getAccessToken();
        }

        ExtendedTokenResponse response = new ExtendedTokenResponse();
        response.setAccessToken(kc.getToken());
        response.setRefreshToken(kc.getRefreshToken());
        response.setTokenType(kc.getTokenType());
        response.setExpiresIn(kc.getExpiresIn());
        response.setScope(kc.getScope());

        try {
            response.setRoles(extractRolesFromJwt(kc.getToken()));
        } catch (Throwable ignored) { }

        return response;
    }

    private TokenResponse doRefresh() {
        try {
            AccessTokenResponse response;
            try (Keycloak keycloak = keycloakFactory.refreshToken()) {
                response = keycloak.tokenManager().refreshToken();
            }

            return TokenResponse.builder()
                    .accessToken(response.getToken())
                    .refreshToken(response.getRefreshToken())
                    .expiresIn(response.getExpiresIn())
                    .tokenType(response.getTokenType())
                    .scope(response.getScope())
                    .build();

        } catch (Exception e) {
            throw new RuntimeException("Error refreshing token", e);
        }
    }

    private List<String> extractRolesFromJwt(String jwtAccessToken) {
        try {
            AccessToken accessToken = TokenVerifier.create(jwtAccessToken, AccessToken.class).getToken();

            Stream<String> realmRoles = Stream.ofNullable(accessToken.getRealmAccess())
                    .map(AccessToken.Access::getRoles)
                    .flatMap(Collection::stream);

            Stream<String> clientRoles = Stream.ofNullable(accessToken.getResourceAccess())
                    .map(Map::values)
                    .flatMap(Collection::stream)
                    .map(AccessToken.Access::getRoles)
                    .filter(Objects::nonNull)
                    .flatMap(Collection::stream);

            return Stream.concat(realmRoles, clientRoles)
                    .filter(Objects::nonNull)
                    .collect(Collectors.collectingAndThen(
                            Collectors.toCollection(java.util.LinkedHashSet::new),
                            java.util.List::copyOf));
        } catch (Throwable ignored) {
            return java.util.List.of();
        }
    }
}
