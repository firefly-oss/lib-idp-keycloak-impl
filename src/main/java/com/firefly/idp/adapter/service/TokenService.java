package com.firefly.idp.adapter.service;

import org.keycloak.representations.AccessToken;

import java.util.List;
import java.util.Optional;

public interface TokenService {
    Optional<AccessToken> parseAccessToken(String tokenString);

    Optional<String> extractUserId(String tokenString);

    Optional<String> extractSessionId(String tokenString);

    List<String> extractRoles(String jwtAccessToken);

    List<String> extractRolesFromAccessToken(AccessToken accessToken);

    boolean isTokenExpired(String tokenString);
}
